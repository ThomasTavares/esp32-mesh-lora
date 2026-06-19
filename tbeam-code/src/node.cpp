#include "Arduino.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <Preferences.h>
#include <RHMesh.h>
#include <RH_RF95.h>
#include <SPI.h>
#include <WiFi.h>
#include <WebServer.h>
#include "cose.h"

#define RH_MESH_MAX_MESSAGE_LEN 200
#define BRIDGE_ADDRESS 1  

// lilygo T3 v2.1.6
// lora SX1276/8
#define LLG_SCK 5
#define LLG_MISO 19
#define LLG_MOSI 27
#define LLG_CS  18
#define LLG_RST 23
#define LLG_DI0 26
#define LLG_DI1 33
#define LLG_DI2 32

#define LLG_LED_GRN 25

Preferences preferences;
uint8_t symmetricKey[32]; // 256-bit AES key

uint8_t nodeAddress;

// Singleton instance of the radio driver
RH_RF95 rf95(LLG_CS, LLG_DI0);

// Class to manage message delivery and receipt, using the driver declared above (temporary address)
RHMesh manager(rf95, 255);

// Initialize WebServer on port 80
WebServer server(80);

// Application-Level Flooding Variables
#define HISTORY_SIZE 10
String messageHistory[HISTORY_SIZE];
uint8_t historyIndex = 0;
uint16_t msgCounter = 0;

bool isMessageNew(String msg) {
    for (int i = 0; i < HISTORY_SIZE; i++)
        if (messageHistory[i] == msg) return false;
    return true;
}

void saveMessage(String msg) {
    messageHistory[historyIndex] = msg;
    historyIndex = (historyIndex + 1) % HISTORY_SIZE;
}

void loadKey() {
    preferences.begin("crypto", true);
    
    if (preferences.getBytesLength("aes_key") == 32) {  // Check if the key length is 32 bytes (256 bits)
        preferences.getBytes("aes_key", symmetricKey, 32);
        Serial.println("[SECURITY] 256-bit AES Master Key successfully loaded from NVS.");
    } else {
        Serial.println("\n[ERROR] CRITICAL SECURITY FAILURE!");
        Serial.println("[ERROR] AES key not found in NVS or invalid length.");
        Serial.println("[ERROR] Verify that the PlatformIO extra_script flashed nvs_key.bin successfully.");
        
        // Halt execution indefinitely to prevent unencrypted transmissions
        while(true) { 
            vTaskDelay(1000 / portTICK_PERIOD_MS); 
        }
    }
    preferences.end();
}

void handleRoot() {
    String html = "<html><head><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"></head><body>";
    html += "<h2>Sistema Armando - Ponto de Acesso " + String(nodeAddress) + "</h2>";
    html += "<form action=\"/send\" method=\"POST\">";
    html += "Mensagem: <input type=\"text\" name=\"msg\" maxlength=\"35\"><br><br>"; // Max length as 35 to leave room for the ID prefix
    html += "<input type=\"submit\" value=\"Enviar\">";
    html += "</form></body></html>";
    server.send(200, "text/html", html);
}

void handleSend() {
    if (server.hasArg("msg")) {
        String originalMsg = server.arg("msg");
        
        // Format: "NodeID_Counter|Message"
        String payload = String(nodeAddress) + "_" + String(msgCounter++) + "|" + originalMsg;

        // Convert plaintext to std::vector for the CoseCrypto class
        std::vector<uint8_t> plaintext(payload.c_str(), payload.c_str() + payload.length());
        std::vector<uint8_t> key(symmetricKey, symmetricKey + 32);
        std::vector<uint8_t> ciphertext;

        // Encrypt payload to CBOR format
        if (CoseCrypto::encrypt(plaintext, key, ciphertext) != ESP_OK) {
            Serial.println("[SECURITY] Falha ao encriptar a mensagem!");
            server.send(500, "text/plain", "Erro interno de criptografia.");
            return;
        }

        // Prevent buffer overflows in the radio driver
        if (ciphertext.size() > RH_MESH_MAX_MESSAGE_LEN) {
            server.send(500, "text/plain", "Mensagem excedeu o limite de bytes após encriptação COSE.");
            return;
        }
        
        Serial.print("Iniciando flood seguro. Tamanho do pacote COSE: ");
        Serial.print(ciphertext.size());
        Serial.println(" bytes.");
        
        // Save to local history to prevent rebroadcasting this message
        saveMessage(payload);
        
        // Send the encrypted vector over the mesh
        uint8_t res = manager.sendtoWait(ciphertext.data(), ciphertext.size(), RH_BROADCAST_ADDRESS);
        
        if (res == RH_ROUTER_ERROR_NONE) {
            server.send(200, "text/plain", "Mensagem segura enviada para a rede.");
        } else {
            server.send(500, "text/plain", "Falha no envio via LoRa. Erro: " + String(res));
        }
    } else {
        server.send(400, "text/plain", "Parâmetro 'msg' ausente.");
    }
}

void setup() {
    Serial.begin(115200);

    // Load the AES key from NVS memory before turning on the radio
    loadKey();

    // Generate unique ID based on MAC Address
    uint8_t mac[6];
    WiFi.macAddress(mac);
    nodeAddress = mac[5];
    
    // Ensure the ID is not the bridge address (1) and not broadcast (255)
    if (nodeAddress == BRIDGE_ADDRESS || nodeAddress == 0 || nodeAddress == 255) {
        nodeAddress = (mac[4] % 253) + 2; 
    }
    
    // Update the mesh manager with the generated ID
    manager.setThisAddress(nodeAddress);

    Serial.print(F("initializing node "));
    Serial.println(nodeAddress);

    // Hardware Reset the LoRa chip
    pinMode(LLG_RST, OUTPUT);
    digitalWrite(LLG_RST, LOW);
    delay(10);
    digitalWrite(LLG_RST, HIGH);
    delay(10);

    // Initialize SPI with the correct pins for T-Beam v0.7
    SPI.begin(LLG_SCK, LLG_MISO, LLG_MOSI, LLG_CS);

    if (!manager.init()) {
        Serial.println(" init failed");
    } else {
        Serial.println(" done");
    }

    // Set power and frequency
    rf95.setTxPower(10, false);
    rf95.setFrequency(915.0);   // Frequency for Brasil (915 MHz)
    rf95.setCADTimeout(500);

    if (!rf95.setModemConfig(RH_RF95::Bw125Cr45Sf128)) {
        Serial.println(F("set config failed"));
    }

    Serial.println("RF95 ready");

    // Start WiFi Access Point
    String ssid = "LoRa_Node_" + String(nodeAddress);
    WiFi.softAP(ssid.c_str(), "disaster123");
    Serial.print("AP IP address: ");
    Serial.println(WiFi.softAPIP());

    // Configure WebServer routes
    server.on("/", HTTP_GET, handleRoot);
    server.on("/send", HTTP_POST, handleSend);
    server.begin();
}

uint8_t buf[RH_MESH_MAX_MESSAGE_LEN];

void loop()
{
    // Handle incoming HTTP requests
    server.handleClient();

    // radio needs to stay always in receive mode
    uint8_t len = sizeof(buf);
    uint8_t from;
    if (manager.recvfromAck(buf, &len, &from))
    {
        // Load the incoming buffer directly into a vector
        std::vector<uint8_t> ciphertext(buf, buf + len);
        std::vector<uint8_t> key(symmetricKey, symmetricKey + 32);
        std::vector<uint8_t> plaintext;

        if (CoseCrypto::decrypt(ciphertext, key, plaintext) == ESP_OK) {
            String receivedPayload((char*)plaintext.data(), plaintext.size());
            
            if (isMessageNew(receivedPayload)) {
                saveMessage(receivedPayload);
                
                int separatorIndex = receivedPayload.indexOf('|');
                String displayMsg = (separatorIndex != -1) ? receivedPayload.substring(separatorIndex + 1) : receivedPayload;
                
                Serial.print("Mensagem decifrada do nó ");
                Serial.print(from);
                Serial.print(": ");
                Serial.print(displayMsg);
                Serial.print(" rssi: ");
                Serial.println(rf95.lastRssi());
                
                manager.sendtoWait(buf, len, RH_BROADCAST_ADDRESS); // Re-broadcast the original ciphertext
            }
        } else {
            Serial.println("[SECURITY] Falha de autenticação. Pacote COSE ignorado ou corrompido.");
        }
    }
}

extern "C" void app_main()
{
    initArduino(); 
    setup();
    while (true) {
        loop();
        vTaskDelay(10 / portTICK_PERIOD_MS); 
    }
}