#include "Arduino.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <Preferences.h>
#include <RHMesh.h>
#include <RH_RF95.h>
#include <SPI.h>
#include <WiFi.h>
#include <WebServer.h>
#include <HardwareSerial.h>
#include <TinyGPSPlus.h>
#include <Wire.h>
#include <XPowersLib.h>

#include "cose.h"

#define TBEAM_1_2_VERSION true
#define RH_MESH_MAX_MESSAGE_LEN 200

// LoRa Pins
#define LLG_SCK 5
#define LLG_MISO 19
#define LLG_MOSI 27
#define LLG_CS  18
#define LLG_RST 23
#define LLG_DI0 26

// GPS Pins
#define GPS_RX_PIN 12
#define GPS_TX_PIN 15

Preferences preferences;
uint8_t symmetricKey[32]; // 256-bit AES key
uint8_t nodeAddress;

// Hardware drivers
RH_RF95 rf95(LLG_CS, LLG_DI0);
RHMesh manager(rf95, 255);
WebServer server(80);
TinyGPSPlus gps;
HardwareSerial GPS(1);
XPowersAXP2101 PMU;

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
    
    // Display current GPS status
    String gpsStatus = gps.location.isValid() ? 
                       (String(gps.location.lat(), 6) + ", " + String(gps.location.lng(), 6)) : 
                       "Buscando satelites...";
    html += "<p><b>Localizacao GPS:</b> " + gpsStatus + "</p>";
    
    html += "<form action=\"/send\" method=\"POST\">";
    html += "Mensagem: <input type=\"text\" name=\"msg\" maxlength=\"35\"><br><br>";
    html += "<input type=\"submit\" value=\"Enviar\">";
    html += "</form></body></html>";
    server.send(200, "text/html", html);
}

void handleSend() {
    if (server.hasArg("msg")) {
        String originalMsg = server.arg("msg");
        
        // Fetch valid coordinates or default to 0.0
        String lat = gps.location.isValid() ? String(gps.location.lat(), 6) : "0.0";
        String lng = gps.location.isValid() ? String(gps.location.lng(), 6) : "0.0";
        String gpsCoords = lat + "," + lng;

        // Protocol Format: "NodeID_Counter|Message|Lat,Lng"
        String payload = String(nodeAddress) + "_" + String(msgCounter++) + "|" + originalMsg + "|" + gpsCoords;
        
        // Save the PLAINTEXT to local history to prevent rebroadcasting our own message
        saveMessage(payload);
        
        // Convert to vector for encryption
        std::vector<uint8_t> plaintext(payload.c_str(), payload.c_str() + payload.length());
        std::vector<uint8_t> key(symmetricKey, symmetricKey + 32);
        std::vector<uint8_t> ciphertext;
        
        // Encrypt payload to COSE format
        if (CoseCrypto::encrypt(plaintext, key, ciphertext) != ESP_OK || ciphertext.size() > RH_MESH_MAX_MESSAGE_LEN) {
            Serial.println("[SECURITY] Falha ao encriptar a mensagem ou buffer excedido!");
            server.send(500, "text/plain", "Erro interno de criptografia.");
            return;
        }

        Serial.print("Iniciando flood seguro. Tamanho: ");
        Serial.print(ciphertext.size());
        Serial.println(" bytes.");
        
        // Send the encrypted vector
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

    if (TBEAM_1_2_VERSION) {
        Wire.begin(21, 22);
        if (PMU.init(Wire, AXP2101_SLAVE_ADDRESS)) {
            Serial.println("AXP2101 PMU initialized.");
            
            // Turn on power to the LoRa Radio
            PMU.setALDO2Voltage(3300);
            PMU.enableALDO2();
            
            // Turn on power to the GPS
            PMU.setALDO3Voltage(3300);
            PMU.enableALDO3();
            
            Serial.println("LoRa and GPS Power rails enabled.");
        }
    }

    // Load the AES key from NVS memory before turning on the radio
    loadKey();

    // Initialize GPS UART
    GPS.begin(9600, SERIAL_8N1, GPS_RX_PIN, GPS_TX_PIN);

    // Generate unique ID based on MAC Address
    uint8_t mac[6];
    WiFi.macAddress(mac);
    nodeAddress = mac[5];
    if (nodeAddress == 0 || nodeAddress == 255) {
        nodeAddress = (mac[4] % 253) + 2; 
    }
    manager.setThisAddress(nodeAddress);

    Serial.print(F("initializing node "));
    Serial.println(nodeAddress);

    // Hardware Reset the LoRa chip
    pinMode(LLG_RST, OUTPUT);
    digitalWrite(LLG_RST, LOW);
    delay(10);
    digitalWrite(LLG_RST, HIGH);
    delay(10);

    // Initialize SPI
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
    String ssid = "Armando - " + String(nodeAddress);
    WiFi.softAP(ssid.c_str(), "senha_armando");
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

    // Process incoming NMEA sentences from the GPS module
    while (GPS.available() > 0) {
        gps.encode(GPS.read());
    }

    uint8_t len = sizeof(buf);
    uint8_t from;

    // Check for incoming mesh data
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

                // Parse the "ID_Count|Message|Lat,Lng" format
                int firstPipe = receivedPayload.indexOf('|');
                int secondPipe = receivedPayload.indexOf('|', firstPipe + 1);
                
                String displayMsg = receivedPayload;
                String gpsData = "Desconhecido";

                if (firstPipe != -1 && secondPipe != -1) {
                    displayMsg = receivedPayload.substring(firstPipe + 1, secondPipe);
                    gpsData = receivedPayload.substring(secondPipe + 1);
                } else if (firstPipe != -1) {
                    displayMsg = receivedPayload.substring(firstPipe + 1);
                }
                
                Serial.printf("Mensagem segura do nó %d | Msg: %s | GPS: %s | rssi: %d\n", 
                              from, displayMsg.c_str(), gpsData.c_str(), rf95.lastRssi());
                
                manager.sendtoWait(buf, len, RH_BROADCAST_ADDRESS); // Re-broadcast the original encrypted packet
            }
        } else {
            Serial.println("[SECURITY] Pacote ignorado. Falha na decodificação COSE.");
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