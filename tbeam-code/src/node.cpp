#include "Arduino.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <RHMesh.h>
#include <RH_RF95.h>
#include <SPI.h>
#include <WiFi.h>
#include <WebServer.h>

#define RH_MESH_MAX_MESSAGE_LEN 50
#define BRIDGE_ADDRESS 1  // address of the bridge

#define NODE_ADDRESS 3    // address of this node

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

uint8_t nodeAddress;

// Singleton instance of the radio driver
RH_RF95 rf95(LLG_CS, LLG_DI0); // slave select pin and interrupt pin

// Class to manage message delivery and receipt, using the driver declared above (temporary address)
RHMesh manager(rf95, 255);

// Initialize WebServer on port 80
WebServer server(80);

void handleRoot() {
    String html = "<html><head><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"></head><body>";
    html += "<h2>Sistema Armando - Ponto de Acesso " + String(nodeAddress) + "</h2>";
    html += "<form action=\"/send\" method=\"POST\">";
    html += "Mensagem: <input type=\"text\" name=\"msg\" maxlength=\"49\"><br><br>";
    html += "<input type=\"submit\" value=\"Enviar\">";
    html += "</form></body></html>";
    server.send(200, "text/html", html);
}

void handleSend() {
    if (server.hasArg("msg")) {
        String msg = server.arg("msg");
        uint8_t data[RH_MESH_MAX_MESSAGE_LEN];
        msg.getBytes(data, RH_MESH_MAX_MESSAGE_LEN);
        
        Serial.print("Enviando via web para o ponto intermediário: ");
        Serial.println(msg);
        
        // Send a message to the bridge
        uint8_t res = manager.sendtoWait(data, msg.length() + 1, BRIDGE_ADDRESS);
        
        if (res == RH_ROUTER_ERROR_NONE) {
            server.send(200, "text/plain", "Mensagem enviada com sucesso.");
        } else {
            server.send(500, "text/plain", "Falha no envio. Erro: " + String(res));
        }
    } else {
        server.send(400, "text/plain", "Parâmetro 'msg' ausente.");
    }
}

void setup() {
    Serial.begin(115200);

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
    rf95.setFrequency(915.0);
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

    // radio needs to stay always in receive mode (to process/forward messages)
    uint8_t len = sizeof(buf);
    uint8_t from;
    if (manager.recvfromAck(buf, &len, &from))
    {
        Serial.print("message from node n.");
        Serial.print(from);
        Serial.print(": ");
        Serial.print((char*)buf);
        Serial.print(" rssi: ");
        Serial.println(rf95.lastRssi());
    }
}

extern "C" void app_main()
{
    // Initialize the Arduino environment
    initArduino(); 
    
    // Call your node configuration
    setup();
    
    // Replicate the standard Arduino loop execution
    while (true) {
        loop();
        // Yield to the underlying RTOS to prevent Watchdog Timer (WDT) resets
        vTaskDelay(10 / portTICK_PERIOD_MS); 
    }
}