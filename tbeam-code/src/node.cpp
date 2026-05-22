#include "Arduino.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <RHMesh.h>
#include <RH_RF95.h>
#include <SPI.h>

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

// tfcard
#define LLG_SD_CS   13
#define LLG_SD_MISO 2
#define LLG_SD_MOSI 15
#define LLG_SD_SCK  14

#define TXINTERVAL 3000  // delay between successive transmissions
unsigned long nextTxTime;

// Singleton instance of the radio driver
RH_RF95 rf95(LLG_CS, LLG_DI0); // slave select pin and interrupt pin

// Class to manage message delivery and receipt, using the driver declared above
RHMesh manager(rf95, NODE_ADDRESS);

void setup() 
{
    Serial.begin(115200);
    Serial.print(F("initializing node "));
    Serial.print(NODE_ADDRESS); // address of this node

    // Hardware Reset the LoRa chip
    pinMode(LLG_RST, OUTPUT); // LLG_RST is defined as 23
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
    rf95.setFrequency(868.0);
    rf95.setCADTimeout(500);

    boolean longRange = false;
    if (longRange) 
    {
        RH_RF95::ModemConfig modem_config = {
            0x78, // Reg 0x1D: BW=125kHz, Coding=4/8, Header=explicit
            0xC4, // Reg 0x1E: Spread=4096chips/symbol, CRC=enable
            0x08  // Reg 0x26: LowDataRate=On, Agc=Off
        };
        rf95.setModemRegisters(&modem_config);
    }
    else
    {
        if (!rf95.setModemConfig(RH_RF95::Bw125Cr45Sf128)) {
            Serial.println(F("set config failed"));
        }
    }

    Serial.println("RF95 ready");
    nextTxTime = millis();
}

uint8_t data[] = "Hello World!";
uint8_t buf[RH_MESH_MAX_MESSAGE_LEN];
uint8_t res;

void loop()
{
    // send message every TXINTERVAL millisecs
    if (millis() > nextTxTime) {
        nextTxTime += TXINTERVAL;
        Serial.print("Sending to bridge n.");
        Serial.print(BRIDGE_ADDRESS);
        Serial.print(" res=");

        // Send a message to a rf95_mesh_server
        // A route to the destination will be automatically discovered.
        res = manager.sendtoWait(data, sizeof(data), BRIDGE_ADDRESS);
        Serial.println(res);
        if (res != RH_ROUTER_ERROR_NONE)
        {
            // Data not delivered to the next node.
            Serial.println("sendtoWait failed. Are the bridge/intermediate mesh nodes running?");
        }
    }

    // radio needs to stay always in receive mode ( to process/forward messages )
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