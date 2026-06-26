#include <Arduino.h>
#include <SPI.h>
#include <RadioLib.h>

// Pinagem interna do SX1262 no Heltec WiFi LoRa 32 V3
#define LORA_NSS   8
#define LORA_DIO1  14
#define LORA_RST   12
#define LORA_BUSY  13
#define LORA_SCK   9
#define LORA_MISO  11
#define LORA_MOSI  10

SX1262 radio = new Module(LORA_NSS, LORA_DIO1, LORA_RST, LORA_BUSY);

#define HISTORY_SIZE 10
String packetHistory[HISTORY_SIZE];
uint8_t historyIndex = 0;

bool isPacketNew(const String &p) {
    for (int i = 0; i < HISTORY_SIZE; i++)
        if (packetHistory[i] == p) return false;
    return true;
}

void savePacket(const String &p) {
    packetHistory[historyIndex] = p;
    historyIndex = (historyIndex + 1) % HISTORY_SIZE;
}

void setup() {
    Serial.begin(115200);
    delay(1000);

    Serial.println("Inicializando radio SX1262 (no relay)...");

    SPI.begin(LORA_SCK, LORA_MISO, LORA_MOSI, LORA_NSS);

    int state = radio.begin(915.0, 125.0, 7, 5, 0x12, 20, 8);
    if (state != RADIOLIB_ERR_NONE) {
        Serial.print("Falha na inicializacao do radio, codigo: ");
        Serial.println(state);
        while (true) { delay(1000); }
    }

    Serial.println("Radio pronto. Aguardando pacotes para repassar.");
}

void loop() {
    String received;
    int state = radio.receive(received);

    if (state == RADIOLIB_ERR_NONE) {
        if (isPacketNew(received)) {
            savePacket(received);

            Serial.print("Pacote recebido, RSSI: ");
            Serial.print(radio.getRSSI());
            Serial.print(" dBm | Conteudo bruto: ");
            Serial.println(received);

            delay(50);
            int txState = radio.transmit(received);
            if (txState == RADIOLIB_ERR_NONE) {
                Serial.println("Pacote repassado.");
            } else {
                Serial.print("Falha ao repassar, codigo: ");
                Serial.println(txState);
            }
        }
    } else if (state != RADIOLIB_ERR_RX_TIMEOUT) {
        Serial.print("Erro na recepcao, codigo: ");
        Serial.println(state);
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