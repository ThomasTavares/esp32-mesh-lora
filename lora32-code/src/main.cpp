#include <Arduino.h>
#include <SPI.h>
#include <RadioLib.h>

#define LORA_NSS   8
#define LORA_DIO1  14
#define LORA_RST   12
#define LORA_BUSY  13
#define LORA_SCK   9
#define LORA_MISO  11
#define LORA_MOSI  10

SX1262 radio = new Module(LORA_NSS, LORA_DIO1, LORA_RST, LORA_BUSY);

#define HISTORY_SIZE 10
#define MAX_PKT_LEN  251

uint8_t packetHistory[HISTORY_SIZE][MAX_PKT_LEN];
size_t  packetLens[HISTORY_SIZE];
uint8_t historyIndex = 0;

unsigned long lastHeartbeat = 0;
#define HEARTBEAT_INTERVAL 10000

bool isPacketNew(const uint8_t* buf, size_t len) {
    for (int i = 0; i < HISTORY_SIZE; i++) {
        if (packetLens[i] == len && memcmp(packetHistory[i], buf, len) == 0)
            return false;
    }
    return true;
}

void savePacket(const uint8_t* buf, size_t len) {
    size_t copy_len = len > MAX_PKT_LEN ? MAX_PKT_LEN : len;
    memcpy(packetHistory[historyIndex], buf, copy_len);
    packetLens[historyIndex] = copy_len;
    historyIndex = (historyIndex + 1) % HISTORY_SIZE;
}

void setup() {
    Serial.begin(115200);
    delay(1000);

    Serial.println("Inicializando radio SX1262 (no relay)...");

    SPI.begin(LORA_SCK, LORA_MISO, LORA_MOSI, LORA_NSS);

    int state = radio.begin(915.0, 125.0, 7, 5, 0x12, 10, 8);
    if (state != RADIOLIB_ERR_NONE) {
        Serial.print("Falha na inicializacao do radio, codigo: ");
        Serial.println(state);
        while (true) { delay(1000); }
    }

    memset(packetLens, 0, sizeof(packetLens));

    Serial.println("Radio pronto. Aguardando pacotes para repassar.");
}

void loop() {
    // Heartbeat
    if (millis() - lastHeartbeat >= HEARTBEAT_INTERVAL) {
        lastHeartbeat = millis();
        Serial.println("[RELAY] No ativo, conectado na rede, esperando mensagem.");
    }

    uint8_t buf[MAX_PKT_LEN];
    size_t  len = sizeof(buf);

    int state = radio.receive(buf, len);

    if (state == RADIOLIB_ERR_NONE) {
        if (isPacketNew(buf, len)) {
            savePacket(buf, len);

            // RadioHead header: [TO][FROM][ID][FLAGS] nos primeiros 4 bytes
            // RHMesh adiciona MeshMessageHeader depois, mas TO e FROM ja estao nos bytes 0 e 1
            uint8_t to   = (len > 0) ? buf[0] : 0xFF;
            uint8_t from = (len > 1) ? buf[1] : 0xFF;

            Serial.printf("[RELAY] Pacote recebido do no 0x%02X para no 0x%02X | %d bytes | RSSI: %.1f dBm. Repassando...\n",
                          from, to, (int)len, radio.getRSSI());

            delay(50);

            int txState = radio.transmit(buf, len);
            if (txState == RADIOLIB_ERR_NONE) {
                Serial.println("[RELAY] Pacote repassado.");
            } else {
                Serial.print("[RELAY] Falha ao repassar, codigo: ");
                Serial.println(txState);
            }
        } else {
            Serial.println("[RELAY] Pacote duplicado, ignorado.");
        }
    } else if (state != RADIOLIB_ERR_RX_TIMEOUT) {
        Serial.print("[RELAY] Erro na recepcao, codigo: ");
        Serial.println(state);
    }
}