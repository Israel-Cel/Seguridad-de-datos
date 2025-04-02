#include <WiFi.h>
#include "esp_wifi.h"
#include <vector>             
using namespace std;       

const char* fakeSSIDs[] = {
  "Free_WiFi1", "Free_WiFi2", "Free_WiFi3", "Free_WiFi4", "Free_WiFi5"
};

const int numFakes = sizeof(fakeSSIDs) / sizeof(fakeSSIDs[0]);

// Lista para evitar MACs duplicadas
std::vector<String> detectedClients;

void setup() {
  Serial.begin(115200);
  delay(1000);

  Serial.println("Iniciando PoC");

  // Modo estación (necesario para enviar beacons)
  WiFi.mode(WIFI_MODE_STA);
  esp_wifi_set_ps(WIFI_PS_NONE);
  esp_wifi_set_channel(6, WIFI_SECOND_CHAN_NONE); // Canal 6 fijo

  // Activar modo sniffer
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(snifferCallback);
}

void loop() {
  // Enviar redes falsas todo el tiempo
  for (int i = 0; i < numFakes; i++) {
    sendFakeBeacon(fakeSSIDs[i], i);
    delay(10); // breve pausa entre cada
  }

  delay(100); // evitar saturación
}

// Enviar un beacon falso con nombre personalizado
void sendFakeBeacon(const char* ssid, int id) {
  int ssidLen = strlen(ssid);
  if (ssidLen > 32) return;

  uint8_t tail[] = {
    0x01, 0x08, 0x82, 0x84, 0x8B, 0x96, 0x24, 0x30, 0x48, 0x6C,
    0x03, 0x01, 0x06 // canal 6
  };

  int packetSize = 38 + ssidLen + sizeof(tail);
  if (packetSize > 128) return;

  uint8_t* beaconPacket = (uint8_t*)malloc(packetSize);
  if (!beaconPacket) return;

  uint8_t header[38] = {
    0x80, 0x00,
    0x00, 0x00,
    // Destino
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    // Origen / BSSID
    0xDE, 0xAD, 0xBE, 0xEF, 0x00, (uint8_t)id,
    0xDE, 0xAD, 0xBE, 0xEF, 0x00, (uint8_t)id,
    0x00, 0x00,
    // Timestamp + intervalo + capabilities
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x64, 0x00,
    0x31, 0x04,
    0x00, (uint8_t)ssidLen
  };

  memcpy(beaconPacket, header, 38);
  memcpy(&beaconPacket[38], ssid, ssidLen);
  memcpy(&beaconPacket[38 + ssidLen], tail, sizeof(tail));

  esp_wifi_80211_tx(WIFI_IF_STA, beaconPacket, packetSize, false);
  free(beaconPacket);
}

// Sniffer para detectar clientes y SSIDs buscadas
void snifferCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT) return;

  const wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
  const uint8_t* payload = pkt->payload;

  // Tipo de paquete = Probe Request
  if (payload[0] == 0x40) {
    char ssid[33] = {0};
    int ssidLen = payload[25];

    if (ssidLen > 0 && ssidLen <= 32) {
      memcpy(ssid, &payload[26], ssidLen);
      ssid[ssidLen] = '\0';

      char macStr[18];
      sprintf(macStr, "%02X:%02X:%02X:%02X:%02X:%02X",
              payload[10], payload[11], payload[12],
              payload[13], payload[14], payload[15]);

      String clientID = String(macStr) + " > " + String(ssid);

      if (std::find(detectedClients.begin(), detectedClients.end(), clientID) == detectedClients.end()) {
        detectedClients.push_back(clientID);
        Serial.printf("Cliente detectado: %s buscando: '%s'\n", macStr, ssid);
      }
    }
  }
}



