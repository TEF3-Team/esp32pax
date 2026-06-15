#include "esp_wifi.h"
#include "soc/soc.h"
#include "soc/rtc_cntl_reg.h"
#include <algorithm>
#include <map>
#include <vector>
#include <WiFi.h>
#include <HTTPClient.h>

// ===== CONFIGURACION =====
const char* WIFI_SSID      = "WifiAX";
const char* WIFI_PASSWORD  = "hkmhkm1234566";
const char* SERVER_HOST    = "192.168.8.194";
const uint16_t SERVER_PORT = 5000;
const char* SERVER_PATH    = "/api/report";

constexpr unsigned long TIEMPO_BARRIDO = 10000;
constexpr unsigned long WIFI_CONNECT_TIMEOUT_MS = 15000;
constexpr uint16_t HTTP_TIMEOUT_MS = 5000;
constexpr int MIN_PROBE_PACKET_LEN = 26;
constexpr unsigned long CHANNEL_DWELL_MS = 350;
constexpr uint8_t SNIFFER_CHANNELS[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13};
constexpr size_t SNIFFER_CHANNEL_COUNT = sizeof(SNIFFER_CHANNELS) / sizeof(SNIFFER_CHANNELS[0]);

// Estructuras de datos
struct PacketTraits {
  String ieSignature, rates, extRates, vendorOUIs, extCaps, htCaps, vhtCaps, rsn, extIds;
  uint8_t channel = 0;
  bool wildcard = false;
};

struct CapturedDevice {
  int bestRssi = -127;
  uint16_t probeCount = 0;
  uint16_t wildcardCount = 0;
  uint16_t observedChannelMask = 0;
  String ieSignature, rates, extRates, vendorOUIs, extCaps, htCaps, vhtCaps, rsn, extIds;
  uint8_t channel = 0;
};

struct Objetivo {
  String id, ieSignature, rates, extRates, vendorOUIs, extCaps, htCaps, vhtCaps, rsn, extIds, observedChannels;
  int prox, rssi;
  uint16_t probeCount, wildcardCount;
  uint8_t channel;
};

std::map<String, CapturedDevice> dispositivos;
unsigned long inicio_ciclo = 0;
unsigned long ultimo_salto_canal = 0;
size_t indice_canal = 0;

// --- Funciones de Utilidad ---
String hex_byte(uint8_t value) {
  char out[3];
  sprintf(out, "%02X", value);
  return String(out);
}

String bytes_a_hex(const uint8_t* data, size_t len, size_t maxLen = 0) {
  size_t usable = (maxLen > 0 && maxLen < len) ? maxLen : len;
  String out;
  out.reserve(usable * 2);
  for (size_t i = 0; i < usable; i++) out += hex_byte(data[i]);
  return out;
}

String canales_a_texto(uint16_t mask) {
  String out;
  for (uint8_t channel = 1; channel <= 13; channel++) {
    if ((mask & (1U << (channel - 1))) == 0) continue;
    if (!out.isEmpty()) out += ",";
    out += String(channel);
  }
  return out;
}

void agregar_token_unico(String& destino, const String& token, char separador) {
  if (token.isEmpty() || destino.indexOf(token) != -1) return;
  if (!destino.isEmpty()) destino += separador;
  destino += token;
}

int riqueza_traits(const PacketTraits& t) {
  return t.ieSignature.length() + t.rates.length() + t.vendorOUIs.length() + t.rsn.length();
}

int riqueza_capturada(const CapturedDevice& d) {
  return d.ieSignature.length() + d.rates.length() + d.vendorOUIs.length() + d.rsn.length();
}

// --- Procesamiento de Probes ---
PacketTraits extraer_traits_probe(const uint8_t* payload, int packetLen) {
  PacketTraits traits;
  int pos = 24;
  while (pos + 2 <= packetLen) {
    uint8_t id = payload[pos];
    uint8_t len = payload[pos + 1];
    pos += 2;
    if (pos + len > packetLen) break;
    const uint8_t* data = payload + pos;

    if (id == 0) traits.wildcard = (len == 0);
    else if (id == 3 && len >= 1) traits.channel = data[0];
    else if (id == 255 && len >= 1) {
      String extId = hex_byte(data[0]);
      agregar_token_unico(traits.extIds, extId, '-');
      agregar_token_unico(traits.ieSignature, "FF" + extId, '-');
    } else {
      agregar_token_unico(traits.ieSignature, hex_byte(id), '-');
    }

    switch (id) {
      case 1: traits.rates = bytes_a_hex(data, len); break;
      case 45: traits.htCaps = bytes_a_hex(data, len, 8); break;
      case 48: traits.rsn = bytes_a_hex(data, len, 12); break;
      case 50: traits.extRates = bytes_a_hex(data, len); break;
      case 127: traits.extCaps = bytes_a_hex(data, len, 10); break;
      case 191: traits.vhtCaps = bytes_a_hex(data, len, 6); break;
      case 221: if (len >= 3) agregar_token_unico(traits.vendorOUIs, bytes_a_hex(data, 3), ';'); break;
    }
    pos += len;
  }
  return traits;
}

// --- Sniffer Core ---
void sniffer(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT) return;
  wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
  if (pkt->rx_ctrl.sig_len < MIN_PROBE_PACKET_LEN || pkt->payload[0] != 0x40) return;

  String id = bytes_a_hex(pkt->payload + 10, 6);
  PacketTraits traits = extraer_traits_probe(pkt->payload, pkt->rx_ctrl.sig_len);
  CapturedDevice& d = dispositivos[id];

  d.probeCount++;
  if (traits.wildcard) d.wildcardCount++;
  uint8_t observedChannel = pkt->rx_ctrl.channel;
  if (observedChannel >= 1 && observedChannel <= 13) {
    d.observedChannelMask |= (1U << (observedChannel - 1));
  }

  int nR = riqueza_traits(traits);
  int aR = riqueza_capturada(d);

  if (d.probeCount == 1 || nR > aR || (nR == aR && pkt->rx_ctrl.rssi > d.bestRssi)) {
    d.ieSignature = traits.ieSignature; d.rates = traits.rates; d.extRates = traits.extRates;
    d.vendorOUIs = traits.vendorOUIs; d.extCaps = traits.extCaps; d.htCaps = traits.htCaps;
    d.vhtCaps = traits.vhtCaps; d.rsn = traits.rsn; d.extIds = traits.extIds;
    d.channel = traits.channel;
  }
  if (pkt->rx_ctrl.rssi > d.bestRssi) d.bestRssi = pkt->rx_ctrl.rssi;
}

void iniciar_sniffer() {
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  esp_wifi_set_promiscuous(false);
  esp_wifi_set_promiscuous_rx_cb(&sniffer);
  indice_canal = 0;
  esp_wifi_set_channel(SNIFFER_CHANNELS[indice_canal], WIFI_SECOND_CHAN_NONE);
  esp_wifi_set_promiscuous(true);
  ultimo_salto_canal = millis();
  Serial.printf(">> Sniffer ON, canal %u\n", SNIFFER_CHANNELS[indice_canal]);
}

void actualizar_canal_sniffer() {
  if (millis() - ultimo_salto_canal < CHANNEL_DWELL_MS) return;

  indice_canal = (indice_canal + 1) % SNIFFER_CHANNEL_COUNT;
  esp_err_t result = esp_wifi_set_channel(SNIFFER_CHANNELS[indice_canal], WIFI_SECOND_CHAN_NONE);
  if (result == ESP_OK) {
    ultimo_salto_canal = millis();
  } else {
    Serial.printf(">> Error cambiando a canal %u: %d\n", SNIFFER_CHANNELS[indice_canal], result);
    ultimo_salto_canal = millis();
  }
}

// --- Comunicación ---
String json_pair(const char* key, const String& value) {
  return String("\"") + key + "\":\"" + value + "\"";
}

String json_pair(const char* key, int value) {
  return String("\"") + key + "\":" + String(value);
}

void enviar_http(const std::vector<Objetivo>& ranking, int total) {
  Serial.println(">> Conectando WiFi...");
  esp_wifi_set_promiscuous(false);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  
  unsigned long t = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - t < WIFI_CONNECT_TIMEOUT_MS) delay(100);

  if (WiFi.status() == WL_CONNECTED) {
    HTTPClient http;
    String url = String("http://") + SERVER_HOST + ":" + SERVER_PORT + SERVER_PATH;
    Serial.print(">> WiFi IP: ");
    Serial.println(WiFi.localIP());
    Serial.print(">> Gateway: ");
    Serial.println(WiFi.gatewayIP());
    Serial.print(">> POST URL: ");
    Serial.println(url);
    http.begin(url);
    http.setTimeout(HTTP_TIMEOUT_MS);
    http.addHeader("Content-Type", "application/json");

    String json = "{\"pax\":" + String(total) + ",\"objetivos\":[";
    for (size_t i = 0; i < ranking.size(); i++) {
      json += "{";
      json += json_pair("id", ranking[i].id);
      json += "," + json_pair("prox", ranking[i].prox);
      json += "," + json_pair("rssi", ranking[i].rssi);
      json += "," + json_pair("ies", ranking[i].ieSignature);
      json += "," + json_pair("rates", ranking[i].rates);
      json += "," + json_pair("xrates", ranking[i].extRates);
      json += "," + json_pair("vendors", ranking[i].vendorOUIs);
      json += "," + json_pair("extcaps", ranking[i].extCaps);
      json += "," + json_pair("htcaps", ranking[i].htCaps);
      json += "," + json_pair("vhtcaps", ranking[i].vhtCaps);
      json += "," + json_pair("rsn", ranking[i].rsn);
      json += "," + json_pair("extids", ranking[i].extIds);
      json += "," + json_pair("observed_channels", ranking[i].observedChannels);
      json += "," + json_pair("probes", ranking[i].probeCount);
      json += "," + json_pair("wildcards", ranking[i].wildcardCount);
      json += "," + json_pair("channel", ranking[i].channel);
      json += "}";
      if (i < ranking.size() - 1) json += ",";
    }
    json += "]}";

    Serial.print(">> Payload bytes: ");
    Serial.println(json.length());
    int code = http.POST(json);
    Serial.printf(">> API Code: %d\n", code);
    if (code <= 0) {
      Serial.print(">> HTTP Error: ");
      Serial.println(http.errorToString(code));
    }
    http.end();
  } else {
    Serial.print(">> Error WiFi, status: ");
    Serial.println(WiFi.status());
  }
  
  WiFi.disconnect();
  iniciar_sniffer();
}

void setup() {
  WRITE_PERI_REG(RTC_CNTL_BROWN_OUT_REG, 0);
  Serial.begin(115200);
  WiFi.persistent(false);
  inicio_ciclo = millis();
  iniciar_sniffer();
}

void loop() {
  actualizar_canal_sniffer();

  if (millis() - inicio_ciclo >= TIEMPO_BARRIDO) {
    esp_wifi_set_promiscuous(false);
    Serial.printf(">> Dispositivos detectados: %d\n", dispositivos.size());
    
    std::vector<Objetivo> ranking;
    for (auto const& [id, d] : dispositivos) {
      int p = constrain(map(d.bestRssi, -100, -30, 0, 100), 0, 100);
      ranking.push_back({
        id, d.ieSignature, d.rates, d.extRates, d.vendorOUIs, d.extCaps,
        d.htCaps, d.vhtCaps, d.rsn, d.extIds, canales_a_texto(d.observedChannelMask),
        p, d.bestRssi, d.probeCount, d.wildcardCount, d.channel
      });
    }

    std::sort(ranking.begin(), ranking.end(), [](const Objetivo& a, const Objetivo& b) {
      return a.prox > b.prox;
    });

    enviar_http(ranking, dispositivos.size());
    dispositivos.clear();
    inicio_ciclo = millis();
  }
  delay(10);
}
