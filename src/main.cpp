#include <Arduino.h>
#include <Wire.h>
#include <WiFi.h>
#include "esp_wifi.h"
#include <math.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>

#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64
#define OLED_ADDR 0x3C

Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, -1);
bool oledAvailable = false;

const int BUZZER_PIN = 19;
const uint8_t QMC_ADDR = 0x0D;
const int THREAT_THRESHOLD = 40;
const unsigned long SIGNAL_TIMEOUT_MS = 6000;

// Locked target state
uint8_t targetBSSID[6] = {0};
String targetSSID = "";
String targetReason = "";
int targetThreatScore = 0;
int lockedChannel = 0;

volatile int latestRSSI = -100;
volatile unsigned long lastPacketTime = 0;
volatile uint32_t packetCount = 0;

// Hard-iron compass calibration bounds
int16_t minX = 32767, maxX = -32768;
int16_t minY = 32767, maxY = -32768;

// 36 directional bins using Exponential Moving Average
float binEMA[36];
bool binInitialized[36] = {false};

struct DroneOUI {
  uint8_t prefix[3];
  const char* vendor;
};

const DroneOUI KNOWN_DRONE_OUIS[] = {
  {{0x60, 0x60, 0x1F}, "DJI Innovations"},
  {{0x34, 0xD2, 0x62}, "DJI Innovations"},
  {{0x48, 0x1C, 0xB9}, "DJI Innovations"},
  {{0xE4, 0x7A, 0x2C}, "DJI Innovations"},
  {{0x90, 0x03, 0xB7}, "Parrot Drone"},
  {{0xA0, 0x14, 0x3D}, "Parrot Drone"},
  {{0x00, 0x26, 0x7E}, "Parrot SA"},
  {{0x00, 0x12, 0x1C}, "Parrot SA"},
  {{0x38, 0x1D, 0x14}, "Skydio UAV"},
  {{0xE0, 0xB6, 0xF5}, "Yuneec Drone"},
  {{0xEC, 0x5B, 0xCD}, "Autel Robotics"},
  {{0x24, 0x62, 0xAB}, "Espressif DIY-UAV"},
  {{0x30, 0xAE, 0xA4}, "Espressif DIY-UAV"}
};

const char* DRONE_SSID_KEYWORDS[] = {
  "DRONE", "UAV", "DJI", "TELLO", "MAVIC", "PHANTOM", "SPARK",
  "INSPIRE", "AUTEL", "PARROT", "ANAFI", "SKYDIO", "YUNEEC",
  "FPV", "ARDUPILOT", "BETAFLIGHT", "PIXHAWK", "ELRS", "CROSSFIRE",
  "QUAD", "COPTER", "HEX", "ROTOR", "RC-", "WIFI-UFO", "SYMA", "JJRC"
};

const char* INFRA_SSID_KEYWORDS[] = {
  "JIO", "AIRTEL", "ACT", "BSNL", "TP-LINK", "TENDA", "NETGEAR",
  "D-LINK", "ASUS", "EDUROAM", "HOSTEL", "CAMPUS", "LIBRARY", "OFFICE", "HOME", "IBUS"
};

int evaluateDroneThreat(const String& ssid, const uint8_t* bssid, int rssi, int channel, String& reasonOut) {
  int score = 0;
  reasonOut = "";

  String upperSSID = ssid;
  upperSSID.toUpperCase();
  upperSSID.trim();

  for (size_t i = 0; i < sizeof(KNOWN_DRONE_OUIS) / sizeof(KNOWN_DRONE_OUIS[0]); i++) {
    if (bssid[0] == KNOWN_DRONE_OUIS[i].prefix[0] &&
        bssid[1] == KNOWN_DRONE_OUIS[i].prefix[1] &&
        bssid[2] == KNOWN_DRONE_OUIS[i].prefix[2]) {
      score += 60;
      reasonOut += String("OUI:") + KNOWN_DRONE_OUIS[i].vendor + " ";
      break;
    }
  }

  for (size_t i = 0; i < sizeof(DRONE_SSID_KEYWORDS) / sizeof(DRONE_SSID_KEYWORDS[0]); i++) {
    if (upperSSID.indexOf(DRONE_SSID_KEYWORDS[i]) >= 0) {
      score += 55;
      reasonOut += String("SSID:") + DRONE_SSID_KEYWORDS[i] + " ";
      break;
    }
  }

  if (upperSSID.length() == 0) {
    score += 25;
    reasonOut += "HIDDEN_TELEMETRY ";
  }

  if ((bssid[0] & 0x02) != 0) {
    score += 15;
    reasonOut += "MOBILE_MAC ";
  }

  if (rssi > -62) {
    score += 25;
    reasonOut += "CLOSE_RANGE ";
  } else if (rssi > -75) {
    score += 15;
  }

  for (size_t i = 0; i < sizeof(INFRA_SSID_KEYWORDS) / sizeof(INFRA_SSID_KEYWORDS[0]); i++) {
    if (upperSSID.indexOf(INFRA_SSID_KEYWORDS[i]) >= 0) {
      score -= 45;
      reasonOut += "FIXED_ROUTER ";
      break;
    }
  }

  if (reasonOut.length() == 0) reasonOut = "AMBIENT_AP";
  return constrain(score, 0, 100);
}

typedef struct {
  uint16_t frame_ctrl;
  uint16_t duration_id;
  uint8_t addr1[6];
  uint8_t addr2[6];
  uint8_t addr3[6];
  uint16_t sequence_ctrl;
} __attribute__((packed)) wifi_ieee80211_mac_hdr_t;

typedef struct {
  wifi_ieee80211_mac_hdr_t hdr;
  uint8_t payload[0];
} __attribute__((packed)) wifi_ieee80211_packet_t;

void IRAM_ATTR snifferCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA) return;

  const wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
  const wifi_ieee80211_packet_t* ipkt = (wifi_ieee80211_packet_t*)pkt->payload;
  const wifi_ieee80211_mac_hdr_t* hdr = &ipkt->hdr;

  if (memcmp(hdr->addr2, targetBSSID, 6) == 0 || memcmp(hdr->addr3, targetBSSID, 6) == 0) {
    latestRSSI = pkt->rx_ctrl.rssi;
    lastPacketTime = millis();
    packetCount++;
    return;
  }

  uint8_t frameSubType = (hdr->frame_ctrl & 0xFF);
  if (type == WIFI_PKT_MGMT && (frameSubType == 0x80 || frameSubType == 0x50)) {
    const uint8_t* taggedParams = ipkt->payload + 12;
    uint8_t tagNumber = taggedParams[0];
    uint8_t ssidLen = taggedParams[1];
    if (tagNumber == 0 && ssidLen > 0 && ssidLen <= 32 && ssidLen == targetSSID.length()) {
      if (memcmp(&taggedParams[2], targetSSID.c_str(), ssidLen) == 0) {
        memcpy(targetBSSID, hdr->addr2, 6);
        latestRSSI = pkt->rx_ctrl.rssi;
        lastPacketTime = millis();
        packetCount++;
      }
    }
  }
}

void initQMC5883L() {
  Wire.beginTransmission(QMC_ADDR);
  Wire.write(0x0B);
  Wire.write(0x01);
  Wire.endTransmission();

  Wire.beginTransmission(QMC_ADDR);
  Wire.write(0x09);
  Wire.write(0x1D);
  Wire.endTransmission();
}

float getCalibratedHeading() {
  Wire.beginTransmission(QMC_ADDR);
  Wire.write(0x00);
  if (Wire.endTransmission() != 0) {
    initQMC5883L();
    return -1.0f;
  }

  if (Wire.requestFrom(QMC_ADDR, (uint8_t)6) != 6) return -1.0f;

  int16_t x = (int16_t)(Wire.read() | (Wire.read() << 8));
  int16_t y = (int16_t)(Wire.read() | (Wire.read() << 8));
  int16_t z = (int16_t)(Wire.read() | (Wire.read() << 8));
  (void)z;

  if (x < minX) minX = x;
  if (x > maxX) maxX = x;
  if (y < minY) minY = y;
  if (y > maxY) maxY = y;

  float offsetX = (maxX + minX) / 2.0f;
  float offsetY = (maxY + minY) / 2.0f;

  float calX = (maxX - minX > 50) ? (x - offsetX) : (float)x;
  float calY = (maxY - minY > 50) ? (y - offsetY) : (float)y;

  float heading = atan2(calY, calX) * 180.0f / PI;
  if (heading < 0) heading += 360.0f;
  return heading;
}

const char* headingToCardinal(float deg) {
  const char* dirs[] = {"N", "NE", "E", "SE", "S", "SW", "W", "NW"};
  int idx = (int)((deg + 22.5f) / 45.0f) % 8;
  return dirs[idx];
}

// Empirically calibrated for Kushagra's Hotspot + ESP32 PCB Antenna
// Fitted against 0.08m (-28dBm), 0.30m (-40.5dBm), 1.0m (-51.5dBm), and 2.0m (-57.5dBm)
float estimateDistanceMeters(int rawRssi) {
  const float RSSI_AT_1M = -51.5f;  // Exact 1.0m baseline from serial capture
  const float PATH_LOSS_EXP = 2.1f; // Fitted log-distance slope between 0.3m, 1m, and 2m

  static float envelopeRssi = -100.0f;
  static int windowBuf[5] = {-52, -52, -52, -52, -52};
  static int bufIdx = 0;
  static bool initialized = false;

  // 1. Reject extreme 1-packet multipath nulls (e.g. -82 dBm destructive cancellation spikes)
  if (initialized && (rawRssi - envelopeRssi) < -14.0f) {
    rawRssi = (int)(envelopeRssi - 6.0f);
  }

  // 2. 5-sample sliding window max-filter (locks onto line-of-sight peak even while rotating)
  windowBuf[bufIdx] = rawRssi;
  bufIdx = (bufIdx + 1) % 5;
  int localPeak = -100;
  for (int i = 0; i < 5; i++) {
    if (!initialized || windowBuf[i] > localPeak) localPeak = windowBuf[i];
  }

  // 3. Asymmetric Peak Envelope EMA:
  // Fast attack (0.45) when signal gets stronger; slow decay (0.08) when antenna turns away
  if (!initialized) {
    envelopeRssi = (float)rawRssi;
    for (int i = 0; i < 5; i++) windowBuf[i] = rawRssi;
    initialized = true;
  } else {
    float target = (float)localPeak;
    float alpha = (target > envelopeRssi) ? 0.45f : 0.08f;
    envelopeRssi = alpha * target + (1.0f - alpha) * envelopeRssi;
  }

  // 4. Compute calibrated distance in meters
  float dist = pow(10.0f, (RSSI_AT_1M - envelopeRssi) / (10.0f * PATH_LOSS_EXP));
  return constrain(dist, 0.05f, 15.0f);
}

void beep(int durationMs, int count = 1) {
  for (int i = 0; i < count; i++) {
    digitalWrite(BUZZER_PIN, HIGH);
    delay(durationMs);
    digitalWrite(BUZZER_PIN, LOW);
    if (i + 1 < count) delay(80);
  }
}

void updateOLEDScanning(int netCount) {
  if (!oledAvailable) return;
  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);
  display.setCursor(0, 0);
  display.println("RF UAV RADAR [SCAN]");
  display.drawLine(0, 10, 127, 10, SSD1306_WHITE);
  display.setCursor(0, 18);
  display.println("Sweeping Ch 1-13...");
  if (netCount >= 0) {
    display.setCursor(0, 32);
    display.printf("Emitters seen: %d", netCount);
    display.setCursor(0, 46);
    display.println("No Drone >= 40% yet");
  }
  display.display();
}

// Renders live telemetry + mini polar radar compass on the 128x64 OLED
void updateOLEDTracking(int rssi, float distM, float heading, int peakBearing, float confDB) {
  if (!oledAvailable) return;
  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);

  // Top Header Bar: Locked Target Name + Score
  display.setCursor(0, 0);
  String shortSSID = targetSSID.substring(0, 13);
  display.printf("%-13s %3d%%", shortSSID.c_str(), targetThreatScore);
  display.drawLine(0, 10, 127, 10, SSD1306_WHITE);

  // Left Column (x = 0..84): Telemetry Readouts
  display.setCursor(0, 14);
  display.printf("RSSI:%ddBm Ch%d", rssi, lockedChannel);

  display.setCursor(0, 25);
  display.printf("Dist: ~%.1fm", distM);

  display.setCursor(0, 36);
  display.printf("Head: %3.0f %s", heading, headingToCardinal(heading));

  display.setCursor(0, 47);
  display.printf("UAV : %3d %s", peakBearing, headingToCardinal((float)peakBearing));

  // Bottom Signal Bar
  int barWidth = map(constrain(rssi, -90, -30), -90, -30, 2, 82);
  display.drawRect(0, 57, 84, 6, SSD1306_WHITE);
  display.fillRect(0, 57, barWidth, 6, SSD1306_WHITE);

  // Right Side (center x=106, y=36, r=20): Live Radar Scope
  int cx = 106, cy = 36, r = 20;
  display.drawCircle(cx, cy, r, SSD1306_WHITE);
  display.drawPixel(cx, cy, SSD1306_WHITE);

  // Draw solid line pointing toward estimated Drone Peak Bearing
  float uavRad = (peakBearing - 90.0f) * PI / 180.0f;
  int ux = cx + (int)(cos(uavRad) * (r - 2));
  int uy = cy + (int)(sin(uavRad) * (r - 2));
  display.drawLine(cx, cy, ux, uy, SSD1306_WHITE);
  display.fillCircle(ux, uy, 2, SSD1306_WHITE); // Blip at tip

  // Draw small tick on rim for current board heading
  float headRad = (heading - 90.0f) * PI / 180.0f;
  int hx = cx + (int)(cos(headRad) * r);
  int hy = cy + (int)(sin(headRad) * r);
  display.fillRect(hx - 1, hy - 1, 3, 3, SSD1306_WHITE);

  display.display();
}

void acquireTarget() {
  esp_wifi_set_promiscuous(false);
  lockedChannel = 0;

  while (lockedChannel == 0) {
    updateOLEDScanning(-1);
    Serial.println("\n[SCAN] Sweeping Ch 1-13 for 2.4GHz emitters...");
    int n = WiFi.scanNetworks(false, true);

    if (n <= 0) {
      Serial.println("No 2.4GHz signals found. Retrying...");
      updateOLEDScanning(0);
      delay(1500);
      continue;
    }

    int bestIdx = -1;
    int highestScore = -1;
    String bestReason = "";

    Serial.println("ID | SSID                     | BSSID (MAC)       | Ch | RSSI | Score | Verdict & Signatures");
    Serial.println("---|--------------------------|-------------------|----|------|-------|---------------------");

    for (int i = 0; i < n; i++) {
      String ssid = WiFi.SSID(i);
      const uint8_t* bssid = WiFi.BSSID(i);
      int rssi = WiFi.RSSI(i);
      int ch = WiFi.channel(i);

      String reason;
      int score = evaluateDroneThreat(ssid, bssid, rssi, ch, reason);
      const char* verdict = (score >= THREAT_THRESHOLD) ? "[DRONE THREAT]" : "[BENIGN AP]";

      String displaySSID = (ssid.length() > 0) ? ssid.substring(0, 24) : "<HIDDEN TELEMETRY>";
      Serial.printf("%2d | %-24s | %02X:%02X:%02X:%02X:%02X:%02X | %2d | %4d | %3d%%  | %s (%s)\n",
                    i + 1, displaySSID.c_str(),
                    bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5],
                    ch, rssi, score, verdict, reason.c_str());

      if (score > highestScore || (score == highestScore && bestIdx >= 0 && rssi > WiFi.RSSI(bestIdx))) {
        highestScore = score;
        bestIdx = i;
        bestReason = reason;
      }
    }

    if (bestIdx >= 0 && highestScore >= THREAT_THRESHOLD) {
      lockedChannel = WiFi.channel(bestIdx);
      latestRSSI = WiFi.RSSI(bestIdx);
      targetSSID = (WiFi.SSID(bestIdx).length() > 0) ? WiFi.SSID(bestIdx) : "<HIDDEN_UAV>";
      targetThreatScore = highestScore;
      targetReason = bestReason;
      memcpy(targetBSSID, WiFi.BSSID(bestIdx), 6);
    } else {
      updateOLEDScanning(n);
      Serial.printf("\n-> No signal >= %d%% threshold. Rescanning in 2s...\n", THREAT_THRESHOLD);
      WiFi.scanDelete();
      delay(2000);
    }
  }

  WiFi.scanDelete();
  for (int b = 0; b < 36; b++) binInitialized[b] = false;

  beep(100, 2);

  Serial.println("\n=======================================================");
  Serial.printf(">>> TARGET ACQUIRED: %s <<<\n", targetSSID.c_str());
  Serial.printf(">>> BSSID: %02X:%02X:%02X:%02X:%02X:%02X | Channel: %d\n",
                targetBSSID[0], targetBSSID[1], targetBSSID[2],
                targetBSSID[3], targetBSSID[4], targetBSSID[5], lockedChannel);
  Serial.printf(">>> Threat Score: %d%% | Match: %s\n", targetThreatScore, targetReason.c_str());
  Serial.println("=======================================================");
  Serial.println("time_ms,ch,rssi_dbm,dist_m,heading_deg,cardinal,peak_bearing_deg,conf_db");

  lastPacketTime = millis();
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_channel(lockedChannel, WIFI_SECOND_CHAN_NONE);
  esp_wifi_set_promiscuous_rx_cb(&snifferCallback);
}

void setup() {
  Serial.begin(115200);
  pinMode(BUZZER_PIN, OUTPUT);
  digitalWrite(BUZZER_PIN, LOW);

  Wire.begin(21, 22);
  Wire.setTimeOut(25);
  initQMC5883L();

  // Check if OLED is present on 0x3C so it never blocks if disconnected
  Wire.beginTransmission(OLED_ADDR);
  if (Wire.endTransmission() == 0 && display.begin(SSD1306_SWITCHCAPVCC, OLED_ADDR)) {
    oledAvailable = true;
    Serial.println("[OLED] 0.96\" Display initialized at 0x3C!");
    updateOLEDScanning(-1);
  } else {
    Serial.println("[OLED] Not detected at 0x3C (Continuing with Serial + Buzzer)");
  }

  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  delay(200);

  wifi_country_t country = {"IN", 1, 13, 20, WIFI_COUNTRY_POLICY_AUTO};
  esp_wifi_set_country(&country);

  Serial.println("\n=======================================================");
  Serial.println("  RF DRONE HEURISTIC CLASSIFIER & DIRECTION FINDER");
  Serial.println("=======================================================");

  acquireTarget();
}

unsigned long lastPrint = 0;
unsigned long lastBeep = 0;
uint32_t lastHandledPacket = 0;

void loop() {
  unsigned long now = millis();

  if (now - lastPacketTime > SIGNAL_TIMEOUT_MS) {
    Serial.println("# [WATCHDOG] Target signal lost or hopped channel! Re-scanning...");
    beep(250, 1);
    acquireTarget();
    return;
  }

  float heading = getCalibratedHeading();

  if (packetCount != lastHandledPacket && heading >= 0) {
    lastHandledPacket = packetCount;
    int rssi = latestRSSI;
    int bin = ((int)heading / 10) % 36;

    if (!binInitialized[bin]) {
      binEMA[bin] = (float)rssi;
      binInitialized[bin] = true;
    } else {
      binEMA[bin] = 0.35f * (float)rssi + 0.65f * binEMA[bin];
    }

    float bestSmoothedRSSI = -120.0f;
    float overallSum = 0;
    int populatedBins = 0;
    int bestBin = bin;

    for (int b = 0; b < 36; b++) {
      if (binInitialized[b]) {
        overallSum += binEMA[b];
        populatedBins++;

        float smoothSum = binEMA[b] * 2.0f;
        float weight = 2.0f;
        int prev = (b + 35) % 36;
        int next = (b + 1) % 36;
        if (binInitialized[prev]) { smoothSum += binEMA[prev]; weight += 1.0f; }
        if (binInitialized[next]) { smoothSum += binEMA[next]; weight += 1.0f; }

        float smoothed = smoothSum / weight;
        if (smoothed > bestSmoothedRSSI) {
          bestSmoothedRSSI = smoothed;
          bestBin = b;
        }
      }
    }

    float meanRSSI = (populatedBins > 0) ? (overallSum / populatedBins) : rssi;
    float confidenceDB = bestSmoothedRSSI - meanRSSI;
    int peakBearing = bestBin * 10 + 5;
    float distM = estimateDistanceMeters(rssi);

    if (now - lastPrint >= 250) {
      lastPrint = now;
      Serial.printf("%lu,%d,%d,%.1f,%.1f,%s,%d,%.1f\n",
                    now, lockedChannel, rssi, distM, heading,
                    headingToCardinal(heading), peakBearing, confidenceDB);
      updateOLEDTracking(rssi, distM, heading, peakBearing, confidenceDB);
    }
  }

  if (now - lastPacketTime < 1500) {
    int clampedRSSI = constrain(latestRSSI, -85, -35);
    unsigned long beepInterval = map(clampedRSSI, -85, -35, 1200, 120);
    if (now - lastBeep >= beepInterval) {
      lastBeep = now;
      digitalWrite(BUZZER_PIN, HIGH);
      delay(30);
      digitalWrite(BUZZER_PIN, LOW);
    }
  }
}