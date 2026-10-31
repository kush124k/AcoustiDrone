# Passive 2.4 GHz Wi-Fi Drone Detector and Direction Finder

A low-cost, pocket-sized tactical radar and direction finder built with an ESP32. This project passively detects 2.4 GHz Wi-Fi telemetry signals from consumer and DIY drones, classifies them using a heuristic scoring engine, calculates their distance, and points toward them using a magnetic compass and an OLED radar HUD.

**Created by Team G009:** Kushagra Singh, Kabir Sharma, and Rohit Koushik.

##  Features
* **IEEE 802.11 Promiscuous Mode Sniffing:** Hijacks the ESP32 radio to intercept raw MAC frames across Channels 1-13 without connecting to a router.
* **Heuristic Threat Classifier:** Scores signals (0-100%) to filter out fixed campus routers while identifying drones via MAC OUIs (DJI, Parrot, etc.), SSID keywords, hidden telemetry networks, and mobile-administered MAC bits.
* **Sensor Fusion (36-Bin Polar DF):** Combines the live Wi-Fi signal strength (RSSI) with a GY-271 (QMC5883L) magnetometer to find the physical bearing of the target.
* **Peak-Envelope Distance Filter:** Uses the Log-Distance Path Loss model with a fast-attack/slow-decay filter to calculate steady distance in meters, rejecting multipath fading and antenna orientation nulls.
* **Tactical OLED HUD & Audio Proximity:** Displays a live circular radar scope and variable-rate Geiger-counter acoustic beeps as the drone gets closer.

##  Hardware Requirements
* **ESP32 Development Board** (ESP-WROOM-32)
* **GY-271 / QMC5883L** 3-Axis Digital Compass
* **0.96" SSD1306 OLED Display** (128x64, I2C)
* **Active Piezo Buzzer** (3.3V-5V)
* Breadboard and jumper wires

##  Wiring Table (Shared I2C Bus)
| Component | Pin | ESP32 Pin |
| :--- | :--- | :--- |
| **GY-271 (QMC5883L)** | VCC | 3.3V |
| **GY-271 (QMC5883L)** | GND | GND |
| **GY-271 (QMC5883L)** | SCL | GPIO 22 |
| **GY-271 (QMC5883L)** | SDA | GPIO 21 |
| **SSD1306 OLED** | VCC | 3.3V |
| **SSD1306 OLED** | GND | GND |
| **SSD1306 OLED** | SCL | GPIO 22 |
| **SSD1306 OLED** | SDA | GPIO 21 |
| **Buzzer** | + (Long) | GPIO 19 |
| **Buzzer** | - (Short)| GND |

##  Software Dependencies
Built using **PlatformIO** (VS Code). 
* Framework: `arduino`
* Libraries: `Adafruit SSD1306`, `Adafruit GFX Library`

##  How It Works
1. **Sweep & Classify:** The ESP32 scans all 2.4 GHz networks. The heuristic engine looks for drone signatures and ignores infrastructure routers. 
2. **Lock & Sniff:** Once a threat scores >40%, the radio locks onto its channel, drops into promiscuous mode, and tracks the raw RSSI of packets matching the target's MAC.
3. **Calibrate & Map:** The QMC5883L constantly zeroes out hard-iron breadboard interference. The system maps incoming RSSI to 36 directional compass bins ($10^\circ$ slices).
4. **Output:** Distance is estimated using a calibrated baseline of -51.5 dBm at 1 meter. The OLED draws a vector pointing to the loudest signal bin, and the buzzer pulse interval maps to the signal strength.