# AcoustiDrone: Passive 2.4 GHz Wi-Fi Drone Detector and Direction Finder

An ESP32-based handheld that passively detects Wi-Fi-emitting drones, estimates their distance from signal strength, and shows an approximate bearing on an OLED radar display using a magnetometer. An acoustic detection stage (INMP441 microphone) is planned.

Built for the Electronics & Instrumentation mini-project.



## What it does

1. **Scans** channels 1-13 and scores every visible network with a heuristic classifier.
2. **Locks** onto the highest-scoring target once it exceeds 40% and tracks its packets in promiscuous mode by MAC address.
3. **Estimates distance** from RSSI using a log-distance path-loss model.
4. **Estimates bearing** by binning RSSI against compass heading while you rotate the device.
5. **Reports** via an OLED radar view and a buzzer whose beep rate increases as the signal strengthens.

## Status

| Stage | State |
|---|---|
| Wi-Fi scan, classification, MAC lock | Working |
| RSSI to distance | Working (calibrated for the setup below) |
| Magnetometer bearing scan | Working |
| OLED radar and buzzer | Working |
| INMP441 acoustic detection | Planned |

## Hardware

| Part | Notes |
|---|---|
| ESP32-WROOM-32 DevKit (38-pin) | |
| GY-271 magnetometer | Board is labeled HMC5883L; the code uses [QMC5883L / HMC5883L, fill in after checking the chip marking and I2C scan] |
| 0.96" SSD1306 OLED, 128x64, I2C | |
| Active buzzer | |
| Breadboard and jumper wires | |

### Wiring (shared I2C bus)

| Component | Pin | ESP32 |
|---|---|---|
| Magnetometer | VCC | 3V3 |
| Magnetometer | GND | GND |
| Magnetometer | SCL | GPIO 22 |
| Magnetometer | SDA | GPIO 21 |
| OLED | VCC | 3V3 |
| OLED | GND | GND |
| OLED | SCL | GPIO 22 |
| OLED | SDA | GPIO 21 |
| Buzzer | + | GPIO 19 |
| Buzzer | - | GND |


## Build and flash

Requires [PlatformIO](https://platformio.org/) (VS Code extension or CLI).

```bash
git clone https://github.com/kush124k/AcoustiDrone.git
cd AcoustiDrone
pio run -t upload
pio device monitor
```

If the upload hangs on "Connecting...", hold the **BOOT** button until it starts. On Windows you may need the CP210x USB driver.

Dependencies (`Adafruit SSD1306`, `Adafruit GFX Library`, plus the magnetometer library) are installed automatically from `platformio.ini`.

## How it works

### Classification
Each network gets a 0-100 score from these signals:
- OUI match against known drone vendors (e.g. DJI, Parrot)
- Drone-related SSID keywords
- Hidden SSIDs (common on telemetry links)
- Locally administered MAC bit set
- Fixed infrastructure (campus routers) is filtered out

A score above 40% triggers the lock.

### Distance
Log-distance path loss:

```
d = 10 ^ ((RSSI_1m - RSSI) / (10 * n))
```

with `RSSI_1m = -51.5 dBm` and path-loss exponent `n = [your value]`. A fast-attack / slow-decay peak filter smooths the reading against multipath fading and antenna nulls.

### Bearing
The compass heading is divided into 36 bins of 10 degrees. As you rotate the device, the peak RSSI per bin is recorded, and the radar arrow points to the strongest bin. Hard-iron offsets from the breadboard are calibrated out at startup. [State whether soft-iron correction is applied.]

## Results

| Test | Result |
|---|---|
| Distance error vs. tape measure | [e.g. +/- X m at 1, 3, 5, 10 m] |
| Bearing error vs. known direction | [e.g. +/- X degrees over N trials] |
| Detection range (line of sight) | [X m] |
| Classifier on campus Wi-Fi | [false positives / total] |

## Limitations

- **Wi-Fi drones only.** Drones using other links are invisible to this device. This is the reason for the planned acoustic stage.
- **Bearing is coarse.** The ESP32 PCB antenna is close to omnidirectional and strongly affected by body position and orientation, so expect tens of degrees of error.
- **Distance depends on calibration.** The 1 m baseline was measured with a specific phone, room, and antenna orientation. Recalibrate for any other emitter.
- **Tested with a phone hotspot** named `Drone-001` as a stand-in, not a real drone.

## Roadmap

- [ ] INMP441 I2S microphone: FFT-based rotor-tone detection
- [ ] Fuse RF and acoustic evidence into one confidence score
- [ ] Directional antenna for better bearing accuracy
- [ ] Soft-iron compass calibration

## Project structure

```
src/        firmware source
include/    headers
lib/        local libraries
docs/       report, photos, wiring diagram
```

## Legal

This device only listens passively to publicly broadcast 802.11 frames and does not transmit, jam, or connect to any network. Check your local regulations before using it outside a lab.

## License

MIT, see [LICENSE](LICENSE).