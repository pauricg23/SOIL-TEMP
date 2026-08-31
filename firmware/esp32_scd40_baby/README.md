# ESP32 SCD40 Baby Room Monitor

## Wiring

| SCD40 | ESP32 DevKit |
| --- | --- |
| VDD / VIN / VCC | 3V3 |
| GND | GND |
| SDA | GPIO 21 |
| SCL | GPIO 22 |

| RGB LED | ESP32 DevKit |
| --- | --- |
| Common cathode | GND |
| Red leg through 220–330 ohm resistor | GPIO 27 |
| Green leg through 220–330 ohm resistor | GPIO 26 |
| Blue leg through 220–330 ohm resistor | GPIO 25 |

| IR receiver | ESP32 DevKit |
| --- | --- |
| G | GND |
| R | 3V3 |
| Y | GPIO 19 |

Disconnect USB power while changing wiring. Keep the sensor openings exposed and place the finished device out of a child's reach.

## Room Light

The RGB LED follows the latest SCD40 temperature locally, even when Wi-Fi is unavailable:

- Below 16 C: purple
- 16–20 C: golden yellow
- Above 20–24 C: amber orange
- Above 24 C: red

Remote controls:

- `POWER`: toggle the room light
- `VOL+` or `UP`: increase brightness
- `VOL-` or `DOWN`: decrease brightness
- `EQ`: restore the gentle default brightness

Brightness and power state are saved on the ESP32 and restored after a restart.

The firmware also reports its uptime and reset reason. Readings from the first three minutes after a restart are marked as warm-up data so they can be retained without distorting the dashboard graphs.

## Configuration

Copy `src/config.example.h` to `src/config.local.h`, then set the Wi-Fi name, Wi-Fi password, Pi ingest token, server URL and device name. The local file is ignored by Git.

The configured Pi endpoint is:

```text
http://192.168.1.16:5050/submit/baby
```

## Build and Upload

```bash
pio run
pio run --target upload --upload-port /dev/cu.usbserial-2120
pio device monitor --port /dev/cu.usbserial-2120 --baud 115200
```

The serial monitor should report `SCD40 detected at 0x62` followed by CO2, temperature and humidity readings.
