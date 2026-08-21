# ESP32 SCD40 Baby Room Monitor

## Wiring

| SCD40 | ESP32 DevKit |
| --- | --- |
| VDD / VIN / VCC | 3V3 |
| GND | GND |
| SDA | GPIO 21 |
| SCL | GPIO 22 |

Disconnect USB power while changing wiring. Keep the sensor openings exposed and place the finished device out of a child's reach.

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
