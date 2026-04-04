# Walter Board Compost Sensor

Compost temperature monitoring system using the Walter board (ESP32-S3 + Sequans GM02SP LTE-M modem) with 3x DS18B20 temperature sensors.

## Hardware

- **Board**: Walter (ESP32-S3 + Sequans GM02SP)
- **Sensors**: 3x DS18B20 temperature sensors
- **Connectivity**: LTE-M (Cat M1) via Sequans GM02SP modem
- **Power**: Battery powered with deep sleep

## Features

- Reads 3 DS18B20 temperature sensors
- Posts data to HTTP endpoint every hour
- Deep sleep between readings for power efficiency
- Battery voltage monitoring (if supported)
- Robust error handling and retry logic

## Pin Configuration

**⚠️ CRITICAL**: The pin assignments in `src/main.cpp` are PLACEHOLDERS. You **MUST** update them based on the official Walter board documentation.

### Official Documentation Sources:

1. **Walter Datasheet (PDF)**: 
   - https://www.quickspot.io/datasheet/walter_datasheet_v0.5.pdf
   - Contains pinout diagram and GPIO assignments

2. **GitHub Documentation**:
   - https://github.com/QuickSpot/walter-documentation
   - Setup guides and hardware details

3. **Arduino Library**:
   - https://github.com/QuickSpot/walter-arduino
   - Example code may show pin usage

### Current Pin Configuration (EDUCATED GUESSES - VERIFY):

Based on research and common ESP32-S3 patterns:

- **Modem UART**: RX=43, TX=44 (UART0 - typical ESP32-S3) ⚠️ VERIFY
- **Modem Control**: Set to -1 (may be handled by board hardware automatically)
- **DS18B20**: GPIO 14 (safe choice, verify available)
- **Battery ADC**: GPIO 4 (may not exist on Walter - check datasheet)
- **I2C**: SDA=8, SCL=9 (if needed for other peripherals)

**Important**: The modem control pins (PWR, RESET, DTR) are set to -1, meaning they may be handled automatically by the Walter board hardware. If the modem doesn't initialize, you may need to find and configure these pins from the datasheet.

### Important Notes:

- **Modem pins may be pre-configured**: The Sequans GM02SP modem pins may be hardwired on the Walter board. Check the datasheet to see if you need to configure them or if they're automatically handled.
- **Walter is Pycom GPy compatible**: If you have GPy documentation, it may be a reference, but always verify with official Walter docs.
- **Battery monitoring**: Walter may not have a battery ADC pin. If not available, the firmware will use a placeholder value.

## Configuration

### APN Settings

Update in `src/main.cpp`:
```cpp
const char* APN = "simbase";  // Your carrier APN
```

### Server Endpoint

Update in `src/main.cpp`:
```cpp
const char* POST_URL = "http://housetemp.pauricgrant.com/submit";
```

### RAT Mode (LTE-M vs NB-IoT)

The Sequans GM02SP supports both LTE-M and NB-IoT. Change in `src/main.cpp`:
```cpp
#define RAT_MODE RAT_MODE_LTEM   // Use LTE-M
// or
#define RAT_MODE RAT_MODE_NBIOT  // Use NB-IoT
// or
#define RAT_MODE RAT_MODE_AUTO   // Auto-select
```

## Sequans GM02SP AT Commands

The firmware uses Sequans-specific AT commands:
- `AT+SQNCTL=1,1` - Set LTE-M mode
- `AT+SQNCTL=1,2` - Set NB-IoT mode
- `AT+SQNCTL=0` - Power down modem

Standard AT commands (CPIN, CGDCONT, HTTP, etc.) should work similarly to other modems.

## Building and Uploading

1. Update pin definitions in `src/main.cpp`
2. Connect Walter board via USB-C
3. Build and upload:
   ```bash
   cd walter_compost_sensor
   pio run --target upload
   ```
4. Monitor serial output:
   ```bash
   pio device monitor
   ```

## Data Format

The ESP32 sends JSON data in this format:
```json
{
  "fw": "WALTER_COMPOST_2025-01-15",
  "seq": 123,
  "vbat": 4.20,
  "t1": 25.50,
  "t2": 24.30,
  "t3": null,
  "reset": "DEEPSLEEP",
  "wake": "TIMER"
}
```

## Troubleshooting

### Modem Not Responding
- Verify UART pins (RX/TX) are correct
- Check modem power sequence
- Ensure SIM card is inserted and active

### No Network Connection
- Verify APN is correct for your carrier
- Check RAT mode (LTE-M vs NB-IoT)
- Ensure you have coverage in your area

### Sensor Readings Fail
- Verify DS18B20 is connected to correct GPIO
- Check OneWire bus has pull-up resistor (4.7kΩ)
- Ensure sensors are powered

### Upload Fails
- Hold BOOT button while connecting USB
- Try different USB cable/port
- Check PlatformIO detects the board

## Differences from LilyGO T-A7670G

1. **Microcontroller**: ESP32-S3 (vs ESP32)
2. **Modem**: Sequans GM02SP (vs A7670G)
3. **AT Commands**: Sequans-specific commands (SQNCTL)
4. **Pin Mappings**: Different GPIO assignments
5. **Power Management**: May differ (verify with docs)

## Resources

### Official Walter Board Documentation:
- **[Walter Datasheet (PDF)](https://www.quickspot.io/datasheet/walter_datasheet_v0.5.pdf)** - **START HERE for pinout!**
- **[GitHub Documentation](https://github.com/QuickSpot/walter-documentation)** - Setup guides and examples
- **[Arduino Library](https://github.com/QuickSpot/walter-arduino)** - Arduino integration examples
- **[DPTechnics Walter Page](https://www.dptechnics.com/walter)** - Official product page

### Modem Documentation:
- [Sequans GM02SP Datasheet](https://www.sequans.com/) - Modem specifications
- [Sequans AT Command Reference](https://www.sequans.com/) - AT command documentation

### Quick Links:
- [Walter on QuickSpot](https://www.quickspot.io/) - Product information
- [Zephyr Project Walter Docs](https://docs.zephyrproject.org/latest/boards/dptechnics/walter/doc/index.html) - Zephyr RTOS support

