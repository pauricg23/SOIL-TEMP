#include <Arduino.h>
#include <Adafruit_NeoPixel.h>
#include <esp_system.h>
#include <HTTPClient.h>
#include <IRrecv.h>
#include <IRremoteESP8266.h>
#include <Preferences.h>
#include <SensirionI2cScd4x.h>
#include <WiFi.h>
#include <Wire.h>

#if __has_include("config.local.h")
#include "config.local.h"
#else
#include "config.example.h"
#warning "Using placeholder configuration; create src/config.local.h before deployment"
#endif

#ifdef NO_ERROR
#undef NO_ERROR
#endif
#define NO_ERROR 0

constexpr uint8_t SDA_PIN = 21;
constexpr uint8_t SCL_PIN = 22;
constexpr uint8_t IR_PIN = 19;
constexpr uint8_t RING_DATA_PIN = 18;
constexpr uint16_t RING_PIXEL_COUNT = 12;
constexpr uint8_t DEFAULT_BRIGHTNESS = 32;
constexpr uint8_t MIN_BRIGHTNESS = 5;
constexpr uint8_t MAX_BRIGHTNESS = 153;
constexpr uint8_t BRIGHTNESS_STEP = 8;
constexpr unsigned long LIGHT_FRAME_INTERVAL_MS = 35;
constexpr unsigned long GLOW_PERIOD_MS = 4500;
constexpr unsigned long SETTINGS_SAVE_DELAY_MS = 1200;
constexpr unsigned long SAMPLE_INTERVAL_MS = 30000;
constexpr unsigned long RETRY_INTERVAL_MS = 5000;
constexpr unsigned long WIFI_RETRY_INTERVAL_MS = 10000;
constexpr unsigned long SENSOR_RETRY_INTERVAL_MS = 10000;
constexpr unsigned long SENSOR_WARMUP_MS = 180000;
constexpr char FIRMWARE_VERSION[] = "BABY_SCD40_1.3.1";

constexpr uint64_t IR_POWER = 0xFFA25D;
constexpr uint64_t IR_VOLUME_UP = 0xFF629D;
constexpr uint64_t IR_VOLUME_DOWN = 0xFFA857;
constexpr uint64_t IR_MODE_TEMPERATURE = 0xFF30CF;
constexpr uint64_t IR_MODE_GLOW = 0xFF18E7;
constexpr uint64_t IR_MODE_WARM_WHITE = 0xFF7A85;
constexpr uint64_t IR_MODE_MANUAL = 0xFF10EF;
constexpr uint64_t IR_MODE_CO2 = 0xFF38C7;
constexpr uint64_t IR_REPEAT = UINT64_MAX;

enum class LightMode : uint8_t {
    TEMPERATURE = 1,
    TEMPERATURE_GLOW = 2,
    WARM_WHITE = 3,
    MANUAL_COLOUR = 4,
    CO2 = 5
};

struct RgbColour {
    uint8_t red;
    uint8_t green;
    uint8_t blue;
};

constexpr RgbColour MANUAL_COLOURS[] = {
    {175, 40, 255},
    {255, 70, 145},
    {65, 145, 255},
    {55, 220, 155},
    {255, 130, 25},
    {255, 45, 8}
};

SensirionI2cScd4x sensor;
IRrecv irReceiver(IR_PIN);
decode_results irResults;
Preferences preferences;
Adafruit_NeoPixel roomRing(
    RING_PIXEL_COUNT, RING_DATA_PIN, NEO_GRB + NEO_KHZ800);
char sensorErrorMessage[96];
unsigned long lastSampleAt = 0;
unsigned long lastRetryAt = 0;
unsigned long lastWifiAttemptAt = 0;
unsigned long lastSensorAttemptAt = 0;
unsigned long lastLightFrameAt = 0;
unsigned long lastSettingsChangeAt = 0;
uint32_t readingSequence = 0;
uint32_t bootId = 0;
String pendingPayload;
bool sensorReady = false;
bool lightEnabled = true;
bool settingsDirty = false;
uint8_t lightBrightness = DEFAULT_BRIGHTNESS;
uint8_t manualColourIndex = 0;
LightMode lightMode = LightMode::TEMPERATURE;
float latestTemperatureC = NAN;
uint16_t latestCo2Ppm = 0;
uint64_t lastIrCode = 0;
esp_reset_reason_t lastResetReason = ESP_RST_UNKNOWN;

const char* resetReasonName(esp_reset_reason_t reason) {
    switch (reason) {
        case ESP_RST_POWERON: return "power_on";
        case ESP_RST_EXT: return "external_reset";
        case ESP_RST_SW: return "software_reset";
        case ESP_RST_PANIC: return "panic";
        case ESP_RST_INT_WDT: return "interrupt_watchdog";
        case ESP_RST_TASK_WDT: return "task_watchdog";
        case ESP_RST_WDT: return "watchdog";
        case ESP_RST_DEEPSLEEP: return "deep_sleep";
        case ESP_RST_BROWNOUT: return "brownout";
        case ESP_RST_SDIO: return "sdio";
        default: return "unknown";
    }
}

const char* lightModeName(LightMode mode) {
    switch (mode) {
        case LightMode::TEMPERATURE: return "temperature";
        case LightMode::TEMPERATURE_GLOW: return "temperature glow";
        case LightMode::WARM_WHITE: return "warm white";
        case LightMode::MANUAL_COLOUR: return "manual colour";
        case LightMode::CO2: return "CO2";
        default: return "temperature";
    }
}

RgbColour temperatureColour() {
    if (!isfinite(latestTemperatureC)) return {0, 0, 0};
    if (latestTemperatureC < 16.0F) return {175, 20, 255};
    if (latestTemperatureC <= 20.0F) return {255, 115, 8};
    if (latestTemperatureC <= 24.0F) return {255, 45, 4};
    return {255, 0, 0};
}

RgbColour co2Colour() {
    if (latestCo2Ppm == 0) return {0, 0, 0};
    if (latestCo2Ppm < 800) return {35, 220, 125};
    if (latestCo2Ppm <= 1000) return {120, 215, 80};
    if (latestCo2Ppm <= 1400) return {255, 115, 8};
    return {255, 0, 0};
}

void renderRing(RgbColour colour, float intensity = 1.0F) {
    if (!lightEnabled) intensity = 0.0F;
    intensity = constrain(intensity, 0.0F, 1.0F);
    uint8_t effectiveBrightness = static_cast<uint8_t>(
        roundf(static_cast<float>(lightBrightness) * intensity));
    uint8_t red = static_cast<uint8_t>(
        static_cast<uint16_t>(colour.red) * effectiveBrightness / 255);
    uint8_t green = static_cast<uint8_t>(
        static_cast<uint16_t>(colour.green) * effectiveBrightness / 255);
    uint8_t blue = static_cast<uint8_t>(
        static_cast<uint16_t>(colour.blue) * effectiveBrightness / 255);
    roomRing.fill(roomRing.Color(red, green, blue));
    roomRing.show();
}

void updateRoomLight(bool force = false) {
    unsigned long now = millis();
    if (!force && now - lastLightFrameAt < LIGHT_FRAME_INTERVAL_MS) return;
    lastLightFrameAt = now;

    RgbColour colour = {0, 0, 0};
    float intensity = 1.0F;
    switch (lightMode) {
        case LightMode::TEMPERATURE:
            colour = temperatureColour();
            break;
        case LightMode::TEMPERATURE_GLOW: {
            colour = temperatureColour();
            float progress = static_cast<float>(now % GLOW_PERIOD_MS) /
                             static_cast<float>(GLOW_PERIOD_MS);
            intensity = 0.25F + 0.75F *
                        (0.5F - 0.5F * cosf(progress * TWO_PI));
            break;
        }
        case LightMode::WARM_WHITE:
            colour = {255, 115, 35};
            break;
        case LightMode::MANUAL_COLOUR:
            colour = MANUAL_COLOURS[manualColourIndex];
            break;
        case LightMode::CO2:
            colour = co2Colour();
            break;
    }
    renderRing(colour, intensity);
}

void saveLightSettings() {
    preferences.putBool("enabled", lightEnabled);
    preferences.putUChar("brightness", lightBrightness);
    preferences.putUChar("mode", static_cast<uint8_t>(lightMode));
    preferences.putUChar("colour", manualColourIndex);
    settingsDirty = false;
}

void markSettingsChanged() {
    settingsDirty = true;
    lastSettingsChangeAt = millis();
}

void setLightMode(LightMode mode) {
    lightMode = mode;
    lightEnabled = true;
    markSettingsChanged();
    updateRoomLight(true);
    Serial.printf("Room light mode: %s\n", lightModeName(lightMode));
}

void adjustBrightness(int change) {
    int updatedBrightness = constrain(
        static_cast<int>(lightBrightness) + change,
        static_cast<int>(MIN_BRIGHTNESS),
        static_cast<int>(MAX_BRIGHTNESS));
    lightBrightness = static_cast<uint8_t>(updatedBrightness);
    lightEnabled = true;
    markSettingsChanged();
    updateRoomLight(true);
    Serial.printf("Room light brightness: %u%%\n",
                  static_cast<unsigned int>(lightBrightness) * 100 / 255);
}

void handleRemote() {
    if (!irReceiver.decode(&irResults)) return;

    uint64_t code = irResults.value;
    irReceiver.resume();
    if (code == IR_REPEAT) {
        if (lastIrCode != IR_VOLUME_UP && lastIrCode != IR_VOLUME_DOWN) return;
        code = lastIrCode;
    } else {
        lastIrCode = code;
        Serial.printf("IR code received: 0x%08llX\n",
                      static_cast<unsigned long long>(code));
    }

    switch (code) {
        case IR_POWER:
            lightEnabled = !lightEnabled;
            markSettingsChanged();
            updateRoomLight(true);
            Serial.printf("Room light: %s\n", lightEnabled ? "on" : "off");
            break;
        case IR_VOLUME_UP:
            adjustBrightness(BRIGHTNESS_STEP);
            break;
        case IR_VOLUME_DOWN:
            adjustBrightness(-BRIGHTNESS_STEP);
            break;
        case IR_MODE_TEMPERATURE:
            setLightMode(LightMode::TEMPERATURE);
            break;
        case IR_MODE_GLOW:
            setLightMode(LightMode::TEMPERATURE_GLOW);
            break;
        case IR_MODE_WARM_WHITE:
            setLightMode(LightMode::WARM_WHITE);
            break;
        case IR_MODE_MANUAL:
            if (lightMode == LightMode::MANUAL_COLOUR && lightEnabled) {
                manualColourIndex = (manualColourIndex + 1) %
                                    (sizeof MANUAL_COLOURS / sizeof MANUAL_COLOURS[0]);
            }
            setLightMode(LightMode::MANUAL_COLOUR);
            Serial.printf("Manual colour: %u\n", manualColourIndex + 1);
            break;
        case IR_MODE_CO2:
            setLightMode(LightMode::CO2);
            break;
        default:
            Serial.println("IR button is not assigned");
            break;
    }
}

void initializeRoomLight() {
    roomRing.begin();
    roomRing.clear();
    roomRing.show();

    preferences.begin("baby-light", false);
    lightEnabled = preferences.getBool("enabled", true);
    lightBrightness = constrain(
        preferences.getUChar("brightness", DEFAULT_BRIGHTNESS),
        MIN_BRIGHTNESS, MAX_BRIGHTNESS);
    uint8_t savedMode = preferences.getUChar(
        "mode", static_cast<uint8_t>(LightMode::TEMPERATURE));
    if (savedMode < static_cast<uint8_t>(LightMode::TEMPERATURE) ||
        savedMode > static_cast<uint8_t>(LightMode::CO2)) {
        savedMode = static_cast<uint8_t>(LightMode::TEMPERATURE);
    }
    lightMode = static_cast<LightMode>(savedMode);
    manualColourIndex = preferences.getUChar("colour", 0) %
                        (sizeof MANUAL_COLOURS / sizeof MANUAL_COLOURS[0]);

    irReceiver.enableIRIn();
    updateRoomLight(true);
    Serial.printf("WS2812 ring ready on GPIO18; mode %s; brightness %u%%\n",
                  lightModeName(lightMode),
                  static_cast<unsigned int>(lightBrightness) * 100 / 255);
    Serial.println("IR receiver ready on GPIO19");
}

void printSensorError(const char* operation, int16_t error) {
    errorToString(error, sensorErrorMessage, sizeof sensorErrorMessage);
    Serial.printf("SCD40 %s failed: %s\n", operation, sensorErrorMessage);
}

bool findScd40() {
    bool found = false;
    Serial.println("Scanning I2C bus on SDA GPIO21 / SCL GPIO22");
    for (uint8_t address = 1; address < 127; address++) {
        Wire.beginTransmission(address);
        if (Wire.endTransmission() == 0) {
            Serial.printf("I2C device found at 0x%02X\n", address);
            if (address == SCD40_I2C_ADDR_62) {
                found = true;
            }
        }
    }
    if (!found) {
        Serial.println("No SCD40 found at 0x62");
    }
    return found;
}

bool initializeSensor() {
    Wire.begin(SDA_PIN, SCL_PIN);
    if (!findScd40()) {
        return false;
    }
    sensor.begin(Wire, SCD40_I2C_ADDR_62);
    delay(30);

    sensor.wakeUp();
    sensor.stopPeriodicMeasurement();
    delay(500);

    int16_t error = sensor.reinit();
    if (error != NO_ERROR) {
        printSensorError("reinit", error);
        return false;
    }

    uint64_t serialNumber = 0;
    error = sensor.getSerialNumber(serialNumber);
    if (error != NO_ERROR) {
        printSensorError("serial-number read", error);
        return false;
    }

    Serial.printf("SCD40 detected at 0x62, serial %08X%08X\n",
                  static_cast<uint32_t>(serialNumber >> 32),
                  static_cast<uint32_t>(serialNumber));

    error = sensor.startPeriodicMeasurement();
    if (error != NO_ERROR) {
        printSensorError("measurement start", error);
        return false;
    }

    return true;
}

void connectWifi() {
    if (WiFi.status() == WL_CONNECTED) {
        return;
    }

    unsigned long now = millis();
    if (now - lastWifiAttemptAt < WIFI_RETRY_INTERVAL_MS) {
        return;
    }
    lastWifiAttemptAt = now;

    Serial.printf("Connecting to Wi-Fi: %s\n", WIFI_SSID);
    WiFi.mode(WIFI_STA);
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
}

bool sendPendingReading() {
    if (pendingPayload.isEmpty() || WiFi.status() != WL_CONNECTED) {
        return false;
    }

    HTTPClient http;
    http.setConnectTimeout(5000);
    http.setTimeout(5000);
    if (!http.begin(BABY_SERVER_URL)) {
        Serial.println("HTTP setup failed");
        return false;
    }

    http.addHeader("Content-Type", "application/json");
    http.addHeader("X-INGEST-TOKEN", INGEST_TOKEN);
    int responseCode = http.POST(pendingPayload);
    String response = http.getString();
    http.end();

    if (responseCode >= 200 && responseCode < 300) {
        Serial.printf("Reading accepted by Pi (%d)\n", responseCode);
        pendingPayload = "";
        return true;
    }

    Serial.printf("Pi submission failed (%d): %s\n", responseCode, response.c_str());
    return false;
}

bool readSensor() {
    bool dataReady = false;
    int16_t error = sensor.getDataReadyStatus(dataReady);
    if (error != NO_ERROR) {
        printSensorError("data-ready check", error);
        return false;
    }
    if (!dataReady) {
        Serial.println("SCD40 measurement is not ready yet");
        return false;
    }

    uint16_t co2Ppm = 0;
    float temperatureC = 0;
    float humidityRh = 0;
    error = sensor.readMeasurement(co2Ppm, temperatureC, humidityRh);
    if (error != NO_ERROR) {
        printSensorError("measurement read", error);
        return false;
    }
    if (co2Ppm == 0 || !isfinite(temperatureC) || !isfinite(humidityRh)) {
        Serial.println("SCD40 returned an invalid reading");
        return false;
    }

    readingSequence++;
    bool warmingUp = millis() < SENSOR_WARMUP_MS;
    char messageId[80];
    snprintf(messageId, sizeof messageId, "%s-%08lx-%lu", BABY_DEVICE_ID,
             static_cast<unsigned long>(bootId),
             static_cast<unsigned long>(readingSequence));

    char payload[512];
    snprintf(payload, sizeof payload,
             "{\"msg_id\":\"%s\",\"device_id\":\"%s\",\"co2_ppm\":%u,"
             "\"temperature_c\":%.2f,\"humidity_rh\":%.2f,\"rssi\":%d,"
             "\"firmware_version\":\"%s\",\"uptime_seconds\":%lu,"
             "\"reset_reason\":\"%s\",\"warmup\":%s}",
             messageId, BABY_DEVICE_ID, co2Ppm, temperatureC, humidityRh,
             WiFi.status() == WL_CONNECTED ? WiFi.RSSI() : -127,
             FIRMWARE_VERSION, static_cast<unsigned long>(millis() / 1000),
             resetReasonName(lastResetReason), warmingUp ? "true" : "false");
    pendingPayload = payload;

    Serial.printf("SCD40: %u ppm, %.2f C, %.2f %%RH\n",
                  co2Ppm, temperatureC, humidityRh);
    if (warmingUp) {
        Serial.println("SCD40 warming up; dashboard will exclude this reading");
    } else {
        latestTemperatureC = temperatureC;
        latestCo2Ppm = co2Ppm;
        updateRoomLight(true);
    }
    return true;
}

void setup() {
    Serial.begin(115200);
    delay(800);
    Serial.println("\nBaby room monitor starting");
    lastResetReason = esp_reset_reason();
    Serial.printf("Reset reason: %s\n", resetReasonName(lastResetReason));
    bootId = esp_random();
    initializeRoomLight();

    sensorReady = initializeSensor();
    if (!sensorReady) {
        Serial.println("Check VDD, GND, SDA GPIO21 and SCL GPIO22, then restart");
    }

    lastWifiAttemptAt = millis() - WIFI_RETRY_INTERVAL_MS;
    connectWifi();
    lastSampleAt = millis() - SAMPLE_INTERVAL_MS;
}

void loop() {
    handleRemote();
    updateRoomLight();
    if (settingsDirty &&
        millis() - lastSettingsChangeAt >= SETTINGS_SAVE_DELAY_MS) {
        saveLightSettings();
    }
    connectWifi();
    unsigned long now = millis();

    if (!sensorReady && now - lastSensorAttemptAt >= SENSOR_RETRY_INTERVAL_MS) {
        lastSensorAttemptAt = now;
        sensorReady = initializeSensor();
    }

    if (!pendingPayload.isEmpty() && now - lastRetryAt >= RETRY_INTERVAL_MS) {
        lastRetryAt = now;
        sendPendingReading();
    }

    if (sensorReady && pendingPayload.isEmpty() && now - lastSampleAt >= SAMPLE_INTERVAL_MS) {
        lastSampleAt = now;
        if (readSensor()) {
            sendPendingReading();
        }
    }

    delay(50);
}
