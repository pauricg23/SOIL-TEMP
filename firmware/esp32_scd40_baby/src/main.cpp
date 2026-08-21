#include <Arduino.h>
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
constexpr uint8_t RGB_RED_PIN = 27;
constexpr uint8_t RGB_GREEN_PIN = 26;
constexpr uint8_t RGB_BLUE_PIN = 25;
constexpr uint8_t RGB_RED_CHANNEL = 0;
constexpr uint8_t RGB_GREEN_CHANNEL = 1;
constexpr uint8_t RGB_BLUE_CHANNEL = 2;
constexpr uint16_t RGB_PWM_FREQUENCY = 5000;
constexpr uint8_t RGB_PWM_RESOLUTION = 8;
constexpr uint8_t DEFAULT_BRIGHTNESS = 40;
constexpr uint8_t MIN_BRIGHTNESS = 8;
constexpr uint8_t BRIGHTNESS_STEP = 16;
constexpr unsigned long SAMPLE_INTERVAL_MS = 30000;
constexpr unsigned long RETRY_INTERVAL_MS = 5000;
constexpr unsigned long WIFI_RETRY_INTERVAL_MS = 10000;
constexpr unsigned long SENSOR_RETRY_INTERVAL_MS = 10000;
constexpr char FIRMWARE_VERSION[] = "BABY_SCD40_1.1.0";

constexpr uint64_t IR_POWER = 0xFFA25D;
constexpr uint64_t IR_VOLUME_UP = 0xFF629D;
constexpr uint64_t IR_VOLUME_DOWN = 0xFFA857;
constexpr uint64_t IR_UP = 0xFF906F;
constexpr uint64_t IR_DOWN = 0xFFE01F;
constexpr uint64_t IR_RESET_BRIGHTNESS = 0xFF9867;
constexpr uint64_t IR_REPEAT = UINT64_MAX;

SensirionI2cScd4x sensor;
IRrecv irReceiver(IR_PIN);
decode_results irResults;
Preferences preferences;
char sensorErrorMessage[96];
unsigned long lastSampleAt = 0;
unsigned long lastRetryAt = 0;
unsigned long lastWifiAttemptAt = 0;
unsigned long lastSensorAttemptAt = 0;
uint32_t readingSequence = 0;
uint32_t bootId = 0;
String pendingPayload;
bool sensorReady = false;
bool lightEnabled = true;
uint8_t lightBrightness = DEFAULT_BRIGHTNESS;
float latestTemperatureC = NAN;

void writeRgb(uint8_t red, uint8_t green, uint8_t blue) {
    if (!lightEnabled) {
        red = 0;
        green = 0;
        blue = 0;
    }

    ledcWrite(RGB_RED_CHANNEL,
              static_cast<uint16_t>(red) * lightBrightness / 255);
    ledcWrite(RGB_GREEN_CHANNEL,
              static_cast<uint16_t>(green) * lightBrightness / 255);
    ledcWrite(RGB_BLUE_CHANNEL,
              static_cast<uint16_t>(blue) * lightBrightness / 255);
}

void updateTemperatureLight() {
    if (!isfinite(latestTemperatureC)) {
        writeRgb(0, 0, 0);
        return;
    }

    if (latestTemperatureC < 16.0F) {
        writeRgb(175, 0, 255);
        Serial.println("Room light: purple (cool)");
    } else if (latestTemperatureC <= 20.0F) {
        writeRgb(255, 110, 0);
        Serial.println("Room light: golden yellow (recommended)");
    } else if (latestTemperatureC <= 24.0F) {
        writeRgb(255, 38, 0);
        Serial.println("Room light: amber orange (warm)");
    } else {
        writeRgb(255, 0, 0);
        Serial.println("Room light: red (too warm)");
    }
}

void saveLightSettings() {
    preferences.putBool("enabled", lightEnabled);
    preferences.putUChar("brightness", lightBrightness);
}

void adjustBrightness(int change) {
    int updatedBrightness = constrain(
        static_cast<int>(lightBrightness) + change,
        static_cast<int>(MIN_BRIGHTNESS), 255);
    lightBrightness = static_cast<uint8_t>(updatedBrightness);
    lightEnabled = true;
    saveLightSettings();
    updateTemperatureLight();
    Serial.printf("Room light brightness: %u/255\n", lightBrightness);
}

void handleRemote() {
    if (!irReceiver.decode(&irResults)) {
        return;
    }

    uint64_t code = irResults.value;
    irReceiver.resume();
    if (code == IR_REPEAT) {
        return;
    }

    Serial.printf("IR code received: 0x%08llX\n",
                  static_cast<unsigned long long>(code));
    switch (code) {
        case IR_POWER:
            lightEnabled = !lightEnabled;
            saveLightSettings();
            updateTemperatureLight();
            Serial.printf("Room light: %s\n", lightEnabled ? "on" : "off");
            break;
        case IR_VOLUME_UP:
        case IR_UP:
            adjustBrightness(BRIGHTNESS_STEP);
            break;
        case IR_VOLUME_DOWN:
        case IR_DOWN:
            adjustBrightness(-BRIGHTNESS_STEP);
            break;
        case IR_RESET_BRIGHTNESS:
            lightBrightness = DEFAULT_BRIGHTNESS;
            lightEnabled = true;
            saveLightSettings();
            updateTemperatureLight();
            Serial.printf("Room light brightness reset: %u/255\n", lightBrightness);
            break;
        default:
            Serial.println("IR button is not assigned");
            break;
    }
}

void initializeRoomLight() {
    ledcSetup(RGB_RED_CHANNEL, RGB_PWM_FREQUENCY, RGB_PWM_RESOLUTION);
    ledcSetup(RGB_GREEN_CHANNEL, RGB_PWM_FREQUENCY, RGB_PWM_RESOLUTION);
    ledcSetup(RGB_BLUE_CHANNEL, RGB_PWM_FREQUENCY, RGB_PWM_RESOLUTION);
    ledcAttachPin(RGB_RED_PIN, RGB_RED_CHANNEL);
    ledcAttachPin(RGB_GREEN_PIN, RGB_GREEN_CHANNEL);
    ledcAttachPin(RGB_BLUE_PIN, RGB_BLUE_CHANNEL);

    preferences.begin("baby-light", false);
    lightEnabled = preferences.getBool("enabled", true);
    lightBrightness = preferences.getUChar("brightness", DEFAULT_BRIGHTNESS);
    lightBrightness = constrain(lightBrightness, MIN_BRIGHTNESS, 255);
    writeRgb(0, 0, 0);

    irReceiver.enableIRIn();
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
    char messageId[80];
    snprintf(messageId, sizeof messageId, "%s-%08lx-%lu", BABY_DEVICE_ID,
             static_cast<unsigned long>(bootId),
             static_cast<unsigned long>(readingSequence));

    char payload[384];
    snprintf(payload, sizeof payload,
             "{\"msg_id\":\"%s\",\"device_id\":\"%s\",\"co2_ppm\":%u,"
             "\"temperature_c\":%.2f,\"humidity_rh\":%.2f,\"rssi\":%d,"
             "\"firmware_version\":\"%s\"}",
             messageId, BABY_DEVICE_ID, co2Ppm, temperatureC, humidityRh,
             WiFi.status() == WL_CONNECTED ? WiFi.RSSI() : -127,
             FIRMWARE_VERSION);
    pendingPayload = payload;

    Serial.printf("SCD40: %u ppm, %.2f C, %.2f %%RH\n",
                  co2Ppm, temperatureC, humidityRh);
    latestTemperatureC = temperatureC;
    updateTemperatureLight();
    return true;
}

void setup() {
    Serial.begin(115200);
    delay(800);
    Serial.println("\nBaby room monitor starting");
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
