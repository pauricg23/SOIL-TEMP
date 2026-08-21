#include <Arduino.h>
#include <HTTPClient.h>
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
constexpr unsigned long SAMPLE_INTERVAL_MS = 30000;
constexpr unsigned long RETRY_INTERVAL_MS = 5000;
constexpr unsigned long WIFI_RETRY_INTERVAL_MS = 10000;
constexpr unsigned long SENSOR_RETRY_INTERVAL_MS = 10000;
constexpr char FIRMWARE_VERSION[] = "BABY_SCD40_1.0.0";

SensirionI2cScd4x sensor;
char sensorErrorMessage[96];
unsigned long lastSampleAt = 0;
unsigned long lastRetryAt = 0;
unsigned long lastWifiAttemptAt = 0;
unsigned long lastSensorAttemptAt = 0;
uint32_t readingSequence = 0;
uint32_t bootId = 0;
String pendingPayload;
bool sensorReady = false;

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
    return true;
}

void setup() {
    Serial.begin(115200);
    delay(800);
    Serial.println("\nBaby room monitor starting");
    bootId = esp_random();

    sensorReady = initializeSensor();
    if (!sensorReady) {
        Serial.println("Check VDD, GND, SDA GPIO21 and SCL GPIO22, then restart");
    }

    lastWifiAttemptAt = millis() - WIFI_RETRY_INTERVAL_MS;
    connectWifi();
    lastSampleAt = millis() - SAMPLE_INTERVAL_MS;
}

void loop() {
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
