// === Walter Board LTE Test with WalterModem Library ===
// Simple test to connect to LTE and send HTTP POST
// Based on: https://github.com/QuickSpot/walter-arduino
//
// To use:
// 1. Open in Arduino IDE
// 2. Select Board: DPTechnics Walter (or ESP32S3 Dev Module)
// 3. Select Port: /dev/cu.usbmodem1301
// 4. Upload and open Serial Monitor (115200 baud)

#include <Arduino.h>
#include <esp_mac.h>
#include <WalterModem.h>

// ---------- CONFIG ----------
#define HTTP_PROFILE 1

// Your mobile APN
static const char* APN = "simbase";

// Your server
static const char* HOST = "housetemp.pauricgrant.com";
static const uint16_t PORT = 80;  // 80 for HTTP
static const char* PATH = "/submit";

// How often to POST (seconds)
static const uint32_t SEND_INTERVAL_SEC = 30;

// ---------- GLOBALS ----------
WalterModem modem;
char deviceId[32] = "walter-";

// Make a stable deviceId from MAC
static void makeDeviceId() {
  uint8_t mac[6];
  esp_read_mac(mac, ESP_MAC_WIFI_STA);
  char macStr[18];
  sprintf(macStr, "%02X%02X%02X%02X%02X%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  strcat(deviceId, macStr);
}

void setup() {
  Serial.begin(115200);
  delay(1500);
  
  Serial.println("\n\n========================================");
  Serial.println("Walter LTE Test - Starting...");
  Serial.println("========================================\n");

  // Init modem UART (Walter uses Serial2 for the Sequans modem)
  Serial.println("Initializing modem...");
  if (WalterModem::begin(&Serial2)) {
    Serial.println("✅ Modem init OK");
  } else {
    Serial.println("❌ Modem init FAILED");
    Serial.println("Check if SIM card is inserted and board is powered");
    while (true) delay(1000);
  }
  Serial.println();

  makeDeviceId();
  Serial.printf("Device ID: %s\n", deviceId);
  Serial.println();

  // Create PDP context (set your APN + auth as needed)
  Serial.printf("Creating PDP context (APN: %s)...\n", APN);
  if (modem.createPDPContext(APN, WALTER_MODEM_PDP_AUTH_PROTO_NONE)) {
    Serial.println("✅ PDP context created");
  } else {
    Serial.println("❌ PDP context FAILED");
    Serial.println("Try WALTER_MODEM_PDP_AUTH_PROTO_PAP if your SIM needs auth");
    while (true) delay(2000);
  }
  Serial.println();

  // Radio to FULL
  Serial.println("Setting operational state to FULL...");
  if (!modem.setOpState(WALTER_MODEM_OPSTATE_FULL)) {
    Serial.println("❌ Failed to set op state FULL");
    while (true) delay(2000);
  }
  Serial.println("✅ Operational state set");
  Serial.println();

  // Wait until registered
  Serial.print("Waiting for network registration");
  WalterModemNetworkRegState st = modem.getNetworkRegState();
  while (!(st == WALTER_MODEM_NETWORK_REG_REGISTERED_HOME ||
           st == WALTER_MODEM_NETWORK_REG_REGISTERED_ROAMING)) {
    delay(200);
    Serial.print(".");
    st = modem.getNetworkRegState();
  }
  Serial.println("\n✅ Network registered");
  Serial.println();

  // Configure HTTP profile to your host:port
  Serial.printf("Configuring HTTP profile %d: %s:%u\n", HTTP_PROFILE, HOST, PORT);
  if (modem.httpConfigProfile(HTTP_PROFILE, HOST, PORT)) {
    Serial.println("✅ HTTP profile configured");
  } else {
    Serial.println("❌ HTTP profile config FAILED");
    while (true) delay(2000);
  }
  
  Serial.println("\n========================================");
  Serial.println("Setup complete - ready to send POST");
  Serial.println("========================================\n");
}

void loop() {
  // Build JSON body with dummy data
  char json[256];
  snprintf(json, sizeof(json),
           "{\"fw\":\"WALTER_LTE_TEST\",\"seq\":1,\"vbat\":4.20,"
           "\"t1\":null,\"t2\":null,\"t3\":null,\"test\":true,"
           "\"device_id\":\"%s\",\"ts\":%lu}",
           deviceId, (unsigned long)(millis() / 1000));

  Serial.printf("\nPOST %s%s\n", HOST, PATH);
  Serial.printf("Body: %s\n", json);

  // Send HTTP POST
  char contentType[32] = "";
  uint8_t responseBody[512] = {0};
  short receiveAttempts = 0;
  WalterModemRsp rsp = {};

  bool ok = modem.httpSend(
      HTTP_PROFILE,
      PATH,
      (uint8_t*)json, strlen(json),
      WALTER_MODEM_HTTP_SEND_CMD_POST,
      WALTER_MODEM_HTTP_POST_PARAM_APP_JSON,
      contentType, sizeof(contentType)
  );

  if (!ok) {
    Serial.println("❌ HTTP send FAILED");
    delay(SEND_INTERVAL_SEC * 1000UL);
    return;
  }

  Serial.println("HTTP query sent; waiting for response…");
  receiveAttempts = 5;  // try a few times
  memset(responseBody, 0, sizeof(responseBody));

  while (receiveAttempts-- > 0) {
    if (modem.httpDidRing(HTTP_PROFILE, responseBody, sizeof(responseBody), &rsp)
        || rsp.result == WALTER_MODEM_STATE_NO_DATA) {
      break;
    }
    delay(500);
  }

  // Print result
  Serial.printf("HTTP status: %d\n", rsp.data.httpResponse.httpStatus);
  Serial.printf("Resp Content-Type: %s\n", contentType);
  Serial.printf("Resp Body: %s\n", responseBody);

  if (rsp.data.httpResponse.httpStatus == 200 || 
      rsp.data.httpResponse.httpStatus == 201 ||
      rsp.data.httpResponse.httpStatus == 204) {
    Serial.println("✅ POST SUCCESS!");
  } else {
    Serial.println("❌ POST FAILED");
  }

  Serial.println("\n========================================\n");

  delay(SEND_INTERVAL_SEC * 1000UL);
}

