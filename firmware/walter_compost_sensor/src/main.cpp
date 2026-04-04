#include <Arduino.h>
#include <OneWire.h>
#include <DallasTemperature.h>
#include "spi_flash_mmap.h"
#include "esp_vfs_fat_compat.h"
#include <WalterModem.h>
#include <HardwareSerial.h>
#include <WiFi.h>
#include <Preferences.h>
#include "esp_sleep.h"
#include <time.h>
#include <sys/time.h>
#include <string.h>

// Walter: 3V3 EN is IO0 (active LOW)
#define V3V3_EN_PIN 0
// DS18B20 data pin (confirmed working)
#define ONE_WIRE_BUS 17

#define HTTP_HOST "housetemp.pauricgrant.com"
#define HTTP_PORT 80
#define HTTP_POST_ENDPOINT "/submit"
#define HTTP_DEBUG_ENDPOINT "/alert"

// Ingest token must not be committed. Define it in one of:
// - `src/ingest_token.local.h` (ignored by git)
// - PlatformIO build flags: `-DHTTP_INGEST_TOKEN=\"...\"`
#if __has_include("ingest_token.local.h")
#include "ingest_token.local.h"
#endif

#ifndef HTTP_INGEST_TOKEN
#define HTTP_INGEST_TOKEN ""
#endif
#define SEND_DEBUG_ALERTS 0
#define SLEEP_SECONDS 3600
#define TEMP_RETRY_COUNT 6
#define TEMP_RETRY_DELAY_MS 1200
#define SENSOR_POWERUP_DELAY_MS 2000
#define SENSOR_STABILIZE_DELAY_MS 300
#define SENSOR_CONVERT_DELAY_MS 1000
#define MIN_SENSOR_COUNT 3
#define USE_FIXED_SENSOR_ADDRS 0
#define MAX_CYCLE_MS 900000UL
#define RETRY_LTE_FAIL_DELAY_MS 5000
#define RETRY_HTTP_FAIL_DELAY_MS 3000
#define HTTP_URC_ASSUME_SENT_WAIT_MS 10000UL
#define HTTP_ACK_WAIT_MS 10000UL
#define FAIL_RETRY_SLEEP_SECONDS 300
#define FAIL_RETRY_SLEEP_MAX_TRIES 3
#define ACK_NO_URC_ASSUME_FOUND_MAX 3
#define WIFI_CONNECT_TIMEOUT_MS 8000
#define QUEUE_SIZE 24
#define QUEUE_NS "txq"

#if __has_include("wifi_secrets.local.h")
#include "wifi_secrets.local.h"
#endif

#ifndef WIFI_DEBUG_FALLBACK
#define WIFI_DEBUG_FALLBACK 0
#endif

#ifndef WIFI_SSID
#define WIFI_SSID ""
#endif

#ifndef WIFI_PASS
#define WIFI_PASS ""
#endif

// Optional fixed DS18B20 ROM addresses for stable probe mapping.
// Set USE_FIXED_SENSOR_ADDRS to 1 and fill these with your real probe addresses.
static const uint8_t SENSOR1_ADDR[8] = {0, 0, 0, 0, 0, 0, 0, 0};
static const uint8_t SENSOR2_ADDR[8] = {0, 0, 0, 0, 0, 0, 0, 0};
static const uint8_t SENSOR3_ADDR[8] = {0, 0, 0, 0, 0, 0, 0, 0};

OneWire ow(ONE_WIRE_BUS);
DallasTemperature dt(&ow);

WalterModem modem;
walter_modem_rsp_t rsp = {};
uint8_t in_buf[1500] = {0};
Preferences prefs;
RTC_DATA_ATTR uint32_t rtc_cycle_counter = 0;
RTC_DATA_ATTR char rtc_last_fail[24] = "none";
RTC_DATA_ATTR uint32_t rtc_last_fail_cycle = 0;
RTC_DATA_ATTR uint32_t rtc_last_wifi_dbg_ms = 0;
RTC_DATA_ATTR uint32_t rtc_boot_id = 0;
RTC_DATA_ATTR uint8_t rtc_fail_retry_sleep_count = 0;
RTC_DATA_ATTR char rtc_pending_ack_msg_id[80] = "";
RTC_DATA_ATTR uint8_t rtc_pending_ack_no_urc_count = 0;
static uint16_t q_head = 0;
static uint16_t q_tail = 0;
static uint16_t q_count = 0;
volatile bool g_http_done = false;
volatile uint16_t g_http_status = 0;

static void wifiDebugFailure(const char* reason, const char* wake_str, const char* reset_str,
                             int http_status = -1);

static void setFail(const char* s) {
  if (!s) s = "unknown";
  strncpy(rtc_last_fail, s, sizeof(rtc_last_fail) - 1);
  rtc_last_fail[sizeof(rtc_last_fail) - 1] = 0;
  rtc_last_fail_cycle = rtc_cycle_counter;
}

static uint32_t nextFailureSleepSeconds() {
  if (rtc_fail_retry_sleep_count < 255) {
    rtc_fail_retry_sleep_count++;
  }

  if (rtc_fail_retry_sleep_count <= FAIL_RETRY_SLEEP_MAX_TRIES) {
    Serial.printf("Failure retry sleep %u/%u: %u s\n",
                  (unsigned)rtc_fail_retry_sleep_count,
                  (unsigned)FAIL_RETRY_SLEEP_MAX_TRIES,
                  (unsigned)FAIL_RETRY_SLEEP_SECONDS);
    return FAIL_RETRY_SLEEP_SECONDS;
  }

  Serial.printf("Failure retry cap reached (%u). Falling back to %u s sleep.\n",
                (unsigned)rtc_fail_retry_sleep_count,
                (unsigned)SLEEP_SECONDS);
  rtc_fail_retry_sleep_count = 0;
  return SLEEP_SECONDS;
}

static void setPendingAckMsgId(const char* msg_id) {
  if (!msg_id || !msg_id[0]) return;
  if (strcmp(rtc_pending_ack_msg_id, msg_id) != 0) {
    rtc_pending_ack_no_urc_count = 0;
  }
  strncpy(rtc_pending_ack_msg_id, msg_id, sizeof(rtc_pending_ack_msg_id) - 1);
  rtc_pending_ack_msg_id[sizeof(rtc_pending_ack_msg_id) - 1] = 0;
}

static void clearPendingAckMsgId() {
  rtc_pending_ack_msg_id[0] = 0;
  rtc_pending_ack_no_urc_count = 0;
}

static bool hasPendingAckForMsgId(const char* msg_id) {
  return msg_id && msg_id[0] &&
         rtc_pending_ack_msg_id[0] &&
         strcmp(rtc_pending_ack_msg_id, msg_id) == 0;
}

static uint8_t notePendingAckNoUrc(const char* msg_id) {
  if (!msg_id || !msg_id[0]) return 0;
  if (!hasPendingAckForMsgId(msg_id)) {
    setPendingAckMsgId(msg_id);
    rtc_pending_ack_no_urc_count = 0;
  }
  if (rtc_pending_ack_no_urc_count < 255) {
    rtc_pending_ack_no_urc_count++;
  }
  return rtc_pending_ack_no_urc_count;
}

static inline const char* wakeName(esp_sleep_wakeup_cause_t w) {
  switch(w) {
    case ESP_SLEEP_WAKEUP_TIMER: return "TIMER";
    case ESP_SLEEP_WAKEUP_EXT0:  return "EXT0";
    case ESP_SLEEP_WAKEUP_EXT1:  return "EXT1";
    case ESP_SLEEP_WAKEUP_TOUCHPAD: return "TOUCHPAD";
    case ESP_SLEEP_WAKEUP_ULP:   return "ULP";
    default: return "OTHER";
  }
}

static inline const char* resetName(esp_reset_reason_t r) {
  switch(r) {
    case ESP_RST_DEEPSLEEP: return "DEEPSLEEP";
    case ESP_RST_POWERON:   return "POWERON";
    case ESP_RST_BROWNOUT:  return "BROWNOUT";
    case ESP_RST_SW:        return "SW";
    case ESP_RST_PANIC:     return "PANIC";
    case ESP_RST_INT_WDT:   return "I-WDT";
    case ESP_RST_TASK_WDT:  return "T-WDT";
    case ESP_RST_WDT:       return "WDT";
    case ESP_RST_EXT:       return "EXT";
    case ESP_RST_SDIO:      return "SDIO";
    default:                return "OTHER";
  }
}

static bool getLocalEpochTime(int64_t* epoch_out) {
  if (!epoch_out) return false;
  time_t now = time(nullptr);
  // Treat pre-2023 values as "clock not initialized".
  if (now < 1700000000) return false;
  *epoch_out = (int64_t)now;
  return true;
}

static void syncLocalClockFromEpoch(int64_t epoch) {
  if (epoch <= 0) return;
  struct timeval tv;
  tv.tv_sec = (time_t)epoch;
  tv.tv_usec = 0;
  settimeofday(&tv, nullptr);
}

static inline int64_t hourBucketEpoch(int64_t epoch) {
  if (epoch <= 0) return 0;
  return (epoch / 3600LL) * 3600LL;
}

bool waitForNetwork(int timeout_sec = 120) {
  int time = 0;
  while (true) {
    WalterModemNetworkRegState reg = modem.getNetworkRegState();
    if (reg == WALTER_MODEM_NETWORK_REG_REGISTERED_HOME ||
        reg == WALTER_MODEM_NETWORK_REG_REGISTERED_ROAMING) {
      return true;
    }
    delay(1000);
    time++;
    if (time > timeout_sec) return false;
  }
}

bool lteConnect() {
  walter_modem_rsp_t r = {};
  static bool rat_config_attempted = false;

  // Best-effort: set RAT once per wake cycle. Repeating this on every retry can cause needless failures.
  if (!rat_config_attempted) {
    rat_config_attempted = true;
    if (!modem.setRAT(WALTER_MODEM_RAT_AUTO, &r) || r.result != WALTER_MODEM_STATE_OK) {
      Serial.println("setRAT(AUTO) failed; continuing with modem default RAT.");
    }
  }

  if (!modem.setOpState(WALTER_MODEM_OPSTATE_NO_RF, &r) || r.result != WALTER_MODEM_STATE_OK) {
    setFail("lte_norf");
    return false;
  }
  if (!WalterModem::definePDPContext(1, "simbase", &r) || r.result != WALTER_MODEM_STATE_OK) {
    setFail("lte_pdpctx");
    return false;
  }
  if (!modem.setOpState(WALTER_MODEM_OPSTATE_FULL, &r) || r.result != WALTER_MODEM_STATE_OK) {
    setFail("lte_full");
    return false;
  }
  if (!modem.setNetworkSelectionMode(WALTER_MODEM_NETWORK_SEL_MODE_AUTOMATIC, NULL,
                                     WALTER_MODEM_OPERATOR_FORMAT_LONG_ALPHANUMERIC, &r) ||
      r.result != WALTER_MODEM_STATE_OK) {
    setFail("lte_sel");
    return false;
  }

  if (!waitForNetwork(120)) {
    setFail("lte_reg");
    return false;
  }

  // Registered does not guarantee packet data is usable; attach and activate PDP explicitly.
  if (!WalterModem::setNetworkAttachmentState(true, &r) || r.result != WALTER_MODEM_STATE_OK) {
    setFail("lte_attach");
    return false;
  }
  if (!WalterModem::setPDPContextActive(true, 1, &r) || r.result != WALTER_MODEM_STATE_OK) {
    setFail("lte_pdp");
    return false;
  }
  if (!WalterModem::getPDPAddress(&r, NULL, NULL, 1) || r.result != WALTER_MODEM_STATE_OK) {
    setFail("lte_ip");
    return false;
  }

  const char* ip = r.data.pdpAddressList.pdpAddress;
  if (!ip || ip[0] == '\0') {
    setFail("lte_ip");
    return false;
  }

  return true;
}

bool lteDisconnect(uint32_t timeout_ms = 15000) {
  if (!modem.setOpState(WALTER_MODEM_OPSTATE_MINIMUM)) return false;
  uint32_t start = millis();
  WalterModemNetworkRegState reg = modem.getNetworkRegState();
  while (reg != WALTER_MODEM_NETWORK_REG_NOT_SEARCHING) {
    if (millis() - start >= timeout_ms) {
      Serial.println("LTE disconnect timeout; proceeding to deep sleep.");
      return false;
    }
    delay(100);
    reg = modem.getNetworkRegState();
  }
  return true;
}

bool httpPost(const char* path, const uint8_t* body, size_t bodyLen) {
  char ctBuf[32] = {0};
  return modem.httpSend(1, path, (uint8_t*)body, (uint16_t)bodyLen,
                        WALTER_MODEM_HTTP_SEND_CMD_POST, WALTER_MODEM_HTTP_POST_PARAM_JSON,
                        ctBuf, sizeof(ctBuf));
}

bool httpGet(const char* path) {
  char ctBuf[32] = {0};
  return modem.httpQuery(1, path, WALTER_MODEM_HTTP_QUERY_CMD_GET, ctBuf, sizeof(ctBuf));
}

static bool getModemEpochTime(int64_t* epoch_out) {
  if (!epoch_out) return false;
  walter_modem_rsp_t clock_rsp = {};
  if (!WalterModem::getClock(&clock_rsp)) return false;
  if (clock_rsp.result != WALTER_MODEM_STATE_OK) return false;
  int64_t epoch = clock_rsp.data.clock.epochTime;
  // Reject clearly invalid modem clock values.
  if (epoch < 1704067200LL) return false; // 2024-01-01T00:00:00Z
  *epoch_out = epoch;
  return true;
}

static bool epochToIso8601UTC(int64_t epoch, char* out, size_t out_len) {
  if (!out || out_len == 0) return false;
  time_t raw = (time_t)epoch;
  struct tm tm_utc;
  if (!gmtime_r(&raw, &tm_utc)) return false;
  size_t n = strftime(out, out_len, "%Y-%m-%dT%H:%M:%S", &tm_utc);
  return n > 0;
}

static uint32_t sleepToNextHourSeconds(int64_t epoch_now) {
  if (epoch_now <= 0) return SLEEP_SECONDS;
  int64_t next_hour = ((epoch_now / 3600LL) + 1LL) * 3600LL;
  int64_t to_next = next_hour - epoch_now;

  // Never schedule an immediate re-wake; clamp to 30s minimum.
  if (to_next < 30) to_next = 30;
  // Safety clamp (shouldn't happen)
  if (to_next > 7200) to_next = 3600;

  return (uint32_t)to_next;
}

static bool waitForHttpResult(uint32_t timeout_ms) {
  uint32_t start = millis();
  while (!g_http_done && (millis() - start) < timeout_ms) {
    delay(50);
  }
  return g_http_done;
}

static void printAddress(const uint8_t* addr) {
  for (int i = 0; i < 8; i++) {
    if (addr[i] < 16) Serial.print("0");
    Serial.print(addr[i], HEX);
  }
}

static bool loadSensorAddresses(DeviceAddress out_addrs[3], int deviceCount) {
  if (deviceCount < MIN_SENSOR_COUNT) return false;
#if USE_FIXED_SENSOR_ADDRS
  memcpy(out_addrs[0], SENSOR1_ADDR, 8);
  memcpy(out_addrs[1], SENSOR2_ADDR, 8);
  memcpy(out_addrs[2], SENSOR3_ADDR, 8);
  return true;
#else
  DeviceAddress detected[8];
  int found = 0;
  for (int i = 0; i < deviceCount && i < 8; i++) {
    if (dt.getAddress(detected[found], i)) {
      found++;
    }
  }
  if (found < MIN_SENSOR_COUNT) return false;

  // Sort ROM codes so probe mapping is stable between boots.
  for (int i = 0; i < found - 1; i++) {
    for (int j = i + 1; j < found; j++) {
      if (memcmp(detected[i], detected[j], 8) > 0) {
        DeviceAddress tmp;
        memcpy(tmp, detected[i], 8);
        memcpy(detected[i], detected[j], 8);
        memcpy(detected[j], tmp, 8);
      }
    }
  }

  memcpy(out_addrs[0], detected[0], 8);
  memcpy(out_addrs[1], detected[1], 8);
  memcpy(out_addrs[2], detected[2], 8);
  return true;
#endif
}

bool sendDebugEvent(const char* stage, bool ok, const char* detail,
                    const char* wake_str, const char* reset_str,
                    float t1 = DEVICE_DISCONNECTED_C,
                    float t2 = DEVICE_DISCONNECTED_C,
                    float t3 = DEVICE_DISCONNECTED_C,
                    bool includeTemps = false) {
#if !SEND_DEBUG_ALERTS
  (void)stage;
  (void)ok;
  (void)detail;
  (void)wake_str;
  (void)reset_str;
  (void)t1;
  (void)t2;
  (void)t3;
  (void)includeTemps;
  return true;
#else
  char body[512];
  if (includeTemps) {
    snprintf(body, sizeof(body),
             "{\"alert\":\"device_debug\",\"battery\":null,"
             "\"message\":\"stage=%s ok=%s detail=%s wake=%s reset=%s cycle=%lu uptime_ms=%lu t1=%.2f t2=%.2f t3=%.2f\"}",
             stage, ok ? "true" : "false", detail, wake_str, reset_str,
             (unsigned long)rtc_cycle_counter, (unsigned long)millis(), t1, t2, t3);
  } else {
    snprintf(body, sizeof(body),
             "{\"alert\":\"device_debug\",\"battery\":null,"
             "\"message\":\"stage=%s ok=%s detail=%s wake=%s reset=%s cycle=%lu uptime_ms=%lu\"}",
             stage, ok ? "true" : "false", detail, wake_str, reset_str,
             (unsigned long)rtc_cycle_counter, (unsigned long)millis());
  }

  Serial.print("DEBUG POST: ");
  Serial.println(body);
  bool sent = httpPost(HTTP_DEBUG_ENDPOINT, (const uint8_t*)body, strlen(body));
  Serial.printf("DEBUG POST result: %s\n", sent ? "sent" : "failed");
  return sent;
#endif
}

static void myURCHandler(const walter_modem_urc_event_t* ev, void* args) {
  (void)args;
  if (!Serial) return;
  if (ev->type == WM_URC_TYPE_HTTP) {
    if (ev->http.event == WALTER_MODEM_HTTP_EVENT_RING) {
      g_http_status = ev->http.status;
      g_http_done = true;
      Serial.printf("HTTP: Status %u, Len %u\n", ev->http.status, ev->http.dataLen);
      // Keep URC handler lightweight; receiving payload here can block for too long
      // and interfere with command sequencing during shutdown/sleep transitions.
    }
  }
}

void enterDeepSleep(uint32_t seconds) {
  Serial.printf("Sleeping for %u s\n", seconds);
  Serial.flush();

  // Walter 3V3_EN is active LOW; drive HIGH before sleep to remove sensor rail power.
  digitalWrite(V3V3_EN_PIN, HIGH);
  delay(100);

  esp_sleep_disable_wakeup_source(ESP_SLEEP_WAKEUP_ALL);
  esp_sleep_enable_timer_wakeup((uint64_t)seconds * 1000000ULL);
  // Keep RTC slow memory for RTC_DATA_ATTR diagnostics; power down others.
  esp_sleep_pd_config(ESP_PD_DOMAIN_RTC_SLOW_MEM, ESP_PD_OPTION_ON);
  esp_sleep_pd_config(ESP_PD_DOMAIN_RTC_FAST_MEM, ESP_PD_OPTION_OFF);
  esp_sleep_pd_config(ESP_PD_DOMAIN_RTC_PERIPH, ESP_PD_OPTION_OFF);
  delay(50);
  esp_deep_sleep_start();
}

static inline bool isValidTempReading(float t) {
  if (!isfinite(t)) return false;
  if (t == DEVICE_DISCONNECTED_C) return false;
  if (t < -55.0f || t > 125.0f) return false;
  // DS18B20 frequently returns 85C when conversion/data is not ready.
  if (fabsf(t - 85.0f) < 0.25f) return false;
  return true;
}

static const char* jsonTempOrNull(float t, char* buf, size_t len) {
  if (!isValidTempReading(t)) return "null";
  snprintf(buf, len, "%.2f", t);
  return buf;
}

static bool extractMsgIdFromJson(const char* json, char* out, size_t out_len) {
  if (!json || !out || out_len == 0) return false;
  out[0] = '\0';
  const char* key = "\"msg_id\":\"";
  const char* p = strstr(json, key);
  if (!p) return false;
  p += strlen(key);
  const char* end = strchr(p, '"');
  if (!end) return false;
  size_t n = (size_t)(end - p);
  if (n == 0) return false;
  if (n >= out_len) n = out_len - 1;
  memcpy(out, p, n);
  out[n] = '\0';
  return true;
}

enum AckCheckResult {
  ACK_CHECK_FOUND,
  ACK_CHECK_MISSING,
  ACK_CHECK_UNKNOWN
};

static AckCheckResult checkAckForMsgId(const char* msg_id) {
  if (!msg_id || !msg_id[0]) return ACK_CHECK_UNKNOWN;

  char uri[256];
  snprintf(uri, sizeof(uri), "/ack?msg_id=%s&ingest_token=%s", msg_id, HTTP_INGEST_TOKEN);

  g_http_done = false;
  g_http_status = 0;
  if (!httpGet(uri)) {
    setFail("ack_send");
    wifiDebugFailure("ack_send", nullptr, nullptr);
    return ACK_CHECK_UNKNOWN;
  }

  bool have_http_result = waitForHttpResult(HTTP_ACK_WAIT_MS);
  if (!have_http_result) {
    setFail("ack_no_urc");
    uint8_t n = notePendingAckNoUrc(msg_id);
    Serial.printf("ACK URC missing for %s (%u/%u)\n", msg_id, (unsigned)n, (unsigned)ACK_NO_URC_ASSUME_FOUND_MAX);
    wifiDebugFailure("ack_no_urc", nullptr, nullptr);
    return ACK_CHECK_UNKNOWN;
  }

  if (g_http_status == 200) {
    setFail("none");
    return ACK_CHECK_FOUND;
  }
  if (g_http_status == 404) {
    setFail("ack_404");
    return ACK_CHECK_MISSING;
  }

  setFail("ack_non200");
  wifiDebugFailure("ack_non200", nullptr, nullptr, (int)g_http_status);
  return ACK_CHECK_UNKNOWN;
}

static void qKey(char* out, size_t outlen, const char* prefix, uint16_t idx) {
  snprintf(out, outlen, "%s%u", prefix, (unsigned)idx);
}

static void queueLoadMeta() {
  prefs.begin(QUEUE_NS, false);
  q_head = prefs.getUShort("head", 0);
  q_tail = prefs.getUShort("tail", 0);
  q_count = prefs.getUShort("count", 0);
  if (q_head >= QUEUE_SIZE) q_head = 0;
  if (q_tail >= QUEUE_SIZE) q_tail = 0;
  if (q_count > QUEUE_SIZE) q_count = 0;
}

static void queueSaveMeta() {
  prefs.putUShort("head", q_head);
  prefs.putUShort("tail", q_tail);
  prefs.putUShort("count", q_count);
}

static uint16_t queueCount() { return q_count; }

static void queuePush(const char* json) {
  if (!json || !json[0]) return;

  if (q_count == QUEUE_SIZE) {
    char k[16];
    qKey(k, sizeof(k), "m", q_head);
    prefs.remove(k);
    q_head = (q_head + 1) % QUEUE_SIZE;
    q_count--;
    setFail("queue_overwrite");
  }

  char k[16];
  qKey(k, sizeof(k), "m", q_tail);
  prefs.putString(k, json);

  q_tail = (q_tail + 1) % QUEUE_SIZE;
  q_count++;
  queueSaveMeta();
}

static bool queueContainsMsgId(const char* msg_id) {
  if (!msg_id || !msg_id[0] || q_count == 0) return false;
  char key[16];
  char found_id[80];
  uint16_t idx = q_head;

  for (uint16_t i = 0; i < q_count; i++) {
    qKey(key, sizeof(key), "m", idx);
    String body = prefs.getString(key, "");
    if (body.length() > 0 &&
        extractMsgIdFromJson(body.c_str(), found_id, sizeof(found_id)) &&
        strcmp(found_id, msg_id) == 0) {
      return true;
    }
    idx = (idx + 1) % QUEUE_SIZE;
  }
  return false;
}

static bool queuePushIfNotPresent(const char* json, const char* msg_id) {
  if (!json || !json[0]) return false;
  if (msg_id && msg_id[0] && queueContainsMsgId(msg_id)) {
    return false;
  }
  queuePush(json);
  return true;
}

static bool queuePeek(String& out) {
  out = "";
  if (q_count == 0) return false;
  char k[16];
  qKey(k, sizeof(k), "m", q_head);
  out = prefs.getString(k, "");
  return out.length() > 0;
}

static void queuePop() {
  if (q_count == 0) return;
  char k[16];
  qKey(k, sizeof(k), "m", q_head);
  prefs.remove(k);
  q_head = (q_head + 1) % QUEUE_SIZE;
  q_count--;
  queueSaveMeta();
}

static bool wifiConnectOnce() {
#if !WIFI_DEBUG_FALLBACK
  return false;
#else
  WiFi.mode(WIFI_STA);
  WiFi.setSleep(true);
  WiFi.begin(WIFI_SSID, WIFI_PASS);

  uint32_t start = millis();
  while (WiFi.status() != WL_CONNECTED && (millis() - start) < WIFI_CONNECT_TIMEOUT_MS) {
    delay(200);
  }
  if (WiFi.status() != WL_CONNECTED) {
    WiFi.disconnect(true);
    WiFi.mode(WIFI_OFF);
    return false;
  }
  return true;
#endif
}

static void wifiOff() {
#if WIFI_DEBUG_FALLBACK
  WiFi.disconnect(true);
  WiFi.mode(WIFI_OFF);
#endif
}

static bool wifiDebugPost(const char* json) {
#if !WIFI_DEBUG_FALLBACK
  (void)json;
  return false;
#else
  if (!json) return false;
  if (!wifiConnectOnce()) return false;

  WiFiClient client;
  if (!client.connect(HTTP_HOST, HTTP_PORT)) {
    wifiOff();
    return false;
  }

  client.print(String("POST ") + HTTP_DEBUG_ENDPOINT + " HTTP/1.1\r\n");
  client.print(String("Host: ") + HTTP_HOST + "\r\n");
  client.print("Content-Type: application/json\r\n");
  client.print(String("Content-Length: ") + strlen(json) + "\r\n");
  client.print("Connection: close\r\n\r\n");
  client.print(json);

  uint32_t start = millis();
  while (client.connected() && (millis() - start) < 2000) {
    while (client.available()) client.read();
    delay(10);
  }
  client.stop();
  wifiOff();
  return true;
#endif
}

static void wifiDebugFailure(const char* reason, const char* wake_str, const char* reset_str, int http_status) {
#if !WIFI_DEBUG_FALLBACK
  (void)reason;
  (void)wake_str;
  (void)reset_str;
  (void)http_status;
#else
  uint32_t now = millis();
  bool is_terminal = reason &&
                     (!strcmp(reason, "max_cycle_timeout") ||
                      !strcmp(reason, "http_urc_missing_assume_sent"));
  if (!is_terminal && rtc_last_wifi_dbg_ms && (now - rtc_last_wifi_dbg_ms) < 60000UL) return;
  rtc_last_wifi_dbg_ms = now;

  char body[320];
  if (http_status >= 0) {
    snprintf(body, sizeof(body),
             "{\"ingest_token\":\"%s\",\"alert\":\"wifi_fallback\","
             "\"message\":\"%s\",\"cycle\":%lu,\"wake\":\"%s\",\"reset\":\"%s\",\"http_status\":%d}",
             HTTP_INGEST_TOKEN, reason ? reason : "unknown",
             (unsigned long)rtc_cycle_counter, wake_str ? wake_str : "OTHER",
             reset_str ? reset_str : "OTHER", http_status);
  } else {
    snprintf(body, sizeof(body),
             "{\"ingest_token\":\"%s\",\"alert\":\"wifi_fallback\","
             "\"message\":\"%s\",\"cycle\":%lu,\"wake\":\"%s\",\"reset\":\"%s\"}",
             HTTP_INGEST_TOKEN, reason ? reason : "unknown",
             (unsigned long)rtc_cycle_counter, wake_str ? wake_str : "OTHER",
             reset_str ? reset_str : "OTHER");
  }
  wifiDebugPost(body);
#endif
}

enum SendAttemptResult {
  SEND_ATTEMPT_OK,
  SEND_ATTEMPT_RETRY_NOW,
  SEND_ATTEMPT_RETRY_LATER
};

static SendAttemptResult trySendSubmit(const char* body, uint32_t cycle_start_ms) {
  (void)cycle_start_ms;
  if (!body || !body[0]) return SEND_ATTEMPT_RETRY_NOW;

  if (!httpPost(HTTP_POST_ENDPOINT, (const uint8_t*)body, strlen(body))) {
    setFail("http_send");
    wifiDebugFailure("http_send", nullptr, nullptr);
    return SEND_ATTEMPT_RETRY_NOW;
  }
  // Simple mode: treat accepted HTTP send command as success; queue/dedupe protects retries.
  clearPendingAckMsgId();
  setFail("none");
  return SEND_ATTEMPT_OK;
}

void setup() {
  Serial.begin(115200);
  delay(1000);
  rtc_cycle_counter++;
  rtc_boot_id++;
  queueLoadMeta();

  // IO0 is a boot strap pin; hold high briefly before actively driving low.
  pinMode(V3V3_EN_PIN, INPUT_PULLUP);
  delay(10);
  // Enable 3V3 OUT (active LOW)
  pinMode(V3V3_EN_PIN, OUTPUT);
  digitalWrite(V3V3_EN_PIN, LOW);
  delay(SENSOR_POWERUP_DELAY_MS);

  Serial.println("\n=== Walter LTE Temp Sender ===");

  // Capture wake/reset early so we can include them in debug events.
  esp_sleep_wakeup_cause_t wake_reason = esp_sleep_get_wakeup_cause();
  esp_reset_reason_t reset_reason = esp_reset_reason();
  const char* wake_str = wakeName(wake_reason);
  const char* reset_str = resetName(reset_reason);

  // Read sensors
  dt.begin();
  dt.setWaitForConversion(false);
  dt.setResolution(12);
  delay(SENSOR_STABILIZE_DELAY_MS);

  int deviceCount = dt.getDeviceCount();
  Serial.printf("Device count: %d\n", deviceCount);
  if (deviceCount < MIN_SENSOR_COUNT) {
    Serial.printf("Need %d DS18B20 sensors, found %d. Sleeping.\n", MIN_SENSOR_COUNT, deviceCount);
    enterDeepSleep(SLEEP_SECONDS);
    return;
  }

  DeviceAddress sensorAddr[3];
  if (!loadSensorAddresses(sensorAddr, deviceCount)) {
    Serial.println("Failed to load sensor addresses. Sleeping.");
    enterDeepSleep(SLEEP_SECONDS);
    return;
  }
  Serial.print("Sensor 1 addr: "); printAddress(sensorAddr[0]); Serial.println();
  Serial.print("Sensor 2 addr: "); printAddress(sensorAddr[1]); Serial.println();
  Serial.print("Sensor 3 addr: "); printAddress(sensorAddr[2]); Serial.println();

  float t1 = DEVICE_DISCONNECTED_C;
  float t2 = DEVICE_DISCONNECTED_C;
  float t3 = DEVICE_DISCONNECTED_C;

  // Throwaway read to clear startup -127 values
  dt.requestTemperatures();
  delay(SENSOR_CONVERT_DELAY_MS);
  dt.getTempC(sensorAddr[0]);
  dt.getTempC(sensorAddr[1]);
  dt.getTempC(sensorAddr[2]);

  // Try multiple reads to avoid startup -127 values
  for (int attempt = 1; attempt <= TEMP_RETRY_COUNT; attempt++) {
    dt.requestTemperatures();
    delay(SENSOR_CONVERT_DELAY_MS);
    float a = dt.getTempC(sensorAddr[0]);
    float b = dt.getTempC(sensorAddr[1]);
    float c = dt.getTempC(sensorAddr[2]);

    if (isValidTempReading(a) &&
        isValidTempReading(b) &&
        isValidTempReading(c)) {
      t1 = a; t2 = b; t3 = c;
      break;
    }

    Serial.printf("Temp read attempt %d/%d failed: t1=%.2f t2=%.2f t3=%.2f\n",
                  attempt, TEMP_RETRY_COUNT, a, b, c);
    delay(TEMP_RETRY_DELAY_MS);
  }

  Serial.printf("Temps: t1=%.2f, t2=%.2f, t3=%.2f\n", t1, t2, t3);

  bool tempsValid = isValidTempReading(t1) &&
                    isValidTempReading(t2) &&
                    isValidTempReading(t3);

  // Battery measurement is not wired in this firmware yet.
  // Keep fields present so backend/UI can display status consistently.
  float battery_v = NAN;
  const char* battery_status = "unavailable";
  char batteryField[24];
  snprintf(batteryField, sizeof(batteryField), "null");
  if (isfinite(battery_v)) {
    snprintf(batteryField, sizeof(batteryField), "%.3f", battery_v);
  }

  char jsonBody[768];
  char msg_id[64] = {0};
  bool msg_id_initialized = false;
  bool currentPayloadBuilt = false;
  bool currentQueuedOrPending = false;

  // Queue-first path: if local clock is already synced from a previous successful cycle,
  // persist this hour's payload before any modem/LTE work so early failures don't lose it.
  int64_t local_epoch_now = -1;
  if (getLocalEpochTime(&local_epoch_now)) {
    int64_t bucket_epoch = hourBucketEpoch(local_epoch_now);
    char tsIso[64];
    char tsHourIso[64];
    char tsField[72];
    char tsHourField[72];

    if (epochToIso8601UTC(local_epoch_now, tsIso, sizeof(tsIso))) {
      snprintf(tsField, sizeof(tsField), "\"%s\"", tsIso);
    } else {
      snprintf(tsField, sizeof(tsField), "null");
    }
    if (epochToIso8601UTC(bucket_epoch, tsHourIso, sizeof(tsHourIso))) {
      snprintf(tsHourField, sizeof(tsHourField), "\"%s\"", tsHourIso);
    } else {
      snprintf(tsHourField, sizeof(tsHourField), "null");
    }

    snprintf(msg_id, sizeof(msg_id), "h-%lld", (long long)(bucket_epoch / 3600LL));
    msg_id_initialized = true;

    if (!tempsValid) {
      char t1buf[16], t2buf[16], t3buf[16];
      const char* jt1 = jsonTempOrNull(t1, t1buf, sizeof(t1buf));
      const char* jt2 = jsonTempOrNull(t2, t2buf, sizeof(t2buf));
      const char* jt3 = jsonTempOrNull(t3, t3buf, sizeof(t3buf));

      snprintf(jsonBody, sizeof(jsonBody),
               "{\"ingest_token\":\"%s\",\"msg_id\":\"%s\",\"t1\":%s,\"t2\":%s,\"t3\":%s,\"battery\":%s,\"battery_status\":\"%s\",\"ts\":%s,\"ts_hour\":%s,"
               "\"debug\":{\"wake_cause\":%d,\"wake_cause_name\":\"%s\","
               "\"reset_reason\":%d,\"reset_reason_name\":\"%s\",\"temps_valid\":false,"
               "\"last_fail\":\"%s\",\"last_fail_cycle\":%lu,"
               "\"note\":\"invalid_temp_reading\"}}",
               HTTP_INGEST_TOKEN, msg_id, jt1, jt2, jt3, batteryField, battery_status, tsField, tsHourField,
               (int)wake_reason, wake_str, (int)reset_reason, reset_str,
               rtc_last_fail, (unsigned long)rtc_last_fail_cycle);
    } else {
      snprintf(jsonBody, sizeof(jsonBody),
               "{\"ingest_token\":\"%s\",\"msg_id\":\"%s\",\"t1\":%.2f,\"t2\":%.2f,\"t3\":%.2f,\"battery\":%s,\"battery_status\":\"%s\",\"ts\":%s,\"ts_hour\":%s,"
               "\"debug\":{\"wake_cause\":%d,\"wake_cause_name\":\"%s\","
               "\"reset_reason\":%d,\"reset_reason_name\":\"%s\",\"temps_valid\":true,"
               "\"last_fail\":\"%s\",\"last_fail_cycle\":%lu}}",
               HTTP_INGEST_TOKEN, msg_id, t1, t2, t3, batteryField, battery_status, tsField, tsHourField,
               (int)wake_reason, wake_str, (int)reset_reason, reset_str,
               rtc_last_fail, (unsigned long)rtc_last_fail_cycle);
    }

    currentPayloadBuilt = true;
    (void)queuePushIfNotPresent(jsonBody, msg_id);
    currentQueuedOrPending = queueContainsMsgId(msg_id);
    if (currentQueuedOrPending) {
      Serial.printf("Current hour payload queued early. Queue depth=%u msg_id=%s\n",
                    (unsigned)queueCount(), msg_id);
    } else {
      Serial.printf("Current hour payload already handled (not queued) msg_id=%s\n", msg_id);
    }
  } else {
    Serial.println("Local clock unavailable at boot; queue-first current-hour persist skipped.");
  }

  if (!modem.begin(&Serial2)) {
    Serial.println("Modem init failed");
    setFail("modem_begin");
    wifiDebugFailure("modem_begin", wake_str, reset_str);
    enterDeepSleep(SLEEP_SECONDS);
    return;
  }

  modem.urcSetEventHandler(myURCHandler, NULL);

  int64_t modem_epoch = -1;
  bool have_modem_time = false;

  sendDebugEvent("boot", true, "woke_and_modem_ready", wake_str, reset_str);
  bool lteDebugSent = false;
  bool sent = false;
  uint32_t cycle_start = millis();
  while (!sent && (millis() - cycle_start < MAX_CYCLE_MS)) {
    if (!lteConnect()) {
      Serial.println("LTE failed, retrying...");
      const char* lte_fail_reason = rtc_last_fail[0] ? rtc_last_fail : "lte_connect";
      wifiDebugFailure(lte_fail_reason, wake_str, reset_str);
      sendDebugEvent("lte_connect", false, lte_fail_reason, wake_str, reset_str);
      lteDisconnect();
      enterDeepSleep(nextFailureSleepSeconds());
      return;
    }

    if (!lteDebugSent) {
      sendDebugEvent("lte_connect", true, "network_registered", wake_str, reset_str);
      lteDebugSent = true;
    }

    if (!modem.httpConfigProfile(1, HTTP_HOST, HTTP_PORT)) {
      Serial.println("HTTP config failed, retrying...");
      setFail("http_profile");
      wifiDebugFailure("http_profile", wake_str, reset_str);
      sendDebugEvent("temp_send", false, "http_profile_failed", wake_str, reset_str, t1, t2, t3, true);
      lteDisconnect();
      delay(RETRY_HTTP_FAIL_DELAY_MS);
      continue;
    }

    bool defer_retry_until_next_wake = false;

    // Flush any older unsent messages first.
    while (queueCount() > 0 && (millis() - cycle_start < MAX_CYCLE_MS)) {
      String oldMsg;
      if (!queuePeek(oldMsg)) {
        queuePop(); // Drop corrupted/empty slot.
        continue;
      }
      char old_msg_id[80] = {0};
      bool have_old_msg_id = extractMsgIdFromJson(oldMsg.c_str(), old_msg_id, sizeof(old_msg_id));

      SendAttemptResult sendRes = trySendSubmit(oldMsg.c_str(), cycle_start);
      if (sendRes == SEND_ATTEMPT_OK) {
        queuePop();
        continue;
      }
      if (sendRes == SEND_ATTEMPT_RETRY_LATER) {
        defer_retry_until_next_wake = true;
      }
      break;
    }

    if (defer_retry_until_next_wake) {
      Serial.println("Deferring repost until next wake (ACK uncertain).");
      lteDisconnect();
      enterDeepSleep(nextFailureSleepSeconds());
      return;
    }

    // If this wake's current-hour payload was queued before LTE init, queue flush is the source
    // of truth. Avoid rebuilding/reposting it directly in this cycle.
    if (msg_id_initialized && currentQueuedOrPending) {
      if (!queueContainsMsgId(msg_id)) {
        Serial.printf("Current hour payload sent from queue flush (%s)\n", msg_id);
        sendDebugEvent("temp_send", true, "submit_ok_queued", wake_str, reset_str, t1, t2, t3, true);
        sent = true;
        break;
      }
      lteDisconnect();
      delay(RETRY_LTE_FAIL_DELAY_MS);
      continue;
    }

    // Refresh modem time on each attempt so payload ts and aligned sleep are based on current time.
    have_modem_time = getModemEpochTime(&modem_epoch);
    if (have_modem_time) {
      Serial.printf("Modem epoch: %lld\n", (long long)modem_epoch);
      syncLocalClockFromEpoch(modem_epoch);
    } else {
      Serial.println("Modem epoch unavailable; using fixed sleep interval.");
    }

    if (!msg_id_initialized) {
      long long msg_epoch = have_modem_time ? (long long)modem_epoch : 0LL;
      snprintf(msg_id, sizeof(msg_id), "%lu-%lld",
               (unsigned long)rtc_cycle_counter, msg_epoch);
      msg_id_initialized = true;
    }

    char tsIso[64];
    char tsField[72];
    if (have_modem_time && epochToIso8601UTC(modem_epoch, tsIso, sizeof(tsIso))) {
      snprintf(tsField, sizeof(tsField), "\"%s\"", tsIso);
    } else {
      snprintf(tsField, sizeof(tsField), "null");
    }

    if (!tempsValid) {
      char t1buf[16], t2buf[16], t3buf[16];
      const char* jt1 = jsonTempOrNull(t1, t1buf, sizeof(t1buf));
      const char* jt2 = jsonTempOrNull(t2, t2buf, sizeof(t2buf));
      const char* jt3 = jsonTempOrNull(t3, t3buf, sizeof(t3buf));

      snprintf(jsonBody, sizeof(jsonBody),
               "{\"ingest_token\":\"%s\",\"msg_id\":\"%s\",\"t1\":%s,\"t2\":%s,\"t3\":%s,\"battery\":%s,\"battery_status\":\"%s\",\"ts\":%s,"
               "\"debug\":{\"wake_cause\":%d,\"wake_cause_name\":\"%s\","
               "\"reset_reason\":%d,\"reset_reason_name\":\"%s\",\"temps_valid\":false,"
               "\"last_fail\":\"%s\",\"last_fail_cycle\":%lu,"
               "\"note\":\"invalid_temp_reading\"}}",
               HTTP_INGEST_TOKEN, msg_id, jt1, jt2, jt3, batteryField, battery_status, tsField,
               (int)wake_reason, wake_str, (int)reset_reason, reset_str,
               rtc_last_fail, (unsigned long)rtc_last_fail_cycle);
      Serial.print("POST (invalid temps): ");
    } else {
      snprintf(jsonBody, sizeof(jsonBody),
               "{\"ingest_token\":\"%s\",\"msg_id\":\"%s\",\"t1\":%.2f,\"t2\":%.2f,\"t3\":%.2f,\"battery\":%s,\"battery_status\":\"%s\",\"ts\":%s,"
               "\"debug\":{\"wake_cause\":%d,\"wake_cause_name\":\"%s\","
               "\"reset_reason\":%d,\"reset_reason_name\":\"%s\",\"temps_valid\":true,"
               "\"last_fail\":\"%s\",\"last_fail_cycle\":%lu}}",
               HTTP_INGEST_TOKEN, msg_id, t1, t2, t3, batteryField, battery_status, tsField,
               (int)wake_reason, wake_str, (int)reset_reason, reset_str,
               rtc_last_fail, (unsigned long)rtc_last_fail_cycle);
      Serial.print("POST: ");
    }
    Serial.println(jsonBody);
    currentPayloadBuilt = true;

    if (httpPost(HTTP_POST_ENDPOINT, (const uint8_t*)jsonBody, strlen(jsonBody))) {
      Serial.println("POST accepted by modem; assuming sent.");
      setFail("none");
      sendDebugEvent("temp_send", true, "submit_assumed_ok", wake_str, reset_str, t1, t2, t3, true);
      sent = true;
      break;
    } else {
      Serial.println("POST failed, retrying...");
      setFail("http_send");
      wifiDebugFailure("http_send", wake_str, reset_str);
      sendDebugEvent("temp_send", false, "submit_failed", wake_str, reset_str, t1, t2, t3, true);
    }

    lteDisconnect();
    delay(RETRY_LTE_FAIL_DELAY_MS);
  }

  if (!sent) {
    Serial.println("Max cycle time reached without successful POST; sleeping.");
    if (currentPayloadBuilt) {
      queuePush(jsonBody);
      Serial.printf("Queued unsent payload. Queue depth=%u\n", (unsigned)queueCount());
    } else {
      Serial.println("No built payload available to queue this cycle.");
    }
    setFail("max_cycle_timeout");
    wifiDebugFailure("max_cycle_timeout", wake_str, reset_str);
    sendDebugEvent("temp_send", false, "max_cycle_timeout", wake_str, reset_str, t1, t2, t3, true);
    lteDisconnect();
    enterDeepSleep(nextFailureSleepSeconds());
    return;
  }

  rtc_fail_retry_sleep_count = 0;
  int64_t final_epoch = -1;
  bool have_final_time = getModemEpochTime(&final_epoch);
  if (have_final_time) {
    syncLocalClockFromEpoch(final_epoch);
  }

  uint32_t sleep_seconds = SLEEP_SECONDS;
  if (have_final_time) {
    sleep_seconds = sleepToNextHourSeconds(final_epoch);
  }
  char sleep_detail[40];
  snprintf(sleep_detail, sizeof(sleep_detail), "deep_sleep_%us", sleep_seconds);
  sendDebugEvent("sleep_arm", true, sleep_detail, wake_str, reset_str);
  Serial.printf("Computed sleep_seconds=%u\n", sleep_seconds);
  lteDisconnect();
  enterDeepSleep(sleep_seconds);
}

void loop() {
  delay(1000);
}
