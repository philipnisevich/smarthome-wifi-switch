/**
 * ESP32 physical button -> Tuya Open API -> Smart Life lights.
 * Signing matches tuya-iot-python-sdk (openapi._calculate_sign).
 */

#include <Arduino.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include <cstring>
#include <sys/time.h>

#include <mbedtls/md.h>
#include <mbedtls/sha256.h>

#include "secrets.h"

#ifndef TUYA_DP_CODE
#define TUYA_DP_CODE "switch_1"
#endif

static constexpr size_t kDeviceCount = sizeof(TUYA_DEVICE_IDS) / sizeof(TUYA_DEVICE_IDS[0]);

/** Per-device on/off DP code from cloud specification (filled at boot). Empty => use TUYA_DP_CODE. */
static String s_switchDpCode[kDeviceCount];

static WiFiClientSecure s_tls;
/** One TLS session for rapid back-to-back device commands (HTTP keep-alive). */
static WiFiClientSecure s_batchTls;
static String s_accessToken;
static String s_refreshToken;
static uint64_t s_tokenExpireMs = 0;

static bool hex_lower_sha256(const uint8_t *data, size_t len, char out_hex[65]) {
  uint8_t hash[32];
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  mbedtls_sha256_starts(&ctx, 0);
  if (data && len) {
    mbedtls_sha256_update(&ctx, data, len);
  }
  mbedtls_sha256_finish(&ctx, hash);
  mbedtls_sha256_free(&ctx);
  static const char *kHex = "0123456789abcdef";
  for (int i = 0; i < 32; ++i) {
    out_hex[i * 2] = kHex[hash[i] >> 4];
    out_hex[i * 2 + 1] = kHex[hash[i] & 15];
  }
  out_hex[64] = '\0';
  return true;
}

static bool hmac_sha256_upper_hex(const char *key, const uint8_t *msg, size_t msg_len,
                                    char out_hex[65]) {
  const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if (!md_info) {
    return false;
  }
  uint8_t mac[32];
  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);
  if (mbedtls_md_setup(&ctx, md_info, 1) != 0) {
    mbedtls_md_free(&ctx);
    return false;
  }
  if (mbedtls_md_hmac_starts(&ctx, reinterpret_cast<const unsigned char *>(key),
                             strlen(key)) != 0) {
    mbedtls_md_free(&ctx);
    return false;
  }
  if (mbedtls_md_hmac_update(&ctx, msg, msg_len) != 0) {
    mbedtls_md_free(&ctx);
    return false;
  }
  if (mbedtls_md_hmac_finish(&ctx, mac) != 0) {
    mbedtls_md_free(&ctx);
    return false;
  }
  mbedtls_md_free(&ctx);
  static const char *kHex = "0123456789ABCDEF";
  for (int i = 0; i < 32; ++i) {
    out_hex[i * 2] = kHex[mac[i] >> 4];
    out_hex[i * 2 + 1] = kHex[mac[i] & 15];
  }
  out_hex[64] = '\0';
  return true;
}

static void build_string_to_sign(const char *method, const String &body_utf8,
                                 const String &path_with_query, String *out) {
  char body_hash[65];
  const uint8_t *body_ptr = reinterpret_cast<const uint8_t *>(body_utf8.c_str());
  const size_t body_len = body_utf8.length();
  hex_lower_sha256(body_ptr, body_len, body_hash);

  *out = String(method) + "\n" + body_hash + "\n\n" + path_with_query;
}

static uint64_t wall_time_ms() {
  struct timeval tv {};
  gettimeofday(&tv, nullptr);
  return static_cast<uint64_t>(tv.tv_sec) * 1000ULL +
         static_cast<uint64_t>(tv.tv_usec) / 1000ULL;
}

static bool sync_sntp() {
  configTime(0, 0, "pool.ntp.org", "time.nist.gov");
  struct tm timeinfo {};
  for (int i = 0; i < 60; ++i) {
    if (getLocalTime(&timeinfo, 0)) {
      log_i("Time synced: %04d-%02d-%02d %02d:%02d:%02d", timeinfo.tm_year + 1900,
            timeinfo.tm_mon + 1, timeinfo.tm_mday, timeinfo.tm_hour, timeinfo.tm_min,
            timeinfo.tm_sec);
      return true;
    }
    delay(500);
  }
  log_e("SNTP sync failed");
  return false;
}

static bool calc_sign(const char *method, const String &body_utf8, const String &path_with_query,
                      bool include_access_token, uint64_t t_ms, char sign_hex[65]) {
  String str_to_sign;
  build_string_to_sign(method, body_utf8, path_with_query, &str_to_sign);

  String message = String(TUYA_CLIENT_ID);
  if (include_access_token && s_accessToken.length() > 0) {
    message += s_accessToken;
  }
  message += String(static_cast<unsigned long long>(t_ms));
  message += str_to_sign;

  return hmac_sha256_upper_hex(TUYA_CLIENT_SECRET,
                               reinterpret_cast<const uint8_t *>(message.c_str()),
                               message.length(), sign_hex);
}

static bool http_tuya_with_tls(WiFiClientSecure &tls, const char *method,
                               const String &path_with_query, const String &body_json,
                               String *response_body, int *http_code) {
  if (WiFi.status() != WL_CONNECTED) {
    log_e("WiFi not connected");
    return false;
  }

  const uint64_t t_ms = wall_time_ms();
  // Match tuya-iot-python-sdk: token URLs omit access_token from the HMAC message.
  const bool sign_with_access_token = !path_with_query.startsWith("/v1.0/token");

  char sign_hex[65];
  if (!calc_sign(method, body_json, path_with_query, sign_with_access_token, t_ms, sign_hex)) {
    log_e("sign failed");
    return false;
  }

  HTTPClient http;
  const String url = String("https://") + TUYA_API_HOST + path_with_query;
  if (!http.begin(tls, url)) {
    log_e("http.begin failed");
    return false;
  }

  http.addHeader("client_id", TUYA_CLIENT_ID);
  http.addHeader("sign", sign_hex);
  http.addHeader("sign_method", "HMAC-SHA256");
  http.addHeader("t", String(static_cast<unsigned long long>(t_ms)));
  http.addHeader("lang", "en");
  if (sign_with_access_token && s_accessToken.length() > 0) {
    http.addHeader("access_token", s_accessToken);
  } else {
    http.addHeader("access_token", "");
  }

  int code = 0;
  if (strcmp(method, "GET") == 0) {
    code = http.GET();
  } else if (strcmp(method, "POST") == 0) {
    http.addHeader("Content-Type", "application/json");
    code = http.POST(body_json);
  } else {
    log_e("unsupported method %s", method);
    http.end();
    return false;
  }

  if (http_code) {
    *http_code = code;
  }
  if (code < 0) {
    log_e("HTTP error: %d %s", code, http.errorToString(code).c_str());
    http.end();
    return false;
  }
  if (response_body) {
    *response_body = http.getString();
  }
  http.end();
  return true;
}

static bool http_tuya(const char *method, const String &path_with_query, const String &body_json,
                      String *response_body, int *http_code) {
  return http_tuya_with_tls(s_tls, method, path_with_query, body_json, response_body, http_code);
}

static bool client_write_all(WiFiClient &client, const String &data) {
  const char *p = data.c_str();
  size_t left = data.length();
  const uint32_t deadline = millis() + 30000;
  while (left > 0 && millis() < deadline) {
    const size_t n = client.write(reinterpret_cast<const uint8_t *>(p), left);
    if (n == 0) {
      yield();
      continue;
    }
    p += n;
    left -= n;
  }
  return left == 0;
}

/** Read one HTTP/1.x response (headers + Content-Length body) from an open connection. */
static bool read_http_json_response(WiFiClient &client, String *body_out, int *http_status) {
  const uint32_t deadline = millis() + 25000;
  String headers;
  headers.reserve(2048);
  while (millis() < deadline) {
    while (client.available()) {
      headers += static_cast<char>(client.read());
      if (headers.length() >= 4 && headers.endsWith("\r\n\r\n")) {
        goto headers_complete;
      }
      if (headers.length() > 32768) {
        return false;
      }
    }
    if (!client.connected() && client.available() == 0) {
      return false;
    }
    yield();
  }
  return false;

headers_complete:
  int status = 0;
  const int sp = headers.indexOf(' ');
  const int sp2 = sp >= 0 ? headers.indexOf(' ', sp + 1) : -1;
  if (sp >= 0 && sp2 > sp) {
    status = headers.substring(sp + 1, sp2).toInt();
  }
  if (http_status) {
    *http_status = status;
  }

  int content_length = -1;
  int search_at = 0;
  while (true) {
    const int pos = headers.indexOf("Content-Length:", search_at);
    if (pos < 0) {
      break;
    }
    const int line_end = headers.indexOf("\r\n", pos);
    if (line_end < 0) {
      break;
    }
    String line = headers.substring(pos + 15, line_end);
    line.trim();
    content_length = line.toInt();
    break;
  }
  if (content_length < 0) {
    const int pos = headers.indexOf("content-length:");
    if (pos >= 0) {
      const int line_end = headers.indexOf("\r\n", pos);
      if (line_end > pos) {
        String line = headers.substring(pos + 15, line_end);
        line.trim();
        content_length = line.toInt();
      }
    }
  }

  const int header_end = headers.indexOf("\r\n\r\n");
  if (header_end < 0) {
    return false;
  }

  body_out->clear();
  String initial = headers.substring(static_cast<unsigned>(header_end) + 4);
  headers = String();

  if (content_length < 0) {
    return false;
  }

  body_out->reserve(static_cast<unsigned>(content_length));
  *body_out = initial;
  while (static_cast<int>(body_out->length()) < content_length && millis() < deadline) {
    while (client.available() && static_cast<int>(body_out->length()) < content_length) {
      *body_out += static_cast<char>(client.read());
    }
    yield();
  }
  return static_cast<int>(body_out->length()) == content_length;
}

/** POST over an existing TLS socket (HTTP keep-alive). Same signing rules as http_tuya_with_tls. */
static bool tuya_post_keepalive(WiFiClientSecure &client, const String &path_with_query,
                                const String &body_json, String *response_body, int *http_code) {
  if (WiFi.status() != WL_CONNECTED) {
    log_e("WiFi not connected");
    return false;
  }

  const uint64_t t_ms = wall_time_ms();
  const bool sign_with_access_token = !path_with_query.startsWith("/v1.0/token");

  char sign_hex[65];
  if (!calc_sign("POST", body_json, path_with_query, sign_with_access_token, t_ms, sign_hex)) {
    log_e("sign failed");
    return false;
  }

  String req;
  req.reserve(body_json.length() + 384);
  req += "POST ";
  req += path_with_query;
  req += " HTTP/1.1\r\nHost: ";
  req += TUYA_API_HOST;
  req += "\r\nConnection: keep-alive\r\nclient_id: ";
  req += TUYA_CLIENT_ID;
  req += "\r\nsign: ";
  req += sign_hex;
  req += "\r\nsign_method: HMAC-SHA256\r\nt: ";
  req += String(static_cast<unsigned long long>(t_ms));
  req += "\r\nlang: en\r\naccess_token: ";
  req += s_accessToken.length() ? s_accessToken : String("");
  req += "\r\nContent-Type: application/json\r\nContent-Length: ";
  req += String(body_json.length());
  req += "\r\n\r\n";
  req += body_json;

  if (!client_write_all(client, req)) {
    log_e("keep-alive write failed");
    return false;
  }

  String resp;
  int status = 0;
  if (!read_http_json_response(client, &resp, &status)) {
    log_e("keep-alive read failed");
    return false;
  }
  if (http_code) {
    *http_code = status;
  }
  if (response_body) {
    *response_body = resp;
  }
  return true;
}

static bool parse_token_response(const String &json) {
  JsonDocument doc;
  DeserializationError err = deserializeJson(doc, json);
  if (err) {
    log_e("token JSON parse: %s", err.c_str());
    return false;
  }
  if (!doc["success"].as<bool>()) {
    log_e("token API success=false code=%d msg=%s", doc["code"].as<int>(),
          doc["msg"].as<const char *>());
    return false;
  }
  JsonObject result = doc["result"].as<JsonObject>();
  if (result.isNull()) {
    log_e("token: missing result");
    return false;
  }
  const char *at = result["access_token"] | "";
  if (!strlen(at)) {
    log_e("token: missing access_token");
    return false;
  }
  s_accessToken = at;
  const char *rt = result["refresh_token"] | "";
  s_refreshToken = rt;

  const int expire_sec = result["expire_time"] | result["expire"] | 7200;
  const uint64_t now_ms = wall_time_ms();
  s_tokenExpireMs = now_ms + static_cast<uint64_t>(expire_sec) * 1000ULL - 60ULL * 1000ULL;

  log_i("Token OK, expires in ~%d s", expire_sec);
  return true;
}

static bool ensure_project_token() {
  const uint64_t now_ms = wall_time_ms();
  if (s_accessToken.length() > 0 && now_ms < s_tokenExpireMs) {
    return true;
  }

  if (s_refreshToken.length() > 0) {
    const String path = String("/v1.0/token/") + s_refreshToken;
    String resp;
    int code = 0;
    if (http_tuya("GET", path, "", &resp, &code) && code == 200 && parse_token_response(resp)) {
      return true;
    }
    log_w("refresh failed, falling back to grant_type=1");
    s_refreshToken = "";
    s_accessToken = "";
  }

  String resp;
  int code = 0;
  if (!http_tuya("GET", "/v1.0/token?grant_type=1", "", &resp, &code)) {
    return false;
  }
  if (code != 200) {
    log_e("token HTTP %d: %s", code, resp.c_str());
    return false;
  }
  return parse_token_response(resp);
}

static bool http_get_device_specification(const char *device_id, String *out_resp) {
  if (!device_id || strlen(device_id) == 0 || !out_resp) {
    return false;
  }
  const String path_v12 =
      String("/v1.2/iot-03/devices/") + device_id + "/specification";
  int http_code = 0;
  if (!http_tuya("GET", path_v12, "", out_resp, &http_code)) {
    return false;
  }
  if (http_code != 200) {
    const String path_v10 =
        String("/v1.0/iot-03/devices/") + device_id + "/specification";
    if (!http_tuya("GET", path_v10, "", out_resp, &http_code)) {
      return false;
    }
  }
  return http_code == 200;
}

/** Choose best Boolean on/off DP for this product (devices differ: switch_1 vs switch_led, etc.). */
static String pick_boolean_switch_dp(JsonArray functions) {
  if (functions.isNull()) {
    return String();
  }
  for (JsonVariant v : functions) {
    JsonObject f = v.as<JsonObject>();
    const char *fc = f["code"] | "";
    const char *ft = f["type"] | "";
    if (strcmp(ft, "Boolean") != 0) {
      continue;
    }
    if (strcmp(fc, TUYA_DP_CODE) == 0) {
      return String(fc);
    }
  }
  static const char *kPreferred[] = {"switch_1", "switch_led", "switch_2", "switch",
                                       "light_switch", "led_switch"};
  const size_t nPref = sizeof(kPreferred) / sizeof(kPreferred[0]);
  for (size_t k = 0; k < nPref; ++k) {
    for (JsonVariant v : functions) {
      JsonObject f = v.as<JsonObject>();
      const char *fc = f["code"] | "";
      const char *ft = f["type"] | "";
      if (strcmp(ft, "Boolean") != 0) {
        continue;
      }
      if (strcmp(fc, kPreferred[k]) == 0) {
        return String(fc);
      }
    }
  }
  for (JsonVariant v : functions) {
    JsonObject f = v.as<JsonObject>();
    const char *fc = f["code"] | "";
    const char *ft = f["type"] | "";
    if (strcmp(ft, "Boolean") != 0) {
      continue;
    }
    if (strncmp(fc, "switch", 6) == 0) {
      return String(fc);
    }
  }
  return String();
}

static void resolve_all_device_switch_dp_codes() {
  for (size_t i = 0; i < kDeviceCount; ++i) {
    const char *id = TUYA_DEVICE_IDS[i];
    if (!id || strlen(id) == 0) {
      continue;
    }
    String resp;
    if (!http_get_device_specification(id, &resp)) {
      log_w("Device[%u]: specification GET failed", static_cast<unsigned>(i));
      continue;
    }
    JsonDocument doc;
    if (deserializeJson(doc, resp)) {
      log_w("Device[%u]: specification JSON parse failed", static_cast<unsigned>(i));
      continue;
    }
    JsonObject result = doc["result"].as<JsonObject>();
    JsonArray functions = result["functions"].as<JsonArray>();
    const String picked = pick_boolean_switch_dp(functions);
    s_switchDpCode[i] = picked;
    if (picked.isEmpty()) {
      log_w("Device[%u]: no Boolean switch in spec; fallback to TUYA_DP_CODE",
            static_cast<unsigned>(i));
    } else {
      log_i("Device[%u] DP code \"%s\"", static_cast<unsigned>(i), picked.c_str());
    }
  }
}

static bool parse_command_json_success(const String &resp) {
  JsonDocument rd;
  if (deserializeJson(rd, resp)) {
    log_e("command response not JSON");
    return false;
  }
  if (!rd["success"].as<bool>()) {
    log_e("command failed code=%d msg=%s", rd["code"].as<int>(), rd["msg"].as<const char *>());
    return false;
  }
  return true;
}

static bool post_device_command_tls(WiFiClientSecure &tls, const char *device_id,
                                    const char *dp_code, bool value) {
  JsonDocument doc;
  JsonArray cmds = doc["commands"].to<JsonArray>();
  JsonObject c = cmds.add<JsonObject>();
  c["code"] = dp_code;
  c["value"] = value;

  String body;
  serializeJson(doc, body);
  const String path = String("/v1.0/iot-03/devices/") + device_id + "/commands";

  String resp;
  int code = 0;
  if (!http_tuya_with_tls(tls, "POST", path, body, &resp, &code)) {
    return false;
  }
  if (code != 200) {
    log_e("command HTTP %d: %s", code, resp.c_str());
    return false;
  }

  return parse_command_json_success(resp);
}

static bool post_device_command_keepalive(WiFiClientSecure &client, const char *device_id,
                                          const char *dp_code, bool value) {
  JsonDocument doc;
  JsonArray cmds = doc["commands"].to<JsonArray>();
  JsonObject c = cmds.add<JsonObject>();
  c["code"] = dp_code;
  c["value"] = value;

  String body;
  serializeJson(doc, body);
  const String path = String("/v1.0/iot-03/devices/") + device_id + "/commands";

  String resp;
  int code = 0;
  if (!tuya_post_keepalive(client, path, body, &resp, &code)) {
    return false;
  }
  if (code != 200) {
    log_e("command HTTP %d: %s", code, resp.c_str());
    return false;
  }

  return parse_command_json_success(resp);
}

static bool set_all_lights(bool on) {
  if (!ensure_project_token()) {
    return false;
  }

  s_batchTls.stop();
  s_batchTls.setTimeout(25000);
  if (!s_batchTls.connect(TUYA_API_HOST, 443)) {
    log_w("keep-alive session connect failed; fallback to per-request TLS");
    bool ok = true;
    for (size_t i = 0; i < kDeviceCount; ++i) {
      const char *id = TUYA_DEVICE_IDS[i];
      if (!id || strlen(id) == 0) {
        continue;
      }
      const char *dp_code =
          s_switchDpCode[i].length() > 0 ? s_switchDpCode[i].c_str() : TUYA_DP_CODE;
      log_i("Device %s -> %s (dp=%s)", id, on ? "ON" : "OFF", dp_code);
      if (!post_device_command_tls(s_tls, id, dp_code, on)) {
        ok = false;
      }
      yield();
    }
    return ok;
  }

  bool ok = true;
  for (size_t i = 0; i < kDeviceCount; ++i) {
    const char *id = TUYA_DEVICE_IDS[i];
    if (!id || strlen(id) == 0) {
      continue;
    }
    const char *dp_code =
        s_switchDpCode[i].length() > 0 ? s_switchDpCode[i].c_str() : TUYA_DP_CODE;
    log_i("Device %s -> %s (dp=%s)", id, on ? "ON" : "OFF", dp_code);
    if (!post_device_command_keepalive(s_batchTls, id, dp_code, on)) {
      ok = false;
    }
    yield();
  }
  s_batchTls.stop();
  return ok;
}

// ---- Button (active LOW, internal pull-up) ----
static bool s_lightOn = false;
static int s_btnReading = HIGH;
static int s_btnStable = HIGH;
static uint32_t s_lastDebounceMs = 0;

static void poll_button() {
  const int reading = digitalRead(BUTTON_GPIO);
  const uint32_t now = millis();
  if (reading != s_btnReading) {
    s_lastDebounceMs = now;
    s_btnReading = reading;
  }
  if ((now - s_lastDebounceMs) >= 50) {
    if (reading != s_btnStable) {
      s_btnStable = reading;
      if (s_btnStable == LOW) {
        s_lightOn = !s_lightOn;
        log_i("Button: toggle -> %s", s_lightOn ? "ON" : "OFF");
        if (!set_all_lights(s_lightOn)) {
          log_e("Control failed; reverting toggle state");
          s_lightOn = !s_lightOn;
        }
      }
    }
  }
}

void setup() {
  Serial.begin(115200);
  delay(200);
  log_i("Tuya light switch starting");

  pinMode(BUTTON_GPIO, INPUT_PULLUP);

  s_tls.setInsecure();
  s_batchTls.setInsecure();

  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  log_i("Connecting WiFi...");
  uint32_t start = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - start < 60000) {
    delay(500);
    Serial.print(".");
  }
  Serial.println();
  if (WiFi.status() != WL_CONNECTED) {
    log_e("WiFi connect failed");
    return;
  }
  log_i("WiFi OK IP=%s", WiFi.localIP().toString().c_str());

  if (!sync_sntp()) {
    log_e("Cannot sign Tuya requests without valid wall time");
    return;
  }

  if (ensure_project_token()) {
    resolve_all_device_switch_dp_codes();
    log_i("Ready: press button (GPIO %d) to toggle lights", BUTTON_GPIO);
  } else {
    log_e("Token failed — fix TUYA_CLIENT_ID / SECRET / host in secrets.h");
  }
}

void loop() {
  poll_button();
  delay(10);
}
