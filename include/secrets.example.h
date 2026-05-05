#pragma once

/**
 * Copy this file to secrets.h and fill in your values (or run `pio run` once;
 * the pre-script copies this file if secrets.h is missing).
 */

#define WIFI_SSID "your-wifi-ssid"
#define WIFI_PASSWORD "your-wifi-password"

#define TUYA_CLIENT_ID "your_access_id"
#define TUYA_CLIENT_SECRET "your_access_secret"

#define TUYA_API_HOST "openapi.tuyaus.com"

// List every bedroom light device ID (same order = same command to all).
static const char *const TUYA_DEVICE_IDS[] = {
    "your_device_id_1",
};

#define TUYA_DP_CODE "switch_led"

#define BUTTON_GPIO 18
