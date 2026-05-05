# Tuya Developer Platform Setup Guide

This guide walks through the Tuya Developer Platform as if you have never used it before. The goal is to get everything you need for the ESP32 light switch project:

- A Tuya developer account
- A cloud project
- Your Smart Life account linked to that project
- Your lights visible in the Tuya console
- Your `Access ID`, `Access Secret`, API host, device IDs, and on/off DP code

## What you are trying to collect

Before you flash the ESP32 firmware, you need these values from Tuya:

- `TUYA_CLIENT_ID` = your Tuya **Access ID**
- `TUYA_CLIENT_SECRET` = your Tuya **Access Secret**
- `TUYA_API_HOST` = your Tuya API host, such as `openapi.tuyaus.com`
- `TUYA_DEVICE_IDS[]` = the device IDs of the lights you want to control
- `TUYA_DP_CODE` = the on/off function code for the lights, such as `switch_led`

## 1. Create a Tuya Developer account

1. Open `https://developer.tuya.com`.
2. Click `Register` in the top-right corner if you do not already have an account.
3. Register with your email and password.
4. Complete any email verification step.
5. Log in and make sure you are on the **Tuya Developer Platform**.

## 2. Create a cloud project

1. After logging in, go to the **Cloud** area of the platform.
2. Open **Projects** or **Cloud Development** depending on what the current UI shows.
3. Click `Create Cloud Project`.
4. Fill in the project form:
   - **Project Name**: something like `Bedroom Light Switch`
   - **Industry** or **Project Type**: choose the option closest to **Smart Home**
   - **Data Center / Region**: choose the region that matches your Smart Life account
5. Click `Create`.
6. Open the new project so you are on its overview page.

## 3. Link your Smart Life account

This is the step that makes your existing Smart Life devices appear in the Tuya developer console.

1. Inside your project, find a section like:
   - `Devices`
   - `Link Devices`
   - `Link App Account`
   - `Link Smart Life Account`
2. Click the button to add or link an app account.
3. The platform should display a QR code.
4. On your phone, open the **Smart Life** app.
5. Look for a scan function in the app and scan the QR code shown on the Tuya Developer Platform.
6. Approve the account linking in the app if prompted.
7. Return to the developer platform and refresh the device page.
8. Confirm that your bedroom lights now appear in the project.

## 4. Get your Access ID and Access Secret

1. In your project, go to the page labeled something like:
   - `Authorization`
   - `Project Configuration`
   - `Basic Information`
2. Find these fields:
   - **Access ID**
   - **Access Secret**
3. Copy them carefully.
4. These map to your firmware like this:

```c
#define TUYA_CLIENT_ID "your_access_id"
#define TUYA_CLIENT_SECRET "your_access_secret"
```

## 5. Find the correct API host for your region

1. On the project overview or configuration page, find the region or endpoint information.
2. Look for the OpenAPI host or base URL.
3. Common examples are:
   - `openapi.tuyaus.com`
   - `openapi.tuyaeu.com`
   - `openapi.tuyacn.com`
   - `openapi.tuyain.com`
4. Use only the hostname in firmware, not `https://`.

Example:

```c
#define TUYA_API_HOST "openapi.tuyaus.com"
```

## 6. Subscribe to the required cloud APIs

Your project must have permission to use the APIs needed by the ESP32.

1. In your project, open a page like:
   - `API Products`
   - `Service API`
   - `API Management`
2. Look for API groups related to:
   - authorization or token management
   - device management
   - device control
3. Click `Subscribe`, `Authorize`, or `Add` for the needed APIs.
4. Confirm that the status shows they are enabled for the project.

If your project does not have the required APIs enabled, token requests or device control calls can fail with permission errors.

## 7. Find each light's device ID

1. Open the **Devices** page inside your Tuya project.
2. Find one of your bedroom lights in the list.
3. Click the device to open its details.
4. Copy the **Device ID**.
5. Repeat for every light you want this switch to control.

Example firmware config:

```c
static const char *const TUYA_DEVICE_IDS[] = {
    "device_id_1",
    "device_id_2",
};
```

## 8. Find the on/off DP code

Each Tuya device exposes functions or capabilities. You need the code for the main on/off action.

1. Open a device's details page.
2. Look for a tab or section like:
   - `Functions`
   - `Instructions`
   - `Specification`
   - `Standard Instruction Set`
3. Find the boolean on/off function.
4. Copy the `code` value exactly.

Common examples:

- `switch_led`
- `switch`
- `switch_1`

Example firmware config:

```c
#define TUYA_DP_CODE "switch_led"
```

## 9. Optionally test the light from the browser first

Before using the ESP32, it is helpful to verify the project and DP code from the Tuya console.

1. Open `API Explorer` or `API Debugging` inside the Tuya project.
2. Find an API similar to:

```text
POST /v1.0/iot-03/devices/{device_id}/commands
```

3. Enter your `device_id`.
4. Use a body like this:

```json
{
  "commands": [
    {
      "code": "switch_led",
      "value": true
    }
  ]
}
```

5. Replace `switch_led` with your real DP code.
6. Send the request.
7. If the light turns on and the API returns success, your setup is correct.

## 10. Put the values into the ESP32 project

Once you have the values above, open `include/secrets.h` in this project and fill in:

```c
#define WIFI_SSID "your-wifi-ssid"
#define WIFI_PASSWORD "your-wifi-password"

#define TUYA_CLIENT_ID "your_access_id"
#define TUYA_CLIENT_SECRET "your_access_secret"
#define TUYA_API_HOST "openapi.tuyaus.com"

static const char *const TUYA_DEVICE_IDS[] = {
    "your_device_id_1",
};

#define TUYA_DP_CODE "switch_led"
#define BUTTON_GPIO 18
```

## Common problems

### Devices do not appear after linking Smart Life

- Make sure you linked the same Smart Life account that actually owns the lights.
- Refresh the Tuya project page after linking.
- Check that you used the Smart Life app, not a different Tuya-based OEM app.

### Token or API requests fail

- Verify that the project region and API host match your account region.
- Confirm the required APIs are subscribed in the project.
- Double-check `Access ID` and `Access Secret`.

### Command succeeds but the light does not react

- The device ID may be wrong.
- The DP code may not be the correct on/off code.
- Some bulbs use a different code than `switch_led`.

### Only some lights work

- Make sure each light's device ID is added to `TUYA_DEVICE_IDS[]`.
- Confirm all lights support the same DP code. If not, the firmware may need per-device DP codes later.

## Final checklist

You are ready for firmware setup when you have all of the following:

- Tuya Developer account created
- Cloud project created
- Smart Life account linked
- Bedroom lights visible in the Tuya project
- Access ID copied
- Access Secret copied
- API host identified
- Device IDs copied
- On/off DP code identified

After that, you can continue with the local build and flash steps in `README.md`.
