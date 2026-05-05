# ESP32 physical switch for Tuya Smart Life lights

Firmware for an ESP32 that reads a debounced push button and toggles one or more **Tuya / Smart Life** Wi‑Fi lights over the **official Open API** (HTTPS). Your lights stay in the Smart Life app; Alexa and the phone continue to work as today.

## What you need

- ESP32 dev board (this project targets the common **ESP32 Dev Module** in PlatformIO).
- Momentary switch wired to a GPIO (default **GPIO 18**), other leg to **GND** (active low, internal pull‑up).
- USB 5 V power for the bench build (do not connect raw mains to the dev board).
- A [Tuya IoT Developer](https://developer.tuya.com/) account and a cloud project linked to your **Smart Life** user so your lights appear under **Devices** in the developer console.

## 1. Tuya IoT Developer (cloud project)

1. Sign in at [developer.tuya.com](https://developer.tuya.com/).
2. Create a **Cloud** project that supports **Smart Home** / consumer devices (wording in the console may vary).
3. Under **Cloud** → **Development** → **API**, subscribe to the APIs you need (at minimum: authorization/token and **device control** / **device management** as offered for your project type).
4. Create **Cloud authorization** credentials: **Access ID** and **Access Secret** (also called Client ID / Client Secret in some docs).
5. Link your **Smart Life** account to the project (**Devices** → link / authorize Smart Life) until your bedroom lights appear in the console device list.
6. Note your **data center** and set `TUYA_API_HOST` in `include/secrets.h` to the matching Open API host (hostname only, no `https://`). Common values:
   - United States: `openapi.tuyaus.com`
   - Europe: `openapi.tuyaeu.com`
   - China: `openapi.tuyacn.com`
   - India: `openapi.tuyain.com`  
   Wrong host → empty device list, invalid sign, or HTTP 401.

## 2. Device IDs and DP codes (functions)

1. In the developer console, open each light and copy its **Device ID**.
2. Find the **on/off function code** (DP / capability code) for that product. Examples: `switch_led`, `switch_1`, `switch`. Use **Device debugging**, **API Explorer**, or `GET /v1.0/iot-03/devices/{device_id}/functions` once from the explorer and read the JSON.
3. Put the IDs in `TUYA_DEVICE_IDS[]` in `include/secrets.h` and set `TUYA_DP_CODE` to the code your bulb uses.
4. If `POST .../iot-03/.../commands` returns an error for your hardware, check Tuya’s docs for your category; some older templates use `POST /v1.0/devices/{device_id}/commands` with a slightly different JSON body—you would adjust the path and body in [`src/main.cpp`](src/main.cpp) accordingly.

## 3. Bench wiring (prototype)

| ESP32 | Switch |
|-------|--------|
| `GPIO18` (default) | One terminal |
| `GND` | Other terminal |

Use a **normally open** momentary switch. The firmware uses `INPUT_PULLUP`, so a press pulls the pin **low**. Change `BUTTON_GPIO` in `include/secrets.h` if you use another pin (avoid strapping pins if possible).

## 4. Build and flash

This repo vendors PlatformIO in a local virtual environment so you do not need a global `pio` install.

```bash
cd smarthome_wifi_switch
python3 -m venv .venv
.venv/bin/pip install platformio
.venv/bin/pio run
.venv/bin/pio run -t upload   # with board USB connected
.venv/bin/pio device monitor
```

On the first build, [`scripts/pio_pre_copy_secrets.py`](scripts/pio_pre_copy_secrets.py) copies [`include/secrets.example.h`](include/secrets.example.h) to `include/secrets.h` if that file is missing. **Edit `include/secrets.h`** with your Wi‑Fi SSID/password, Tuya credentials, host, device IDs, and DP code. `include/secrets.h` is gitignored so secrets are not committed.

Serial log level follows the ESP32 core (see `CORE_DEBUG_LEVEL` in [`platformio.ini`](platformio.ini)).

## How it works

- After Wi‑Fi connect, the chip runs **SNTP** so request timestamps match Tuya’s expectation (13‑digit **Unix epoch ms**).
- **Token**: `GET /v1.0/token?grant_type=1` using project credentials; refresh via `GET /v1.0/token/{refresh_token}` when a refresh token is returned.
- **Sign**: Same construction as the official [tuya-iot-python-sdk `openapi.py`](https://github.com/tuya/tuya-iot-python-sdk/blob/master/tuya_iot/openapi.py) (`_calculate_sign`): HMAC‑SHA256 over `client_id` + optional `access_token` + `t` + canonical string (method, SHA256 of body, blank headers line, URL path including query).
- **Control**: `POST /v1.0/iot-03/devices/{device_id}/commands` with `{"commands":[{"code":"<TUYA_DP_CODE>","value":true|false}]}` for each device ID in the array.

TLS uses `WiFiClientSecure::setInsecure()` for a simple home prototype. For a production device, pin the Tuya API roots or use the ESP certificate bundle.

## Limitations

- Requires **internet** and reachable Tuya cloud when you press the button.
- **Rate limits** and project quotas apply per Tuya policy.
- On/off state is tracked locally after each successful toggle; it is not read back from the cloud on boot (optional improvement: query status API and sync).

## License

Use and modify for personal smart-home projects. Tuya is a trademark of Tuya Inc.; this project is not affiliated with Tuya.
