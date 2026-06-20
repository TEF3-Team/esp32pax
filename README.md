# PaxRadar

Passive WiFi probe-request scanner built on ESP32 + Python/Flask.  
Detects nearby devices, tracks them across MAC rotations using RF fingerprinting, and sends periodic AI-generated pattern analysis to Telegram.

---

## How it works

```
ESP32 (sniffer)
    │  probe requests captured in promiscuous mode
    │  POST /api/report  every ~20 s
    ▼
Flask server (server.py)
    │  RF fingerprint matching + entity memory (MongoDB)
    │  saves detection events → pax_events collection
    │
    ├── Live dashboard  →  http://localhost:8000
    │
    └── AI cron (every N hours)
            │  reads pax_events from MongoDB
            │  sends to GPT-5 for pattern analysis
            ▼
        Telegram bot → analysis report
```

---

## Requirements

| Layer | Stack |
|-------|-------|
| Firmware | ESP32 · Arduino IDE · `esp_wifi.h` |
| Server | Python 3.10+ · Flask · PyMongo |
| Database | MongoDB (local or Atlas) |
| AI analysis | OpenAI API (gpt-5 or any chat model) |
| Notifications | Telegram Bot API |

Install Python dependencies:

```bash
pip install -r requirements.txt
```

---

## Setup

### 1. Firmware

Copy `pax/secrets.h.example` to `pax/secrets.h` and fill in your values:

```cpp
#define SECRET_WIFI_SSID      "YourNetwork"
#define SECRET_WIFI_PASSWORD  "YourPassword"
#define SECRET_SERVER_HOST    "192.168.x.x"   // server LAN IP
#define SECRET_SERVER_PORT    8000
#define SECRET_PAX_API_TOKEN  ""              // optional, match PAX_API_TOKEN in .env
```

Flash `pax/pax.ino` to the ESP32 from Arduino IDE.

### 2. Server

Copy `.env.example` to `.env` and fill in your values (see table below), then:

```bash
python server.py
```

Dashboard available at `http://localhost:8000`.

---

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8000` | Server port |
| `MONGO_URI` | `mongodb://localhost:27017` | MongoDB connection string |
| `MONGO_DB_NAME` | `omnistatus` | Database name |
| `OPENAI_API_KEY` | — | OpenAI API key |
| `OPENAI_MODEL` | `gpt-5` | Chat model for analysis |
| `COMPLEX_ANALYSIS_CRON_HOURS` | `3` | Interval between AI analysis runs |
| `COMPLEX_ANALYSIS_LOOKBACK_HOURS` | `12` | Event window fed to the model |
| `COMPLEX_ANALYSIS_SUMMARY_MAX_CHARS` | `200` | Max length of the AI summary |
| `ENABLE_TELEGRAM` | `0` | Set to `1` to enable Telegram alerts |
| `TELEGRAM_BOT_TOKEN` | — | Telegram bot token |
| `TELEGRAM_CHAT_ID` | — | Telegram chat/group ID |
| `PAX_API_TOKEN` | — | Optional shared token for ESP32 auth (`X-Pax-Token` header) |

---

## API endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Live dashboard UI |
| `GET` | `/api/data` | Current device list (JSON) |
| `POST` | `/api/report` | ESP32 scan upload |
| `POST` | `/api/name` | Assign custom name to a device |
| `GET` | `/api/analyze` | Trigger manual AI analysis |

---

## MongoDB collections

| Collection | Purpose |
|------------|---------|
| `pax_memory` | Persistent entity state (fingerprints, custom names, history) |
| `pax_events` | Detection events — read by the AI cron for pattern analysis |

---

## Firmware parameters (pax.ino)

| Constant | Default | Description |
|----------|---------|-------------|
| `TIEMPO_BARRIDO` | `20000 ms` | Scan window before uploading |
| `CHANNEL_DWELL_MS` | `200 ms` | Time per channel hop |
| `SNIFFER_CHANNELS` | `1,6,11,2,7,3,8,4,9,5,10` | Channels to scan (non-overlapping first) |
| `ESP_ID` | `esp32-01` | Node identifier sent in every report |
| `ESP_LOCATION` | `Casa_Celia` | Physical location label |

---

## License

MIT — see [LICENSE](LICENSE)
