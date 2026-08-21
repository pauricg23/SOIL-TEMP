# Soil/Compost Temperature Monitor

End-to-end temperature monitoring for a compost heap (or soil) with:

- A Flask dashboard + SQLite storage (runs well on a Raspberry Pi).
- Firmware for a Walter-based LTE device that POSTs readings to the server.
- Optional Cloudflare Tunnel exposure (no inbound ports needed on your home network).
- An ESP32 + SCD40 baby-room monitor for CO2, temperature and humidity.

## Architecture

- Device sends readings to the server:
  - `POST /submit` (JSON body, token-protected)
  - Optional: `POST /alert` for debug events
  - Optional: `GET /ack?msg_id=...` for idempotency/ack checks
- Dashboard reads data from the server (Basic Auth protected):
  - `GET /` (monitor chooser)
  - `GET /soil` (soil dashboard)
  - `GET /baby` (baby-room dashboard)
  - `GET /api/data`
  - `GET /api/stats`
  - `GET /api/debug`

## Baby Room Monitor

The PlatformIO project is in `firmware/esp32_scd40_baby`. It reads one SCD40 on GPIO 21/22 and posts to `POST /submit/baby` every 30 seconds over local Wi-Fi. Baby readings use a separate `baby_readings` table in the same SQLite database.

Copy `firmware/esp32_scd40_baby/src/config.example.h` to `config.local.h` before uploading. Configure the Wi-Fi credentials, existing ingest token and the Pi endpoint. Local secrets are ignored by Git.

## Running Locally

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 app.py
```

Open `http://<host-ip>:5050`.

## Authentication Model

- Ingest endpoints (`/submit`, `/alert`, `/ack`) require a shared ingest token.
  - Device can send it as `"ingest_token": "..."` in JSON (supported for constrained firmware).
  - Or via header `X-INGEST-TOKEN: ...`.
- Dashboard/API endpoints require Basic Auth (user + password).

## Secrets (Do Not Commit)

On first run the server generates these files (or loads them from env). Keep them local:

- `.secret_key` (Flask session key)
- `.ingest_token` (device shared token)
- `.dashboard_password` (Basic Auth password)

Environment overrides:

- `SOIL_MONITOR_SECRET_KEY`
- `SOIL_MONITOR_INGEST_TOKEN`
- `SOIL_MONITOR_USER` (default `admin`)
- `SOIL_MONITOR_PASSWORD`

## Data Storage

- SQLite DB file: `temperature_data.db` (ignored by git).
- WAL mode is enabled for better concurrency on Pi.

## Raspberry Pi Deployment (systemd)

Typical `systemd` setup:

- Create a venv and install deps in the repo directory.
- Run `app.py` with a service like `soil-monitor.service`.
- Ensure `Restart=always` and `WantedBy=multi-user.target` so it comes back after power cuts.

## Cloudflare Tunnel (Optional)

If you use `cloudflared`, configure ingress to forward to your local service:

- `http://127.0.0.1:5050`

This keeps the Pi off the public internet while still allowing remote access via your hostname.

## Firmware (Walter LTE)

Firmware lives in `firmware/walter_compost_sensor` (PlatformIO).

Local-only config files (ignored by git):

- Copy `firmware/walter_compost_sensor/src/ingest_token.example.h` to `firmware/walter_compost_sensor/src/ingest_token.local.h`
- Copy `firmware/walter_compost_sensor/src/wifi_secrets.example.h` to `firmware/walter_compost_sensor/src/wifi_secrets.local.h`

Do not hardcode the real ingest token in a public repo.

## Development Notes

- For reliable ingest, firmware should send a stable unique `msg_id` per reading. The server de-dupes by `msg_id`.
