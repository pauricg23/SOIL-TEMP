# Soil Monitor Web App

Flask dashboard for compost/soil temperature monitoring.

## Run locally

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 app.py
```

Open: http://<host-ip>:5050

## Secrets (do not commit)

The server generates/loads these on first run and they should stay local:

- `.secret_key` (Flask session secret)
- `.ingest_token` (shared ingest token for devices)
- `.dashboard_password` (Basic Auth password for dashboard APIs)

You can also override them via environment variables:

- `SOIL_MONITOR_SECRET_KEY`
- `SOIL_MONITOR_INGEST_TOKEN`
- `SOIL_MONITOR_PASSWORD`
- `SOIL_MONITOR_USER` (defaults to `admin`)

## Firmware (Walter)

Walter/ESP firmware used to post readings lives under `firmware/`.

- `firmware/walter_compost_sensor` is a PlatformIO project.
- Do not commit tokens/WiFi creds:
  - Copy `firmware/walter_compost_sensor/src/ingest_token.example.h` to `firmware/walter_compost_sensor/src/ingest_token.local.h`
  - Copy `firmware/walter_compost_sensor/src/wifi_secrets.example.h` to `firmware/walter_compost_sensor/src/wifi_secrets.local.h`

## Includes

- `app.py` - Flask app
- `logs/` - runtime logs (ignored by git)
- `requirements.txt` - Python dependencies
