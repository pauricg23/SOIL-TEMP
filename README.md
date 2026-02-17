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

## Includes

- `app.py` - Flask app
- `temperature_data.db` - SQLite data
- `logs/` - runtime logs (ignored by git)
- `requirements.txt` - Python dependencies
