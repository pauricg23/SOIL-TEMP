import base64
import os
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone


TEST_DIR = tempfile.mkdtemp(prefix="soil-monitor-tests-")
TEST_DB = os.path.join(TEST_DIR, "temperature_data.db")
os.environ["SOIL_MONITOR_DB_PATH"] = TEST_DB
os.environ["SOIL_MONITOR_SECRET_KEY"] = "test-secret-key"
os.environ["SOIL_MONITOR_INGEST_TOKEN"] = "test-ingest-token"
os.environ["SOIL_MONITOR_USER"] = "admin"
os.environ["SOIL_MONITOR_PASSWORD"] = "test-password"

import app as monitor_app


class BabyMonitorTest(unittest.TestCase):
    def setUp(self):
        monitor_app.app.config.update(TESTING=True)
        self.client = monitor_app.app.test_client()
        conn = sqlite3.connect(TEST_DB)
        conn.execute("DELETE FROM baby_readings")
        conn.execute("DELETE FROM baby_events")
        conn.commit()
        conn.close()

    def auth_headers(self):
        token = base64.b64encode(b"admin:test-password").decode("ascii")
        return {"Authorization": f"Basic {token}"}

    def ingest_headers(self):
        return {"X-INGEST-TOKEN": "test-ingest-token"}

    def valid_reading(self):
        return {
            "msg_id": "baby-room-testboot-7",
            "device_id": "baby-room-esp32",
            "co2_ppm": 612,
            "temperature_c": 18.4,
            "humidity_rh": 48.2,
            "rssi": -58,
            "firmware_version": "BABY_SCD40_1.2.0",
            "uptime_seconds": 240,
            "reset_reason": "power_on",
            "warmup": False
        }

    def test_database_contains_soil_and_baby_tables(self):
        conn = sqlite3.connect(TEST_DB)
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        conn.close()
        self.assertIn("temperature_readings", tables)
        self.assertIn("baby_readings", tables)
        self.assertIn("baby_events", tables)

    def test_baby_submission_requires_ingest_token(self):
        response = self.client.post("/submit/baby", json=self.valid_reading())
        self.assertEqual(response.status_code, 401)

    def test_valid_submission_and_duplicate_are_idempotent(self):
        first = self.client.post("/submit/baby", json=self.valid_reading(), headers=self.ingest_headers())
        second = self.client.post("/submit/baby", json=self.valid_reading(), headers=self.ingest_headers())
        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)
        self.assertIn("Duplicate", second.get_json()["message"])

        conn = sqlite3.connect(TEST_DB)
        count = conn.execute("SELECT COUNT(*) FROM baby_readings").fetchone()[0]
        conn.close()
        self.assertEqual(count, 1)

    def test_invalid_sensor_values_are_rejected(self):
        reading = self.valid_reading()
        reading["humidity_rh"] = 120
        response = self.client.post("/submit/baby", json=reading, headers=self.ingest_headers())
        self.assertEqual(response.status_code, 400)

    def test_baby_data_and_stats_are_authenticated(self):
        self.client.post("/submit/baby", json=self.valid_reading(), headers=self.ingest_headers())
        self.assertEqual(self.client.get("/api/baby/data").status_code, 401)

        data = self.client.get("/api/baby/data", headers=self.auth_headers())
        stats = self.client.get("/api/baby/stats", headers=self.auth_headers())
        self.assertEqual(data.status_code, 200)
        self.assertEqual(stats.status_code, 200)
        self.assertEqual(data.get_json()[0]["co2_ppm"], 612)
        self.assertEqual(data.get_json()[0]["reset_reason"], "power_on")
        self.assertTrue(stats.get_json()["latest"]["online"])

    def test_warmup_readings_are_retained_but_excluded_from_charts(self):
        warmup = self.valid_reading()
        warmup.update({
            "msg_id": "baby-room-restart-1", "temperature_c": 28.0,
            "humidity_rh": 30.0, "co2_ppm": 1500, "warmup": True
        })
        self.client.post("/submit/baby", json=warmup, headers=self.ingest_headers())
        self.client.post("/submit/baby", json=self.valid_reading(), headers=self.ingest_headers())

        raw = self.client.get("/api/baby/data", headers=self.auth_headers()).get_json()
        chart = self.client.get("/api/baby/chart", headers=self.auth_headers()).get_json()
        stats = self.client.get("/api/baby/stats", headers=self.auth_headers()).get_json()
        self.assertEqual(len(raw), 2)
        self.assertEqual(len(chart), 1)
        self.assertEqual(chart[0]["temperature_c"], 18.4)
        self.assertEqual(stats["temperature"]["max"], 18.4)

    def test_baby_events_and_night_summary(self):
        self.assertEqual(self.client.get("/api/baby/events").status_code, 401)
        invalid = self.client.post(
            "/api/baby/events", json={"event_type": "unknown"},
            headers=self.auth_headers()
        )
        self.assertEqual(invalid.status_code, 400)

        bedtime = self.client.post(
            "/api/baby/events", json={"event_type": "bedtime"},
            headers=self.auth_headers()
        )
        got_up = self.client.post(
            "/api/baby/events", json={"event_type": "got_up"},
            headers=self.auth_headers()
        )
        self.assertEqual(bedtime.status_code, 201)
        self.assertEqual(got_up.status_code, 201)

        now_utc = datetime.now(timezone.utc).replace(tzinfo=None)
        start = now_utc - timedelta(hours=9)
        end = now_utc - timedelta(minutes=10)
        conn = sqlite3.connect(TEST_DB)
        conn.execute(
            "UPDATE baby_events SET timestamp = ? WHERE id = ?",
            (start.strftime("%Y-%m-%d %H:%M:%S"), bedtime.get_json()["id"])
        )
        conn.execute(
            "UPDATE baby_events SET timestamp = ? WHERE id = ?",
            (end.strftime("%Y-%m-%d %H:%M:%S"), got_up.get_json()["id"])
        )
        rows = []
        for index in range(9):
            timestamp = start + timedelta(hours=index)
            rows.append((
                timestamp.strftime("%Y-%m-%d %H:%M:%S"), f"night-{index}",
                "baby-room-esp32", 850 + index * 10, 18.0, 52.0, -60,
                "BABY_SCD40_1.2.0", 1000 + index * 3600, "power_on", 0
            ))
        conn.executemany('''
            INSERT INTO baby_readings
                (timestamp, msg_id, device_id, co2_ppm, temperature_c,
                 humidity_rh, rssi, firmware_version, uptime_seconds,
                 reset_reason, warmup)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', rows)
        conn.commit()
        conn.close()

        summary = self.client.get(
            "/api/baby/night-summary", headers=self.auth_headers()
        ).get_json()
        self.assertEqual(summary["source"], "recorded")
        self.assertEqual(summary["temperature"]["ideal_pct"], 100)
        self.assertEqual(summary["co2"]["below_1000_pct"], 100)

    def test_baby_csv_export(self):
        self.client.post("/submit/baby", json=self.valid_reading(), headers=self.ingest_headers())
        response = self.client.get("/api/baby/export.csv?hours=24", headers=self.auth_headers())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, "text/csv")
        self.assertIn(b"timestamp_utc,co2_ppm,temperature_c", response.data)
        self.assertIn(b"power_on", response.data)

    def test_baby_chart_spans_history_and_limits_points(self):
        now_utc = datetime.now(timezone.utc).replace(tzinfo=None)
        rows = []
        for index in range(7 * 24 * 12):
            timestamp = now_utc - timedelta(minutes=index * 5)
            rows.append((
                timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                f"history-{index}", "baby-room-esp32", 600 + index % 100,
                18.0 + index % 10 / 10, 45.0 + index % 20 / 10, -60,
                "BABY_SCD40_1.1.0"
            ))

        conn = sqlite3.connect(TEST_DB)
        conn.executemany('''
            INSERT INTO baby_readings
                (timestamp, msg_id, device_id, co2_ppm, temperature_c,
                 humidity_rh, rssi, firmware_version)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', rows)
        conn.commit()
        conn.close()

        response = self.client.get(
            "/api/baby/chart?hours=168&max_points=100",
            headers=self.auth_headers()
        )
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertLessEqual(len(data), 100)
        self.assertGreater(len(data), 90)
        oldest = datetime.fromisoformat(data[-1]["timestamp"])
        self.assertLess(oldest, now_utc - timedelta(days=6))

    def test_landing_baby_and_soil_pages_are_available(self):
        headers = self.auth_headers()
        landing = self.client.get("/", headers=headers)
        baby = self.client.get("/baby", headers=headers)
        soil = self.client.get("/soil", headers=headers)
        self.assertIn(b"Baby room", landing.data)
        self.assertIn(b"Sleepwear helper", baby.data)
        self.assertIn(b'id="temperatureChart"', baby.data)
        self.assertIn(b'id="humidityChart"', baby.data)
        self.assertIn(b'id="co2Chart"', baby.data)
        self.assertIn(b'id="nightSummary"', baby.data)
        self.assertIn(b'data-event="bedtime"', baby.data)
        self.assertIn(b'id="exportLink"', baby.data)
        self.assertIn(b'id="healthUptime"', baby.data)
        self.assertNotIn(b'id="signalValue"', baby.data)
        self.assertNotIn(b"Recent readings", baby.data)
        self.assertIn(b"Soil Monitor", soil.data)


if __name__ == "__main__":
    unittest.main()
