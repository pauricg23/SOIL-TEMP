import base64
import io
import json
import os
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock


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

    def test_stats_include_current_and_extrema_timestamps(self):
        now_utc = datetime.now(timezone.utc).replace(tzinfo=None, microsecond=0)
        rows = [
            (now_utc - timedelta(minutes=30), "extrema-1", 800, 17.0, 48.0),
            (now_utc - timedelta(minutes=20), "extrema-2", 500, 21.0, 65.0),
            (now_utc - timedelta(minutes=10), "extrema-3", 650, 19.0, 55.0)
        ]
        conn = sqlite3.connect(TEST_DB)
        conn.executemany('''
            INSERT INTO baby_readings
                (timestamp, msg_id, device_id, co2_ppm, temperature_c,
                 humidity_rh, firmware_version)
            VALUES (?, ?, 'baby-room-esp32', ?, ?, ?, 'BABY_SCD40_1.1.0')
        ''', [
            (timestamp.strftime("%Y-%m-%d %H:%M:%S"), msg_id, co2, temperature, humidity)
            for timestamp, msg_id, co2, temperature, humidity in rows
        ])
        conn.commit()
        conn.close()

        stats = self.client.get(
            "/api/baby/stats?hours=1", headers=self.auth_headers()
        ).get_json()
        self.assertEqual(stats["co2"]["current"], 650)
        self.assertEqual(stats["co2"]["min"], 500)
        self.assertEqual(stats["co2"]["min_at"], rows[1][0].strftime("%Y-%m-%d %H:%M:%S"))
        self.assertEqual(stats["temperature"]["max_at"], rows[1][0].strftime("%Y-%m-%d %H:%M:%S"))
        self.assertEqual(stats["humidity"]["min_at"], rows[0][0].strftime("%Y-%m-%d %H:%M:%S"))

    def test_weather_service_caches_current_temperature(self):
        payload = json.dumps({
            "current": {"time": "2026-08-31T12:15", "temperature_2m": 14.6}
        }).encode("utf-8")
        service = monitor_app.WeatherService(54.27, -8.47, "Sligo area")
        with mock.patch("urllib.request.urlopen", return_value=io.BytesIO(payload)) as urlopen:
            first = service.get_current()
            second = service.get_current()
        self.assertTrue(first["available"])
        self.assertEqual(first["temperature_c"], 14.6)
        self.assertEqual(first["observed_at"], "2026-08-31 12:15:00")
        self.assertEqual(second, first)
        urlopen.assert_called_once()

    def test_weather_service_compares_previous_five_nights(self):
        dublin = monitor_app.ZoneInfo("Europe/Dublin")
        now_local = datetime.now(timezone.utc).astimezone(dublin)
        end_local = now_local.replace(hour=9, minute=0, second=0, microsecond=0)
        if now_local.hour < 9:
            end_local -= timedelta(days=1)
        start_local = (end_local - timedelta(days=1)).replace(hour=23)
        temperatures = [8.0, 10.0, 11.0, 12.0, 13.0, 14.0]
        timestamps = [
            (start_local - timedelta(days=day_offset) + timedelta(hours=2))
            .astimezone(timezone.utc).replace(tzinfo=None).isoformat(timespec="minutes")
            for day_offset in range(6)
        ]
        comparison = monitor_app.WeatherService._night_comparison({
            "hourly": {"time": timestamps, "temperature_2m": temperatures}
        })
        self.assertEqual(comparison["nights"], 5)
        self.assertEqual(comparison["position"], "coldest")
        self.assertEqual(comparison["last_night_avg_c"], 8.0)
        self.assertLess(comparison["delta_c"], 0)

    def test_weather_endpoint_is_authenticated(self):
        self.assertEqual(self.client.get("/api/weather/current").status_code, 401)
        weather = {
            "available": True, "temperature_c": 14.6,
            "observed_at": "2026-08-31 12:15:00", "label": "Sligo area",
            "source": "Open-Meteo", "stale": False
        }
        with mock.patch.object(monitor_app.weather_service, "get_current", return_value=weather):
            response = self.client.get(
                "/api/weather/current", headers=self.auth_headers()
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["temperature_c"], 14.6)

    def test_event_toggles_accept_backdated_times_and_report_state(self):
        self.assertEqual(self.client.get("/api/baby/event-states").status_code, 401)
        now_utc = datetime.now(timezone.utc).replace(microsecond=0)
        heating_on_time = now_utc - timedelta(hours=2)
        heating_off_time = now_utc - timedelta(hours=1)
        heating_on = self.client.post(
            "/api/baby/events",
            json={"event_type": "heating_on", "occurred_at": heating_on_time.isoformat()},
            headers=self.auth_headers()
        )
        heating_off = self.client.post(
            "/api/baby/events",
            json={"event_type": "heating_off", "occurred_at": heating_off_time.isoformat()},
            headers=self.auth_headers()
        )
        window_opened = self.client.post(
            "/api/baby/events",
            json={"event_type": "window_opened", "occurred_at": heating_on_time.isoformat()},
            headers=self.auth_headers()
        )
        window_closed = self.client.post(
            "/api/baby/events",
            json={"event_type": "window_closed", "occurred_at": heating_off_time.isoformat()},
            headers=self.auth_headers()
        )
        future = self.client.post(
            "/api/baby/events",
            json={
                "event_type": "bedtime",
                "occurred_at": (now_utc + timedelta(hours=1)).isoformat()
            },
            headers=self.auth_headers()
        )
        dublin = monitor_app.ZoneInfo("Europe/Dublin")
        chosen_local_time = (now_utc.astimezone(dublin) - timedelta(hours=3)).replace(
            second=0, microsecond=0
        )
        local_time_event = self.client.post(
            "/api/baby/events",
            json={
                "event_type": "dehumidifier_on",
                "occurred_at": chosen_local_time.replace(tzinfo=None).isoformat(
                    timespec="minutes"
                )
            },
            headers=self.auth_headers()
        )

        self.assertEqual(heating_on.status_code, 201)
        self.assertEqual(
            heating_on.get_json()["timestamp"],
            heating_on_time.replace(tzinfo=None).strftime("%Y-%m-%d %H:%M:%S")
        )
        self.assertEqual(heating_off.status_code, 201)
        self.assertEqual(window_opened.status_code, 201)
        self.assertEqual(window_closed.get_json()["label"], "Window closed")
        self.assertEqual(future.status_code, 400)
        self.assertEqual(local_time_event.status_code, 201)
        self.assertEqual(
            local_time_event.get_json()["timestamp"],
            chosen_local_time.astimezone(timezone.utc).replace(tzinfo=None).strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        )

        states = self.client.get(
            "/api/baby/event-states", headers=self.auth_headers()
        ).get_json()
        self.assertFalse(states["heating"]["active"])
        self.assertEqual(states["heating"]["latest_event"]["event_type"], "heating_off")
        self.assertFalse(states["window"]["active"])
        self.assertEqual(states["window"]["latest_event"]["event_type"], "window_closed")

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
        heating_on = self.client.post(
            "/api/baby/events", json={"event_type": "heating_on"},
            headers=self.auth_headers()
        )
        heating_off = self.client.post(
            "/api/baby/events", json={"event_type": "heating_off"},
            headers=self.auth_headers()
        )
        self.assertEqual(bedtime.status_code, 201)
        self.assertEqual(got_up.status_code, 201)
        self.assertEqual(heating_on.status_code, 201)
        self.assertEqual(heating_on.get_json()["label"], "Heating on")
        self.assertEqual(heating_off.status_code, 201)
        self.assertEqual(heating_off.get_json()["label"], "Heating off")

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
        for day_offset in range(1, 6):
            for index in range(9):
                timestamp = start - timedelta(days=day_offset) + timedelta(hours=index)
                rows.append((
                    timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                    f"previous-{day_offset}-{index}", "baby-room-esp32",
                    900 + day_offset * 10, 19.0 + day_offset / 10, 50.0,
                    -60, "BABY_SCD40_1.2.0", 1000 + index * 3600,
                    "power_on", 0
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
        self.assertEqual(summary["rolling_comparison"]["nights"], 5)
        self.assertEqual(
            summary["rolling_comparison"]["temperature_position"], "coldest"
        )
        self.assertLess(summary["rolling_comparison"]["temperature_avg_delta"], 0)

    def test_baby_event_deletion_removes_only_selected_tag(self):
        bedtime = self.client.post(
            "/api/baby/events", json={"event_type": "bedtime"},
            headers=self.auth_headers()
        ).get_json()
        heating = self.client.post(
            "/api/baby/events", json={"event_type": "heating_on"},
            headers=self.auth_headers()
        ).get_json()
        self.client.post(
            "/submit/baby", json=self.valid_reading(),
            headers=self.ingest_headers()
        )

        route = f"/api/baby/events/{bedtime['id']}"
        self.assertEqual(self.client.delete(route).status_code, 401)
        deleted = self.client.delete(route, headers=self.auth_headers())
        self.assertEqual(deleted.status_code, 200)
        self.assertEqual(deleted.get_json()["deleted"]["event_type"], "bedtime")
        self.assertEqual(
            self.client.delete(route, headers=self.auth_headers()).status_code,
            404
        )

        conn = sqlite3.connect(TEST_DB)
        events = conn.execute(
            "SELECT id, event_type FROM baby_events ORDER BY id"
        ).fetchall()
        reading_count = conn.execute("SELECT COUNT(*) FROM baby_readings").fetchone()[0]
        conn.close()
        self.assertEqual(events, [(heating["id"], "heating_on")])
        self.assertEqual(reading_count, 1)

    def test_estimated_night_window_runs_eleven_to_nine(self):
        now_utc = datetime(2026, 8, 31, 12, 0, tzinfo=timezone.utc)
        start, end, completed = monitor_app.BabyDataManager._estimated_night_window(now_utc)
        dublin = monitor_app.ZoneInfo("Europe/Dublin")
        self.assertEqual(start.astimezone(dublin).hour, 23)
        self.assertEqual(end.astimezone(dublin).hour, 9)
        self.assertEqual((end - start).total_seconds(), 10 * 3600)
        self.assertTrue(completed)

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
        self.assertIn(b'id="outsideValue"', baby.data)
        self.assertIn(b'id="outsideTrend"', baby.data)
        self.assertIn(b"Estimated 11pm\xe2\x80\x939am", baby.data)
        self.assertIn(b'window.addEventListener("pageshow", closeExpandedChart)', baby.data)
        self.assertIn(b".chart-wrap canvas", baby.data)
        self.assertIn(b"function resizeAllCharts()", baby.data)
        self.assertIn(b'data-chart-card="temperature"', baby.data)
        self.assertIn(b'class="expand-chart"', baby.data)
        self.assertIn(b'id="nightSummary"', baby.data)
        self.assertIn(b'data-toggle="sleep"', baby.data)
        self.assertIn(b'data-toggle="window"', baby.data)
        self.assertIn(b'data-toggle="dehumidifier"', baby.data)
        self.assertIn(b'data-toggle="heating"', baby.data)
        self.assertIn(b'id="eventTime"', baby.data)
        self.assertIn(b"occurredAt = chosenTime", baby.data)
        self.assertIn(b"The next change will be saved for", baby.data)
        self.assertNotIn(b'data-event="heating_off"', baby.data)
        self.assertIn(b'id="exportLink"', baby.data)
        self.assertIn(b'id="healthUptime"', baby.data)
        self.assertNotIn(b'id="signalValue"', baby.data)
        self.assertNotIn(b"Recent readings", baby.data)
        self.assertIn(b"Soil Monitor", soil.data)


if __name__ == "__main__":
    unittest.main()
