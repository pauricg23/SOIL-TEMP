from flask import Flask, render_template, render_template_string, jsonify, request, send_from_directory
from datetime import datetime, timedelta, timezone
import json
import math
import os
import sqlite3
from collections import defaultdict
import statistics
import threading
import time
from functools import wraps
import hashlib
import secrets
import logging

# ============ Configuration ============
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(BASE_DIR, "logs")
DB_PATH = os.environ.get("SOIL_MONITOR_DB_PATH", os.path.join(BASE_DIR, "temperature_data.db"))

def _load_or_create_secret(env_var, file_name, length=32):
    value = os.environ.get(env_var)
    if value:
        return value.strip()
    path = os.path.join(BASE_DIR, file_name)
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            existing = f.read().strip()
            if existing:
                return existing
    generated = secrets.token_urlsafe(length)
    with open(path, "w", encoding="utf-8") as f:
        f.write(generated)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return generated

SECRET_KEY = _load_or_create_secret("SOIL_MONITOR_SECRET_KEY", ".secret_key", 32)
INGEST_TOKEN = _load_or_create_secret("SOIL_MONITOR_INGEST_TOKEN", ".ingest_token", 32)
DASHBOARD_USER = os.environ.get("SOIL_MONITOR_USER", "admin")
DASHBOARD_PASSWORD = _load_or_create_secret("SOIL_MONITOR_PASSWORD", ".dashboard_password", 24)
INGEST_TOKEN_HEADER = "X-INGEST-TOKEN"

class OnlyPostFilter(logging.Filter):
    def filter(self, record):
        msg = record.getMessage()
        if 'HTTP/' not in msg:
            return True
        return ('"POST /submit ' in msg) or ('"POST /alert ' in msg) or ('"GET /ack?' in msg)

def configure_request_logging():
    logger = logging.getLogger("werkzeug")
    flt = None
    for f in logger.filters:
        if isinstance(f, OnlyPostFilter):
            flt = f
            break
    if flt is None:
        flt = OnlyPostFilter()
        logger.addFilter(flt)
    for h in logger.handlers:
        if not any(isinstance(f, OnlyPostFilter) for f in h.filters):
            h.addFilter(flt)


def get_db_connection():
    conn = sqlite3.connect(DB_PATH, timeout=5)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn

# ============ Database Setup ============
def init_database():
    """Initialize SQLite database for better performance"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS temperature_readings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            msg_id TEXT,
            timestamp_raw TEXT,
            timestamp_source TEXT DEFAULT 'server',
            timestamp_epoch INTEGER,
            t1 REAL,
            t2 REAL,
            t3 REAL,
            battery REAL,
            battery_status TEXT,
            sensor_status TEXT DEFAULT 'active',
            wake_cause INTEGER,
            wake_cause_name TEXT,
            reset_reason INTEGER,
            reset_reason_name TEXT,
            last_fail TEXT,
            last_fail_cycle INTEGER,
            boot_count INTEGER,
            last_boot_count INTEGER,
            probe_mode_completed BOOLEAN,
            should_run_probe BOOLEAN,
            probe_done_this_cycle BOOLEAN,
            rtc_sleep_armed BOOLEAN,
            unsafe_wake BOOLEAN
        )
    ''')
    
    cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_timestamp ON temperature_readings(timestamp)
    ''')
    
    # Add battery columns if they don't exist (for existing databases)
    try:
        cursor.execute('ALTER TABLE temperature_readings ADD COLUMN battery REAL')
    except sqlite3.OperationalError:
        pass  # Column already exists
    
    try:
        cursor.execute('ALTER TABLE temperature_readings ADD COLUMN battery_status TEXT')
    except sqlite3.OperationalError:
        pass  # Column already exists
    
    # Add debug columns if they don't exist
    debug_columns = [
        ('msg_id', 'TEXT'),
        ('wake_cause', 'INTEGER'),
        ('wake_cause_name', 'TEXT'),
        ('reset_reason', 'INTEGER'),
        ('reset_reason_name', 'TEXT'),
        ('last_fail', 'TEXT'),
        ('last_fail_cycle', 'INTEGER'),
        ('boot_count', 'INTEGER'),
        ('last_boot_count', 'INTEGER'),
        ('probe_mode_completed', 'BOOLEAN'),
        ('should_run_probe', 'BOOLEAN'),
        ('probe_done_this_cycle', 'BOOLEAN'),
        ('rtc_sleep_armed', 'BOOLEAN'),
        ('unsafe_wake', 'BOOLEAN')
    ]
    
    for column_name, column_type in debug_columns:
        try:
            cursor.execute(f'ALTER TABLE temperature_readings ADD COLUMN {column_name} {column_type}')
        except sqlite3.OperationalError:
            pass  # Column already exists

    try:
        cursor.execute('''
            CREATE UNIQUE INDEX IF NOT EXISTS idx_msg_id_unique
            ON temperature_readings(msg_id)
            WHERE msg_id IS NOT NULL
        ''')
    except (sqlite3.OperationalError, sqlite3.IntegrityError) as e:
        print(f"Skipping msg_id unique index creation: {e}")

    # Add timestamp tracking columns for unambiguous source/format
    timestamp_columns = [
        ('timestamp_raw', 'TEXT'),
        ('timestamp_source', "TEXT DEFAULT 'server'"),
        ('timestamp_epoch', 'INTEGER')
    ]

    for column_name, column_type in timestamp_columns:
        try:
            cursor.execute(f'ALTER TABLE temperature_readings ADD COLUMN {column_name} {column_type}')
        except sqlite3.OperationalError:
            pass  # Column already exists

    # Backfill legacy rows so old data has a comparable epoch and a known source label.
    cursor.execute('''
        UPDATE temperature_readings
        SET timestamp_epoch = CAST(strftime('%s', timestamp) AS INTEGER)
        WHERE timestamp IS NOT NULL AND timestamp_epoch IS NULL
    ''')
    cursor.execute('''
        UPDATE temperature_readings
        SET timestamp_source = 'legacy'
        WHERE timestamp_source IS NULL OR timestamp_source = ''
    ''')
    
    conn.commit()
    conn.close()

# ============ Authentication ============
def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            response = jsonify({'error': 'Authentication required'})
            response.status_code = 401
            response.headers["WWW-Authenticate"] = 'Basic realm="Soil Monitor"'
            return response
        return f(*args, **kwargs)
    return decorated_function

def require_ingest_token(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        supplied = request.headers.get(INGEST_TOKEN_HEADER, "")
        if supplied and secrets.compare_digest(supplied, INGEST_TOKEN):
            return f(*args, **kwargs)

        query_token = request.args.get("ingest_token", "")
        if query_token and secrets.compare_digest(str(query_token), INGEST_TOKEN):
            return f(*args, **kwargs)

        # Walter firmware can send the token in JSON when custom headers are awkward.
        data = request.get_json(silent=True)
        body_token = ""
        if isinstance(data, dict):
            raw = data.get("ingest_token", "")
            body_token = raw if isinstance(raw, str) else str(raw)

        if not body_token or not secrets.compare_digest(body_token, INGEST_TOKEN):
            return jsonify({'error': 'Valid ingest token required'}), 401
        return f(*args, **kwargs)
    return decorated_function

def check_auth(username, password):
    user = username or ""
    pwd = password or ""
    return secrets.compare_digest(user, DASHBOARD_USER) and secrets.compare_digest(pwd, DASHBOARD_PASSWORD)

def coerce_bool(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        v = value.strip().lower()
        if v in ("true", "1", "yes", "y", "on"):
            return True
        if v in ("false", "0", "no", "n", "off"):
            return False
    return None

# ============ Data Management ============
class TemperatureDataManager:
    def __init__(self):
        self.cache = {}
        self.cache_timeout = 60  # seconds
        init_database()
    
    def add_reading(self, t1, t2, t3, battery=None, battery_status=None, timestamp=None, debug_data=None, msg_id=None):
        """Add new temperature reading to database"""
        conn = get_db_connection()
        cursor = conn.cursor()
        msg_id = None if msg_id in (None, "") else str(msg_id)[:96]
        
        # Extract debug data
        wake_cause = debug_data.get('wake_cause') if debug_data else None
        wake_cause_name = debug_data.get('wake_cause_name') if debug_data else None
        reset_reason = debug_data.get('reset_reason') if debug_data else None
        reset_reason_name = debug_data.get('reset_reason_name') if debug_data else None
        last_fail = debug_data.get('last_fail') if debug_data else None
        last_fail_cycle = debug_data.get('last_fail_cycle') if debug_data else None
        boot_count = debug_data.get('boot_count') if debug_data else None
        last_boot_count = debug_data.get('last_boot_count') if debug_data else None
        probe_mode_completed = coerce_bool(debug_data.get('probe_mode_completed')) if debug_data else None
        should_run_probe = coerce_bool(debug_data.get('should_run_probe')) if debug_data else None
        probe_done_this_cycle = coerce_bool(debug_data.get('probe_done_this_cycle')) if debug_data else None
        rtc_sleep_armed = coerce_bool(debug_data.get('rtc_sleep_armed')) if debug_data else None
        unsafe_wake = coerce_bool(debug_data.get('unsafe_wake')) if debug_data else None
        temps_valid = coerce_bool(debug_data.get('temps_valid')) if debug_data else None
        sensor_status = "invalid_temp" if temps_valid is False else "active"
        
        normalized_ts, ts_source, raw_ts, ts_epoch = self._resolve_timestamp(timestamp)

        cursor.execute('''
            INSERT OR IGNORE INTO temperature_readings (timestamp, msg_id, timestamp_raw, timestamp_source, timestamp_epoch,
                t1, t2, t3, battery, battery_status, sensor_status,
                wake_cause, wake_cause_name, reset_reason, reset_reason_name, last_fail, last_fail_cycle, boot_count, 
                last_boot_count, probe_mode_completed, should_run_probe, probe_done_this_cycle,
                rtc_sleep_armed, unsafe_wake)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (normalized_ts, msg_id, raw_ts, ts_source, ts_epoch, t1, t2, t3, battery, battery_status, sensor_status,
              wake_cause, wake_cause_name, reset_reason, reset_reason_name, last_fail, last_fail_cycle, boot_count,
              last_boot_count, probe_mode_completed, should_run_probe, probe_done_this_cycle,
              rtc_sleep_armed, unsafe_wake))
        inserted = cursor.rowcount > 0
        conn.commit()
        conn.close()
        self.cache.clear()
        return inserted

    def _resolve_timestamp(self, timestamp):
        """Resolve a reading timestamp and record where it came from."""
        raw_ts = None if timestamp is None else str(timestamp).strip()
        if not raw_ts or raw_ts.lower() == "null":
            now = datetime.now()
            return now.strftime("%Y-%m-%d %H:%M:%S"), "server", None, int(now.timestamp())
        try:
            normalized = raw_ts.replace('Z', '+00:00').replace('T', ' ')
            dt = datetime.fromisoformat(normalized)
            if dt.tzinfo is not None:
                epoch = int(dt.timestamp())
                dt_utc = dt.astimezone(timezone.utc).replace(tzinfo=None)
            else:
                dt_utc = dt
                epoch = int(dt_utc.replace(tzinfo=timezone.utc).timestamp())
            return dt_utc.strftime("%Y-%m-%d %H:%M:%S"), "device", raw_ts, epoch
        except Exception:
            now = datetime.now()
            print("Using server timestamp (invalid ESP32 ts)")
            return now.strftime("%Y-%m-%d %H:%M:%S"), "server", raw_ts, int(now.timestamp())

    def has_msg_id(self, msg_id):
        if not msg_id:
            return False
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT 1 FROM temperature_readings WHERE msg_id = ? LIMIT 1', (str(msg_id)[:96],))
        exists = cursor.fetchone() is not None
        conn.close()
        return exists
    
    def get_recent_readings(self, hours=24, limit=1000):
        """Get recent temperature readings with caching"""
        cache_key = f"recent_{hours}_{limit}"
        now = time.time()
        
        if cache_key in self.cache:
            data, timestamp = self.cache[cache_key]
            if now - timestamp < self.cache_timeout:
                return data
        
        conn = get_db_connection()
        cursor = conn.cursor()

        if hours is None or hours <= 0:
            cursor.execute('''
                SELECT timestamp, t1, t2, t3, battery, battery_status, timestamp_source, timestamp_epoch
                FROM temperature_readings
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (limit,))
        else:
            cutoff_time = (datetime.now() - timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute('''
                SELECT timestamp, t1, t2, t3, battery, battery_status, timestamp_source, timestamp_epoch
                FROM temperature_readings
                WHERE timestamp >= ?
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (cutoff_time, limit))
        
        data = []
        for row in cursor.fetchall():
            ts_dt = datetime.fromisoformat(row[0])
            display_dt = ts_dt
            # Keep the stored timestamp exact, but bucket device-timestamped readings
            # to the nearest hour for display on the chart.
            if row[6] == "device":
                if ts_dt.minute >= 30:
                    display_dt = (ts_dt.replace(minute=0, second=0, microsecond=0) +
                                  timedelta(hours=1))
                else:
                    display_dt = ts_dt.replace(minute=0, second=0, microsecond=0)
            data.append({
                'time': display_dt.strftime('%H:%M'),
                'ts': row[0],
                't1': row[1],
                't2': row[2],
                't3': row[3],
                'battery': row[4],
                'battery_status': row[5],
                'timestamp_source': row[6],
                'timestamp_epoch': row[7]
            })
        
        conn.close()
        
        # Cache the result
        self.cache[cache_key] = (data, now)
        return data
    
    def get_statistics(self, hours=24):
        """Get temperature statistics for the specified period"""
        conn = get_db_connection()
        cursor = conn.cursor()

        if hours is None or hours <= 0:
            cursor.execute('''
                SELECT t1, t2, t3, timestamp
                FROM temperature_readings
                ORDER BY timestamp ASC
            ''')
        else:
            cutoff_time = (datetime.now() - timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute('''
                SELECT t1, t2, t3, timestamp
                FROM temperature_readings
                WHERE timestamp >= ?
                ORDER BY timestamp ASC
            ''', (cutoff_time,))
        
        data = cursor.fetchall()
        conn.close()
        
        if not data:
            return {'t1': None, 't2': None, 't3': None}
        
        stats = {}
        for sensor in ['t1', 't2', 't3']:
            values = [row[0] if sensor == 't1' else row[1] if sensor == 't2' else row[2] 
                     for row in data if row[0] is not None or row[1] is not None or row[2] is not None]
            
            # Filter out None values
            values = [v for v in values if v is not None]
            
            if values:
                min_val = min(values)
                max_val = max(values)
                avg_val = statistics.mean(values)
                
                # Find timestamps for min/max
                min_time = next(row[3] for row in data if (row[0] if sensor == 't1' else row[1] if sensor == 't2' else row[2]) == min_val)
                max_time = next(row[3] for row in data if (row[0] if sensor == 't1' else row[1] if sensor == 't2' else row[2]) == max_val)
                
                stats[sensor] = {
                    'min': {'val': min_val, 'time': datetime.fromisoformat(min_time).strftime('%H:%M')},
                    'max': {'val': max_val, 'time': datetime.fromisoformat(max_time).strftime('%H:%M')},
                    'avg': round(avg_val, 2),
                    'current': values[-1] if values else None
                }
            else:
                stats[sensor] = None
        
        return stats


class BabyDataManager:
    def __init__(self):
        self.init_database()

    def init_database(self):
        conn = get_db_connection()
        conn.execute('''
            CREATE TABLE IF NOT EXISTS baby_readings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                msg_id TEXT NOT NULL UNIQUE,
                device_id TEXT NOT NULL,
                co2_ppm INTEGER NOT NULL,
                temperature_c REAL NOT NULL,
                humidity_rh REAL NOT NULL,
                rssi INTEGER,
                firmware_version TEXT
            )
        ''')
        conn.execute('''
            CREATE INDEX IF NOT EXISTS idx_baby_timestamp
            ON baby_readings(timestamp)
        ''')
        conn.commit()
        conn.close()

    def add_reading(self, msg_id, device_id, co2_ppm, temperature_c,
                    humidity_rh, rssi=None, firmware_version=None):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR IGNORE INTO baby_readings
                (msg_id, device_id, co2_ppm, temperature_c, humidity_rh,
                 rssi, firmware_version)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            str(msg_id)[:96], str(device_id)[:64], co2_ppm, temperature_c,
            humidity_rh, rssi, str(firmware_version or "")[:48]
        ))
        inserted = cursor.rowcount > 0
        conn.commit()
        conn.close()
        return inserted

    def get_recent_readings(self, hours=24, limit=1000):
        hours = max(1, min(int(hours), 24 * 365))
        limit = max(1, min(int(limit), 5000))
        now_utc = datetime.now(timezone.utc).replace(tzinfo=None)
        cutoff = (now_utc - timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")
        conn = get_db_connection()
        rows = conn.execute('''
            SELECT timestamp, co2_ppm, temperature_c, humidity_rh,
                   device_id, rssi, firmware_version
            FROM baby_readings
            WHERE timestamp >= ?
            ORDER BY timestamp DESC
            LIMIT ?
        ''', (cutoff, limit)).fetchall()
        conn.close()
        return [
            {
                "timestamp": row[0],
                "co2_ppm": row[1],
                "temperature_c": row[2],
                "humidity_rh": row[3],
                "device_id": row[4],
                "rssi": row[5],
                "firmware_version": row[6]
            }
            for row in rows
        ]

    def get_chart_readings(self, hours=24, max_points=1500):
        hours = max(1, min(int(hours), 24 * 365))
        max_points = max(100, min(int(max_points), 5000))
        now_utc = datetime.now(timezone.utc).replace(tzinfo=None)
        cutoff = (now_utc - timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")
        bucket_seconds = max(30, math.ceil(hours * 3600 / (max_points - 1)))
        bucket_seconds = math.ceil(bucket_seconds / 30) * 30

        conn = get_db_connection()
        rows = conn.execute('''
            SELECT MAX(timestamp),
                   CAST(ROUND(AVG(co2_ppm)) AS INTEGER),
                   AVG(temperature_c), AVG(humidity_rh)
            FROM baby_readings
            WHERE timestamp >= ?
            GROUP BY CAST(strftime('%s', timestamp) AS INTEGER) / ?
            ORDER BY MAX(timestamp) DESC
        ''', (cutoff, bucket_seconds)).fetchall()
        conn.close()
        return [
            {
                "timestamp": row[0],
                "co2_ppm": row[1],
                "temperature_c": round(row[2], 2),
                "humidity_rh": round(row[3], 2)
            }
            for row in rows
        ]

    def get_statistics(self, hours=24):
        hours = max(1, min(int(hours), 24 * 365))
        now_utc = datetime.now(timezone.utc).replace(tzinfo=None)
        cutoff = (now_utc - timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")
        conn = get_db_connection()
        row = conn.execute('''
            SELECT COUNT(*),
                   MIN(co2_ppm), MAX(co2_ppm), AVG(co2_ppm),
                   MIN(temperature_c), MAX(temperature_c), AVG(temperature_c),
                   MIN(humidity_rh), MAX(humidity_rh), AVG(humidity_rh)
            FROM baby_readings
            WHERE timestamp >= ?
        ''', (cutoff,)).fetchone()
        latest = conn.execute('''
            SELECT timestamp, co2_ppm, temperature_c, humidity_rh,
                   device_id, rssi, firmware_version
            FROM baby_readings
            ORDER BY timestamp DESC
            LIMIT 1
        ''').fetchone()
        conn.close()

        if not latest:
            return {"count": 0, "latest": None, "co2": None, "temperature": None, "humidity": None}

        latest_time = datetime.fromisoformat(latest[0])
        age_seconds = max(0, int((now_utc - latest_time).total_seconds()))
        return {
            "count": row[0],
            "latest": {
                "timestamp": latest[0],
                "co2_ppm": latest[1],
                "temperature_c": latest[2],
                "humidity_rh": latest[3],
                "device_id": latest[4],
                "rssi": latest[5],
                "firmware_version": latest[6],
                "age_seconds": age_seconds,
                "online": age_seconds <= 120
            },
            "co2": {"min": row[1], "max": row[2], "avg": round(row[3], 1)},
            "temperature": {"min": row[4], "max": row[5], "avg": round(row[6], 1)},
            "humidity": {"min": row[7], "max": row[8], "avg": round(row[9], 1)}
        }

# ============ Flask App ============
app = Flask(__name__)
configure_request_logging()
app.secret_key = SECRET_KEY

data_manager = TemperatureDataManager()
baby_data_manager = BabyDataManager()

# ============ Routes ============
@app.route("/submit", methods=["POST"])
@require_ingest_token
def submit():
    """Receive temperature data from ESP32"""
    try:
        data = request.get_json(force=True)
        
        # Validate temperature values
        t1 = validate_temp(data.get("t1"))
        t2 = validate_temp(data.get("t2"))
        t3 = validate_temp(data.get("t3"))
        msg_id = data.get("msg_id")
        
        # Get battery data
        battery = data.get("battery")
        battery_status = data.get("battery_status")
        
        # Get debug data
        debug_data = data.get("debug")
        
        temps_valid_flag = coerce_bool(debug_data.get("temps_valid")) if isinstance(debug_data, dict) else None
        is_invalid_temp_heartbeat = (
            temps_valid_flag is False and
            isinstance(debug_data, dict) and
            debug_data.get("note") == "invalid_temp_reading"
        )

        if t1 is not None or t2 is not None or t3 is not None or is_invalid_temp_heartbeat:
            inserted = data_manager.add_reading(
                t1, t2, t3, battery, battery_status, data.get("ts"), debug_data, msg_id=msg_id
            )
            if not inserted:
                return jsonify({"status": "ok", "message": "Duplicate msg_id ignored"}), 200
            if is_invalid_temp_heartbeat and t1 is None and t2 is None and t3 is None:
                return jsonify({"status": "ok", "message": "Heartbeat recorded (invalid temps)"}), 200
            return jsonify({"status": "ok", "message": "Data recorded successfully"}), 200
        else:
            return jsonify({"status": "error", "message": "No valid temperature data"}), 400
            
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400


@app.route("/submit/baby", methods=["POST"])
@require_ingest_token
def submit_baby():
    try:
        data = request.get_json(force=True)
        if not isinstance(data, dict):
            return jsonify({"status": "error", "message": "JSON object required"}), 400

        msg_id = str(data.get("msg_id") or "").strip()
        device_id = str(data.get("device_id") or "").strip()
        co2_ppm = validate_number(data.get("co2_ppm"), 0, 40000, integer=True)
        temperature_c = validate_number(data.get("temperature_c"), -10, 60)
        humidity_rh = validate_number(data.get("humidity_rh"), 0, 100)
        rssi = validate_number(data.get("rssi"), -127, 0, integer=True, optional=True)

        if not msg_id or not device_id:
            return jsonify({"status": "error", "message": "msg_id and device_id are required"}), 400
        if co2_ppm is None or temperature_c is None or humidity_rh is None:
            return jsonify({"status": "error", "message": "Invalid SCD40 reading"}), 400

        inserted = baby_data_manager.add_reading(
            msg_id, device_id, co2_ppm, temperature_c, humidity_rh,
            rssi, data.get("firmware_version")
        )
        message = "Reading recorded" if inserted else "Duplicate msg_id ignored"
        return jsonify({"status": "ok", "message": message}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400

@app.route("/alert", methods=["POST"])
@require_ingest_token
def battery_alert():
    """Receive battery alerts from ESP32"""
    try:
        data = request.get_json(force=True)
        
        alert_type = data.get("alert")
        battery_voltage = data.get("battery")
        message = data.get("message")
        
        # Log the alert
        if alert_type == "wifi_fallback":
            prefix = "WIFI DEBUG"
        elif alert_type == "device_debug":
            prefix = "DEVICE DEBUG"
        else:
            prefix = "ALERT"
        if battery_voltage is None:
            print(f"{prefix}: {alert_type} - {message}")
        else:
            print(f"{prefix}: {alert_type} - {message} (Voltage: {battery_voltage}V)")
        
        # You could add email notifications, database logging, etc. here
        # For now, just log to console and return success
        
        return jsonify({
            "status": "ok", 
            "message": "Alert received",
            "alert_type": alert_type,
            "battery_voltage": battery_voltage
        }), 200
            
    except Exception as e:
        print(f"Error processing battery alert: {e}")
        return jsonify({"status": "error", "message": str(e)}), 400

@app.route("/ack", methods=["GET"])
@require_ingest_token
def ack_msg():
    msg_id = (request.args.get("msg_id") or "").strip()
    if not msg_id:
        return jsonify({"status": "error", "message": "msg_id required"}), 400
    if data_manager.has_msg_id(msg_id):
        return jsonify({"status": "ok", "msg_id": msg_id, "exists": True}), 200
    return jsonify({"status": "missing", "msg_id": msg_id, "exists": False}), 404

@app.route("/api/data")
@require_auth
def get_data():
    """Get temperature data with optional filtering"""
    hours = request.args.get('hours', 24, type=int)
    limit = request.args.get('limit', 1000, type=int)
    
    data = data_manager.get_recent_readings(hours, limit)
    return jsonify(data)

@app.route("/api/stats")
@require_auth
def get_stats():
    """Get temperature statistics"""
    hours = request.args.get('hours', 24, type=int)
    stats = data_manager.get_statistics(hours)
    return jsonify(stats)

@app.route("/api/debug")
@require_auth
def get_debug_info():
    """Get latest debug information from device"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get the most recent reading with debug data
        cursor.execute('''
            SELECT timestamp, timestamp_source, sensor_status,
                   wake_cause, wake_cause_name, reset_reason, reset_reason_name,
                   last_fail, last_fail_cycle, battery, battery_status
            FROM temperature_readings 
            WHERE wake_cause IS NOT NULL 
            ORDER BY timestamp DESC 
            LIMIT 1
        ''')
        
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return jsonify({
                "timestamp": row[0],
                "timestamp_source": row[1],
                "sensor_status": row[2],
                "wake_cause": row[3],
                "wake_cause_name": row[4],
                "reset_reason": row[5],
                "reset_reason_name": row[6],
                "last_fail": row[7],
                "last_fail_cycle": row[8],
                "battery": row[9],
                "battery_status": row[10]
            }), 200
        else:
            return jsonify({"message": "No debug data available"}), 404
            
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/health")
@require_auth
def health_check():
    """Health check endpoint"""
    try:
        # Check database connection
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM temperature_readings")
        count = cursor.fetchone()[0]
        conn.close()
        
        return jsonify({
            "status": "healthy",
            "database": "connected",
            "total_readings": count,
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }), 500


@app.route("/api/baby/data")
@require_auth
def get_baby_data():
    hours = request.args.get("hours", 24, type=int)
    limit = request.args.get("limit", 1000, type=int)
    return jsonify(baby_data_manager.get_recent_readings(hours, limit))


@app.route("/api/baby/chart")
@require_auth
def get_baby_chart():
    hours = request.args.get("hours", 24, type=int)
    max_points = request.args.get("max_points", 1500, type=int)
    return jsonify(baby_data_manager.get_chart_readings(hours, max_points))


@app.route("/api/baby/stats")
@require_auth
def get_baby_stats():
    hours = request.args.get("hours", 24, type=int)
    return jsonify(baby_data_manager.get_statistics(hours))

def validate_temp(val):
    """Validate temperature values"""
    try:
        v = float(val)
        if -10 <= v <= 80:
            return v
    except (TypeError, ValueError):
        pass
    return None


def validate_number(value, minimum, maximum, integer=False, optional=False):
    if value is None and optional:
        return None
    try:
        number = float(value)
        if minimum <= number <= maximum:
            return int(number) if integer else round(number, 2)
    except (TypeError, ValueError):
        pass
    return None

# ============ Enhanced HTML Template ============
TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Soil Monitor</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.3/dist/chart.umd.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/date-fns@2.29.3/index.min.js"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        :root {
            --primary-color: #2f855a;
            --secondary-color: #65a30d;
            --success-color: #059669;
            --warning-color: #d97706;
            --danger-color: #dc2626;
            --bg-primary: #ffffff;
            --bg-secondary: #f8fafc;
            --bg-tertiary: #e2e8f0;
            --text-primary: #1e293b;
            --text-secondary: #64748b;
            --border-color: #e2e8f0;
            --shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
            --shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.1);
        }

        [data-theme="dark"] {
            --bg-primary: #0f172a;
            --bg-secondary: #1e293b;
            --bg-tertiary: #334155;
            --text-primary: #f1f5f9;
            --text-secondary: #94a3b8;
            --border-color: #334155;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: var(--bg-secondary);
            color: var(--text-primary);
            line-height: 1.6;
            transition: all 0.3s ease;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 1rem;
        }

        .header {
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            text-align: center;
            gap: 1rem;
            margin-bottom: 2rem;
            padding: 1.5rem;
            background: var(--bg-primary);
            border-radius: 16px;
            box-shadow: var(--shadow);
        }

        .header h1 {
            font-size: 1.8rem;
            font-weight: 700;
            color: #14532d;
            display: flex;
            align-items: center;
            gap: 0.55rem;
        }

        .controls {
            display: flex;
            gap: 1rem;
            align-items: center;
            justify-content: center;
            width: 100%;
        }

        .theme-toggle {
            background: var(--bg-tertiary);
            border: none;
            border-radius: 8px;
            padding: 0.5rem;
            cursor: pointer;
            color: var(--text-primary);
            transition: all 0.3s ease;
        }

        .theme-toggle:hover {
            background: var(--border-color);
        }

        .time-selector {
            background: var(--bg-primary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 0.5rem 1rem;
            color: var(--text-primary);
            cursor: pointer;
        }

        .status-bar {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }

        .status-card {
            background: var(--bg-primary);
            border-radius: 16px;
            padding: 1.5rem;
            box-shadow: var(--shadow);
            border-left: 4px solid var(--primary-color);
            transition: all 0.3s ease;
        }

        .status-card:hover {
            transform: translateY(-2px);
            box-shadow: var(--shadow-lg);
        }

        .status-card h3 {
            font-size: 0.875rem;
            font-weight: 600;
            color: var(--text-secondary);
            margin-bottom: 0.5rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .status-card .value {
            font-size: 2rem;
            font-weight: 700;
            color: var(--text-primary);
            margin-bottom: 0.5rem;
        }

        .status-card .subtitle {
            font-size: 0.875rem;
            color: var(--text-secondary);
        }

        .chart-container {
            background: var(--bg-primary);
            border-radius: 16px;
            padding: 2rem;
            box-shadow: var(--shadow);
            margin-bottom: 2rem;
        }

        .chart-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1.5rem;
        }

        .chart-title {
            font-size: 1.25rem;
            font-weight: 600;
            color: var(--text-primary);
        }

        .chart-controls {
            display: flex;
            gap: 0.5rem;
        }

        .chart-btn {
            background: var(--bg-tertiary);
            border: none;
            border-radius: 6px;
            padding: 0.5rem;
            cursor: pointer;
            color: var(--text-primary);
            transition: all 0.3s ease;
        }

        .chart-btn:hover, .chart-btn.active {
            background: var(--primary-color);
            color: white;
        }

        .chart-wrapper {
            position: relative;
            height: 800px;
        }

        .compost-legend {
            display: flex;
            flex-wrap: wrap;
            gap: 0.5rem;
            margin-top: 1rem;
        }

        .compost-chip {
            display: inline-flex;
            align-items: center;
            gap: 0.4rem;
            font-size: 0.8rem;
            color: var(--text-secondary);
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 999px;
            padding: 0.3rem 0.6rem;
        }

        .compost-dot {
            width: 10px;
            height: 10px;
            border-radius: 50%;
            display: inline-block;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }

        .stat-card {
            background: var(--bg-primary);
            border-radius: 16px;
            padding: 1.5rem;
            box-shadow: var(--shadow);
            transition: all 0.3s ease;
        }

        .stat-card:hover {
            transform: translateY(-2px);
            box-shadow: var(--shadow-lg);
        }

        .stat-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1rem;
        }

        .stat-title {
            font-size: 1.125rem;
            font-weight: 600;
            color: var(--text-primary);
        }

        .stat-icon {
            width: 40px;
            height: 40px;
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.25rem;
            color: white;
        }

        .stat-icon.t1 { background: linear-gradient(135deg, #ef4444, #dc2626); }
        .stat-icon.t2 { background: linear-gradient(135deg, #3b82f6, #2563eb); }
        .stat-icon.t3 { background: linear-gradient(135deg, #10b981, #059669); }

        /* Debug Information Styles */
        .debug-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 1.5rem;
            margin-top: 1rem;
        }

        .debug-card {
            background: var(--bg-secondary);
            border-radius: 12px;
            padding: 1.5rem;
            border: 1px solid var(--border-color);
        }

        .debug-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1rem;
        }

        .debug-header h3 {
            font-size: 1.1rem;
            font-weight: 600;
            color: var(--text-primary);
        }

        .debug-header i {
            font-size: 1.2rem;
            color: var(--primary-color);
        }

        .debug-content {
            display: flex;
            flex-direction: column;
            gap: 0.75rem;
        }

        .debug-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 0.5rem 0;
            border-bottom: 1px solid var(--border-color);
        }

        .debug-item:last-child {
            border-bottom: none;
        }

        .debug-label {
            font-weight: 500;
            color: var(--text-secondary);
            font-size: 0.9rem;
        }

        .debug-value {
            font-weight: 600;
            color: var(--text-primary);
            font-size: 0.9rem;
            padding: 0.25rem 0.5rem;
            background: var(--bg-tertiary);
            border-radius: 6px;
            min-width: 60px;
            text-align: center;
        }

        @media (max-width: 768px) {
            .debug-grid {
                grid-template-columns: 1fr;
            }
        }

        .stat-content {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 1rem;
        }

        .stat-item {
            text-align: center;
        }

        .stat-label {
            font-size: 0.875rem;
            color: var(--text-secondary);
            margin-bottom: 0.25rem;
        }

        .stat-value {
            font-size: 1.5rem;
            font-weight: 700;
            color: var(--text-primary);
        }

        .loading {
            display: flex;
            justify-content: center;
            align-items: center;
            height: 200px;
            color: var(--text-secondary);
        }

        .spinner {
            width: 40px;
            height: 40px;
            border: 4px solid var(--border-color);
            border-top: 4px solid var(--primary-color);
            border-radius: 50%;
            animation: spin 1s linear infinite;
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        .error {
            background: #fef2f2;
            border: 1px solid #fecaca;
            color: #dc2626;
            padding: 1rem;
            border-radius: 8px;
            margin: 1rem 0;
        }

        .success {
            background: #f0fdf4;
            border: 1px solid #bbf7d0;
            color: #059669;
            padding: 1rem;
            border-radius: 8px;
            margin: 1rem 0;
        }

        @media (max-width: 768px) {
            .container {
                padding: 0.5rem;
            }
            
            .header {
                flex-direction: column;
                gap: 1rem;
                text-align: center;
            }
            
            .controls {
                flex-wrap: wrap;
                justify-content: center;
            }
            
            .status-bar {
                grid-template-columns: 1fr;
            }
            
            .stats-grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <h1><i class="fas fa-seedling"></i> Soil Monitor</h1>
            <div class="controls">
                <select class="time-selector" id="timeRange">
                    <option value="6">Last 6 Hours</option>
                    <option value="24" selected>Last 24 Hours</option>
                    <option value="168">Last Week</option>
                    <option value="720">Last Month</option>
                    <option value="-1">All Time</option>
                </select>
                <button class="theme-toggle" id="themeToggle">
                    <i class="fas fa-moon"></i>
                </button>
                <a class="theme-toggle" href="/debug-view" title="Open debug page">
                    <i class="fas fa-bug"></i>
                </a>
                <button class="theme-toggle" id="refreshBtn">
                    <i class="fas fa-sync-alt"></i>
                </button>
            </div>
        </div>

        <!-- Status Bar -->
        <div class="status-bar">
            <div class="status-card">
                <h3>Average Temperature</h3>
                <div class="value" id="avgTemp">--</div>
                <div class="subtitle">Across all sensors</div>
            </div>
            <div class="status-card">
                <h3>Compost Stage</h3>
                <div class="value" id="compostStage">--</div>
                <div class="subtitle" id="compostStageHint">Waiting for data</div>
            </div>
        </div>

        <!-- Main Chart -->
        <div class="chart-container">
            <div class="chart-header">
                <h2 class="chart-title">Temperature Trends</h2>
                <div class="chart-controls">
                    <button class="chart-btn active" data-chart="line">
                        <i class="fas fa-chart-line"></i>
                    </button>
                    <button class="chart-btn" data-chart="area">
                        <i class="fas fa-chart-area"></i>
                    </button>
                </div>
            </div>
            <div class="chart-wrapper">
                <canvas id="mainChart"></canvas>
            </div>
            <div class="compost-legend">
                <span class="compost-chip"><span class="compost-dot" style="background:#93c5fd;"></span>Cold (&lt;20C)</span>
                <span class="compost-chip"><span class="compost-dot" style="background:#86efac;"></span>Mesophilic (20-40C)</span>
                <span class="compost-chip"><span class="compost-dot" style="background:#fde68a;"></span>Thermophilic Active (40-55C)</span>
                <span class="compost-chip"><span class="compost-dot" style="background:#fb923c;"></span>Thermophilic Optimal (55-65C)</span>
                <span class="compost-chip"><span class="compost-dot" style="background:#fca5a5;"></span>Too Hot (&gt;65C)</span>
            </div>
        </div>

        <!-- Statistics Grid -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-header">
                    <h3 class="stat-title">Sensor T1</h3>
                    <div class="stat-icon t1">
                        <i class="fas fa-thermometer-half"></i>
                    </div>
                </div>
                <div class="stat-content">
                    <div class="stat-item">
                        <div class="stat-label">Current</div>
                        <div class="stat-value" id="t1Current">--</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-label">Average</div>
                        <div class="stat-value" id="t1Avg">--</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-label">Min</div>
                        <div class="stat-value" id="t1Min">--</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-label">Max</div>
                        <div class="stat-value" id="t1Max">--</div>
                    </div>
                </div>
            </div>

            <div class="stat-card">
                <div class="stat-header">
                    <h3 class="stat-title">Sensor T2</h3>
                    <div class="stat-icon t2">
                        <i class="fas fa-thermometer-half"></i>
                    </div>
                </div>
                <div class="stat-content">
                    <div class="stat-item">
                        <div class="stat-label">Current</div>
                        <div class="stat-value" id="t2Current">--</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-label">Average</div>
                        <div class="stat-value" id="t2Avg">--</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-label">Min</div>
                        <div class="stat-value" id="t2Min">--</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-label">Max</div>
                        <div class="stat-value" id="t2Max">--</div>
                    </div>
                </div>
            </div>

            <div class="stat-card">
                <div class="stat-header">
                    <h3 class="stat-title">Sensor T3</h3>
                    <div class="stat-icon t3">
                        <i class="fas fa-thermometer-half"></i>
                    </div>
                </div>
                <div class="stat-content">
                    <div class="stat-item">
                        <div class="stat-label">Current</div>
                        <div class="stat-value" id="t3Current">--</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-label">Average</div>
                        <div class="stat-value" id="t3Avg">--</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-label">Min</div>
                        <div class="stat-value" id="t3Min">--</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-label">Max</div>
                        <div class="stat-value" id="t3Max">--</div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        // Global variables
        let mainChart;
        let currentTheme = 'light';
        let currentTimeRange = 24;
        let refreshInterval;
        const COMPOST_ZONES = [
            { min: -20, max: 20, label: 'Cold', color: 'rgba(147, 197, 253, 0.22)' },
            { min: 20, max: 40, label: 'Mesophilic', color: 'rgba(134, 239, 172, 0.20)' },
            { min: 40, max: 55, label: 'Thermophilic Active', color: 'rgba(253, 230, 138, 0.22)' },
            { min: 55, max: 65, label: 'Thermophilic Optimal', color: 'rgba(251, 146, 60, 0.20)' },
            { min: 65, max: 100, label: 'Too Hot', color: 'rgba(252, 165, 165, 0.22)' }
        ];

        const compostZonesPlugin = {
            id: 'compostZones',
            beforeDatasetsDraw(chart) {
                const { ctx, chartArea, scales } = chart;
                const y = scales.y;
                if (!chartArea || !y) return;
                ctx.save();
                COMPOST_ZONES.forEach(zone => {
                    const yTop = y.getPixelForValue(zone.max);
                    const yBottom = y.getPixelForValue(zone.min);
                    const top = Math.max(chartArea.top, Math.min(yTop, yBottom));
                    const bottom = Math.min(chartArea.bottom, Math.max(yTop, yBottom));
                    if (bottom <= chartArea.top || top >= chartArea.bottom) return;
                    ctx.fillStyle = zone.color;
                    ctx.fillRect(chartArea.left, top, chartArea.right - chartArea.left, bottom - top);
                });
                ctx.restore();
            }
        };
        Chart.register(compostZonesPlugin);

        // Initialize the application
        document.addEventListener('DOMContentLoaded', function() {
            initializeTheme();
            initializeChart();
            initializeEventListeners();
            loadData();
            startAutoRefresh();
        });

        // Theme management
        function initializeTheme() {
            const savedTheme = localStorage.getItem('theme') || 'light';
            setTheme(savedTheme);
        }

        function setTheme(theme) {
            currentTheme = theme;
            document.documentElement.setAttribute('data-theme', theme);
            localStorage.setItem('theme', theme);
            
            const themeIcon = document.getElementById('themeToggle').querySelector('i');
            themeIcon.className = theme === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
        }

        // Chart initialization
        function initializeChart() {
            const ctx = document.getElementById('mainChart').getContext('2d');
            
            mainChart = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [
                        {
                            label: 'Sensor T1',
                            data: [],
                            borderColor: '#ef4444',
                            backgroundColor: 'rgba(239, 68, 68, 0.1)',
                            borderWidth: 3,
                            pointRadius: 0,
                            pointHoverRadius: 6,
                            tension: 0.4,
                            fill: false
                        },
                        {
                            label: 'Sensor T2',
                            data: [],
                            borderColor: '#3b82f6',
                            backgroundColor: 'rgba(59, 130, 246, 0.1)',
                            borderWidth: 3,
                            pointRadius: 0,
                            pointHoverRadius: 6,
                            tension: 0.4,
                            fill: false
                        },
                        {
                            label: 'Sensor T3',
                            data: [],
                            borderColor: '#10b981',
                            backgroundColor: 'rgba(16, 185, 129, 0.1)',
                            borderWidth: 3,
                            pointRadius: 0,
                            pointHoverRadius: 6,
                            tension: 0.4,
                            fill: false
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    interaction: {
                        mode: 'index',
                        intersect: false
                    },
                    plugins: {
                        legend: {
                            position: 'top',
                            labels: {
                                usePointStyle: true,
                                padding: 20,
                                font: {
                                    size: 14,
                                    weight: '500'
                                }
                            }
                        },
                        tooltip: {
                            backgroundColor: 'rgba(0, 0, 0, 0.8)',
                            titleColor: '#ffffff',
                            bodyColor: '#ffffff',
                            borderColor: '#374151',
                            borderWidth: 1,
                            cornerRadius: 8,
                            displayColors: true,
                            callbacks: {
                                title: function(context) {
                                    return 'Time: ' + context[0].label;
                                },
                                label: function(context) {
                                    return context.dataset.label + ': ' + context.parsed.y.toFixed(2) + '°C';
                                }
                            }
                        },
                        compostZones: {
                            enabled: true
                        }
                    },
                    scales: {
                        x: {
                            grid: {
                                color: 'rgba(0, 0, 0, 0.1)',
                                drawBorder: false
                            },
                            ticks: {
                                color: '#6b7280',
                                font: {
                                    size: 12
                                }
                            }
                        },
                        y: {
                            grid: {
                                color: 'rgba(0, 0, 0, 0.1)',
                                drawBorder: false
                            },
                            ticks: {
                                color: '#6b7280',
                                font: {
                                    size: 12
                                },
                                callback: function(value) {
                                    return value + '°C';
                                }
                            },
                            suggestedMin: 15,
                            suggestedMax: 70
                        }
                    },
                    animation: {
                        duration: 1000,
                        easing: 'easeInOutQuart'
                    }
                }
            });
        }

        // Event listeners
        function initializeEventListeners() {
            // Theme toggle
            document.getElementById('themeToggle').addEventListener('click', function() {
                setTheme(currentTheme === 'light' ? 'dark' : 'light');
            });

            // Time range selector
            document.getElementById('timeRange').addEventListener('change', function() {
                currentTimeRange = parseInt(this.value);
                loadData();
            });

            // Refresh button
            document.getElementById('refreshBtn').addEventListener('click', function() {
                loadData();
            });

            // Chart type buttons
            document.querySelectorAll('.chart-btn').forEach(btn => {
                btn.addEventListener('click', function() {
                    const chartType = this.dataset.chart;
                    changeChartType(chartType);
                    
                    // Update active button
                    document.querySelectorAll('.chart-btn').forEach(b => b.classList.remove('active'));
                    this.classList.add('active');
                });
            });
        }

        // Data loading
        async function loadData() {
            try {
                showLoading();
                
                const [dataResponse, statsResponse] = await Promise.all([
                    fetch(`/api/data?hours=${currentTimeRange}`),
                    fetch(`/api/stats?hours=${currentTimeRange}`)
                ]);

                if (!dataResponse.ok || !statsResponse.ok) {
                    throw new Error('Failed to fetch data');
                }

                const data = await dataResponse.json();
                const stats = await statsResponse.json();

                updateChart(data);
                updateStatistics(stats);
                updateStatusBar(data, stats);
                
                hideLoading();
            } catch (error) {
                console.error('Error loading data:', error);
                showError('Failed to load data. Please try again.');
            }
        }

        // Chart updates
        function updateChart(data) {
            if (!data || data.length === 0) return;

            const labels = data.map(d => d.time).reverse();
            const t1Data = data.map(d => d.t1).reverse();
            const t2Data = data.map(d => d.t2).reverse();
            const t3Data = data.map(d => d.t3).reverse();

            mainChart.data.labels = labels;
            mainChart.data.datasets[0].data = t1Data;
            mainChart.data.datasets[1].data = t2Data;
            mainChart.data.datasets[2].data = t3Data;

            mainChart.update('active');
        }

        function changeChartType(type) {
            const chartTypes = {
                'line': 'line',
                'area': 'line'
            };

            mainChart.config.type = chartTypes[type] || 'line';
            
            if (type === 'area') {
                mainChart.data.datasets.forEach(dataset => {
                    dataset.fill = true;
                });
            } else {
                mainChart.data.datasets.forEach(dataset => {
                    dataset.fill = false;
                });
            }

            mainChart.update();
        }

        // Statistics updates
        function updateStatistics(stats) {
            ['t1', 't2', 't3'].forEach(sensor => {
                const sensorStats = stats[sensor];
                if (sensorStats) {
                    document.getElementById(`${sensor}Current`).textContent = 
                        sensorStats.current ? sensorStats.current.toFixed(1) + '°C' : '--';
                    document.getElementById(`${sensor}Avg`).textContent = 
                        sensorStats.avg ? sensorStats.avg + '°C' : '--';
                    document.getElementById(`${sensor}Min`).textContent = 
                        sensorStats.min ? sensorStats.min.val.toFixed(1) + '°C' : '--';
                    document.getElementById(`${sensor}Max`).textContent = 
                        sensorStats.max ? sensorStats.max.val.toFixed(1) + '°C' : '--';
                } else {
                    document.getElementById(`${sensor}Current`).textContent = '--';
                    document.getElementById(`${sensor}Avg`).textContent = '--';
                    document.getElementById(`${sensor}Min`).textContent = '--';
                    document.getElementById(`${sensor}Max`).textContent = '--';
                }
            });
        }

        // Status bar updates
        function updateStatusBar(data, stats) {
            // Calculate average temperature
            const allTemps = [];
            data.forEach(d => {
                if (d.t1 !== null) allTemps.push(d.t1);
                if (d.t2 !== null) allTemps.push(d.t2);
                if (d.t3 !== null) allTemps.push(d.t3);
            });
            
            if (allTemps.length > 0) {
                const avg = allTemps.reduce((a, b) => a + b, 0) / allTemps.length;
                document.getElementById('avgTemp').textContent = avg.toFixed(1) + '°C';
                updateCompostStage(avg);
            } else {
                document.getElementById('avgTemp').textContent = '--';
                updateCompostStage(null);
            }
        }

        function updateCompostStage(avgTemp) {
            const stageEl = document.getElementById('compostStage');
            const hintEl = document.getElementById('compostStageHint');
            if (avgTemp === null || Number.isNaN(avgTemp)) {
                stageEl.textContent = '--';
                hintEl.textContent = 'Waiting for data';
                return;
            }

            let stage = 'Cold';
            let hint = 'Low activity, pile may need more nitrogen and moisture.';
            if (avgTemp >= 20 && avgTemp < 40) {
                stage = 'Mesophilic';
                hint = 'Early activity; microbes are ramping up.';
            } else if (avgTemp >= 40 && avgTemp < 55) {
                stage = 'Thermophilic';
                hint = 'Active decomposition; good pathogen reduction.';
            } else if (avgTemp >= 55 && avgTemp <= 65) {
                stage = 'Optimal';
                hint = 'Best composting zone for fast breakdown.';
            } else if (avgTemp > 65) {
                stage = 'Too Hot';
                hint = 'Turn/aerate pile to cool and protect microbes.';
            }

            stageEl.textContent = stage;
            hintEl.textContent = `${hint} (avg ${avgTemp.toFixed(1)}C)`;
        }

        // UI helpers
        function showLoading() {
            // Could add loading indicators here
        }

        function hideLoading() {
            // Hide loading indicators
        }

        function showError(message) {
            // Could show error messages here
            console.error(message);
        }

        // Auto refresh
        function startAutoRefresh() {
            refreshInterval = setInterval(loadData, 30000); // Refresh every 30 seconds
        }

        function stopAutoRefresh() {
            if (refreshInterval) {
                clearInterval(refreshInterval);
            }
        }

        // Cleanup on page unload
        window.addEventListener('beforeunload', stopAutoRefresh);
    </script>
</body>
</html>
"""

DEBUG_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Device Debug</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #f3f4f6; color: #111827; margin: 0; padding: 24px; }
        .card { max-width: 760px; margin: 0 auto; background: #fff; border-radius: 12px; box-shadow: 0 8px 20px rgba(0,0,0,0.08); padding: 20px; }
        .head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; }
        h1 { margin: 0; font-size: 1.3rem; }
        a.btn { text-decoration: none; background: #2563eb; color: #fff; border-radius: 8px; padding: 8px 12px; font-size: 0.9rem; }
        .row { display: grid; grid-template-columns: 220px 1fr; gap: 8px; padding: 8px 0; border-bottom: 1px solid #e5e7eb; }
        .row:last-child { border-bottom: none; }
        .k { color: #4b5563; font-weight: 600; }
        .v { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
        .muted { color: #6b7280; font-size: 0.9rem; margin-top: 12px; }
    </style>
</head>
<body>
    <div class="card">
        <div class="head">
            <h1><i class="fas fa-bug"></i> Device Debug</h1>
            <a class="btn" href="/">Back to Dashboard</a>
        </div>
        <div class="row"><div class="k">Last Seen</div><div class="v" id="timestamp">--</div></div>
        <div class="row"><div class="k">Timestamp Source</div><div class="v" id="timestamp_source">--</div></div>
        <div class="row"><div class="k">Reading Status</div><div class="v" id="sensor_status">--</div></div>
        <div class="row"><div class="k">Wake Cause</div><div class="v" id="wake_cause_name">--</div></div>
        <div class="row"><div class="k">Reset Reason</div><div class="v" id="reset_reason_name">--</div></div>
        <div class="row"><div class="k">Last Failure</div><div class="v" id="last_fail">--</div></div>
        <div class="row"><div class="k">Last Failure Cycle</div><div class="v" id="last_fail_cycle">--</div></div>
        <div class="row"><div class="k">Battery</div><div class="v" id="battery">--</div></div>
        <div class="row"><div class="k">Battery Status</div><div class="v" id="battery_status">--</div></div>
        <div class="muted">Auto-refreshes every 10 seconds.</div>
    </div>
    <script>
        const fields = [
            "timestamp", "timestamp_source", "sensor_status",
            "wake_cause_name", "reset_reason_name",
            "last_fail", "last_fail_cycle",
            "battery", "battery_status"
        ];

        function setValue(id, val) {
            const el = document.getElementById(id);
            if (!el) return;
            el.textContent = (val === null || val === undefined || val === "") ? "--" : String(val);
        }

        async function refreshDebug() {
            try {
                const response = await fetch("/api/debug");
                if (!response.ok) {
                    fields.forEach(id => setValue(id, "--"));
                    return;
                }
                const data = await response.json();
                fields.forEach(id => setValue(id, data[id]));
            } catch (_) {
                fields.forEach(id => setValue(id, "--"));
            }
        }

        refreshDebug();
        setInterval(refreshDebug, 10000);
    </script>
</body>
</html>
"""

@app.route("/")
@require_auth
def index():
    return render_template("landing.html")


@app.route("/soil")
@require_auth
def soil_dashboard():
    return render_template_string(TEMPLATE)


@app.route("/baby")
@require_auth
def baby_dashboard():
    return render_template("baby.html")

@app.route("/debug-view")
@require_auth
def debug_view():
    return render_template_string(DEBUG_TEMPLATE)

if __name__ == "__main__":
    # Migrate existing JSON data to database
    def migrate_json_data():
        if os.path.exists(LOG_DIR):
            for filename in os.listdir(LOG_DIR):
                if filename.endswith('.json'):
                    filepath = os.path.join(LOG_DIR, filename)
                    try:
                        with open(filepath, 'r') as f:
                            data = json.load(f)
                            for entry in data:
                                data_manager.add_reading(
                                    entry.get('t1'),
                                    entry.get('t2'),
                                    entry.get('t3'),
                                    entry.get('battery'),
                                    entry.get('battery_status')
                                )
                        print(f"Migrated data from {filename}")
                    except Exception as e:
                        print(f"Error migrating {filename}: {e}")

    # Run migration in background
    migration_thread = threading.Thread(target=migrate_json_data)
    migration_thread.daemon = True
    migration_thread.start()

    debug_mode = os.environ.get("SOIL_MONITOR_DEBUG", "0") == "1"
    app.run(host="0.0.0.0", port=5050, debug=debug_mode)
