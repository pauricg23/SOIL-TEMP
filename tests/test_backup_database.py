import sqlite3
import tempfile
import unittest
from pathlib import Path

from scripts.backup_database import create_backup


class DatabaseBackupTest(unittest.TestCase):
    def test_backup_contains_committed_data(self):
        with tempfile.TemporaryDirectory(prefix="soil-backup-test-") as directory:
            root = Path(directory)
            database = root / "source.db"
            output = root / "backups"
            with sqlite3.connect(database) as conn:
                conn.execute("CREATE TABLE readings (value INTEGER)")
                conn.execute("INSERT INTO readings VALUES (42)")

            backup = create_backup(database, output, keep=30)
            with sqlite3.connect(backup) as conn:
                value = conn.execute("SELECT value FROM readings").fetchone()[0]
            self.assertEqual(value, 42)


if __name__ == "__main__":
    unittest.main()
