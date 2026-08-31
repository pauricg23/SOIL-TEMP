#!/usr/bin/env python3
import argparse
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


def create_backup(database_path, output_directory, keep):
    database = Path(database_path).resolve()
    output = Path(output_directory).resolve()
    output.mkdir(parents=True, exist_ok=True)

    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    destination = output / f"temperature_data-{stamp}.db"
    temporary = output / f".{destination.name}.tmp"

    with sqlite3.connect(database) as source, sqlite3.connect(temporary) as target:
        source.backup(target)
    os.replace(temporary, destination)

    backups = sorted(output.glob("temperature_data-*.db"), key=lambda path: path.stat().st_mtime)
    for stale_backup in backups[:-keep]:
        stale_backup.unlink()
    return destination


def main():
    parser = argparse.ArgumentParser(description="Create a safe SQLite backup")
    parser.add_argument("--database", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--keep", type=int, default=30)
    args = parser.parse_args()
    destination = create_backup(args.database, args.output_dir, max(1, args.keep))
    print(destination)


if __name__ == "__main__":
    main()
