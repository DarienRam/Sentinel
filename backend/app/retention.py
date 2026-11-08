"""Opt-in scheduled retention entry point. Never enabled by application startup."""
import argparse
import os
import sys
import time
from datetime import datetime, timezone

from sqlalchemy import create_engine, func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.models.scan import Scan
from app.services.retention import purge_expired_batch


def main(argv=None):
    parser = argparse.ArgumentParser(description="Count expired temporary scans; deletion requires explicit approval.")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--confirm-retention-policy", action="store_true")
    parser.add_argument("--loop", action="store_true")
    parser.add_argument("--interval-seconds", type=int, default=300)
    parser.add_argument("--max-batches", type=int, default=10)
    args = parser.parse_args(argv)
    url = os.environ.get("RETENTION_DATABASE_URL")
    if not url or (args.apply and not args.confirm_retention_policy):
        parser.error("Set RETENTION_DATABASE_URL explicitly; deletion also requires --apply --confirm-retention-policy.")
    if args.interval_seconds < 60 or not 1 <= args.max_batches <= 100:
        parser.error("Use interval >=60 seconds and 1-100 batches per cycle.")
    engine = None
    try:
        engine = create_engine(url, hide_parameters=True)
        while True:
            with Session(engine) as db:
                if args.apply:
                    count = 0
                    for _ in range(args.max_batches):
                        deleted = purge_expired_batch(db)
                        count += deleted
                        if deleted < 100:
                            break
                    print(f"Retention cycle: {count} expired temporary scans deleted.", flush=True)
                else:
                    count = db.scalar(select(func.count()).select_from(Scan).where(
                        Scan.is_saved.is_(False), Scan.expires_at <= datetime.now(timezone.utc)))
                    print(f"Dry run: {count} expired temporary scans eligible; nothing deleted.", flush=True)
            if not args.loop:
                break
            time.sleep(args.interval_seconds)
    except (SQLAlchemyError, ValueError):
        print("Retention database operation failed; no sensitive details logged.", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        pass
    finally:
        if engine is not None:
            engine.dispose()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
