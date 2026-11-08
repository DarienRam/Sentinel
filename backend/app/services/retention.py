"""Bounded expiry deletion, shared by request fallback and explicit worker."""
from datetime import datetime, timezone

from sqlalchemy import select

from app.models.scan import Scan


def purge_expired_batch(db, *, batch_size=100, now=None):
    if not 1 <= batch_size <= 100:
        raise ValueError("Retention batches must contain 1-100 scans.")
    cutoff = now or datetime.now(timezone.utc)
    scans = db.scalars(select(Scan).where(Scan.is_saved.is_(False), Scan.expires_at.is_not(None),
                                        Scan.expires_at <= cutoff)
                       .order_by(Scan.expires_at, Scan.id).limit(batch_size).with_for_update(skip_locked=True)).all()
    try:
        for scan in scans:
            db.delete(scan)
        db.commit()
    except BaseException:
        db.rollback()
        raise
    return len(scans)
