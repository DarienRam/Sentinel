from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class Scan(Base):
    __tablename__ = "scans"
    __table_args__ = (
        Index("ix_scans_user_created", "user_id", "created_at", "id"),
        Index("ix_scans_anon_created", "anonymous_session_id", "created_at", "id"),
        Index("ix_scans_expiry", "is_saved", "expires_at", "id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    anonymous_session_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    input_type: Mapped[str] = mapped_column(String(20), nullable=False)
    raw_content: Mapped[str] = mapped_column(Text, nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    confidence_score: Mapped[int] = mapped_column(Integer, nullable=False)
    risk_level: Mapped[str] = mapped_column(String(20), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    recommendation: Mapped[str] = mapped_column(Text, nullable=False)
    is_saved: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    expires_at: Mapped[DateTime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    created_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    findings: Mapped[list["ScanFinding"]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
        order_by="ScanFinding.id",
    )
    categories: Mapped[list["ScanCategory"]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
        order_by="ScanCategory.id",
    )
    feedback: Mapped["ScanFeedback | None"] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
        uselist=False,
    )


class ScanFinding(Base):
    __tablename__ = "scan_findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), nullable=False, index=True)
    category: Mapped[str] = mapped_column(String(80), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    matched_text: Mapped[str | None] = mapped_column(Text, nullable=True)

    scan: Mapped[Scan] = relationship(back_populates="findings")


class ScanCategory(Base):
    __tablename__ = "scan_categories"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(80), nullable=False)

    scan: Mapped[Scan] = relationship(back_populates="categories")


class ScanFeedback(Base):
    __tablename__ = "scan_feedback"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), unique=True, nullable=False)
    label: Mapped[str] = mapped_column(String(30), nullable=False)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    scan: Mapped[Scan] = relationship(back_populates="feedback")
