"""Frozen current schema baseline. Existing databases need reviewed adoption."""
from alembic import op
import sqlalchemy as sa

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    if set(sa.inspect(op.get_bind()).get_table_names()) & {"users", "scans", "scan_findings", "scan_categories", "scan_feedback"}:
        raise RuntimeError("Existing unversioned schema: stop for private schema review and approved baseline adoption.")
    op.create_table("users", sa.Column("id", sa.Integer, primary_key=True),
                    sa.Column("username", sa.String(50), nullable=False, unique=True),
                    sa.Column("email", sa.String(255), nullable=False, unique=True),
                    sa.Column("password_hash", sa.String(255), nullable=False),
                    sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False))
    op.create_table("scans", sa.Column("id", sa.Integer, primary_key=True),
                    sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id")),
                    sa.Column("anonymous_session_id", sa.String(128)),
                    sa.Column("input_type", sa.String(20), nullable=False),
                    sa.Column("raw_content", sa.Text, nullable=False),
                    sa.Column("risk_score", sa.Integer, nullable=False),
                    sa.Column("confidence_score", sa.Integer, nullable=False),
                    sa.Column("risk_level", sa.String(20), nullable=False),
                    sa.Column("summary", sa.Text, nullable=False),
                    sa.Column("recommendation", sa.Text, nullable=False),
                    sa.Column("is_saved", sa.Boolean, nullable=False),
                    sa.Column("expires_at", sa.DateTime(timezone=True)),
                    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()))
    op.create_table("scan_findings", sa.Column("id", sa.Integer, primary_key=True),
                    sa.Column("scan_id", sa.Integer, sa.ForeignKey("scans.id"), nullable=False),
                    sa.Column("category", sa.String(80), nullable=False),
                    sa.Column("severity", sa.String(20), nullable=False),
                    sa.Column("message", sa.Text, nullable=False), sa.Column("matched_text", sa.Text))
    op.create_table("scan_categories", sa.Column("id", sa.Integer, primary_key=True),
                    sa.Column("scan_id", sa.Integer, sa.ForeignKey("scans.id"), nullable=False),
                    sa.Column("name", sa.String(80), nullable=False))
    op.create_table("scan_feedback", sa.Column("id", sa.Integer, primary_key=True),
                    sa.Column("scan_id", sa.Integer, sa.ForeignKey("scans.id"), nullable=False, unique=True),
                    sa.Column("label", sa.String(30), nullable=False), sa.Column("note", sa.Text),
                    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
                    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()))
    for table in ("users", "scans", "scan_findings", "scan_categories", "scan_feedback"):
        op.create_index(f"ix_{table}_id", table, ["id"])
    op.create_index("ix_scans_anonymous_session_id", "scans", ["anonymous_session_id"])


def downgrade():
    # Data-destructive baseline rollback is deliberately not automated.
    raise RuntimeError("Dropping the baseline requires a separately approved recovery plan.")
