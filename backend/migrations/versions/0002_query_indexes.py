"""Owner/history, expiry and child lookup indexes; no record rewrites."""
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None
INDEXES = (
    ("ix_scans_user_created", "scans", ["user_id", "created_at", "id"]),
    ("ix_scans_anon_created", "scans", ["anonymous_session_id", "created_at", "id"]),
    ("ix_scans_expiry", "scans", ["is_saved", "expires_at", "id"]),
    ("ix_scan_findings_scan_id", "scan_findings", ["scan_id"]),
    ("ix_scan_categories_scan_id", "scan_categories", ["scan_id"]),
)


def upgrade():
    for name, table, columns in INDEXES:
        op.create_index(name, table, columns)


def downgrade():
    for name, table, _ in reversed(INDEXES):
        op.drop_index(name, table_name=table)
