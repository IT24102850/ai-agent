"""Add human identity/RBAC and tamper-evident audit foundations."""

from alembic import op
import sqlalchemy as sa

revision = "20261118_02"
down_revision = "20261118_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "human_users",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("display_name", sa.String(255), nullable=False),
        sa.Column("email_normalized", sa.String(320), nullable=False),
        sa.Column("password_hash", sa.Text(), nullable=True),
        sa.Column("role", sa.String(32), nullable=False),
        sa.Column("mfa_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("status", sa.String(32), nullable=False, server_default="active"),
        sa.Column("created_at", sa.String(64), nullable=False),
        sa.UniqueConstraint("tenant_id", "email_normalized", name="uq_human_users_tenant_email"),
    )
    op.add_column("audit_log", sa.Column("previous_hash", sa.String(64), nullable=False, server_default=""))
    op.add_column("audit_log", sa.Column("hash", sa.String(64), nullable=False, server_default=""))
    op.create_index("human_users_tenant_role_idx", "human_users", ["tenant_id", "role"])


def downgrade() -> None:
    op.drop_index("human_users_tenant_role_idx", table_name="human_users")
    op.drop_table("human_users")
    op.drop_column("audit_log", "hash")
    op.drop_column("audit_log", "previous_hash")
