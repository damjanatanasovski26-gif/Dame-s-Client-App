"""add login throttle table

Revision ID: 5d9d3bc4fa1b
Revises: 22d64b22b993
Create Date: 2026-02-17 12:20:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "5d9d3bc4fa1b"
down_revision = "22d64b22b993"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "login_throttle",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("key", sa.String(length=255), nullable=False),
        sa.Column("count", sa.Integer(), nullable=False),
        sa.Column("first_ts", sa.DateTime(), nullable=False),
        sa.Column("lock_until", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("key"),
    )
    op.create_index(op.f("ix_login_throttle_key"), "login_throttle", ["key"], unique=False)


def downgrade():
    op.drop_index(op.f("ix_login_throttle_key"), table_name="login_throttle")
    op.drop_table("login_throttle")

