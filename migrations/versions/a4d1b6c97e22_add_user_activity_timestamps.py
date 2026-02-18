"""add user activity timestamps

Revision ID: a4d1b6c97e22
Revises: f2ab9d4e71c0
Create Date: 2026-02-18 02:10:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "a4d1b6c97e22"
down_revision = "f2ab9d4e71c0"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("user", schema=None) as batch_op:
        batch_op.add_column(sa.Column("last_login_at", sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column("last_seen_at", sa.DateTime(), nullable=True))


def downgrade():
    with op.batch_alter_table("user", schema=None) as batch_op:
        batch_op.drop_column("last_seen_at")
        batch_op.drop_column("last_login_at")

