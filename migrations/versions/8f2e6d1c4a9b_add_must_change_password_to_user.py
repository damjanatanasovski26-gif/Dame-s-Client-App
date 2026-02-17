"""add must_change_password to user

Revision ID: 8f2e6d1c4a9b
Revises: 5d9d3bc4fa1b
Create Date: 2026-02-17 15:30:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "8f2e6d1c4a9b"
down_revision = "5d9d3bc4fa1b"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("user", schema=None) as batch_op:
        batch_op.add_column(sa.Column("must_change_password", sa.Boolean(), nullable=False, server_default=sa.false()))

    with op.batch_alter_table("user", schema=None) as batch_op:
        batch_op.alter_column("must_change_password", server_default=None)


def downgrade():
    with op.batch_alter_table("user", schema=None) as batch_op:
        batch_op.drop_column("must_change_password")

