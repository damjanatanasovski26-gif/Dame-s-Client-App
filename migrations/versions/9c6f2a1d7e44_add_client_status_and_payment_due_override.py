"""add client status and payment due override

Revision ID: 9c6f2a1d7e44
Revises: b7f2c1aa9e31
Create Date: 2026-03-21 12:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "9c6f2a1d7e44"
down_revision = "b7f2c1aa9e31"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("client", schema=None) as batch_op:
        batch_op.add_column(sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()))

    with op.batch_alter_table("client", schema=None) as batch_op:
        batch_op.alter_column("is_active", server_default=None)

    with op.batch_alter_table("payment", schema=None) as batch_op:
        batch_op.add_column(sa.Column("due_date_override", sa.Date(), nullable=True))


def downgrade():
    with op.batch_alter_table("payment", schema=None) as batch_op:
        batch_op.drop_column("due_date_override")

    with op.batch_alter_table("client", schema=None) as batch_op:
        batch_op.drop_column("is_active")

