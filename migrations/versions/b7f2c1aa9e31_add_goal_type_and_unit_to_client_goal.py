"""add goal type and unit to client_goal

Revision ID: b7f2c1aa9e31
Revises: a4d1b6c97e22
Create Date: 2026-02-18 03:10:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "b7f2c1aa9e31"
down_revision = "a4d1b6c97e22"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("client_goal", schema=None) as batch_op:
        batch_op.add_column(sa.Column("goal_type", sa.String(length=20), nullable=False, server_default="custom"))
        batch_op.add_column(sa.Column("unit", sa.String(length=20), nullable=True))

    with op.batch_alter_table("client_goal", schema=None) as batch_op:
        batch_op.alter_column("goal_type", server_default=None)


def downgrade():
    with op.batch_alter_table("client_goal", schema=None) as batch_op:
        batch_op.drop_column("unit")
        batch_op.drop_column("goal_type")

