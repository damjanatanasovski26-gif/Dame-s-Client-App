"""add food import metadata

Revision ID: e5f6a7b8c9d0
Revises: d3c4f5a6b7c8
Create Date: 2026-03-21 13:05:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "e5f6a7b8c9d0"
down_revision = "d3c4f5a6b7c8"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("food_item", sa.Column("source_ref", sa.String(length=120), nullable=True))
    op.add_column("food_item", sa.Column("barcode", sa.String(length=64), nullable=True))


def downgrade():
    op.drop_column("food_item", "barcode")
    op.drop_column("food_item", "source_ref")
