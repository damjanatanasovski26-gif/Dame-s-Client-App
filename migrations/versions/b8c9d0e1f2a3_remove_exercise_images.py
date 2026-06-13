"""remove exercise image table

Revision ID: b8c9d0e1f2a3
Revises: a7b8c9d0e1f2
Create Date: 2026-06-13 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


revision = "b8c9d0e1f2a3"
down_revision = "a7b8c9d0e1f2"
branch_labels = None
depends_on = None


def _table_exists(table_name: str) -> bool:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    return table_name in inspector.get_table_names()


def upgrade():
    if _table_exists("exercise_image"):
        op.drop_index(op.f("ix_exercise_image_exercise_name"), table_name="exercise_image")
        op.drop_table("exercise_image")


def downgrade():
    if not _table_exists("exercise_image"):
        op.create_table(
            "exercise_image",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("exercise_name", sa.String(length=160), nullable=False),
            sa.Column("matched_name", sa.String(length=160), nullable=True),
            sa.Column("source", sa.String(length=30), nullable=False),
            sa.Column("source_ref", sa.String(length=120), nullable=True),
            sa.Column("image_url", sa.String(length=600), nullable=True),
            sa.Column("local_file", sa.String(length=255), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("exercise_name"),
        )
        op.create_index(op.f("ix_exercise_image_exercise_name"), "exercise_image", ["exercise_name"], unique=True)
