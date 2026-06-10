"""add exercise images

Revision ID: a7b8c9d0e1f2
Revises: f6a7b8c9d0e1
Create Date: 2026-06-10 12:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


revision = "a7b8c9d0e1f2"
down_revision = "f6a7b8c9d0e1"
branch_labels = None
depends_on = None


def upgrade():
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


def downgrade():
    op.drop_index(op.f("ix_exercise_image_exercise_name"), table_name="exercise_image")
    op.drop_table("exercise_image")
