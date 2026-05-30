"""add strength log entries

Revision ID: f6a7b8c9d0e1
Revises: e5f6a7b8c9d0
Create Date: 2026-05-30 18:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


revision = "f6a7b8c9d0e1"
down_revision = "e5f6a7b8c9d0"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "strength_log_entry",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("client_id", sa.Integer(), nullable=False),
        sa.Column("source", sa.String(length=30), nullable=False),
        sa.Column("workout_title", sa.String(length=120), nullable=True),
        sa.Column("logged_at", sa.DateTime(), nullable=False),
        sa.Column("exercise", sa.String(length=160), nullable=False),
        sa.Column("weight", sa.Float(), nullable=True),
        sa.Column("reps", sa.Integer(), nullable=True),
        sa.Column("rir_rpe", sa.String(length=20), nullable=True),
        sa.Column("duration", sa.String(length=20), nullable=True),
        sa.Column("set_type", sa.String(length=30), nullable=True),
        sa.Column("source_file", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["client_id"], ["client.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_strength_log_entry_client_id"), "strength_log_entry", ["client_id"], unique=False)
    op.create_index(op.f("ix_strength_log_entry_exercise"), "strength_log_entry", ["exercise"], unique=False)
    op.create_index(op.f("ix_strength_log_entry_logged_at"), "strength_log_entry", ["logged_at"], unique=False)


def downgrade():
    op.drop_index(op.f("ix_strength_log_entry_logged_at"), table_name="strength_log_entry")
    op.drop_index(op.f("ix_strength_log_entry_exercise"), table_name="strength_log_entry")
    op.drop_index(op.f("ix_strength_log_entry_client_id"), table_name="strength_log_entry")
    op.drop_table("strength_log_entry")
