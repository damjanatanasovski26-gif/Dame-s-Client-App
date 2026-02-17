"""add appointments photos goals

Revision ID: f2ab9d4e71c0
Revises: c1b7a2d913ef
Create Date: 2026-02-17 17:10:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "f2ab9d4e71c0"
down_revision = "c1b7a2d913ef"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "appointment",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("client_id", sa.Integer(), nullable=False),
        sa.Column("scheduled_for", sa.DateTime(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("note", sa.String(length=200), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("created_by_role", sa.String(length=20), nullable=False),
        sa.ForeignKeyConstraint(["client_id"], ["client.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_appointment_client_id"), "appointment", ["client_id"], unique=False)

    op.create_table(
        "progress_photo",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("client_id", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("file_name", sa.String(length=255), nullable=False),
        sa.Column("note", sa.String(length=200), nullable=True),
        sa.Column("uploaded_by_role", sa.String(length=20), nullable=False),
        sa.ForeignKeyConstraint(["client_id"], ["client.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_progress_photo_client_id"), "progress_photo", ["client_id"], unique=False)

    op.create_table(
        "client_goal",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("client_id", sa.Integer(), nullable=False),
        sa.Column("title", sa.String(length=120), nullable=False),
        sa.Column("target_value", sa.Float(), nullable=True),
        sa.Column("current_value", sa.Float(), nullable=True),
        sa.Column("target_date", sa.Date(), nullable=True),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("note", sa.String(length=300), nullable=True),
        sa.ForeignKeyConstraint(["client_id"], ["client.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_client_goal_client_id"), "client_goal", ["client_id"], unique=False)


def downgrade():
    op.drop_index(op.f("ix_client_goal_client_id"), table_name="client_goal")
    op.drop_table("client_goal")

    op.drop_index(op.f("ix_progress_photo_client_id"), table_name="progress_photo")
    op.drop_table("progress_photo")

    op.drop_index(op.f("ix_appointment_client_id"), table_name="appointment")
    op.drop_table("appointment")

