"""add client notes table

Revision ID: c1b7a2d913ef
Revises: 8f2e6d1c4a9b
Create Date: 2026-02-17 16:10:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "c1b7a2d913ef"
down_revision = "8f2e6d1c4a9b"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "client_note",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("client_id", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("text", sa.String(length=500), nullable=False),
        sa.Column("is_private", sa.Boolean(), nullable=False),
        sa.Column("created_by_role", sa.String(length=20), nullable=False),
        sa.ForeignKeyConstraint(["client_id"], ["client.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_client_note_client_id"), "client_note", ["client_id"], unique=False)


def downgrade():
    op.drop_index(op.f("ix_client_note_client_id"), table_name="client_note")
    op.drop_table("client_note")

