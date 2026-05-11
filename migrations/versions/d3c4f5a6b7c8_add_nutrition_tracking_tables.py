"""add nutrition tracking tables

Revision ID: d3c4f5a6b7c8
Revises: 9c6f2a1d7e44
Create Date: 2026-03-21 12:15:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "d3c4f5a6b7c8"
down_revision = "9c6f2a1d7e44"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("client", sa.Column("daily_calorie_target", sa.Integer(), nullable=True))

    op.create_table(
        "food_item",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("client_id", sa.Integer(), nullable=True),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("brand", sa.String(length=120), nullable=True),
        sa.Column("serving_label", sa.String(length=80), nullable=True),
        sa.Column("source", sa.String(length=30), nullable=False),
        sa.Column("calories_per_100g", sa.Float(), nullable=False),
        sa.Column("protein_per_100g", sa.Float(), nullable=False),
        sa.Column("carbs_per_100g", sa.Float(), nullable=False),
        sa.Column("fat_per_100g", sa.Float(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["client_id"], ["client.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_food_item_client_id"), "food_item", ["client_id"], unique=False)

    op.create_table(
        "food_log_entry",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("client_id", sa.Integer(), nullable=False),
        sa.Column("food_id", sa.Integer(), nullable=False),
        sa.Column("logged_for", sa.Date(), nullable=False),
        sa.Column("meal_type", sa.String(length=20), nullable=False),
        sa.Column("quantity_grams", sa.Float(), nullable=False),
        sa.Column("food_name", sa.String(length=160), nullable=False),
        sa.Column("calories", sa.Float(), nullable=False),
        sa.Column("protein", sa.Float(), nullable=False),
        sa.Column("carbs", sa.Float(), nullable=False),
        sa.Column("fat", sa.Float(), nullable=False),
        sa.Column("note", sa.String(length=200), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["client_id"], ["client.id"]),
        sa.ForeignKeyConstraint(["food_id"], ["food_item.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_food_log_entry_client_id"), "food_log_entry", ["client_id"], unique=False)
    op.create_index(op.f("ix_food_log_entry_food_id"), "food_log_entry", ["food_id"], unique=False)
    op.create_index(op.f("ix_food_log_entry_logged_for"), "food_log_entry", ["logged_for"], unique=False)


def downgrade():
    op.drop_index(op.f("ix_food_log_entry_logged_for"), table_name="food_log_entry")
    op.drop_index(op.f("ix_food_log_entry_food_id"), table_name="food_log_entry")
    op.drop_index(op.f("ix_food_log_entry_client_id"), table_name="food_log_entry")
    op.drop_table("food_log_entry")

    op.drop_index(op.f("ix_food_item_client_id"), table_name="food_item")
    op.drop_table("food_item")

    op.drop_column("client", "daily_calorie_target")
