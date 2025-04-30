"""Ensure unique email in Employee table.

Revision ID: 5c8a368dd81c
Revises:
Create Date: 2025-03-11 16:41:03.732975
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '5c8a368dd81c'
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    with op.batch_alter_table("employee", schema=None) as batch_op:
        batch_op.create_unique_constraint("uq_employee_email", ["email"])

def downgrade():
    with op.batch_alter_table("employee", schema=None) as batch_op:
        batch_op.drop_constraint("uq_employee_email", type_="unique")
