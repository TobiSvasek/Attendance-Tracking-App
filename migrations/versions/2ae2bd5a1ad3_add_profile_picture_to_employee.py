"""Add profile_picture to Employee

Revision ID: 2ae2bd5a1ad3
Revises: 5c8a368dd81c
Create Date: 2025-04-21 14:47:52.357854

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '2ae2bd5a1ad3'
down_revision = '5c8a368dd81c'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('employee', schema=None) as batch_op:
        batch_op.add_column(sa.Column('profile_picture', sa.String(length=255), nullable=True))
        batch_op.alter_column('name',
               existing_type=sa.VARCHAR(length=100),
               nullable=True)
        batch_op.alter_column('surname',
               existing_type=sa.VARCHAR(length=100),
               nullable=True)
        batch_op.create_unique_constraint("uq_employee_uid", ['uid'])  # ✅ pojmenuj constraint



def downgrade():
    with op.batch_alter_table('employee', schema=None) as batch_op:
        batch_op.drop_constraint('uq_employee_uid', type_='unique')  # 🛠 stejné jméno jako výše
        batch_op.alter_column('surname',
               existing_type=sa.VARCHAR(length=100),
               nullable=False)
        batch_op.alter_column('name',
               existing_type=sa.VARCHAR(length=100),
               nullable=False)
        batch_op.drop_column('profile_picture')

    op.create_table('valid_nfc',
        sa.Column('id', sa.INTEGER(), nullable=False),
        sa.Column('nfc_name', sa.VARCHAR(length=50), nullable=False),
        sa.Column('token', sa.VARCHAR(length=100), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('nfc_name'),
        sa.UniqueConstraint('token')
    )

