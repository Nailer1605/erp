"""Initial migration.

Revision ID: 21e113141ae2
Revises: 
Create Date: 2023-09-30 11:27:10.012757

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = '21e113141ae2'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('user',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('username', sa.String(length=80), nullable=False),
    sa.Column('email', sa.String(length=120), nullable=False),
    sa.Column('password', sa.String(length=120), nullable=False),
    sa.Column('role', sa.String(length=80), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('email'),
    sa.UniqueConstraint('username')
    )
    op.drop_table('products')
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_index('email')

    op.drop_table('users')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('users',
    sa.Column('id', mysql.INTEGER(), autoincrement=True, nullable=False),
    sa.Column('username', mysql.VARCHAR(collation='utf8mb4_general_ci', length=80), nullable=False),
    sa.Column('email', mysql.VARCHAR(collation='utf8mb4_general_ci', length=120), nullable=False),
    sa.Column('password', mysql.VARCHAR(collation='utf8mb4_general_ci', length=120), nullable=False),
    sa.Column('role', mysql.VARCHAR(collation='utf8mb4_general_ci', length=80), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    mysql_collate='utf8mb4_general_ci',
    mysql_default_charset='utf8mb4',
    mysql_engine='InnoDB'
    )
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.create_index('email', ['email'], unique=False)

    op.create_table('products',
    sa.Column('id', mysql.INTEGER(), autoincrement=True, nullable=False),
    sa.Column('name', mysql.VARCHAR(collation='utf8mb4_general_ci', length=80), nullable=False),
    sa.Column('description', mysql.TEXT(collation='utf8mb4_general_ci'), nullable=False),
    sa.Column('price', mysql.FLOAT(), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    mysql_collate='utf8mb4_general_ci',
    mysql_default_charset='utf8mb4',
    mysql_engine='InnoDB'
    )
    op.drop_table('user')
    # ### end Alembic commands ###
