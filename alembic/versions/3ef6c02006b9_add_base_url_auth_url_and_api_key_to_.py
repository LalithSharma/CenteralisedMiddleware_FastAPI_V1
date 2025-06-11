"""Add base_url, auth_url, and api_key to channels

Revision ID: 3ef6c02006b9
Revises: a860a720a5dc
Create Date: 2025-06-06 13:10:06.235749

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '3ef6c02006b9'
down_revision: Union[str, None] = 'a860a720a5dc'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('channels', sa.Column('base_url', sa.String(), nullable=True))
    op.add_column('channels', sa.Column('auth_url', sa.String(), nullable=True))
    op.add_column('channels', sa.Column('api_key', sa.String(), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('channels', 'base_url')
    op.drop_column('channels', 'auth_url')
    op.drop_column('channels', 'api_key')
