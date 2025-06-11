"""drop all tables

Revision ID: a860a720a5dc
Revises: d98558921a34
Create Date: 2025-05-30 17:21:00.726607

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a860a720a5dc'
down_revision: Union[str, None] = 'd98558921a34'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.drop_table('user_tokens')
    op.drop_table('user_api')
    op.drop_table('users')


def downgrade() -> None:
    """Downgrade schema."""
    pass
