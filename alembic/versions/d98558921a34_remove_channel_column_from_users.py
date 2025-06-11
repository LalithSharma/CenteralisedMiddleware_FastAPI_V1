"""remove channel column from users

Revision ID: d98558921a34
Revises: 2a5321a3fa5b
Create Date: 2025-05-30 16:50:55.680770

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd98558921a34'
down_revision: Union[str, None] = '2a5321a3fa5b'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.drop_column('users', 'channel')

def downgrade() -> None:
    """Downgrade schema."""
    op.add_column('users', sa.Column('channel', sa.String(), nullable=True))
