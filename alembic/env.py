"""Alembic environment.

Reads the URL from the application's own resolver so there is exactly one
place that knows how to find the database, and takes target metadata from the
ORM models so `alembic revision --autogenerate` can diff against them.
"""

from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool

from alembic import context
from netwatch.db.models import Base
from netwatch.db.session import database_url

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

config.set_main_option('sqlalchemy.url', database_url().replace('%', '%%'))
target_metadata = Base.metadata


def run_migrations_offline():
    context.configure(url=config.get_main_option('sqlalchemy.url'),
                      target_metadata=target_metadata, literal_binds=True,
                      dialect_opts={'paramstyle': 'named'},
                      compare_type=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online():
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix='sqlalchemy.', poolclass=pool.NullPool)
    with connectable.connect() as connection:
        context.configure(connection=connection,
                          target_metadata=target_metadata, compare_type=True)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
