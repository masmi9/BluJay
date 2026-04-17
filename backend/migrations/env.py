"""
Alembic environment for BluJay.

Uses a synchronous SQLite connection for migrations (sqlite+pysqlite) even though
the runtime app uses aiosqlite. Migrations run once at startup before the async
event loop starts serving requests — sync is fine here and avoids asyncio complexity.
"""
import sys
from logging.config import fileConfig
from pathlib import Path

from alembic import context
from sqlalchemy import engine_from_config, pool

# Make sure the backend package is importable when alembic is invoked from the
# backend/ directory (e.g. `alembic upgrade head`).
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import settings so we can derive the DB path.
from config import settings  # noqa: E402

# Import Base and ALL models so their tables are registered on metadata.
from database import Base  # noqa: E402
import models.analysis      # noqa: F401, E402
import models.session       # noqa: F401, E402
import models.agent         # noqa: F401, E402
import models.owasp         # noqa: F401, E402
import models.testing       # noqa: F401, E402
import models.screenshot    # noqa: F401, E402
import models.cve           # noqa: F401, E402
import models.tls_audit     # noqa: F401, E402
import models.jwt_test      # noqa: F401, E402
import models.fuzzing       # noqa: F401, E402
import models.brute_force   # noqa: F401, E402
import models.api_testing   # noqa: F401, E402
import models.analysis_diff # noqa: F401, E402
import models.campaign      # noqa: F401, E402

# ---------------------------------------------------------------------------
# Alembic Config object (gives access to values in alembic.ini)
# ---------------------------------------------------------------------------
config = context.config

# Override sqlalchemy.url with the real DB path from settings.
# Convert aiosqlite URL → pysqlite so migrations run synchronously.
sync_url = str(settings.db_url).replace("sqlite+aiosqlite", "sqlite+pysqlite")
config.set_main_option("sqlalchemy.url", sync_url)

# Interpret the config file for Python logging.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode (emit SQL to stdout, no live connection)."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=True,   # required for SQLite ALTER TABLE support
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations against a live database connection."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=True,   # required for SQLite ALTER TABLE support
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
