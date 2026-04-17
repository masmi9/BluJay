import asyncio
from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from config import settings

import structlog

logger = structlog.get_logger()


class Base(DeclarativeBase):
    pass


engine = create_async_engine(
    settings.db_url,
    echo=False,
    connect_args={"check_same_thread": False},
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


def _run_migrations_sync() -> None:
    """Run all pending Alembic migrations synchronously.

    Called once at startup (inside run_in_executor so the event loop is not
    blocked). Uses a plain sqlite+pysqlite connection — no aiosqlite needed
    for migration time.
    """
    from alembic.config import Config
    from alembic import command

    ini_path = Path(__file__).parent / "alembic.ini"
    cfg = Config(str(ini_path))
    command.upgrade(cfg, "head")


async def init_db() -> None:
    """Apply any pending migrations and ensure the DB is up to date."""
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, _run_migrations_sync)
    logger.info("Database migrations applied")


async def get_db() -> AsyncSession:
    async with AsyncSessionLocal() as session:
        yield session
