from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from config import settings


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


async def init_db() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        # Add columns introduced after initial schema creation.
        # ALTER TABLE ADD COLUMN raises an error if the column already exists
        # in SQLite, so we check existing columns first.
        await _migrate_table(conn, "analyses", [
            ("platform",         "VARCHAR NOT NULL DEFAULT 'android'"),
            ("bundle_id",        "VARCHAR"),
            ("min_ios_version",  "VARCHAR"),
            ("ats_config_json",  "TEXT"),
        ])
        await _migrate_table(conn, "owasp_scans", [
            ("platform", "VARCHAR NOT NULL DEFAULT 'android'"),
        ])
        await _migrate_table(conn, "dynamic_sessions", [
            ("platform", "TEXT NOT NULL DEFAULT 'android'"),
        ])


async def _migrate_table(conn, table: str, new_columns: list[tuple[str, str]]) -> None:
    """Add any missing columns to a table."""
    result = await conn.execute(__import__("sqlalchemy").text(f"PRAGMA table_info({table})"))
    existing = {row[1] for row in result.fetchall()}

    for col_name, col_def in new_columns:
        if col_name not in existing:
            await conn.execute(
                __import__("sqlalchemy").text(
                    f"ALTER TABLE {table} ADD COLUMN {col_name} {col_def}"
                )
            )


# Keep old name as alias so any external callers aren't broken
async def _migrate_analyses_columns(conn) -> None:
    await _migrate_table(conn, "analyses", [
        ("platform",         "VARCHAR NOT NULL DEFAULT 'android'"),
        ("bundle_id",        "VARCHAR"),
        ("min_ios_version",  "VARCHAR"),
        ("ats_config_json",  "TEXT"),
    ])


async def get_db() -> AsyncSession:
    async with AsyncSessionLocal() as session:
        yield session
