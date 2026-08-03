"""
Async SQLAlchemy engine + session factory.

For a government-scale deployment, swap DATABASE_URL to PostgreSQL
(e.g. postgresql+asyncpg://malinfo:***@db-host/malinfo) — SQLite is fine
for a pilot / single-node deployment but will not hold up under concurrent
write load from many simultaneous analyses.
"""
from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.config import settings

engine = create_async_engine(settings.DATABASE_URL, echo=settings.DEBUG, future=True)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


class Base(DeclarativeBase):
    pass


async def get_db() -> AsyncSession:
    async with AsyncSessionLocal() as session:
        yield session


async def init_db() -> None:
    """Create tables on startup. Use Alembic migrations in production."""
    async with engine.begin() as conn:
        from app import models  # noqa: F401  (register models on Base.metadata)
        await conn.run_sync(Base.metadata.create_all)
