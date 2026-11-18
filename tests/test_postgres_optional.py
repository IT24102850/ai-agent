import asyncio
import os

import pytest

from api.app.persistence import to_async_url


def test_async_postgres_url_conversion():
    assert to_async_url("postgresql://db/app") == "postgresql+asyncpg://db/app"
    assert to_async_url("postgresql+asyncpg://db/app") == "postgresql+asyncpg://db/app"
    with pytest.raises(ValueError):
        to_async_url("sqlite:///test.db")


@pytest.mark.skipif(
    not os.getenv("AGENTBLACKBOX_TEST_POSTGRES_URL"),
    reason="PostgreSQL integration URL not configured",
)
def test_postgresql_async_engine_available():
    from sqlalchemy import text

    from api.app.persistence import create_async_database

    async def run():
        engine, _ = create_async_database(os.environ["AGENTBLACKBOX_TEST_POSTGRES_URL"])
        async with engine.connect() as connection:
            assert (await connection.execute(text("SELECT 1"))).scalar_one() == 1
        await engine.dispose()

    asyncio.run(run())
