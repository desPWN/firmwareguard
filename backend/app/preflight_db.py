"""Database preflight verification script for FirmwareGuard.

Verifies connectivity to the configured PostgreSQL database and provisions
the target role or database if missing on a freshly initialized cluster.
"""

import asyncio
import logging
import re
from urllib.parse import urlparse

import asyncpg

from app.config import get_settings

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("firmwareguard.preflight_db")


def _quote_ident(ident: str) -> str:
    """Safely quote a SQL identifier in PostgreSQL, escaping embedded double-quotes."""
    escaped = ident.replace('"', '""')
    return f'"{escaped}"'


def _parse_db_url(raw_url: str) -> dict:
    cleaned = re.sub(r"^postgresql\+asyncpg://", "postgresql://", raw_url)
    parsed = urlparse(cleaned)
    return {
        "user": parsed.username or "firmwareguard",
        "password": parsed.password or "firmwareguard",
        "host": parsed.hostname or "localhost",
        "port": parsed.port or 5432,
        "database": parsed.path.lstrip("/") or "firmwareguard",
    }


async def _try_connect(params: dict) -> bool:
    try:
        conn = await asyncpg.connect(
            user=params["user"],
            password=params["password"],
            host=params["host"],
            port=params["port"],
            database=params["database"],
            timeout=5,
        )
        await conn.execute("SELECT 1")
        await conn.close()
        return True
    except Exception as exc:
        logger.debug("Test connection to %s failed: %s", params["database"], exc)
        return False


async def run_preflight() -> None:
    settings = get_settings()
    params = _parse_db_url(settings.database_url)

    logger.info(
        "Checking database connectivity to '%s' on %s:%s...",
        params["database"],
        params["host"],
        params["port"],
    )

    if await _try_connect(params):
        logger.info("Database '%s' is reachable and credentials are valid.", params["database"])
        return

    logger.warning(
        "Could not connect directly to '%s' with user '%s'. Checking maintenance database...",
        params["database"],
        params["user"],
    )

    admin_candidates = [
        {"user": params["user"], "password": params["password"], "db": "postgres"},
        {"user": "postgres", "password": "postgres", "db": "postgres"},
        {"user": params["user"], "password": params["password"], "db": "template1"},
        {"user": "postgres", "password": "postgres", "db": "template1"},
    ]

    admin_conn = None
    for cand in admin_candidates:
        try:
            admin_conn = await asyncpg.connect(
                user=cand["user"],
                password=cand["password"],
                host=params["host"],
                port=params["port"],
                database=cand["db"],
                timeout=5,
            )
            logger.info("Connected to maintenance database '%s' using role '%s'.", cand["db"], cand["user"])
            break
        except Exception:
            continue

    if not admin_conn:
        logger.error(
            "Could not connect using maintenance credentials. Proceeding and letting Alembic report status."
        )
        return

    try:
        target_user = params["user"]
        target_password = params["password"].replace("'", "''")
        target_user_ident = _quote_ident(target_user)

        role_exists = await admin_conn.fetchval(
            "SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = $1", target_user
        )
        if not role_exists:
            logger.info("Creating role '%s'...", target_user)
            await admin_conn.execute(
                f"CREATE ROLE {target_user_ident} WITH LOGIN SUPERUSER PASSWORD '{target_password}'"
            )

        target_db = params["database"]
        target_db_ident = _quote_ident(target_db)

        target_db_exists = await admin_conn.fetchval(
            "SELECT 1 FROM pg_catalog.pg_database WHERE datname = $1", target_db
        )
        if not target_db_exists:
            logger.info("Creating database '%s'...", target_db)
            await admin_conn.execute(f"CREATE DATABASE {target_db_ident} OWNER {target_user_ident}")
    finally:
        await admin_conn.close()

    if await _try_connect(params):
        logger.info("Preflight succeeded: '%s' is online and ready.", params["database"])
    else:
        logger.warning("Preflight completed, but direct connection check did not succeed. Continuing.")


def main() -> None:
    asyncio.run(run_preflight())


if __name__ == "__main__":
    main()
