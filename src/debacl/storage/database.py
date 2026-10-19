"""
SQLAlchemy engine and session management.

@decision DEC-STORE-001
@title SQLite via SQLAlchemy — zero infrastructure, migration path to Postgres
@status accepted
@rationale get_engine() accepts a db_url parameter so tests can pass
           sqlite:///:memory: and production code points to a file-based DB.
           The contextmanager pattern on get_session() ensures commit-on-success
           and rollback-on-exception with deterministic resource cleanup.
"""

from collections.abc import Generator
from contextlib import contextmanager

from sqlalchemy import Engine, create_engine, inspect
from sqlalchemy.orm import Session, sessionmaker


def get_engine(db_url: str = "sqlite:///debacl.db") -> Engine:
    """Create and return a SQLAlchemy engine for the given database URL."""
    return create_engine(db_url, echo=False)


def init_db(engine: Engine) -> None:
    """Create tables and add nullable provenance columns to older SQLite databases."""
    from .tables import Base

    Base.metadata.create_all(engine)

    # create_all() does not alter existing tables. These additive nullable columns
    # preserve previously stored records and make repeated init_db() calls safe.
    if engine.dialect.name == "sqlite":
        with engine.begin() as connection:
            for table_name in ("endpoint_telemetry", "connection_events"):
                columns = {column["name"] for column in inspect(connection).get_columns(table_name)}
                if "raw_data_json" not in columns:
                    connection.exec_driver_sql(
                        f"ALTER TABLE {table_name} ADD COLUMN raw_data_json TEXT"
                    )


@contextmanager
def get_session(engine: Engine) -> Generator[Session, None, None]:
    """Yield a database session, committing on success or rolling back on error."""
    session_factory = sessionmaker(bind=engine)
    session: Session = session_factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
