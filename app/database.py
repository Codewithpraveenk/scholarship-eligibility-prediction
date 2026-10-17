"""Small DB-API adapter: local SQLite or durable hosted PostgreSQL."""
from contextlib import contextmanager
import os
from pathlib import Path
import sqlite3


class Connection:
    def __init__(self, connection, postgres):
        self.connection = connection
        self.postgres = postgres

    def execute(self, query, parameters=()):
        if self.postgres:
            query = query.replace('?', '%s')
        return self.connection.execute(query, parameters)

    def executemany(self, query, rows):
        cursor = self.connection.cursor()
        cursor.executemany(query.replace('?', '%s') if self.postgres else query, rows)
        return cursor

    def executescript(self, script):
        if self.postgres:
            script = script.replace('id INTEGER PRIMARY KEY', 'id SERIAL PRIMARY KEY')
            script = script.replace('DEFAULT CURRENT_TIMESTAMP', "DEFAULT (to_char(CURRENT_TIMESTAMP AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS'))")
        for statement in script.split(';'):
            if statement.strip():
                self.execute(statement)

    def commit(self):
        self.connection.commit()


@contextmanager
def database():
    url = os.environ.get('DATABASE_URL', '')
    postgres = bool(url)
    if postgres:
        import psycopg
        from psycopg.rows import dict_row
        connection = psycopg.connect(url, row_factory=dict_row, connect_timeout=15,
                                    sslmode='require' if os.environ.get('APP_ENV') == 'production' else 'prefer')
    else:
        if os.environ.get('APP_ENV') == 'production':
            raise RuntimeError('Production requires a durable PostgreSQL DATABASE_URL')
        path = Path(os.environ.get('DATABASE_PATH', 'data/scholarpath.db'))
        path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(path, timeout=15)
        connection.row_factory = sqlite3.Row
        connection.execute('PRAGMA foreign_keys=ON')
    try:
        yield Connection(connection, postgres)
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
