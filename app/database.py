import os
import sqlite3
from typing import Any, List, Optional
from dotenv import load_dotenv

load_dotenv()

TURSO_URL = os.getenv("TURSO_DATABASE_URL", "").strip()
TURSO_TOKEN = os.getenv("TURSO_AUTH_TOKEN", "").strip()
LOCAL_DB_PATH = os.getenv("LOCAL_DB_PATH", "vilco_licenses.db")


class LibSQLRow(dict):
    """Permite acceso tanto por nombre de columna row['col'] como por índice row[0]."""
    def __init__(self, columns: List[str], values: tuple):
        super().__init__(zip(columns, values))
        self._values = values

    def __getitem__(self, key: Any) -> Any:
        if isinstance(key, int):
            return self._values[key]
        return super().__getitem__(key)


class LibSQLCursorWrapper:
    def __init__(self, cursor):
        self._cursor = cursor

    @property
    def lastrowid(self):
        return getattr(self._cursor, "lastrowid", None)

    @property
    def rowcount(self):
        return getattr(self._cursor, "rowcount", -1)

    def execute(self, sql: str, params: tuple = ()):
        self._cursor.execute(sql, params)
        return self

    def _wrap_row(self, row) -> Optional[LibSQLRow]:
        if row is None:
            return None
        if isinstance(row, sqlite3.Row):
            return LibSQLRow(list(row.keys()), tuple(row))
        cols = [desc[0] for desc in (self._cursor.description or [])]
        return LibSQLRow(cols, tuple(row))

    def fetchone(self) -> Optional[LibSQLRow]:
        return self._wrap_row(self._cursor.fetchone())

    def fetchall(self) -> List[LibSQLRow]:
        rows = self._cursor.fetchall()
        if not rows:
            return []
        cols = [desc[0] for desc in (self._cursor.description or [])]
        result = []
        for r in rows:
            if isinstance(r, sqlite3.Row):
                result.append(LibSQLRow(list(r.keys()), tuple(r)))
            else:
                result.append(LibSQLRow(cols, tuple(r)))
        return result


class LibSQLConnectionWrapper:
    def __init__(self, conn, is_turso: bool = False):
        self._conn = conn
        self._is_turso = is_turso

    def cursor(self) -> LibSQLCursorWrapper:
        return LibSQLCursorWrapper(self._conn.cursor())

    def execute(self, sql: str, params: tuple = ()) -> LibSQLCursorWrapper:
        cur = self.cursor()
        cur.execute(sql, params)
        return cur

    def commit(self):
        self._conn.commit()
        if self._is_turso and hasattr(self._conn, "sync"):
            self._conn.sync()

    def close(self):
        self._conn.close()


def get_db() -> LibSQLConnectionWrapper:
    if TURSO_URL and TURSO_TOKEN:
        import libsql_experimental as libsql
        conn = libsql.connect(database=TURSO_URL, auth_token=TURSO_TOKEN)
        return LibSQLConnectionWrapper(conn, is_turso=True)

    conn = sqlite3.connect(LOCAL_DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 30000")
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return LibSQLConnectionWrapper(conn, is_turso=False)


def init_db():
    """Inicialización no destructiva de tablas y semillas base."""
    from app.security import hash_password

    db = get_db()
    try:
        statements = [
            """
            CREATE TABLE IF NOT EXISTS config_params (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('admin', 'auditor')),
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS apps (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                app_code TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                description TEXT DEFAULT '',
                active INTEGER DEFAULT 1,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS licenses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                license_key TEXT UNIQUE NOT NULL,
                app_code TEXT NOT NULL,
                customer_name TEXT NOT NULL,
                customer_email TEXT DEFAULT '',
                max_devices INTEGER NOT NULL DEFAULT 2,
                status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK(status IN ('ACTIVE', 'SUSPENDED', 'REVOKED')),
                expires_at TEXT DEFAULT NULL,
                notes TEXT DEFAULT '',
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (app_code) REFERENCES apps(app_code)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                license_id INTEGER NOT NULL,
                device_fingerprint TEXT NOT NULL,
                device_name TEXT DEFAULT 'Desconocido',
                platform TEXT DEFAULT 'android',
                app_version TEXT DEFAULT '1.0.0',
                status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK(status IN ('ACTIVE', 'REVOKED')),
                activated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                last_seen_at TEXT DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(license_id, device_fingerprint),
                FOREIGN KEY (license_id) REFERENCES licenses(id)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS releases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                app_code TEXT NOT NULL,
                platform TEXT NOT NULL CHECK(platform IN ('android', 'windows', 'ios', 'linux')),
                version TEXT NOT NULL,
                build_number INTEGER NOT NULL,
                download_url TEXT NOT NULL,
                sha256_hash TEXT NOT NULL,
                changelog TEXT DEFAULT '',
                force_update INTEGER DEFAULT 0,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(app_code, platform, build_number),
                FOREIGN KEY (app_code) REFERENCES apps(app_code)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                detail TEXT DEFAULT '',
                ip_address TEXT DEFAULT '',
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
            """
        ]
        for stmt in statements:
            db.execute(stmt)

        db.execute(
            "INSERT OR IGNORE INTO config_params (key, value) VALUES (?, ?)",
            ("brand_name", "@VilcoSystem")
        )
        db.execute(
            "INSERT OR IGNORE INTO config_params (key, value) VALUES (?, ?)",
            ("hub_version", "1.0.0")
        )

        db.execute(
            "INSERT OR IGNORE INTO apps (app_code, name, description) VALUES (?, ?, ?)",
            ("AEGIS_VAULT", "AegisVault", "Gestor de contraseñas, 2FA y bóveda cifrada multiplataforma")
        )

        admin_pwd = os.getenv("ADMIN_INIT_PASSWORD", "AdminVilco2026!")
        auditor_pwd = os.getenv("AUDITOR_INIT_PASSWORD", "AuditorVilco2026!")

        if not db.execute("SELECT id FROM users WHERE username = ?", ("admin",)).fetchone():
            db.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                ("admin", hash_password(admin_pwd), "admin")
            )
        if not db.execute("SELECT id FROM users WHERE username = ?", ("auditor",)).fetchone():
            db.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                ("auditor", hash_password(auditor_pwd), "auditor")
            )

        db.commit()
    finally:
        db.close()
