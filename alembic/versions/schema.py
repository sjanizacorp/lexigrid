"""Create the current LexiGrid schema. Author: Shahryar Jahangir, Aniza Inc."""
import json
from pathlib import Path

from alembic import op

revision = "lexigrid_schema"
down_revision = None
branch_labels = None
depends_on = None

SCHEMA_DIR = Path(__file__).resolve().parent


def upgrade():
    context = op.get_context()
    if context.dialect.name == "sqlite":
        for statement in json.loads((SCHEMA_DIR / "sqlite.json").read_text()):
            op.execute(statement)
        return
    if context.dialect.name != "postgresql":
        raise RuntimeError("LexiGrid supports PostgreSQL and SQLite")

    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'lexigrid_runtime') THEN
                CREATE ROLE lexigrid_runtime NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
            END IF;
        END
        $$;
    """)
    sql = (SCHEMA_DIR / "postgres.sql").read_text()
    if context.as_sql:
        context.static_output(sql)
    else:
        driver = op.get_bind().connection.driver_connection
        with driver.cursor() as cursor:
            cursor.execute(sql, prepare=False)
    op.execute("GRANT SELECT ON public.alembic_version TO lexigrid_runtime")


def downgrade():
    raise RuntimeError("LexiGrid schema downgrade is unsupported")
