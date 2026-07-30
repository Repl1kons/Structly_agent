import json
import logging
import os
import subprocess
import sys
import time
from datetime import UTC, datetime
from typing import Any

import httpx


def _getenv_str(name: str, default: str = "") -> str:
    value = os.getenv(name)
    if value is None:
        return default
    value = value.strip()
    return value or default


def _getenv_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    raw = raw.strip()
    if not raw:
        return default
    return int(raw)


BACKEND_URL = _getenv_str("STRUCTLY_BACKEND_URL", "https://structly.elevo.space").rstrip("/")
AGENT_TOKEN = _getenv_str("STRUCTLY_AGENT_TOKEN")
DB_PASSWORD = _getenv_str("DB_PASSWORD")

POLL_INTERVAL_SECONDS = _getenv_int("STRUCTLY_AGENT_POLL_INTERVAL", 10)

HTTP_TIMEOUT_SECONDS = _getenv_int("STRUCTLY_AGENT_HTTP_TIMEOUT", 30)
CONNECT_TIMEOUT_SECONDS = _getenv_int("STRUCTLY_AGENT_TIMEOUT_CONNECT", 10)
QUERY_TIMEOUT_SECONDS = _getenv_int("STRUCTLY_AGENT_TIMEOUT_QUERY", 60)
DUMP_TIMEOUT_SECONDS = _getenv_int("STRUCTLY_AGENT_TIMEOUT_DUMP", 600)
LOG_MAX_VALUE_LENGTH = _getenv_int("STRUCTLY_AGENT_LOG_MAX_VALUE_LENGTH", 4000)

PG_DUMP_BIN = _getenv_str("PG_DUMP_BIN", "pg_dump")
PSQL_BIN = _getenv_str("PSQL_BIN", "psql")


logger = logging.getLogger("structly_agent")


class BackendRequestError(RuntimeError):
    def __init__(
        self,
        *,
        path: str,
        status_code: int,
        response_body: Any,
        elapsed_ms: int,
    ) -> None:
        self.path = path
        self.status_code = status_code
        self.response_body = response_body
        self.elapsed_ms = elapsed_ms
        super().__init__(f"Backend returned {status_code} for {path}")


def _utc_timestamp() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds")


def _truncate_text(value: str, max_length: int = LOG_MAX_VALUE_LENGTH) -> str:
    if len(value) <= max_length:
        return value
    omitted = len(value) - max_length
    return f"{value[:max_length]}...<truncated {omitted} chars>"


def _json_safe(value: Any) -> Any:
    if isinstance(value, str):
        return _truncate_text(value)
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [_json_safe(item) for item in value]
    if isinstance(value, int | float | bool) or value is None:
        return value
    return _truncate_text(str(value))


def _payload_summary(payload: dict[str, Any] | None) -> dict[str, Any] | None:
    if payload is None:
        return None
    summary: dict[str, Any] = {"keys": sorted(payload.keys())}
    if "databases" in payload and isinstance(payload["databases"], list):
        databases = payload["databases"]
        summary["databases_count"] = len(databases)
        summary["schemas_count"] = sum(len(item.get("schemas") or []) for item in databases if isinstance(item, dict))
    if "sql" in payload and isinstance(payload["sql"], str):
        summary["sql_length"] = len(payload["sql"])
    return summary


def _response_body(response: httpx.Response) -> Any:
    text = response.text
    if not text:
        return None
    try:
        return response.json()
    except ValueError:
        return _truncate_text(text)


def _setup_logging() -> None:
    level_name = _getenv_str("STRUCTLY_AGENT_LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)

    handler = logging.StreamHandler(sys.stdout)

    class JsonFormatter(logging.Formatter):
        def format(self, record: logging.LogRecord) -> str:
            payload: dict[str, Any] = {
                "timestamp": _utc_timestamp(),
                "level": record.levelname.lower(),
                "message": record.getMessage(),
                "logger": record.name,
                "pid": os.getpid(),
            }
            extra = getattr(record, "extra_data", None)
            if isinstance(extra, dict):
                payload.update(_json_safe(extra))

            if record.exc_info:
                payload["exception"] = self.formatException(record.exc_info)

            return json.dumps(payload, ensure_ascii=False, default=str)

    handler.setFormatter(JsonFormatter())
    logger.setLevel(level)
    logger.handlers.clear()
    logger.addHandler(handler)
    logger.propagate = False


def _log(level: int, message: str, *, exc_info: bool = False, **extra: Any) -> None:
    logger.log(level, message, extra={"extra_data": extra}, exc_info=exc_info)


def _headers() -> dict[str, str]:
    return {
        "X-Agent-Token": AGENT_TOKEN,
        "Content-Type": "application/json",
    }


def _client() -> httpx.Client:
    return httpx.Client(
        base_url=BACKEND_URL,
        headers=_headers(),
        timeout=HTTP_TIMEOUT_SECONDS,
    )

def decode(data: bytes) -> str:
    for enc in ("utf-8", "cp1251", "cp866"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            pass
    return data.decode("utf-8", errors="replace")

def _post(
    client: httpx.Client,
    path: str,
    payload: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    started = time.perf_counter()
    payload_summary = _payload_summary(payload)
    _log(logging.DEBUG, "backend_request_started", path=path, payload_summary=payload_summary)

    try:
        response = client.post(path, json=payload)
    except httpx.RequestError as exc:
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        _log(
            logging.ERROR,
            "backend_request_failed",
            path=path,
            elapsed_ms=elapsed_ms,
            error=str(exc),
            exc_info=True,
        )
        raise RuntimeError(f"Backend request failed for {path}: {exc}") from exc

    elapsed_ms = int((time.perf_counter() - started) * 1000)
    if response.is_error:
        body = _response_body(response)
        _log(
            logging.ERROR,
            "backend_response_error",
            path=path,
            status_code=response.status_code,
            elapsed_ms=elapsed_ms,
            response_body=body,
            payload_summary=payload_summary,
        )
        raise BackendRequestError(
            path=path,
            status_code=response.status_code,
            response_body=body,
            elapsed_ms=elapsed_ms,
        )

    _log(
        logging.DEBUG,
        "backend_request_completed",
        path=path,
        status_code=response.status_code,
        elapsed_ms=elapsed_ms,
    )

    try:
        body = response.json()
    except ValueError as exc:
        _log(
            logging.ERROR,
            "backend_invalid_json_response",
            path=path,
            status_code=response.status_code,
            elapsed_ms=elapsed_ms,
            response_body=_response_body(response),
            exc_info=True,
        )
        raise RuntimeError(f"Backend returned invalid JSON for {path}") from exc
    return body.get("result")


def _heartbeat(client: httpx.Client) -> None:
    result = _post(client, "/api/v1/agent/heartbeat")
    _log(logging.DEBUG, "heartbeat", result=result)


def _claim_job(client: httpx.Client) -> dict[str, Any] | None:
    return _post(client, "/api/v1/agent/jobs/claim")


def _start_job(client: httpx.Client, job_uuid: str) -> None:
    _post(client, f"/api/v1/agent/jobs/{job_uuid}/start")


def _fail_job(client: httpx.Client, job_uuid: str, error_message: str) -> None:
    try:
        _post(
            client,
            f"/api/v1/agent/jobs/{job_uuid}/fail",
            {"error_message": error_message},
        )
    except Exception as exc:  # noqa: BLE001
        _log(
            logging.ERROR,
            "failed_to_report_job_error",
            job_uuid=job_uuid,
            error=str(exc),
        )


def _complete_connection_test(
    client: httpx.Client,
    job_uuid: str,
    ok: bool,
    message: str,
) -> dict[str, Any] | None:
    return _post(
        client,
        f"/api/v1/agent/jobs/{job_uuid}/complete-connection-test",
        {"ok": ok, "message": message},
    )


def _complete_scan(
    client: httpx.Client,
    job_uuid: str,
    databases: list[dict[str, Any]],
) -> dict[str, Any] | None:
    return _post(
        client,
        f"/api/v1/agent/jobs/{job_uuid}/complete-scan",
        {"databases": databases},
    )


def _upload_sql(
    client: httpx.Client,
    job_uuid: str,
    sql: str,
) -> dict[str, Any] | None:
    return _post(client, f"/api/v1/agent/jobs/{job_uuid}/upload_sql", {"sql": sql})


def _build_pg_dump_command(connection: dict[str, Any]) -> list[str]:
    return [
        PG_DUMP_BIN,
        "--schema-only",
        "--no-owner",
        "--no-privileges",
        "-h",
        connection["host"],
        "-p",
        str(connection["port"]),
        "-U",
        connection["username"],
        "-d",
        connection["database_name"],
    ]


def _build_pg_env(connection: dict[str, Any]) -> dict[str, str]:
    env = os.environ.copy()
    env["PGPASSWORD"] = DB_PASSWORD
    return env


def _run_command(
    command: list[str],
    env: dict[str, str],
    timeout_label: str,
    host: str,
    database: str,
    timeout_seconds: int,
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=False,
            env=env,
            check=False,
            timeout=timeout_seconds,
        )
        
        result.stdout = decode(result.stdout)
        result.stderr = decode(result.stderr)
        
        return result
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"{timeout_label} timed out after {timeout_seconds} seconds "
            f"(host={host}, database={database})"
        ) from exc


def _raise_on_command_failure(
    result: subprocess.CompletedProcess[str],
    default_message: str,
) -> None:
    if result.returncode == 0:
        return

    stderr = (result.stderr or "").strip()
    stdout = (result.stdout or "").strip()
    message = stderr or stdout or default_message
    raise RuntimeError(message)


def _dump_schema(connection: dict[str, Any]) -> str:
    env = _build_pg_env(connection)
    command = _build_pg_dump_command(connection)

    _log(
        logging.INFO,
        "running_pg_dump",
        command=command,
        host=connection["host"],
        database=connection["database_name"],
        timeout_seconds=DUMP_TIMEOUT_SECONDS,
    )

    result = _run_command(
        command=command,
        env=env,
        timeout_label="pg_dump",
        host=connection["host"],
        database=connection["database_name"],
        timeout_seconds=DUMP_TIMEOUT_SECONDS,
    )
    _raise_on_command_failure(result, "pg_dump failed")

    sql = result.stdout or ""
    if not sql.strip():
        raise RuntimeError("pg_dump returned empty schema")

    return sql


def _run_select_1(connection: dict[str, Any]) -> str:
    env = _build_pg_env(connection)
    command = [
        PSQL_BIN,
        "-h",
        connection["host"],
        "-p",
        str(connection["port"]),
        "-U",
        connection["username"],
        "-d",
        connection["database_name"],
        "-tAc",
        "SELECT 1;",
    ]

    _log(
        logging.INFO,
        "running_select_1",
        command=command,
        host=connection["host"],
        database=connection["database_name"],
        timeout_seconds=CONNECT_TIMEOUT_SECONDS,
    )

    result = _run_command(
        command=command,
        env=env,
        timeout_label="connection_test",
        host=connection["host"],
        database=connection["database_name"],
        timeout_seconds=CONNECT_TIMEOUT_SECONDS,
    )
    _raise_on_command_failure(result, "psql SELECT 1 failed")

    output = (result.stdout or "").strip()
    if output != "1":
        raise RuntimeError(f"Unexpected SELECT 1 result: {output!r}")

    return "Connection successful"


def _run_psql_query(connection: dict[str, Any], database_name: str, sql: str) -> list[str]:
    env = _build_pg_env(connection)
    command = [
        PSQL_BIN,
        "-h",
        connection["host"],
        "-p",
        str(connection["port"]),
        "-U",
        connection["username"],
        "-d",
        database_name,
        "-tA",
        "-c",
        sql,
    ]

    _log(
        logging.DEBUG,
        "running_psql_query",
        command=command,
        host=connection["host"],
        database=database_name,
        sql=sql,
        timeout_seconds=QUERY_TIMEOUT_SECONDS,
    )

    result = _run_command(
        command=command,
        env=env,
        timeout_label="psql query",
        host=connection["host"],
        database=database_name,
        timeout_seconds=QUERY_TIMEOUT_SECONDS,
    )
    _raise_on_command_failure(result, "psql query failed")

    return [line.strip() for line in (result.stdout or "").splitlines() if line.strip()]


def _scan_databases_and_schemas(connection: dict[str, Any]) -> list[dict[str, Any]]:
    control_database = connection.get("database_name") or "postgres"

    databases = _run_psql_query(
        connection,
        control_database,
        """
        SELECT datname
        FROM pg_database
        WHERE datistemplate = FALSE
        ORDER BY datname;
        """.strip(),
    )

    result: list[dict[str, Any]] = []
    for database_name in databases:
        schemas = _run_psql_query(
            connection,
            database_name,
            """
            SELECT schema_name
            FROM information_schema.schemata
            WHERE schema_name <> 'information_schema'
              AND schema_name NOT LIKE 'pg_%'
            ORDER BY schema_name;
            """.strip(),
        )
        result.append(
            {
                "database_name": database_name,
                "external_database_key": database_name,
                "schemas": [
                    {
                        "schema_name": schema_name,
                        "external_schema_key": schema_name,
                    }
                    for schema_name in schemas
                ],
            }
        )

    return result


def _process_job(client: httpx.Client, job: dict[str, Any]) -> None:
    job_uuid = job["job_uuid"]
    job_type = job.get("job_type", "sync")
    connection = job["connection"]

    _log(
        logging.INFO,
        "job_claimed",
        job_uuid=job_uuid,
        job_type=job_type,
        agent_uuid=connection["agent_uuid"],
        host=connection.get("host"),
        database=connection.get("database_name"),
    )

    try:
        _start_job(client, job_uuid)

        if job_type == "connection_test":
            message = _run_select_1(connection)
            result = _complete_connection_test(client, job_uuid, True, message)
        elif job_type == "scan":
            databases = _scan_databases_and_schemas(connection)
            result = _complete_scan(client, job_uuid, databases)
        else:
            sql = _dump_schema(connection)
            result = _upload_sql(client, job_uuid, sql)

        _log(
            logging.INFO,
            "job_completed",
            job_uuid=job_uuid,
            job_type=job_type,
            result=result,
        )

    except Exception as exc:  # noqa: BLE001
        _log(
            logging.ERROR,
            "job_failed",
            job_uuid=job_uuid,
            job_type=job_type,
            error=str(exc),
        )

        if job_type == "connection_test":
            try:
                _complete_connection_test(client, job_uuid, False, str(exc))
            except Exception as complete_exc:  # noqa: BLE001
                _log(
                    logging.ERROR,
                    "failed_to_report_connection_test",
                    job_uuid=job_uuid,
                    error=str(complete_exc),
                )
                _fail_job(client, job_uuid, str(exc))
        else:
            _fail_job(client, job_uuid, str(exc))


def main() -> int:
    _setup_logging()

    if not AGENT_TOKEN:
        _log(logging.ERROR, "missing_agent_token", env_var="STRUCTLY_AGENT_TOKEN")
        return 1
    if not DB_PASSWORD:
        _log(logging.ERROR, "missing_db_password", env_var="DB_PASSWORD")
        return 1

    try:
        with _client() as client:
            _log(
                logging.INFO,
                "agent_started",
                backend_url=BACKEND_URL,
                poll_interval_seconds=POLL_INTERVAL_SECONDS,
                http_timeout_seconds=HTTP_TIMEOUT_SECONDS,
                connect_timeout_seconds=CONNECT_TIMEOUT_SECONDS,
                query_timeout_seconds=QUERY_TIMEOUT_SECONDS,
                dump_timeout_seconds=DUMP_TIMEOUT_SECONDS,
            )

            while True:
                try:
                    _heartbeat(client)
                    job = _claim_job(client)

                    if not job:
                        time.sleep(POLL_INTERVAL_SECONDS)
                        continue

                    _process_job(client, job)

                except KeyboardInterrupt:
                    _log(logging.INFO, "agent_stopped")
                    return 0
                except Exception as exc:  # noqa: BLE001
                    _log(logging.ERROR, "agent_loop_error", error=str(exc))
                    time.sleep(POLL_INTERVAL_SECONDS)

    except KeyboardInterrupt:
        _log(logging.INFO, "agent_stopped")
        return 0
    except Exception as exc:  # noqa: BLE001
        _log(logging.ERROR, "agent_startup_failed", error=str(exc))
        return 1


if __name__ == "__main__":
    sys.exit(main())
