import base64
import datetime as dt
import json
import logging
import os
from pathlib import Path
import subprocess
import sys
import time
from typing import Any

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID


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

POLL_INTERVAL_SECONDS = _getenv_int("STRUCTLY_AGENT_POLL_INTERVAL", 10)

HTTP_TIMEOUT_SECONDS = _getenv_int("STRUCTLY_AGENT_HTTP_TIMEOUT", 30)
CONNECT_TIMEOUT_SECONDS = _getenv_int("STRUCTLY_AGENT_TIMEOUT_CONNECT", 10)
QUERY_TIMEOUT_SECONDS = _getenv_int("STRUCTLY_AGENT_TIMEOUT_QUERY", 60)
DUMP_TIMEOUT_SECONDS = _getenv_int("STRUCTLY_AGENT_TIMEOUT_DUMP", 600)

PG_DUMP_BIN = _getenv_str("PG_DUMP_BIN", "pg_dump")
PSQL_BIN = _getenv_str("PSQL_BIN", "psql")

AGENT_STATE_DIR = Path(_getenv_str("STRUCTLY_AGENT_STATE_DIR", "/agent/state"))
PRIVATE_KEY_PATH = AGENT_STATE_DIR / "agent_private_key.pem"
CERTIFICATE_PATH = AGENT_STATE_DIR / "agent_certificate.pem"

ENCRYPTED_SECRET_PREFIX = "rsa_oaep_sha256:"


logger = logging.getLogger("structly_agent")


def _setup_logging() -> None:
    level_name = _getenv_str("STRUCTLY_AGENT_LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)

    handler = logging.StreamHandler(sys.stdout)

    class JsonFormatter(logging.Formatter):
        def format(self, record: logging.LogRecord) -> str:
            payload: dict[str, Any] = {
                "level": record.levelname.lower(),
                "message": record.getMessage(),
                "logger": record.name,
            }
            extra = getattr(record, "extra_data", None)
            if isinstance(extra, dict):
                payload.update(extra)

            if record.exc_info:
                payload["exception"] = self.formatException(record.exc_info)

            return json.dumps(payload, ensure_ascii=False)

    handler.setFormatter(JsonFormatter())
    logger.setLevel(level)
    logger.handlers.clear()
    logger.addHandler(handler)
    logger.propagate = False


def _log(level: int, message: str, **extra: Any) -> None:
    logger.log(level, message, extra={"extra_data": extra})


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


def _post(
    client: httpx.Client,
    path: str,
    payload: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    response = client.post(path, json=payload)
    response.raise_for_status()
    body = response.json()
    return body.get("result")


def _certificate_fingerprint(certificate_pem: str) -> str:
    certificate = x509.load_pem_x509_certificate(certificate_pem.encode("utf-8"))
    return certificate.fingerprint(hashes.SHA256()).hex()


def _heartbeat(client: httpx.Client) -> None:
    result = _post(client, "/api/v1/agent/heartbeat")
    _log(logging.DEBUG, "heartbeat", result=result)


def _claim_job(client: httpx.Client) -> dict[str, Any] | None:
    return _post(client, "/api/v1/agent/jobs/claim")


def _register_certificate(
    client: httpx.Client,
    certificate_public_pem: str,
) -> dict[str, Any] | None:
    return _post(
        client,
        "/api/v1/agent/certificate/register",
        {"certificate_public_pem": certificate_public_pem},
    )


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


def _generate_self_signed_certificate(common_name: str) -> tuple[str, str]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])

    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=1))
        .not_valid_after(dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(private_key, hashes.SHA256())
    )

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    certificate_pem = certificate.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    return private_key_pem, certificate_pem


def _ensure_certificate_pair() -> tuple[str, str]:
    AGENT_STATE_DIR.mkdir(parents=True, exist_ok=True)

    if PRIVATE_KEY_PATH.exists() and CERTIFICATE_PATH.exists():
        private_key_pem = PRIVATE_KEY_PATH.read_text(encoding="utf-8")
        certificate_pem = CERTIFICATE_PATH.read_text(encoding="utf-8")
        _log(
            logging.INFO,
            "certificate_loaded",
            state_dir=str(AGENT_STATE_DIR),
            certificate_fingerprint=_certificate_fingerprint(certificate_pem),
        )
        return private_key_pem, certificate_pem

    common_name = os.getenv("STRUCTLY_AGENT_COMMON_NAME", os.getenv("COMPUTERNAME", "structly-agent"))
    private_key_pem, certificate_pem = _generate_self_signed_certificate(common_name)

    PRIVATE_KEY_PATH.write_text(private_key_pem, encoding="utf-8")
    CERTIFICATE_PATH.write_text(certificate_pem, encoding="utf-8")

    _log(
        logging.INFO,
        "certificate_created",
        state_dir=str(AGENT_STATE_DIR),
        certificate_fingerprint=_certificate_fingerprint(certificate_pem),
    )
    return private_key_pem, certificate_pem


def _decrypt_secret(secret: str, private_key_pem: str) -> str:
    if not secret.startswith(ENCRYPTED_SECRET_PREFIX):
        return secret

    encrypted = base64.b64decode(secret[len(ENCRYPTED_SECRET_PREFIX):])
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode("utf-8"),
        password=None,
    )

    try:
        plaintext = private_key.decrypt(
            encrypted,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    except ValueError as exc:
        raise RuntimeError(
            "Decryption failed: the encrypted secret does not match the current agent private key. "
            "If the agent was restarted in a new container, make sure STRUCTLY_AGENT_STATE_DIR is persisted."
        ) from exc

    return plaintext.decode("utf-8")


def _build_pg_env(connection: dict[str, Any]) -> dict[str, str]:
    env = os.environ.copy()
    private_key_pem = PRIVATE_KEY_PATH.read_text(encoding="utf-8")
    env["PGPASSWORD"] = _decrypt_secret(connection["password_encrypted"], private_key_pem)
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
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            env=env,
            check=False,
            timeout=timeout_seconds,
        )
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
                "schemas": [{"schema_name": schema_name} for schema_name in schemas],
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

    try:
        _, certificate_pem = _ensure_certificate_pair()

        with _client() as client:
            register_result = _register_certificate(client, certificate_pem)

            _log(
                logging.INFO,
                "certificate_registered",
                result=register_result,
            )
            _log(
                logging.INFO,
                "agent_started",
                backend_url=BACKEND_URL,
                poll_interval_seconds=POLL_INTERVAL_SECONDS,
                http_timeout_seconds=HTTP_TIMEOUT_SECONDS,
                connect_timeout_seconds=CONNECT_TIMEOUT_SECONDS,
                query_timeout_seconds=QUERY_TIMEOUT_SECONDS,
                dump_timeout_seconds=DUMP_TIMEOUT_SECONDS,
                state_dir=str(AGENT_STATE_DIR),
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