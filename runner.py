import json
import os
from pathlib import Path
import subprocess
import sys
import time
from typing import Any

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
import base64
import datetime as dt


def _getenv_str(name: str, default: str = "") -> str:
    value = os.getenv(name)
    if value is None:
        return default
    value = value.strip()
    return value or default


BACKEND_URL = _getenv_str("STRUCTLY_BACKEND_URL", "https://structly.elevo.space").rstrip("/")
AGENT_TOKEN = _getenv_str("STRUCTLY_AGENT_TOKEN")
POLL_INTERVAL_SECONDS = int(os.getenv("STRUCTLY_AGENT_POLL_INTERVAL", "10"))
REQUEST_TIMEOUT_SECONDS = int(os.getenv("STRUCTLY_AGENT_TIMEOUT", "120"))
PG_DUMP_BIN = _getenv_str("PG_DUMP_BIN", "pg_dump")
PSQL_BIN = _getenv_str("PSQL_BIN", "psql")
AGENT_STATE_DIR = Path(_getenv_str("STRUCTLY_AGENT_STATE_DIR", "/agent/state"))
PRIVATE_KEY_PATH = AGENT_STATE_DIR / "agent_private_key.pem"
CERTIFICATE_PATH = AGENT_STATE_DIR / "agent_certificate.pem"
ENCRYPTED_SECRET_PREFIX = "rsa_oaep_sha256:"


def _require_env(name: str, value: str) -> str:
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


def _headers() -> dict[str, str]:
    return {
        "X-Agent-Token": _require_env("STRUCTLY_AGENT_TOKEN", AGENT_TOKEN),
        "Content-Type": "application/json",
    }


def _client() -> httpx.Client:
    return httpx.Client(
        base_url=_require_env("STRUCTLY_BACKEND_URL", BACKEND_URL),
        headers=_headers(),
        timeout=REQUEST_TIMEOUT_SECONDS,
    )


def _log(message: str, **extra: Any) -> None:
    payload = {"message": message, **extra}
    print(json.dumps(payload, ensure_ascii=False), flush=True)


def _post(client: httpx.Client, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    response = client.post(path, json=payload)
    response.raise_for_status()
    body = response.json()
    return body.get("result")


def _heartbeat(client: httpx.Client) -> None:
    result = _post(client, "/api/v1/agent/heartbeat")
    _log("heartbeat", result=result)


def _claim_job(client: httpx.Client) -> dict[str, Any] | None:
    return _post(client, "/api/v1/agent/jobs/claim")


def _register_certificate(client: httpx.Client, certificate_public_pem: str) -> dict[str, Any]:
    return _post(client, "/api/v1/agent/certificate/register", {"certificate_public_pem": certificate_public_pem})


def _start_job(client: httpx.Client, job_uuid: str) -> None:
    _post(client, f"/api/v1/agent/jobs/{job_uuid}/start")


def _fail_job(client: httpx.Client, job_uuid: str, error_message: str) -> None:
    try:
        _post(client, f"/api/v1/agent/jobs/{job_uuid}/fail", {"error_message": error_message})
    except Exception as exc:  # noqa: BLE001
        _log("failed_to_report_job_error", job_uuid=job_uuid, error=str(exc))


def _complete_connection_test(client: httpx.Client, job_uuid: str, ok: bool, message: str) -> dict[str, Any]:
    return _post(
        client,
        f"/api/v1/agent/jobs/{job_uuid}/complete-connection-test",
        {"ok": ok, "message": message},
    )


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
        return PRIVATE_KEY_PATH.read_text(encoding="utf-8"), CERTIFICATE_PATH.read_text(encoding="utf-8")

    common_name = os.getenv("STRUCTLY_AGENT_COMMON_NAME", os.getenv("COMPUTERNAME", "structly-agent"))
    private_key_pem, certificate_pem = _generate_self_signed_certificate(common_name)
    PRIVATE_KEY_PATH.write_text(private_key_pem, encoding="utf-8")
    CERTIFICATE_PATH.write_text(certificate_pem, encoding="utf-8")
    return private_key_pem, certificate_pem


def _decrypt_secret(secret: str, private_key_pem: str) -> str:
    if not secret.startswith(ENCRYPTED_SECRET_PREFIX):
        return secret

    encrypted = base64.b64decode(secret[len(ENCRYPTED_SECRET_PREFIX):])
    private_key = serialization.load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
    plaintext = private_key.decrypt(
        encrypted,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return plaintext.decode("utf-8")


def _dump_schema(connection: dict[str, Any]) -> str:
    env = os.environ.copy()
    env["PGPASSWORD"] = _decrypt_secret(connection["password_encrypted"], PRIVATE_KEY_PATH.read_text(encoding="utf-8"))
    env["PGSSLMODE"] = "require" if connection.get("ssl_on") else "disable"

    command = _build_pg_dump_command(connection)
    _log("running_pg_dump", command=command, host=connection["host"], database=connection["database_name"])
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    if result.returncode != 0:
        stderr = (result.stderr or "").strip() or "pg_dump failed"
        raise RuntimeError(stderr)

    sql = result.stdout or ""
    if not sql.strip():
        raise RuntimeError("pg_dump returned empty schema")
    return sql


def _run_select_1(connection: dict[str, Any]) -> str:
    env = os.environ.copy()
    env["PGPASSWORD"] = _decrypt_secret(connection["password_encrypted"], PRIVATE_KEY_PATH.read_text(encoding="utf-8"))
    env["PGSSLMODE"] = "require" if connection.get("ssl_on") else "disable"

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
    _log("running_select_1", command=command, host=connection["host"], database=connection["database_name"])
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    if result.returncode != 0:
        stderr = (result.stderr or "").strip() or "psql SELECT 1 failed"
        raise RuntimeError(stderr)

    output = (result.stdout or "").strip()
    if output != "1":
        raise RuntimeError(f"Unexpected SELECT 1 result: {output!r}")
    return "Connection successful"


def _upload_sql(client: httpx.Client, job_uuid: str, sql: str) -> dict[str, Any]:
    return _post(client, f"/api/v1/agent/jobs/{job_uuid}/upload_sql", {"sql": sql})


def _process_job(client: httpx.Client, job: dict[str, Any]) -> None:
    job_uuid = job["job_uuid"]
    job_type = job.get("job_type", "sync")
    connection = job["connection"]
    _log("job_claimed", job_uuid=job_uuid, job_type=job_type, integration_uuid=connection["integration_uuid"])

    try:
        _start_job(client, job_uuid)
        if job_type == "connection_test":
            message = _run_select_1(connection)
            result = _complete_connection_test(client, job_uuid, True, message)
        else:
            sql = _dump_schema(connection)
            result = _upload_sql(client, job_uuid, sql)
        _log("job_completed", job_uuid=job_uuid, result=result)
    except Exception as exc:  # noqa: BLE001
        _log("job_failed", job_uuid=job_uuid, error=str(exc))
        if job_type == "connection_test":
            try:
                _complete_connection_test(client, job_uuid, False, str(exc))
            except Exception as complete_exc:  # noqa: BLE001
                _log("failed_to_report_connection_test", job_uuid=job_uuid, error=str(complete_exc))
                _fail_job(client, job_uuid, str(exc))
        else:
            _fail_job(client, job_uuid, str(exc))


def main() -> int:
    _require_env("STRUCTLY_BACKEND_URL", BACKEND_URL)
    _require_env("STRUCTLY_AGENT_TOKEN", AGENT_TOKEN)
    _, certificate_pem = _ensure_certificate_pair()

    with _client() as client:
        register_result = _register_certificate(client, certificate_pem)
        _log("certificate_registered", result=register_result)
        _log("agent_started", poll_interval_seconds=POLL_INTERVAL_SECONDS)
        while True:
            try:
                _heartbeat(client)
                job = _claim_job(client)
                if not job:
                    time.sleep(POLL_INTERVAL_SECONDS)
                    continue
                _process_job(client, job)
            except KeyboardInterrupt:
                _log("agent_stopped")
                return 0
            except Exception as exc:  # noqa: BLE001
                _log("agent_loop_error", error=str(exc))
                time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    sys.exit(main())
