"""Policy-aware TLS diagnostics from one correlated network observation."""

from __future__ import annotations

import ipaddress
import re
import shutil
import ssl
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime


_FINGERPRINT_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_SECRET_RE = re.compile(r"(?i)(password|secret|token|cookie)\s*=\s*[^\s,;]+")
_PEM_RE = re.compile(
    rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
    re.DOTALL,
)
_VERIFY_CODE_RE = re.compile(r"Verify return code:\s*(\d+)\s*\(([^\r\n)]*)\)", re.I)
_VERIFY_ERROR_RE = re.compile(r"verify error:num=\d+:([^\r\n]+)", re.I)
_POLICIES = {
    "legacy-pinned",
    "system-ca",
    "system-ca-with-pinned-fallback",
}
# Este perfil confirmado não envia SNI e usa X509_check_host com flags padrão.
_SUPPORTED_CLIENT_VERSION = "1.21.0"


@dataclass(frozen=True)
class TLSObservation:
    hostname: str
    port: int
    certificate_der: bytes
    ca_valid: bool | None
    ca_error: str = ""


@dataclass(frozen=True)
class CertificateDiagnostic:
    hostname: str
    subject: str
    san: tuple[str, ...]
    issuer: str
    not_before: str
    not_after: str
    fingerprint_sha256: str
    ca_status: str
    hostname_status: str
    fingerprint_match: str
    reason: str
    ca_reason: str = "Indisponível"
    validity_status: str = "Indisponível"
    policy: str = "legacy-pinned"
    severity: str = "WARNING"
    ok_count: int = 0
    warning_count: int = 1
    critical_count: int = 0
    indeterminate_count: int = 0
    fallback_used: bool = False


def _safe(value: str, limit: int = 1024) -> str:
    value = _CONTROL_RE.sub(" ", value).strip()
    value = _SECRET_RE.sub(r"\1=[redacted]", value)
    return value[:limit]


def _openssl_endpoint(hostname: str, port: int) -> str:
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        return f"{hostname}:{port}"
    if address.version == 6:
        return f"[{hostname}]:{port}"
    return f"{hostname}:{port}"


def _observe_tls(hostname: str, port: int, timeout: float) -> TLSObservation:
    command = [
        "openssl",
        "s_client",
        "-4",
        "-connect",
        _openssl_endpoint(hostname, port),
        "-noservername",
        "-verify",
        "10",
        "-verify_return_error",
        "-showcerts",
    ]
    result = subprocess.run(
        command,
        input=b"",
        capture_output=True,
        timeout=timeout,
        check=False,
    )
    combined = result.stdout + b"\n" + result.stderr
    match = _PEM_RE.search(combined)
    if match is None:
        detail = _safe(combined.decode("utf-8", "replace"))
        raise ValueError(detail or "o servidor não apresentou certificado")
    try:
        der = ssl.PEM_cert_to_DER_cert(match.group().decode("ascii"))
    except (UnicodeError, ValueError) as exc:
        raise ValueError("o servidor apresentou um certificado inválido") from exc

    text = combined.decode("utf-8", "replace")
    verify_codes = _VERIFY_CODE_RE.findall(text)
    verify_errors = _VERIFY_ERROR_RE.findall(text)
    if verify_codes:
        code, description = verify_codes[-1]
        ca_valid: bool | None = code == "0"
        ca_error = "" if ca_valid else _safe(description)
    elif verify_errors:
        ca_valid = False
        ca_error = _safe(verify_errors[-1])
    else:
        ca_valid = None
        ca_error = "resultado da validação CA não foi comprovado"
    return TLSObservation(hostname, port, der, ca_valid, ca_error)


def _decode_certificate(
    der: bytes,
    hostname: str,
) -> tuple[str, tuple[str, ...], str, str, str, str, bool | None]:
    result = subprocess.run(
        [
            "openssl",
            "x509",
            "-inform",
            "DER",
            "-noout",
            "-subject",
            "-issuer",
            "-startdate",
            "-enddate",
            "-fingerprint",
            "-sha256",
            "-ext",
            "subjectAltName",
            "-checkhost",
            hostname,
        ],
        input=der,
        capture_output=True,
        timeout=4,
        check=False,
    )
    if result.returncode != 0:
        raise ValueError("não foi possível interpretar o certificado apresentado")

    lines = [_safe(line.decode("utf-8", "replace")) for line in result.stdout.splitlines()]
    subject = issuer = not_before = not_after = fingerprint = ""
    san: list[str] = []
    hostname_match: bool | None = None
    in_san = False
    for line in lines:
        if line.startswith("subject="):
            subject = line.split("=", 1)[1].strip()
        elif line.startswith("issuer="):
            issuer = line.split("=", 1)[1].strip()
        elif line.startswith("notBefore="):
            not_before = line.split("=", 1)[1].strip()
        elif line.startswith("notAfter="):
            not_after = line.split("=", 1)[1].strip()
        elif "sha256 Fingerprint=" in line:
            fingerprint = line.split("=", 1)[1].replace(":", "").lower()
        elif line.startswith("X509v3 Subject Alternative Name:"):
            in_san = True
        elif line.endswith(" does NOT match certificate"):
            hostname_match = False
        elif line.endswith(" does match certificate"):
            hostname_match = True
        elif in_san and line:
            san.extend(part.strip() for part in line.split(",") if part.strip())
            in_san = False

    if not _FINGERPRINT_RE.fullmatch(fingerprint):
        raise ValueError("o fingerprint apresentado não está em SHA-256 válido")
    return (
        subject,
        tuple(san),
        issuer,
        not_before,
        not_after,
        fingerprint,
        hostname_match,
    )


def _supported_client_version(timeout: float = 2.0) -> str | None:
    executable = shutil.which(
        "openfortivpn",
        path="/usr/sbin:/usr/bin:/sbin:/bin",
    )
    if not executable:
        return None
    try:
        result = subprocess.run(
            [executable, "--version"],
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    version = result.stdout.strip()
    if result.returncode != 0 or version != _SUPPORTED_CLIENT_VERSION:
        return None
    return version


def _validity_status(not_before: str, not_after: str) -> str:
    try:
        start = parsedate_to_datetime(not_before).astimezone(timezone.utc)
        end = parsedate_to_datetime(not_after).astimezone(timezone.utc)
    except (TypeError, ValueError, OverflowError):
        return "Indisponível"
    now = datetime.now(timezone.utc)
    if now < start:
        return "Ainda não válida"
    if now > end:
        return "Expirada"
    return "Válida"


def _classify_ca_error(error: str) -> str:
    lowered = error.lower()
    if "unable to get local issuer" in lowered or "unknown issuer" in lowered:
        return "Cadeia incompleta ou CA ausente"
    if "self signed" in lowered or "self-signed" in lowered:
        return "CA ausente ou certificado autoassinado"
    if "expired" in lowered or "not yet valid" in lowered:
        return "Certificado da cadeia expirado ou ainda não válido"
    return "Falha na validação da cadeia"


def _counts(severity: str, *, indeterminate: bool = False) -> tuple[int, int, int, int]:
    return (
        int(severity == "OK"),
        int(severity == "WARNING"),
        int(severity == "CRITICAL"),
        int(indeterminate),
    )


def _empty_result(
    hostname: str,
    policy: str,
    severity: str,
    reason: str,
    *,
    indeterminate: bool = False,
) -> CertificateDiagnostic:
    ok_count, warning_count, critical_count, indeterminate_count = _counts(
        severity,
        indeterminate=indeterminate,
    )
    return CertificateDiagnostic(
        hostname=hostname or "Indisponível",
        subject="Indisponível",
        san=(),
        issuer="Indisponível",
        not_before="Indisponível",
        not_after="Indisponível",
        fingerprint_sha256="Indisponível",
        ca_status="Indisponível",
        hostname_status="Indisponível",
        fingerprint_match="Indisponível",
        reason=_safe(reason),
        policy=policy,
        severity=severity,
        ok_count=ok_count,
        warning_count=warning_count,
        critical_count=critical_count,
        indeterminate_count=indeterminate_count,
    )


def configuration_failure(hostname: str, policy: str, reason: str) -> CertificateDiagnostic:
    """Create a critical result without attempting TLS for an invalid saved snapshot."""
    return _empty_result(hostname, policy or "Indisponível", "CRITICAL", reason)


def diagnose(
    hostname: str,
    port: int,
    configured_fingerprint: str = "",
    policy: str = "legacy-pinned",
    timeout: float = 5.0,
) -> CertificateDiagnostic:
    hostname = _safe(hostname, 253)
    normalized_policy = policy.strip().lower() or "legacy-pinned"
    configured = configured_fingerprint.lower()
    if normalized_policy not in _POLICIES:
        return configuration_failure(hostname, normalized_policy, "Política de certificado inválida.")
    if not hostname or not 1 <= port <= 65535:
        return configuration_failure(
            hostname,
            normalized_policy,
            "Host ou porta do endpoint TLS é inválido.",
        )
    if normalized_policy == "system-ca" and configured:
        return configuration_failure(
            hostname,
            normalized_policy,
            "trusted-cert é proibido pela política system-ca.",
        )
    if normalized_policy != "system-ca" and not _FINGERPRINT_RE.fullmatch(configured):
        return configuration_failure(
            hostname,
            normalized_policy,
            "trusted-cert obrigatório está ausente ou não é um SHA-256 válido.",
        )
    if _supported_client_version() is None:
        return _empty_result(
            hostname,
            normalized_policy,
            "WARNING",
            "A versão instalada do openfortivpn não possui perfil TLS comprovado; "
            "a equivalência do certificado observado não pode ser afirmada.",
            indeterminate=True,
        )

    try:
        observation = _observe_tls(hostname, port, timeout)
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        reason = _safe(str(exc)) or "não foi possível obter uma observação TLS correlacionada"
        return _empty_result(
            hostname,
            normalized_policy,
            "WARNING",
            reason,
            indeterminate=True,
        )
    if observation.hostname != hostname or observation.port != port:
        return _empty_result(
            hostname,
            normalized_policy,
            "WARNING",
            "A observação TLS não corresponde ao endpoint solicitado.",
            indeterminate=True,
        )
    if observation.ca_valid is None:
        return _empty_result(
            hostname,
            normalized_policy,
            "WARNING",
            observation.ca_error or "A validação CA da observação não pôde ser comprovada.",
            indeterminate=True,
        )

    try:
        (
            subject,
            san,
            issuer,
            not_before,
            not_after,
            fingerprint,
            hostname_match,
        ) = _decode_certificate(observation.certificate_der, hostname)
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        return _empty_result(
            hostname,
            normalized_policy,
            "WARNING",
            _safe(str(exc)) or "falha ao interpretar a observação TLS",
            indeterminate=True,
        )

    ca_status = "Válida" if observation.ca_valid else "Inválida"
    ca_reason = "Válida" if observation.ca_valid else _classify_ca_error(observation.ca_error)
    hostname_status = (
        "Indeterminado"
        if hostname_match is None
        else "Válido" if hostname_match else "Inválido"
    )
    validity_status = _validity_status(not_before, not_after)
    classic_valid = (
        observation.ca_valid
        and hostname_match is True
        and validity_status == "Válida"
    )
    fingerprint_match = (
        "Não configurado"
        if normalized_policy == "system-ca"
        else "Correspondente" if configured == fingerprint else "Divergente"
    )

    reasons: list[str] = []
    if not observation.ca_valid:
        reasons.append(f"Cadeia de confiança: {observation.ca_error or 'certificado não confiável'}")
    if hostname_match is None:
        reasons.append(
            "A equivalência da validação de hostname com o cliente não pôde ser comprovada"
        )
    elif not hostname_match:
        reasons.append("Hostname não corresponde ao certificado segundo X509_check_host")
    if validity_status != "Válida":
        reasons.append(f"Validade: {validity_status.lower()}")

    fallback_used = False
    indeterminate = hostname_match is None
    if indeterminate:
        severity = "WARNING"
        reasons.append("Nenhum resultado OK ou fallback foi afirmado sem equivalência comprovada")
    elif normalized_policy == "system-ca":
        severity = "OK" if classic_valid else "CRITICAL"
        if not classic_valid:
            reasons.append("A política system-ca exige validação clássica integral")
    elif fingerprint_match == "Divergente":
        severity = "WARNING" if classic_valid else "CRITICAL"
        reasons.append("O fingerprint observado diverge de trusted-cert")
    elif classic_valid:
        severity = "OK"
    else:
        severity = "WARNING"
        fallback_used = True
        reasons.append("Pin correlacionado aceito como fallback pela política configurada")

    ok_count, warning_count, critical_count, indeterminate_count = _counts(
        severity,
        indeterminate=indeterminate,
    )
    return CertificateDiagnostic(
        hostname=hostname,
        subject=subject or "Indisponível",
        san=san,
        issuer=issuer or "Indisponível",
        not_before=not_before or "Indisponível",
        not_after=not_after or "Indisponível",
        fingerprint_sha256=fingerprint,
        ca_status=ca_status,
        hostname_status=hostname_status,
        fingerprint_match=fingerprint_match,
        reason="; ".join(reasons),
        ca_reason=ca_reason,
        validity_status=validity_status,
        policy=normalized_policy,
        severity=severity,
        fallback_used=fallback_used,
        ok_count=ok_count,
        warning_count=warning_count,
        critical_count=critical_count,
        indeterminate_count=indeterminate_count,
    )


def format_diagnostic(result: CertificateDiagnostic) -> str:
    san = ", ".join(result.san) if result.san else "Indisponível"
    lines = [
        f"Política: {result.policy}",
        f"Severidade TLS: {result.severity}",
        f"Hostname: {result.hostname}",
        f"Subject: {result.subject}",
        f"SAN: {san}",
        f"Emissor: {result.issuer}",
        f"Validade inicial: {result.not_before}",
        f"Validade final: {result.not_after}",
        f"Validade: {result.validity_status}",
        f"Fingerprint SHA-256: {result.fingerprint_sha256}",
        f"Cadeia CA: {result.ca_status} ({result.ca_reason})",
        f"Hostname/SAN: {result.hostname_status}",
        f"Correspondência com trusted-cert: {result.fingerprint_match}",
        f"Fallback por pin: {'Sim' if result.fallback_used else 'Não'}",
        "Contagens TLS: "
        f"OK={result.ok_count} WARNING={result.warning_count} "
        f"CRITICAL={result.critical_count} INDETERMINATE={result.indeterminate_count}",
    ]
    if result.reason:
        lines.append(f"Motivo: {_safe(result.reason)}")
    return "\n".join(lines)
