from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


DEFAULT_TIMEOUT_SECONDS = 8.0
DEFAULT_USER_AGENT = "Wireglass/1.0"


def normalize_external_lookup_config(config: dict[str, Any] | None) -> dict[str, Any]:
    raw = config or {}
    providers = raw.get("providers", {}) if isinstance(raw.get("providers"), dict) else {}
    virustotal = providers.get("virustotal", {}) if isinstance(providers.get("virustotal"), dict) else {}
    malwarebazaar = providers.get("malwarebazaar", {}) if isinstance(providers.get("malwarebazaar"), dict) else {}

    vt_key = str(virustotal.get("api_key") or os.environ.get("VIRUSTOTAL_API_KEY") or os.environ.get("VT_API_KEY") or "")
    mb_key = str(
        malwarebazaar.get("api_key")
        or os.environ.get("MALWAREBAZAAR_API_KEY")
        or os.environ.get("ABUSECH_AUTH_KEY")
        or ""
    )

    return {
        "enabled": bool(raw.get("enabled")),
        "timeout_seconds": max(3.0, min(float(raw.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS)), 20.0)),
        "max_hashes": max(1, min(int(raw.get("max_hashes", 6)), 12)),
        "max_domains": max(1, min(int(raw.get("max_domains", 8)), 16)),
        "providers": {
            "virustotal": {
                "enabled": bool(virustotal.get("enabled")),
                "api_key": vt_key,
            },
            "malwarebazaar": {
                "enabled": bool(malwarebazaar.get("enabled")),
                "api_key": mb_key,
            },
        },
    }


def run_external_enrichment(
    artifact_inputs: list[dict[str, Any]],
    domain_inputs: list[dict[str, Any]],
    config: dict[str, Any] | None,
) -> dict[str, Any]:
    normalized = normalize_external_lookup_config(config)
    requested = bool(normalized["enabled"])
    providers_summary: list[dict[str, Any]] = []
    items: list[dict[str, Any]] = []
    warnings: list[str] = []

    if not requested:
        return {
            "requested": False,
            "enabled": False,
            "providers": [],
            "items": [],
            "warnings": [],
            "summary": {"lookup_count": 0, "high": 0, "medium": 0, "low": 0},
        }

    timeout = float(normalized["timeout_seconds"])
    max_hashes = int(normalized["max_hashes"])
    max_domains = int(normalized["max_domains"])
    vt_config = normalized["providers"]["virustotal"]
    mb_config = normalized["providers"]["malwarebazaar"]

    vt_hash_inputs = artifact_inputs[:max_hashes]
    vt_domain_inputs = domain_inputs[:max_domains]

    if vt_config["enabled"]:
        if not vt_config["api_key"]:
            providers_summary.append(
                {
                    "provider": "virustotal",
                    "label": "VirusTotal",
                    "enabled": True,
                    "configured": False,
                    "status": "missing_api_key",
                    "message": "VirusTotal is enabled but no API key was provided.",
                }
            )
        else:
            vt_items, vt_warning = _run_virustotal(vt_hash_inputs, vt_domain_inputs, str(vt_config["api_key"]), timeout)
            items.extend(vt_items)
            if vt_warning:
                warnings.append(vt_warning)
                providers_summary.append(
                    {
                        "provider": "virustotal",
                        "label": "VirusTotal",
                        "enabled": True,
                        "configured": True,
                        "status": "error",
                        "message": vt_warning,
                    }
                )
            else:
                providers_summary.append(
                    {
                        "provider": "virustotal",
                        "label": "VirusTotal",
                        "enabled": True,
                        "configured": True,
                        "status": "ok",
                        "message": f"Looked up {len(vt_hash_inputs)} hashes and {len(vt_domain_inputs)} domains.",
                    }
                )
    else:
        providers_summary.append(
            {
                "provider": "virustotal",
                "label": "VirusTotal",
                "enabled": False,
                "configured": bool(vt_config["api_key"]),
                "status": "disabled",
                "message": "Provider disabled.",
            }
        )

    if mb_config["enabled"]:
        if not mb_config["api_key"]:
            providers_summary.append(
                {
                    "provider": "malwarebazaar",
                    "label": "MalwareBazaar",
                    "enabled": True,
                    "configured": False,
                    "status": "missing_api_key",
                    "message": "MalwareBazaar is enabled but no Auth-Key was provided.",
                }
            )
        else:
            mb_items, mb_warning = _run_malwarebazaar(vt_hash_inputs, str(mb_config["api_key"]), timeout)
            items.extend(mb_items)
            if mb_warning:
                warnings.append(mb_warning)
                providers_summary.append(
                    {
                        "provider": "malwarebazaar",
                        "label": "MalwareBazaar",
                        "enabled": True,
                        "configured": True,
                        "status": "error",
                        "message": mb_warning,
                    }
                )
            else:
                providers_summary.append(
                    {
                        "provider": "malwarebazaar",
                        "label": "MalwareBazaar",
                        "enabled": True,
                        "configured": True,
                        "status": "ok",
                        "message": f"Looked up {len(vt_hash_inputs)} hashes.",
                    }
                )
    else:
        providers_summary.append(
            {
                "provider": "malwarebazaar",
                "label": "MalwareBazaar",
                "enabled": False,
                "configured": bool(mb_config["api_key"]),
                "status": "disabled",
                "message": "Provider disabled.",
            }
        )

    severity_counts = {
        "high": sum(1 for item in items if item["severity"] == "high"),
        "medium": sum(1 for item in items if item["severity"] == "medium"),
        "low": sum(1 for item in items if item["severity"] == "low"),
    }
    return {
        "requested": True,
        "enabled": True,
        "providers": providers_summary,
        "items": items[:24],
        "warnings": warnings[:8],
        "summary": {
            "lookup_count": len(items),
            **severity_counts,
        },
    }


def _run_virustotal(
    artifact_inputs: list[dict[str, Any]],
    domain_inputs: list[dict[str, Any]],
    api_key: str,
    timeout: float,
) -> tuple[list[dict[str, Any]], str | None]:
    items: list[dict[str, Any]] = []
    try:
        for artifact in artifact_inputs:
            sha256 = str(artifact.get("sha256", ""))
            if not sha256:
                continue
            payload = _vt_get_json(f"https://www.virustotal.com/api/v3/files/{urllib.parse.quote(sha256)}", api_key, timeout)
            items.append(_normalize_virustotal_file(payload, artifact))

        for domain in domain_inputs:
            name = str(domain.get("domain", ""))
            if not name:
                continue
            payload = _vt_get_json(
                f"https://www.virustotal.com/api/v3/domains/{urllib.parse.quote(name)}",
                api_key,
                timeout,
            )
            items.append(_normalize_virustotal_domain(payload, domain))
        return items, None
    except Exception as exc:
        return items, f"VirusTotal lookup failed: {exc}"


def _run_malwarebazaar(
    artifact_inputs: list[dict[str, Any]],
    auth_key: str,
    timeout: float,
) -> tuple[list[dict[str, Any]], str | None]:
    items: list[dict[str, Any]] = []
    try:
        for artifact in artifact_inputs:
            sha256 = str(artifact.get("sha256", ""))
            if not sha256:
                continue
            payload = urllib.parse.urlencode({"query": "get_info", "hash": sha256}).encode("utf-8")
            response = _http_request_json(
                "https://mb-api.abuse.ch/api/v1/",
                timeout=timeout,
                data=payload,
                headers={
                    "Auth-Key": auth_key,
                    "Content-Type": "application/x-www-form-urlencoded",
                },
            )
            items.append(_normalize_malwarebazaar_hash(response, artifact))
        return items, None
    except Exception as exc:
        return items, f"MalwareBazaar lookup failed: {exc}"


def _vt_get_json(url: str, api_key: str, timeout: float) -> dict[str, Any]:
    return _http_request_json(
        url,
        timeout=timeout,
        headers={"x-apikey": api_key},
    )


def _http_request_json(
    url: str,
    timeout: float,
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    request_headers = {"User-Agent": DEFAULT_USER_AGENT}
    if headers:
        request_headers.update(headers)
    request = urllib.request.Request(url, data=data, headers=request_headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8", "ignore"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {"_wireglass_not_found": True}
        message = exc.read().decode("utf-8", "ignore")[:240]
        raise RuntimeError(f"HTTP {exc.code} {message}".strip()) from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(str(exc.reason)) from exc


def _normalize_virustotal_file(payload: dict[str, Any], artifact: dict[str, Any]) -> dict[str, Any]:
    if payload.get("_wireglass_not_found"):
        return {
            "provider": "virustotal",
            "provider_label": "VirusTotal",
            "indicator_type": "file_hash",
            "indicator": artifact["sha256"],
            "indicator_label": artifact.get("filename") or artifact["sha256"],
            "severity": "low",
            "disposition": "not_found",
            "summary": f"VirusTotal does not currently have a public report for {artifact.get('filename') or artifact['sha256']}.",
            "details": {},
            "context": _artifact_context(artifact),
        }

    attributes = (((payload.get("data") or {}).get("attributes")) or {})
    stats = attributes.get("last_analysis_stats") or {}
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    harmless = int(stats.get("harmless", 0))
    undetected = int(stats.get("undetected", 0))
    threat_verdict = str(attributes.get("threat_verdict", ""))
    severity = "high" if malicious or threat_verdict == "VERDICT_MALICIOUS" else "medium" if suspicious or threat_verdict == "VERDICT_SUSPICIOUS" else "low"
    disposition = "malicious" if severity == "high" else "suspicious" if severity == "medium" else "clean"

    malware_names: list[str] = []
    for sandbox in (attributes.get("sandbox_verdicts") or {}).values():
        if not isinstance(sandbox, dict):
            continue
        for name in sandbox.get("malware_names") or []:
            if isinstance(name, str) and name not in malware_names:
                malware_names.append(name)

    return {
        "provider": "virustotal",
        "provider_label": "VirusTotal",
        "indicator_type": "file_hash",
        "indicator": artifact["sha256"],
        "indicator_label": str(attributes.get("meaningful_name") or artifact.get("filename") or artifact["sha256"]),
        "severity": severity,
        "disposition": disposition,
        "summary": (
            f"VirusTotal reports {malicious} malicious and {suspicious} suspicious detections "
            f"for {attributes.get('meaningful_name') or artifact.get('filename') or artifact['sha256']}."
        ),
        "details": {
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "reputation": int(attributes.get("reputation", 0) or 0),
            "meaningful_name": attributes.get("meaningful_name", ""),
            "tags": list(attributes.get("tags") or [])[:6],
            "malware_names": malware_names[:5],
            "threat_verdict": threat_verdict,
            "threat_severity": ((attributes.get("threat_severity") or {}).get("threat_severity_level") or ""),
        },
        "context": _artifact_context(artifact),
    }


def _normalize_virustotal_domain(payload: dict[str, Any], domain_input: dict[str, Any]) -> dict[str, Any]:
    name = str(domain_input.get("domain", ""))
    if payload.get("_wireglass_not_found"):
        return {
            "provider": "virustotal",
            "provider_label": "VirusTotal",
            "indicator_type": "domain",
            "indicator": name,
            "indicator_label": name,
            "severity": "low",
            "disposition": "not_found",
            "summary": f"VirusTotal does not currently have a public report for domain {name}.",
            "details": {},
            "context": _domain_context(domain_input),
        }

    attributes = (((payload.get("data") or {}).get("attributes")) or {})
    stats = attributes.get("last_analysis_stats") or {}
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    reputation = int(attributes.get("reputation", 0) or 0)
    severity = "high" if malicious or reputation < 0 else "medium" if suspicious else "low"
    disposition = "malicious" if severity == "high" else "suspicious" if severity == "medium" else "clean"
    return {
        "provider": "virustotal",
        "provider_label": "VirusTotal",
        "indicator_type": "domain",
        "indicator": name,
        "indicator_label": name,
        "severity": severity,
        "disposition": disposition,
        "summary": f"VirusTotal reports {malicious} malicious and {suspicious} suspicious verdicts for domain {name}.",
        "details": {
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": int(stats.get("harmless", 0)),
            "undetected": int(stats.get("undetected", 0)),
            "reputation": reputation,
            "categories": attributes.get("categories") or {},
            "tags": list(attributes.get("tags") or [])[:6],
            "registrar": attributes.get("registrar", ""),
        },
        "context": _domain_context(domain_input),
    }


def _normalize_malwarebazaar_hash(payload: dict[str, Any], artifact: dict[str, Any]) -> dict[str, Any]:
    status = str(payload.get("query_status", ""))
    if status in {"hash_not_found", "no_results"}:
        return {
            "provider": "malwarebazaar",
            "provider_label": "MalwareBazaar",
            "indicator_type": "file_hash",
            "indicator": artifact["sha256"],
            "indicator_label": artifact.get("filename") or artifact["sha256"],
            "severity": "low",
            "disposition": "not_found",
            "summary": f"MalwareBazaar does not currently list {artifact.get('filename') or artifact['sha256']}.",
            "details": {},
            "context": _artifact_context(artifact),
        }

    entries = payload.get("data") or []
    first = entries[0] if isinstance(entries, list) and entries else {}
    if not isinstance(first, dict):
        first = {}

    signature = str(first.get("signature") or "")
    tags = list(first.get("tags") or [])[:6]
    delivery_method = list((first.get("delivery_method") or {}).keys())[:4] if isinstance(first.get("delivery_method"), dict) else []
    vendor_intel_sources = list((first.get("vendor_intel") or {}).keys())[:6] if isinstance(first.get("vendor_intel"), dict) else []

    return {
        "provider": "malwarebazaar",
        "provider_label": "MalwareBazaar",
        "indicator_type": "file_hash",
        "indicator": artifact["sha256"],
        "indicator_label": str(first.get("file_name") or artifact.get("filename") or artifact["sha256"]),
        "severity": "high",
        "disposition": "malicious",
        "summary": (
            f"MalwareBazaar lists {artifact.get('filename') or artifact['sha256']} "
            f"as {signature or 'known malware'}."
        ),
        "details": {
            "signature": signature,
            "file_name": first.get("file_name", ""),
            "first_seen": first.get("first_seen", ""),
            "last_seen": first.get("last_seen", ""),
            "reporter": first.get("reporter", ""),
            "file_type": first.get("file_type", ""),
            "mime": first.get("file_type_mime", ""),
            "tags": tags,
            "delivery_methods": delivery_method,
            "vendor_intel_sources": vendor_intel_sources,
        },
        "context": _artifact_context(artifact),
    }


def _artifact_context(artifact: dict[str, Any]) -> dict[str, Any]:
    return {
        "destination_ip": artifact.get("destination_ip", ""),
        "source_ip": artifact.get("source_ip", ""),
        "request_host": artifact.get("request_host", ""),
        "request_path": artifact.get("request_path", ""),
        "filename": artifact.get("filename", ""),
    }


def _domain_context(domain_input: dict[str, Any]) -> dict[str, Any]:
    return {
        "host_ip": domain_input.get("host_ip", ""),
        "peer_ip": domain_input.get("peer_ip", ""),
        "source": domain_input.get("source", ""),
    }
