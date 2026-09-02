#!/usr/bin/env python3
"""Policy-enforcing Splunk REST client for live threat-hunting agents."""

import base64
import hashlib
import json
import os
import re
import ssl
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional
from urllib import error, request
from urllib.parse import urlencode


DEFAULT_ALLOWED_INDEXES = {
    "ad", "aws", "azure", "cloud", "email", "endpoint", "gcp", "identity",
    "main", "network", "notable", "proxy", "security", "threat_intel",
}
BLOCKED_COMMANDS = {
    "collect", "delete", "dump", "map", "outputcsv", "outputlookup",
    "runshellscript", "script", "sendalert",
}
_INDEX_RE = re.compile(r"\bindex\s*=\s*(?:\"([^\"]+)\"|'([^']+)'|([^\s|()]+))", re.I)
_INLINE_EARLIEST_RE = re.compile(r"\bearliest\s*=\s*([^\s|)]+)", re.I)
_RELATIVE_TIME_RE = re.compile(r"^-(\d+)([smhdw])(?:@[smhdw])?$", re.I)
_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}


class QueryPolicyError(ValueError):
    """Raised before a query that violates the live-hunting policy is sent."""


@dataclass
class SearchResult:
    sid: str
    rows: List[Dict[str, object]]


def _allowed_indexes() -> set:
    configured = os.environ.get("SPLUNK_ALLOWED_INDEXES", "")
    if not configured.strip():
        return set(DEFAULT_ALLOWED_INDEXES)
    return {value.strip() for value in configured.split(",") if value.strip()}


def validate_query(spl: str, earliest: str, max_results: int = 500) -> None:
    """Validate a read-only, scoped SPL query before network execution."""
    if not spl or not spl.strip():
        raise QueryPolicyError("SPL query cannot be empty")

    commands = {
        segment.strip().split(None, 1)[0].lower()
        for segment in spl.split("|")
        if segment.strip()
    }
    blocked = sorted(commands & BLOCKED_COMMANDS)
    if blocked:
        raise QueryPolicyError(f"blocked SPL command: {', '.join(blocked)}")
    if "`" in spl:
        raise QueryPolicyError("SPL macros are not permitted because their expansion cannot be validated")

    indexes = {next(value for value in match.groups() if value is not None) for match in _INDEX_RE.finditer(spl)}
    if not indexes:
        raise QueryPolicyError("query must explicitly scope at least one index")
    if any("*" in value for value in indexes):
        raise QueryPolicyError("wildcard indexes are not permitted")
    disallowed = indexes - _allowed_indexes()
    if disallowed:
        raise QueryPolicyError(f"index is not allowlisted: {', '.join(sorted(disallowed))}")

    maximum = int(os.environ.get("SPLUNK_MAX_LOOKBACK_DAYS", "90")) * 86400
    time_values = [earliest.strip(), *[match.group(1) for match in _INLINE_EARLIEST_RE.finditer(spl)]]
    for value in time_values:
        relative = _RELATIVE_TIME_RE.fullmatch(value)
        if not relative:
            raise QueryPolicyError("earliest must be a bounded negative relative time such as -24h or -30d@d")
        amount, unit = int(relative.group(1)), relative.group(2).lower()
        if amount * _UNIT_SECONDS[unit] > maximum:
            raise QueryPolicyError("earliest exceeds SPLUNK_MAX_LOOKBACK_DAYS")

    maximum_results = int(os.environ.get("SPLUNK_MAX_RESULTS", "500"))
    if max_results < 1 or max_results > maximum_results:
        raise QueryPolicyError(f"result limit must be between 1 and {maximum_results}")


def _audit(event: Dict[str, object]) -> None:
    path = Path(os.environ.get("AGENT_AUDIT_LOG", "/tmp/threat-intel-agent-audit.jsonl"))
    path.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **event,
    }
    line = json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
    fd = os.open(str(path), os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
    try:
        os.write(fd, line.encode("utf-8"))
    finally:
        os.close(fd)


class SplunkClient:
    """Small Splunk REST client that cannot bypass the local query policy."""

    def __init__(self, base_url: Optional[str] = None, verify_ssl: Optional[bool] = None):
        self.base_url = (base_url or os.environ.get("SPLUNK_URL", "")).rstrip("/")
        if not self.base_url:
            raise ValueError("SPLUNK_URL is required")
        self.verify_ssl = (
            os.environ.get("SPLUNK_VERIFY_SSL", "true").lower() != "false"
            if verify_ssl is None else verify_ssl
        )

    @staticmethod
    def _auth_header() -> Dict[str, str]:
        token = os.environ.get("SPLUNK_TOKEN")
        if token:
            return {"Authorization": f"Bearer {token}"}
        user = os.environ.get("SPLUNK_USERNAME", "")
        password = os.environ.get("SPLUNK_PASSWORD", "")
        if user and password:
            encoded = base64.b64encode(f"{user}:{password}".encode()).decode()
            return {"Authorization": f"Basic {encoded}"}
        raise ValueError("set SPLUNK_TOKEN or SPLUNK_USERNAME and SPLUNK_PASSWORD")

    def _request(self, url: str, method: str = "GET", data: Optional[Dict[str, object]] = None) -> Dict[str, object]:
        headers = {**self._auth_header(), "Content-Type": "application/x-www-form-urlencoded"}
        body = urlencode(data).encode() if data else None
        req = request.Request(url, data=body, headers=headers, method=method)
        context = None
        if not self.verify_ssl:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        for attempt in range(3):
            try:
                with request.urlopen(req, context=context, timeout=30) as response:
                    return json.loads(response.read())
            except error.HTTPError as exc:
                if exc.code != 429 and exc.code < 500:
                    raise
                if attempt == 2:
                    raise
            except error.URLError:
                if attempt == 2:
                    raise
            time.sleep(2 ** attempt)
        raise RuntimeError("unreachable")

    def search(self, spl: str, earliest: str, max_results: int = 500) -> SearchResult:
        validate_query(spl, earliest, max_results)
        query = spl if spl.lstrip().startswith("search ") else f"search {spl}"
        created = self._request(
            f"{self.base_url}/services/search/jobs",
            method="POST",
            data={
                "search": query,
                "earliest_time": earliest,
                "latest_time": "now",
                "output_mode": "json",
                "exec_mode": "normal",
            },
        )
        sid = str(created["sid"])
        state = "UNKNOWN"
        for _ in range(120):
            status = self._request(f"{self.base_url}/services/search/jobs/{sid}?output_mode=json")
            state = str(status["entry"][0]["content"]["dispatchState"])
            if state in {"DONE", "FAILED"}:
                break
            time.sleep(2)
        if state != "DONE":
            raise RuntimeError(f"Splunk search {sid} ended in state {state}")

        rows: List[Dict[str, object]] = []
        offset = 0
        while len(rows) < max_results:
            page_size = min(500, max_results - len(rows))
            page = self._request(
                f"{self.base_url}/services/search/jobs/{sid}/results"
                f"?output_mode=json&count={page_size}&offset={offset}"
            )
            batch = page.get("results", [])
            if not isinstance(batch, list):
                raise RuntimeError("Splunk returned a malformed results payload")
            rows.extend(batch)
            offset += len(batch)
            if len(batch) < page_size:
                break
        return SearchResult(sid=sid, rows=rows)


def count_then_search(
    count_spl: str,
    detail_spl: str,
    earliest: str,
    *,
    threshold: int = 10000,
    max_results: int = 500,
    agent: str = "unknown",
    operator: str = "unknown",
    model: str = "unknown",
    client: Optional[SplunkClient] = None,
) -> List[Dict[str, object]]:
    """Run an inexpensive count first, then a bounded detail query when approved."""
    common = {"agent": agent, "operator": operator, "model": model, "earliest": earliest}
    try:
        if not re.search(r"\|\s*stats\s+count\s*$", count_spl, re.I):
            raise QueryPolicyError("count query must end in a scalar stats count aggregation")
        validate_query(count_spl, earliest, 1)
        validate_query(detail_spl, earliest, max_results)
    except QueryPolicyError as exc:
        _audit({
            **common,
            "action": "policy_blocked",
            "reason": str(exc),
            "count_query_sha256": hashlib.sha256(count_spl.encode()).hexdigest(),
            "detail_query_sha256": hashlib.sha256(detail_spl.encode()).hexdigest(),
        })
        raise
    client = client or SplunkClient()
    count_result = client.search(count_spl, earliest, 1)
    try:
        event_count = int(count_result.rows[0]["count"]) if count_result.rows else 0
    except (KeyError, TypeError, ValueError) as exc:
        raise RuntimeError("count query did not return an integer count field") from exc

    _audit({
        **common,
        "action": "count",
        "sid": count_result.sid,
        "event_count": event_count,
        "query_sha256": hashlib.sha256(count_spl.encode()).hexdigest(),
    })
    if event_count > threshold:
        _audit({**common, "action": "detail_blocked", "event_count": event_count, "threshold": threshold})
        raise QueryPolicyError(f"count {event_count} exceeds threshold {threshold}")

    detail_result = client.search(detail_spl, earliest, max_results)
    _audit({
        **common,
        "action": "detail",
        "sid": detail_result.sid,
        "result_count": len(detail_result.rows),
        "query_sha256": hashlib.sha256(detail_spl.encode()).hexdigest(),
    })
    return detail_result.rows
