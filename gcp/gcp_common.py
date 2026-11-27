#!/usr/bin/env python3
"""
Shared read-only GCP REST client (Application Default Credentials), pagination,
CSV & Markdown helpers for GCP Security Audits.
"""

from __future__ import annotations

import csv
import datetime as dt
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import google.auth
from google.auth.transport.requests import Request as GoogleAuthRequest
import requests

GCP_SCOPES = ["https://www.googleapis.com/auth/cloud-platform.read-only"]


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def parse_iso_dt(value: Optional[str]) -> Optional[dt.datetime]:
    if not value:
        return None
    try:
        cleaned = value.replace("Z", "+00:00")
        parsed = dt.datetime.fromisoformat(cleaned)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=dt.timezone.utc)
        return parsed
    except ValueError:
        return None


def fmt_dt(timestamp: Optional[dt.datetime]) -> str:
    if not timestamp:
        return ""
    return timestamp.astimezone(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def days_ago(timestamp: Optional[dt.datetime], now: dt.datetime) -> Optional[int]:
    if not timestamp:
        return None
    return max(0, (now - timestamp).days)


def log(msg: str) -> None:
    print(f"[{dt.datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


@dataclass
class GcpAuditContext:
    output_dir: Path
    csv_dir: Path
    days: int
    stale_days: int
    now: dt.datetime = field(default_factory=utc_now)
    warnings: List[str] = field(default_factory=list)

    def warn(self, msg: str) -> None:
        log(f"WARNING: {msg}")
        self.warnings.append(msg)


class GcpClient:
    """Strictly read-only GCP REST client using Application Default Credentials."""

    def __init__(self) -> None:
        self.credentials, self.default_project = google.auth.default(scopes=GCP_SCOPES)
        self.session = requests.Session()

    def _get_token(self) -> str:
        if not self.credentials.valid:
            self.credentials.refresh(GoogleAuthRequest())
        return str(self.credentials.token)

    def request(
        self,
        method: str,
        url: str,
        json_body: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
        timeout: int = 60,
    ) -> requests.Response:
        resp = None
        for attempt in range(5):
            headers = {
                "Authorization": f"Bearer {self._get_token()}",
                "Content-Type": "application/json",
            }
            resp = self.session.request(
                method, url, headers=headers, json=json_body, params=params, timeout=timeout
            )
            if resp.status_code in (429, 502, 503, 504):
                time.sleep(min(2 ** (attempt + 1), 30))
                continue
            return resp
        assert resp is not None
        return resp

    def get_paginated(
        self, url: str, list_key: str, params: Optional[Dict[str, Any]] = None
    ) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        items: List[Dict[str, Any]] = []
        q = dict(params or {})
        while True:
            resp = self.request("GET", url, params=q)
            if resp.status_code >= 400:
                return items, f"HTTP {resp.status_code} on {url}: {resp.text[:250]}"
            data = resp.json()
            items.extend(data.get(list_key, []))
            token = data.get("nextPageToken")
            if not token:
                break
            q["pageToken"] = token
        return items, None


def write_csv(path: Path, fieldnames: List[str], rows: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def md_table(headers: List[str], rows: List[List[str]]) -> str:
    if not rows:
        return "_No findings in this category._\n"
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join(["---"] * len(headers)) + " |",
    ]
    for r in rows:
        safe = [str(c).replace("|", "\\|").replace("\n", " ") for c in r]
        lines.append("| " + " | ".join(safe) + " |")
    return "\n".join(lines) + "\n"
