from __future__ import annotations

import csv
import base64
import io
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener, urlopen

from . import __version__
from .case import (
    add_artifact_bytes,
    add_observation,
    add_provider_run,
    add_source,
    append_ledger,
    assert_case_mutable,
)
from .util import ensure_case, new_id, read_json, safe_filename, utc_now, write_json
from .policy import normalized_target, provider_profiles, reserve_approved_run


MAX_RESPONSE_BYTES = 20 * 1024 * 1024
MAX_RETRIES = 2
MAX_RETRY_DELAY_SECONDS = 10
USER_AGENT = f"OSINT-Toolbox/{__version__} (evidence-first passive collector)"
IANA_RDAP_BOOTSTRAP = "https://data.iana.org/rdap/dns.json"
WHATS_MY_NAME_DATA = "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json"
SECURITYTRAILS_API_ROOT = "https://api.securitytrails.com/v1"
SHERLOCK_PROJECT_URL = "https://github.com/sherlock-project/sherlock"
HIBP_API_ROOT = "https://haveibeenpwned.com/api/v3"

PROVIDERS = {
    "wayback": {
        "name": "Internet Archive Wayback CDX",
        "mode": "passive",
        "target": "URL or domain",
        "target_disclosure": "external",
        "options": ("match_type", "from", "to", "limit", "timeout"),
        "notes": "Queries the CDX index; it does not replay archived pages.",
    },
    "rdap": {
        "name": "ICANN/IANA-bootstrapped RDAP",
        "mode": "passive-authoritative",
        "target": "domain",
        "target_disclosure": "external",
        "options": ("timeout",),
        "notes": "Discovers the authoritative RDAP service from the IANA bootstrap registry.",
    },
    "crtsh": {
        "name": "crt.sh certificate transparency search",
        "mode": "passive-community",
        "target": "domain",
        "target_disclosure": "external",
        "options": ("include_subdomains", "limit", "timeout"),
        "notes": "Uses crt.sh's public JSON query interface; treat availability and fields as unstable.",
    },
    "commoncrawl": {
        "name": "Common Crawl index",
        "mode": "passive",
        "target": "URL pattern or domain",
        "target_disclosure": "external",
        "options": ("index", "match_type", "limit", "timeout"),
        "notes": "Queries the current crawl index only; it does not retrieve WARC content or target pages.",
    },
    "dns": {
        "name": "Google Public DNS-over-HTTPS",
        "mode": "passive-resolver",
        "target": "domain",
        "target_disclosure": "external",
        "options": ("record_type", "dnssec", "timeout"),
        "notes": "Queries one explicit DNS record type per run and preserves the JSON response.",
    },
    "securitytrails": {
        "name": "SecurityTrails historical DNS",
        "mode": "passive-licensed",
        "target": "domain",
        "target_disclosure": "external",
        "options": ("record_type", "page", "limit", "timeout"),
        "notes": "Requires SECURITYTRAILS_API_KEY; queries one historical DNS record type and page per run.",
    },
    "searxng": {
        "name": "SearXNG JSON search",
        "mode": "passive-configured",
        "target": "search query",
        "target_disclosure": "external",
        "options": ("base_url", "categories", "language", "time_range", "safesearch", "limit", "timeout"),
        "notes": "Requires --option base_url=... or OSINT_SEARXNG_URL and JSON output enabled on that instance.",
    },
    "sherlock": {
        "name": "Sherlock scoped username checks",
        "mode": "passive-local-runner",
        "target": "username",
        "target_disclosure": "external",
        "options": ("sites", "timeout", "max_runtime"),
        "notes": "Requires a local sherlock command and an explicit comma-separated sites allowlist (maximum 25).",
    },
    "whatsmyname": {
        "name": "WhatsMyName manual-review queue",
        "mode": "dataset-only",
        "target": "username",
        "target_disclosure": "none",
        "options": ("limit", "include_nsfw", "timeout"),
        "notes": "Downloads the community dataset and creates unverified candidate URLs; never requests profile sites.",
    },
    "hibp-account": {
        "name": "HIBP authorized account breach lookup", "mode": "passive-licensed-high-risk",
        "target": "self/authorized email", "target_disclosure": "external", "options": ("timeout",),
        "notes": "Requires exact-target approval and HIBP_API_KEY; no password or stealer-log queries.",
    },
    "hibp-domain": {
        "name": "HIBP verified-domain breach lookup", "mode": "passive-licensed-high-risk",
        "target": "verified domain", "target_disclosure": "external", "options": ("limit", "timeout"),
        "notes": "Requires exact-target approval, HIBP_API_KEY, and provider-side subscribed-domain verification.",
    },
    "hunter-domain": {
        "name": "Hunter authorized domain search", "mode": "passive-licensed-high-risk",
        "target": "authorized domain", "target_disclosure": "external", "options": ("limit", "timeout"),
        "notes": "Requires exact-target approval and HUNTER_API_KEY; returns candidate professional addresses.",
    },
    "censys-host": {
        "name": "Censys Platform v3 host lookup", "mode": "passive-licensed-high-risk",
        "target": "authorized public IP", "target_disclosure": "external", "options": ("timeout",),
        "notes": "Requires exact-target approval and CENSYS_PAT; lookup only, never a live rescan.",
    },
    "companies-house": {
        "name": "UK Companies House company search", "mode": "official-registry-api",
        "target": "company name", "target_disclosure": "external", "options": ("limit", "timeout"),
        "notes": "Requires exact-target approval and COMPANIES_HOUSE_API_KEY; one bounded search.",
    },
}


@dataclass
class FetchResult:
    requested_url: str
    final_url: str
    content: bytes
    content_type: str
    status: int = 200


@dataclass
class PreparedCollection:
    provider: str
    request_url: str
    source_title: str
    topic: str
    reliability: str
    credibility: str
    raw_name: str
    raw_content: bytes
    content_type: str
    records: list[dict[str, Any]]
    source_notes: str = ""


class _SameOriginRedirect(HTTPRedirectHandler):
    """Keep credentialed requests and their target/query on one HTTPS origin."""

    def __init__(self, origin: str) -> None:
        self.origin = origin

    def redirect_request(self, req: Request, fp: Any, code: int, msg: str,
                         headers: Any, newurl: str) -> Request | None:
        parsed = urlsplit(newurl)
        if parsed.scheme != "https" or parsed.netloc.lower() != self.origin:
            raise ValueError("Credentialed provider redirect to another origin was refused")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _retry_delay(headers: Any, attempt: int) -> float:
    retry_after = headers.get("Retry-After") if headers is not None else None
    if retry_after:
        try:
            return min(max(float(retry_after), 0.0), MAX_RETRY_DELAY_SECONDS)
        except ValueError:
            pass
    return min(float(2**attempt), MAX_RETRY_DELAY_SECONDS)


def _fetch(
    url: str,
    timeout: int = 30,
    accept: str = "application/json",
    retries: int = MAX_RETRIES,
    headers: dict[str, str] | None = None,
    allow_statuses: set[int] | None = None,
) -> FetchResult:
    if not url.startswith(("https://", "http://")):
        raise ValueError("Provider URL must use HTTP or HTTPS")
    if headers and urlsplit(url).scheme != "https":
        raise ValueError("Credentialed provider requests require HTTPS")
    if not 0 <= retries <= 4:
        raise ValueError("Provider retries must be between 0 and 4")
    transient_statuses = {429, 500, 502, 503, 504}
    for attempt in range(retries + 1):
        request_headers = {"User-Agent": USER_AGENT, "Accept": accept}
        request = Request(url, headers=request_headers)
        # Credential headers are intentionally not copied to redirected
        # requests by urllib's redirect handler.
        for name, value in (headers or {}).items():
            request.add_unredirected_header(name, value)
        try:
            opener = build_opener(_SameOriginRedirect(urlsplit(url).netloc.lower())) if headers else None
            with (opener.open(request, timeout=timeout) if opener else urlopen(request, timeout=timeout)) as response:
                content = response.read(MAX_RESPONSE_BYTES + 1)
                if len(content) > MAX_RESPONSE_BYTES:
                    raise ValueError(f"Provider response exceeded {MAX_RESPONSE_BYTES} bytes")
                return FetchResult(
                    requested_url=url,
                    final_url=response.geturl(),
                    content=content,
                    content_type=response.headers.get_content_type(),
                    status=response.status,
                )
        except HTTPError as exc:
            if exc.code in (allow_statuses or set()):
                content = exc.read(MAX_RESPONSE_BYTES + 1)
                if len(content) > MAX_RESPONSE_BYTES:
                    raise ValueError(f"Provider response exceeded {MAX_RESPONSE_BYTES} bytes")
                return FetchResult(url, exc.geturl(), content, exc.headers.get_content_type(), exc.code)
            if exc.code in transient_statuses and attempt < retries:
                time.sleep(_retry_delay(exc.headers, attempt))
                continue
            raise ValueError(f"Provider returned HTTP {exc.code} for {url} after {attempt + 1} attempt(s)") from exc
        except URLError as exc:
            if attempt < retries:
                time.sleep(_retry_delay(None, attempt))
                continue
            raise ValueError(f"Provider request failed for {url} after {attempt + 1} attempt(s): {exc.reason}") from exc
    raise ValueError(f"Provider request failed unexpectedly: {url}")  # pragma: no cover


def _json(fetch: FetchResult) -> Any:
    try:
        return json.loads(fetch.content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Provider did not return valid UTF-8 JSON: {fetch.final_url}") from exc


def _integer(options: dict[str, str], name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(options.get(name, str(default)))
    except ValueError as exc:
        raise ValueError(f"Provider option {name} must be an integer") from exc
    if not minimum <= value <= maximum:
        raise ValueError(f"Provider option {name} must be between {minimum} and {maximum}")
    return value


def _boolean(options: dict[str, str], name: str, default: bool) -> bool:
    value = options.get(name, str(default)).strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"Provider option {name} must be true or false")


def _validate_collection_options(provider: str, options: dict[str, str]) -> None:
    allowed = set(PROVIDERS[provider]["options"])
    unknown = sorted(set(options) - allowed)
    if unknown:
        raise ValueError(
            f"Unsupported {provider} provider option(s): {', '.join(unknown)}; "
            f"allowed options: {', '.join(sorted(allowed))}"
        )


def _domain(target: str) -> str:
    value = target.strip().lower().rstrip(".")
    if "://" in value:
        value = (urlsplit(value).hostname or "").lower().rstrip(".")
    if not value or "." not in value or any(char.isspace() for char in value):
        raise ValueError(f"Expected a domain, received: {target}")
    try:
        return value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"Invalid internationalized domain: {target}") from exc


def parse_wayback_rows(payload: Any, limit: int) -> list[dict[str, Any]]:
    if not isinstance(payload, list) or not payload:
        return []
    if not isinstance(payload[0], list):
        raise ValueError("Unexpected Wayback CDX response shape")
    headers = [str(item) for item in payload[0]]
    records: list[dict[str, Any]] = []
    for row in payload[1 : limit + 1]:
        if not isinstance(row, list):
            continue
        value = dict(zip(headers, row))
        records.append({
            "kind": "archive.capture",
            "value": value,
            "observed_at": str(value.get("timestamp", "")),
            "status": "observed",
        })
    return records


def _wayback(target: str, options: dict[str, str]) -> PreparedCollection:
    limit = _integer(options, "limit", 100, 1, 1000)
    inferred_match = "domain" if "://" not in target and "/" not in target else "exact"
    match_type = options.get("match_type", inferred_match).lower()
    if match_type not in {"exact", "prefix", "host", "domain"}:
        raise ValueError("Wayback match_type must be exact, prefix, host, or domain")
    params = {
        "url": target.strip(), "output": "json", "fl": "timestamp,original,mimetype,statuscode,digest,length",
        "matchType": match_type, "limit": str(limit), "filter": "statuscode:200", "collapse": "digest",
    }
    for name in ("from", "to"):
        if options.get(name):
            params[name] = options[name]
    url = "https://web.archive.org/cdx/search/cdx?" + urlencode(params)
    fetched = _fetch(url, _integer(options, "timeout", 30, 5, 120))
    records = parse_wayback_rows(_json(fetched), limit)
    return PreparedCollection(
        "wayback", fetched.final_url, "Wayback CDX query", "archives", "secondary", "medium",
        "wayback-cdx.json", fetched.content, fetched.content_type, records,
        "Index results are leads. Open and assess relevant archived captures separately.",
    )


def select_rdap_base(bootstrap: Any, domain: str) -> str:
    if not isinstance(bootstrap, dict) or not isinstance(bootstrap.get("services"), list):
        raise ValueError("Invalid IANA RDAP bootstrap data")
    tld = domain.rsplit(".", 1)[-1].lower()
    for service in bootstrap["services"]:
        if not isinstance(service, list) or len(service) != 2:
            continue
        names, urls = service
        if isinstance(names, list) and tld in {str(name).lower() for name in names} and isinstance(urls, list) and urls:
            return str(urls[0])
    raise ValueError(f"No RDAP service found for .{tld}")


def parse_rdap(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        raise ValueError("Unexpected RDAP response shape")
    records: list[dict[str, Any]] = []
    if payload.get("ldhName"):
        records.append({"kind": "domain.name", "value": payload["ldhName"], "status": "observed"})
    for status in payload.get("status", []):
        records.append({"kind": "domain.status", "value": status, "status": "observed"})
    for event in payload.get("events", []):
        if isinstance(event, dict):
            records.append({
                "kind": "domain.event", "value": event,
                "observed_at": str(event.get("eventDate", "")), "status": "observed",
            })
    for nameserver in payload.get("nameservers", []):
        if isinstance(nameserver, dict) and nameserver.get("ldhName"):
            records.append({"kind": "domain.nameserver", "value": nameserver["ldhName"], "status": "observed"})
    for entity in payload.get("entities", []):
        if isinstance(entity, dict):
            records.append({
                "kind": "domain.rdap-entity",
                "value": {key: entity.get(key) for key in ("handle", "roles", "publicIds") if entity.get(key)},
                "status": "observed",
            })
    return records


def _rdap(target: str, options: dict[str, str]) -> PreparedCollection:
    domain = _domain(target)
    timeout = _integer(options, "timeout", 30, 5, 120)
    bootstrap_fetch = _fetch(IANA_RDAP_BOOTSTRAP, timeout)
    base = select_rdap_base(_json(bootstrap_fetch), domain)
    url = base.rstrip("/") + "/domain/" + quote(domain, safe="")
    fetched = _fetch(url, timeout)
    return PreparedCollection(
        "rdap", fetched.final_url, f"Authoritative RDAP record for {domain}", "domain", "primary", "high",
        f"rdap-{safe_filename(domain)}.json", fetched.content, fetched.content_type, parse_rdap(_json(fetched)),
        f"Service endpoint selected using the IANA RDAP DNS bootstrap registry: {IANA_RDAP_BOOTSTRAP}",
    )


def parse_crtsh(payload: Any, limit: int) -> list[dict[str, Any]]:
    if not isinstance(payload, list):
        raise ValueError("Unexpected crt.sh response shape")
    records: list[dict[str, Any]] = []
    for certificate in payload[:limit]:
        if not isinstance(certificate, dict):
            continue
        names: list[str] = []
        for field in ("common_name", "name_value"):
            value = certificate.get(field, "")
            if isinstance(value, str):
                names.extend(part.strip().lower() for part in value.splitlines() if part.strip())
        normalized = {
            key: certificate.get(key) for key in
            ("id", "issuer_ca_id", "issuer_name", "common_name", "name_value", "entry_timestamp", "not_before", "not_after", "serial_number")
            if certificate.get(key) is not None
        }
        normalized["dns_names"] = sorted(set(names))
        records.append({
            "kind": "certificate-transparency.entry", "value": normalized,
            "observed_at": str(certificate.get("entry_timestamp", "")), "status": "observed",
        })
    return records


def _crtsh(target: str, options: dict[str, str]) -> PreparedCollection:
    domain = _domain(target)
    include_subdomains = _boolean(options, "include_subdomains", True)
    limit = _integer(options, "limit", 250, 1, 2000)
    query = f"%.{domain}" if include_subdomains else domain
    url = "https://crt.sh/?" + urlencode({"q": query, "output": "json"})
    fetched = _fetch(url, _integer(options, "timeout", 45, 5, 120))
    return PreparedCollection(
        "crtsh", fetched.final_url, f"crt.sh certificate search for {domain}", "domain", "secondary", "medium",
        f"crtsh-{safe_filename(domain)}.json", fetched.content, fetched.content_type, parse_crtsh(_json(fetched), limit),
        "Public certificate-transparency index. Names are leads, not proof of current control or service availability.",
    )


def parse_commoncrawl(content: bytes, limit: int) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line_number, line in enumerate(content.decode("utf-8").splitlines(), 1):
        if not line.strip() or len(records) >= limit:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid Common Crawl JSON on response line {line_number}") from exc
        if not isinstance(item, dict):
            raise ValueError("Unexpected Common Crawl response shape")
        if item.get("message") and not item.get("url"):
            raise ValueError(f"Common Crawl index error: {item['message']}")
        value = {
            key: item.get(key) for key in
            ("urlkey", "timestamp", "url", "mime", "mime-detected", "status", "digest", "length", "offset", "filename", "languages", "encoding")
            if item.get(key) is not None
        }
        records.append({
            "kind": "web-crawl.index-entry", "value": value,
            "observed_at": str(item.get("timestamp", "")), "status": "observed",
        })
    return records


def _commoncrawl(target: str, options: dict[str, str]) -> PreparedCollection:
    value = target.strip()
    if not value or any(char.isspace() for char in value):
        raise ValueError("Common Crawl requires one URL, domain, or URL pattern without spaces")
    timeout = _integer(options, "timeout", 45, 5, 120)
    catalog_fetch = _fetch("https://index.commoncrawl.org/collinfo.json", timeout)
    catalog = _json(catalog_fetch)
    if not isinstance(catalog, list) or not catalog:
        raise ValueError("Common Crawl returned no index catalog")
    requested_index = options.get("index", "")
    selected = next(
        (
            item for item in catalog
            if isinstance(item, dict) and (not requested_index or item.get("id") == requested_index)
        ),
        None,
    )
    if not selected or not selected.get("cdx-api"):
        raise ValueError(f"Common Crawl index was not found: {requested_index}")
    limit = _integer(options, "limit", 100, 1, 1000)
    params = {"url": value, "output": "json", "limit": str(limit), "filter": "status:200", "collapse": "digest"}
    if options.get("match_type"):
        match_type = options["match_type"].lower()
        if match_type not in {"exact", "prefix", "host", "domain"}:
            raise ValueError("Common Crawl match_type must be exact, prefix, host, or domain")
        params["matchType"] = match_type
    url = str(selected["cdx-api"]) + "?" + urlencode(params)
    fetched = _fetch(url, timeout, "application/x-ndjson, application/json")
    return PreparedCollection(
        "commoncrawl", fetched.final_url, f"Common Crawl index query ({selected.get('id', 'unknown index')})",
        "archives", "secondary", "medium", "commoncrawl-index.ndjson", fetched.content,
        fetched.content_type, parse_commoncrawl(fetched.content, limit),
        "Index results are leads. WARC content was not retrieved. Index selected from https://index.commoncrawl.org/collinfo.json",
    )


DNS_TYPES = {"A", "AAAA", "CAA", "CNAME", "MX", "NS", "PTR", "SOA", "SRV", "TXT"}
DNS_TYPE_NAMES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 257: "CAA"}


def parse_dns(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, dict) or "Status" not in payload:
        raise ValueError("Unexpected DNS-over-HTTPS response shape")
    records: list[dict[str, Any]] = [{
        "kind": "dns.response-status",
        "value": {
            "rcode": payload.get("Status"), "truncated": payload.get("TC", False),
            "recursion_desired": payload.get("RD", False), "recursion_available": payload.get("RA", False),
            "authenticated_data": payload.get("AD", False), "checking_disabled": payload.get("CD", False),
            "comment": payload.get("Comment", ""),
        },
        "status": "observed",
    }]
    for answer in payload.get("Answer", []):
        if not isinstance(answer, dict):
            continue
        normalized = dict(answer)
        normalized["type_name"] = DNS_TYPE_NAMES.get(answer.get("type"), str(answer.get("type", "unknown")))
        records.append({"kind": "dns.answer", "value": normalized, "status": "observed"})
    return records


def _dns(target: str, options: dict[str, str]) -> PreparedCollection:
    domain = _domain(target)
    record_type = options.get("record_type", "A").upper()
    if record_type not in DNS_TYPES:
        raise ValueError("DNS record_type must be one of: " + ", ".join(sorted(DNS_TYPES)))
    params = {"name": domain, "type": record_type}
    if _boolean(options, "dnssec", True):
        params["do"] = "1"
    url = "https://dns.google/resolve?" + urlencode(params)
    fetched = _fetch(url, _integer(options, "timeout", 30, 5, 120), "application/dns-json")
    return PreparedCollection(
        "dns", fetched.final_url, f"Google Public DNS {record_type} response for {domain}", "domain",
        "secondary", "high", f"dns-{safe_filename(domain)}-{record_type}.json", fetched.content,
        fetched.content_type, parse_dns(_json(fetched)),
        "Recursive-resolver response; query authoritative DNS separately when that distinction matters.",
    )


SECURITYTRAILS_DNS_TYPES = {"A", "AAAA", "MX", "NS", "SOA", "TXT"}


def parse_securitytrails_history(payload: Any, record_type: str, limit: int) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        raise ValueError("Unexpected SecurityTrails DNS-history response shape")
    if "records" not in payload:
        message = payload.get("message")
        if isinstance(message, str) and message.strip():
            raise ValueError(f"SecurityTrails API error: {message.strip()}")
        raise ValueError("SecurityTrails DNS-history response omitted records")
    raw_records = payload["records"]
    if not isinstance(raw_records, list):
        raise ValueError("SecurityTrails DNS-history records must be a list")
    records: list[dict[str, Any]] = []
    for item in raw_records[:limit]:
        if not isinstance(item, dict):
            continue
        value = {
            "record_type": record_type.upper(),
            "first_seen": item.get("first_seen", ""),
            "last_seen": item.get("last_seen", ""),
            "organizations": item.get("organizations", []),
            "values": item.get("values", []),
        }
        records.append({
            "kind": "dns.history",
            "value": value,
            "observed_at": str(item.get("last_seen") or item.get("first_seen") or ""),
            "status": "observed",
            "notes": "Provider-derived historical DNS observation; coverage varies by provider plan and collection window.",
        })
    return records


def _securitytrails(target: str, options: dict[str, str]) -> PreparedCollection:
    domain = _domain(target)
    api_key = os.environ.get("SECURITYTRAILS_API_KEY", "").strip()
    if not api_key:
        raise ValueError("SecurityTrails requires the SECURITYTRAILS_API_KEY environment variable")
    if "\r" in api_key or "\n" in api_key:
        raise ValueError("SECURITYTRAILS_API_KEY contains an invalid newline")
    record_type = options.get("record_type", "A").upper()
    if record_type not in SECURITYTRAILS_DNS_TYPES:
        raise ValueError(
            "SecurityTrails record_type must be one of: " + ", ".join(sorted(SECURITYTRAILS_DNS_TYPES))
        )
    page = _integer(options, "page", 1, 1, 10000)
    limit = _integer(options, "limit", 100, 1, 1000)
    url = (
        f"{SECURITYTRAILS_API_ROOT}/history/{quote(domain, safe='')}/dns/{record_type.lower()}?"
        + urlencode({"page": str(page)})
    )
    fetched = _fetch(
        url,
        _integer(options, "timeout", 30, 5, 120),
        headers={"APIKEY": api_key},
    )
    return PreparedCollection(
        "securitytrails",
        fetched.final_url,
        f"SecurityTrails {record_type} DNS history for {domain}, page {page}",
        "domain",
        "secondary",
        "medium",
        f"securitytrails-{safe_filename(domain)}-{record_type}-page-{page}.json",
        fetched.content,
        fetched.content_type,
        parse_securitytrails_history(_json(fetched), record_type, limit),
        "Licensed passive-DNS history. Coverage, retention, pagination, and completeness depend on the account plan; corroborate important records.",
    )


def _licensed_key(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value or "\r" in value or "\n" in value:
        raise ValueError(f"A valid {name} environment credential is required")
    return value


def _hibp_key() -> str:
    value = _licensed_key("HIBP_API_KEY")
    if not re.fullmatch(r"[a-fA-F0-9]{32}", value):
        raise ValueError("HIBP_API_KEY must be a 32-character hexadecimal subscription key")
    return value


def _hibp_account(target: str, options: dict[str, str]) -> PreparedCollection:
    email = normalized_target("hibp-account", target)
    url = f"{HIBP_API_ROOT}/breachedAccount/{quote(email, safe='')}?truncateResponse=true"
    fetched = _fetch(url, _integer(options, "timeout", 30, 5, 120),
                     headers={"hibp-api-key": _hibp_key()}, allow_statuses={404})
    payload = [] if fetched.status == 404 else _json(fetched)
    if not isinstance(payload, list):
        raise ValueError("Unexpected HIBP account response shape")
    records = []
    for item in payload:
        if not isinstance(item, dict) or not isinstance(item.get("Name"), str):
            raise ValueError("Unexpected HIBP account breach item")
        records.append({"kind": "breach.account-membership", "value": {"breach_name": item["Name"]},
                        "status": "observed", "notes": "HIBP account match; verify breach relevance and timing separately."})
    return PreparedCollection(
        "hibp-account", fetched.final_url, f"HIBP account breach lookup for {email}", "breach-exposure",
        "secondary", "medium", "hibp-account-response.json", fetched.content, fetched.content_type,
        records, "Authorized account lookup only. HTTP 404 means no match in HIBP's current coverage, not proof of safety.",
    )


def _hibp_domain(target: str, options: dict[str, str]) -> PreparedCollection:
    domain = normalized_target("hibp-domain", target)
    timeout = _integer(options, "timeout", 30, 5, 120)
    headers = {"hibp-api-key": _hibp_key()}
    subscribed = _json(_fetch(f"{HIBP_API_ROOT}/subscribedDomains", timeout, headers=headers))
    if not isinstance(subscribed, list):
        raise ValueError("Unexpected HIBP subscribed-domain response")
    verified = {str(row.get("DomainName", "")).lower() for row in subscribed if isinstance(row, dict)}
    if domain not in verified:
        raise ValueError("Domain is not verified in this HIBP subscriber account; breach query was not sent")
    url = f"{HIBP_API_ROOT}/breachedDomain/{quote(domain, safe='')}"
    fetched = _fetch(url, timeout, headers=headers, allow_statuses={404})
    payload = {} if fetched.status == 404 else _json(fetched)
    if not isinstance(payload, dict):
        raise ValueError("Unexpected HIBP domain response shape")
    limit = _integer(options, "limit", 100, 1, 1000)
    records = []
    for alias, breaches in list(payload.items())[:limit]:
        if not isinstance(alias, str) or not isinstance(breaches, list):
            raise ValueError("Unexpected HIBP domain breach item")
        records.append({"kind": "breach.domain-alias", "value": {"alias": alias, "breach_names": breaches},
                        "status": "observed", "notes": "Alias from provider-verified domain; not a verified individual identity."})
    return PreparedCollection(
        "hibp-domain", fetched.final_url, f"HIBP verified-domain lookup for {domain}", "breach-exposure",
        "secondary", "medium", "hibp-domain-response.json", fetched.content, fetched.content_type,
        records, f"HIBP subscriber verification checked before query. Normalized {len(records)} of {len(payload)} aliases; raw response preserved. HTTP 404 is a current-coverage zero result.",
    )


def _hunter_domain(target: str, options: dict[str, str]) -> PreparedCollection:
    domain = normalized_target("hunter-domain", target)
    limit = _integer(options, "limit", 25, 1, 25)
    url = "https://api.hunter.io/v2/domain-search?" + urlencode({"domain": domain, "limit": limit})
    fetched = _fetch(url, _integer(options, "timeout", 30, 5, 120),
                     headers={"X-API-KEY": _licensed_key("HUNTER_API_KEY")})
    payload = _json(fetched)
    if not isinstance(payload, dict) or not isinstance(payload.get("data"), dict):
        raise ValueError("Unexpected Hunter domain-search response shape")
    emails = payload["data"].get("emails", [])
    if not isinstance(emails, list):
        raise ValueError("Unexpected Hunter email list")
    records = []
    for item in emails[:limit]:
        if isinstance(item, dict) and isinstance(item.get("value"), str):
            records.append({"kind": "email.professional-candidate", "value": {
                "email": item["value"], "confidence": item.get("confidence"),
                "sources": item.get("sources", []),
            }, "status": "candidate-unverified", "notes": "Discovery lead only; no outreach or identity attribution authorized by this result."})
    return PreparedCollection(
        "hunter-domain", fetched.final_url, f"Hunter domain search for {domain}", "professional-email",
        "secondary", "low", "hunter-domain-response.json", fetched.content, fetched.content_type,
        records, "One bounded domain-search page. Candidate addresses require source review and case-authorized use.",
    )


def _censys_host(target: str, options: dict[str, str]) -> PreparedCollection:
    address = normalized_target("censys-host", target)
    url = f"https://api.platform.censys.io/v3/global/asset/host/{quote(address, safe='')}"
    fetched = _fetch(url, _integer(options, "timeout", 30, 5, 120),
                     headers={"Authorization": "Bearer " + _licensed_key("CENSYS_PAT")})
    payload = _json(fetched)
    resource = payload.get("result", {}).get("resource") if isinstance(payload, dict) else None
    if not isinstance(resource, dict):
        raise ValueError("Unexpected Censys Platform v3 host response shape")
    services = resource.get("services", [])
    if not isinstance(services, list):
        services = []
    value = {"ip": resource.get("ip", address), "last_updated_at": resource.get("last_updated_at", ""),
             "services": [{"port": item.get("port"), "protocol": item.get("transport_protocol")}
                          for item in services[:100] if isinstance(item, dict)]}
    return PreparedCollection(
        "censys-host", fetched.final_url, f"Censys Platform host lookup for {address}", "host-exposure",
        "secondary", "medium", "censys-host-response.json", fetched.content, fetched.content_type,
        [{"kind": "host.indexed-services", "value": value, "status": "observed",
          "observed_at": str(value["last_updated_at"]), "notes": "Passive index snapshot, not a live scan."}],
        "Censys Platform v3 passive host lookup only; no live rescan was requested.",
    )


def _companies_house(target: str, options: dict[str, str]) -> PreparedCollection:
    query = normalized_target("companies-house", target)
    limit = _integer(options, "limit", 20, 1, 50)
    url = "https://api.company-information.service.gov.uk/search/companies?" + urlencode({"q": query, "items_per_page": limit})
    credential = base64.b64encode((_licensed_key("COMPANIES_HOUSE_API_KEY") + ":").encode("utf-8")).decode("ascii")
    fetched = _fetch(url, _integer(options, "timeout", 30, 5, 120),
                     headers={"Authorization": "Basic " + credential})
    payload = _json(fetched)
    if not isinstance(payload, dict) or not isinstance(payload.get("items", []), list):
        raise ValueError("Unexpected Companies House search response shape")
    records = []
    for item in payload.get("items", [])[:limit]:
        if isinstance(item, dict) and item.get("company_number"):
            records.append({"kind": "registry.company-candidate", "value": {
                "company_number": item["company_number"], "title": item.get("title", ""),
                "company_status": item.get("company_status", ""),
            }, "status": "candidate-unverified", "notes": "Name-search candidate; match registration number before attribution."})
    return PreparedCollection(
        "companies-house", fetched.final_url, f"Companies House company search: {query}", "official-registry",
        "primary", "high", "companies-house-search.json", fetched.content, fetched.content_type,
        records, "Official UK company-name search. Results remain candidates until identifier and filings are reviewed.",
    )


def parse_searxng(payload: Any, limit: int) -> list[dict[str, Any]]:
    if not isinstance(payload, dict) or not isinstance(payload.get("results", []), list):
        raise ValueError("Unexpected SearXNG response shape")
    records: list[dict[str, Any]] = []
    for result in payload.get("results", [])[:limit]:
        if not isinstance(result, dict):
            continue
        value = {
            key: result.get(key) for key in ("url", "title", "content", "engine", "engines", "score", "publishedDate")
            if result.get(key) is not None
        }
        records.append({
            "kind": "search.result", "value": value,
            "observed_at": str(result.get("publishedDate", "")), "status": "observed",
        })
    return records


def _searxng(target: str, options: dict[str, str]) -> PreparedCollection:
    query = target.strip()
    if not query:
        raise ValueError("SearXNG requires a non-empty search query")
    base = options.get("base_url") or os.environ.get("OSINT_SEARXNG_URL", "")
    if not base:
        raise ValueError("SearXNG requires --option base_url=https://... or OSINT_SEARXNG_URL")
    endpoint = base.rstrip("/")
    if not endpoint.endswith("/search"):
        endpoint += "/search"
    limit = _integer(options, "limit", 50, 1, 200)
    params = {"q": query, "format": "json"}
    time_range = options.get("time_range", "")
    if time_range and time_range not in {"day", "month", "year"}:
        raise ValueError("SearXNG time_range must be day, month, or year")
    if options.get("safesearch"):
        _integer(options, "safesearch", 0, 0, 2)
    for name in ("categories", "language", "time_range", "safesearch"):
        if options.get(name):
            params[name] = options[name]
    url = endpoint + "?" + urlencode(params)
    fetched = _fetch(url, _integer(options, "timeout", 30, 5, 120))
    return PreparedCollection(
        "searxng", fetched.final_url, f"SearXNG search: {query}", "search", "secondary", "medium",
        "searxng-results.json", fetched.content, fetched.content_type, parse_searxng(_json(fetched), limit),
        "Aggregated search results require review against the original pages.",
    )


SHERLOCK_USERNAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
SHERLOCK_SITE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._+&'-]{0,63}$")
SHERLOCK_OPTIONS = {"sites", "timeout", "max_runtime"}


def parse_sherlock_csv(content: bytes, limit: int) -> list[dict[str, Any]]:
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError("Sherlock CSV output was not valid UTF-8") from exc
    reader = csv.DictReader(io.StringIO(text))
    required = {"username", "name", "url_main", "url_user", "exists", "http_status", "response_time_s"}
    if reader.fieldnames is None or not required.issubset(set(reader.fieldnames)):
        raise ValueError("Sherlock CSV output omitted required columns")
    records: list[dict[str, Any]] = []
    for row in reader:
        if len(records) >= limit:
            break
        profile_url = str(row.get("url_user", "")).strip()
        if profile_url and not profile_url.startswith(("https://", "http://")):
            raise ValueError("Sherlock returned a non-HTTP profile URL")
        outcome = str(row.get("exists", "")).strip()
        outcome_key = outcome.lower()
        if "claimed" in outcome_key:
            kind = "username.profile-candidate"
            status = "candidate-unverified"
            note = "Sherlock reported a possible profile. Manually review stable identifiers and contrary evidence before attribution."
        elif "available" in outcome_key:
            kind = "username.profile-check"
            status = "unavailable"
            note = "Sherlock reported that this username was not claimed at collection time; this is not evidence that it was never used."
        else:
            kind = "username.profile-check"
            status = "unavailable"
            note = "Sherlock returned an inconclusive, blocked, invalid, or unknown result; do not interpret it as absence."
        records.append({
            "kind": kind,
            "value": {
                "username": str(row.get("username", "")).strip(),
                "site": str(row.get("name", "")).strip(),
                "site_url": str(row.get("url_main", "")).strip(),
                "profile_url": profile_url,
                "outcome": outcome,
                "http_status": str(row.get("http_status", "")).strip(),
                "response_time_s": str(row.get("response_time_s", "")).strip(),
                "verification": "manual_required" if status == "candidate-unverified" else "not_applicable",
            },
            "status": status,
            "notes": note,
        })
    return records


def _sherlock_version(executable: str) -> str:
    try:
        process = subprocess.run(
            [executable, "--version"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "unknown"
    output = (process.stdout or process.stderr).decode("utf-8", errors="replace").splitlines()
    return output[0].strip()[:200] if output else "unknown"


def _sherlock(target: str, options: dict[str, str]) -> PreparedCollection:
    unknown_options = sorted(set(options) - SHERLOCK_OPTIONS)
    if unknown_options:
        raise ValueError("Unsupported Sherlock option(s): " + ", ".join(unknown_options))
    username = target.strip().lstrip("@")
    if not SHERLOCK_USERNAME.fullmatch(username):
        raise ValueError("Sherlock requires one 1-64 character ASCII username using letters, digits, dot, underscore, or hyphen")
    raw_sites = [site.strip() for site in options.get("sites", "").split(",") if site.strip()]
    sites: list[str] = []
    seen_sites: set[str] = set()
    for site in raw_sites:
        key = site.casefold()
        if key not in seen_sites:
            sites.append(site)
            seen_sites.add(key)
    if not sites:
        raise ValueError("Sherlock requires --option sites=SiteOne,SiteTwo; broad all-site runs are disabled")
    if len(sites) > 25:
        raise ValueError("Sherlock sites allowlist is limited to 25 entries per run")
    invalid_sites = [site for site in sites if not SHERLOCK_SITE.fullmatch(site)]
    if invalid_sites:
        raise ValueError("Invalid Sherlock site name(s): " + ", ".join(invalid_sites))
    per_site_timeout = _integer(options, "timeout", 10, 1, 60)
    max_runtime = _integer(options, "max_runtime", 120, 10, 600)
    executable = shutil.which("sherlock")
    if not executable:
        raise ValueError("Sherlock is not installed or not on PATH; install the official sherlock-project package")
    version = _sherlock_version(executable)
    with tempfile.TemporaryDirectory(prefix="osint-sherlock-") as temporary:
        command = [
            executable,
            username,
            "--csv",
            "--print-all",
            "--no-color",
            "--folderoutput",
            temporary,
            "--timeout",
            str(per_site_timeout),
        ]
        for site in sites:
            command.extend(["--site", site])
        try:
            process = subprocess.run(
                command,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=max_runtime,
            )
        except subprocess.TimeoutExpired as exc:
            raise ValueError(f"Sherlock exceeded the {max_runtime}-second total execution limit") from exc
        output = (process.stdout + b"\n" + process.stderr).decode("utf-8", errors="replace")
        if process.returncode != 0:
            raise ValueError(f"Sherlock failed with exit code {process.returncode}: {output.strip()[-1000:]}")
        if "Desired sites not found:" in output:
            raise ValueError("Sherlock did not recognize every requested site: " + output.strip()[-1000:])
        output_path = Path(temporary) / f"{username}.csv"
        if not output_path.is_file():
            raise ValueError("Sherlock completed without creating the expected CSV output")
        raw_content = output_path.read_bytes()
    records = parse_sherlock_csv(raw_content, len(sites))
    allowed_sites = {site.casefold() for site in sites}
    unexpected_sites = sorted({
        str(record["value"].get("site", ""))
        for record in records
        if str(record["value"].get("site", "")).casefold() not in allowed_sites
    })
    if unexpected_sites:
        raise ValueError("Sherlock returned site(s) outside the explicit allowlist: " + ", ".join(unexpected_sites))
    return PreparedCollection(
        "sherlock",
        SHERLOCK_PROJECT_URL,
        f"Scoped Sherlock username checks for {username}",
        "username",
        "secondary",
        "low",
        f"sherlock-{safe_filename(username)}.csv",
        raw_content,
        "text/csv",
        records,
        f"Executed {version} against the explicit site allowlist: {', '.join(sites)}. Per-site timeout {per_site_timeout}s; total limit {max_runtime}s. Results are leads requiring manual review.",
    )


def build_whatsmyname_queue(payload: Any, username: str, limit: int, include_nsfw: bool = False) -> list[dict[str, Any]]:
    if not isinstance(payload, dict) or not isinstance(payload.get("sites"), list):
        raise ValueError("Unexpected WhatsMyName dataset shape")
    encoded = quote(username, safe="")
    records: list[dict[str, Any]] = []
    for site in payload["sites"]:
        if len(records) >= limit or not isinstance(site, dict) or site.get("valid") is False:
            continue
        category = str(site.get("cat", ""))
        name = str(site.get("name", "Unnamed site"))
        if not include_nsfw and ("nsfw" in category.lower() or "adult" in name.lower()):
            continue
        templates = [site.get("uri_pretty"), site.get("uri_check")]
        template = next(
            (
                candidate for candidate in templates
                if isinstance(candidate, str)
                and "{account}" in candidate
                and candidate.startswith(("https://", "http://"))
            ),
            None,
        )
        if not isinstance(template, str) or "{account}" not in template or not template.startswith(("https://", "http://")):
            continue
        records.append({
            "kind": "username.profile-candidate",
            "value": {
                "site": name, "category": category, "profile_url": template.replace("{account}", encoded),
                "verification": "manual_required", "dataset_known_account": site.get("known", ""),
            },
            "status": "candidate-unverified",
            "notes": "No request was made to this profile URL. Manually review and corroborate before attribution.",
        })
    return records


def _whatsmyname(target: str, options: dict[str, str]) -> PreparedCollection:
    username = target.strip().lstrip("@")
    if not username or any(char.isspace() for char in username):
        raise ValueError("WhatsMyName requires one username without spaces")
    limit = _integer(options, "limit", 200, 1, 1000)
    fetched = _fetch(WHATS_MY_NAME_DATA, _integer(options, "timeout", 30, 5, 120))
    records = build_whatsmyname_queue(_json(fetched), username, limit, _boolean(options, "include_nsfw", False))
    return PreparedCollection(
        "whatsmyname", fetched.final_url, "WhatsMyName community dataset", "username", "secondary", "medium",
        "whatsmyname-dataset.json", fetched.content, fetched.content_type, records,
        "Dataset-only workflow: generated candidate URLs were not requested and are not confirmed accounts.",
    )


PREPARERS = {
    "wayback": _wayback,
    "commoncrawl": _commoncrawl,
    "rdap": _rdap,
    "dns": _dns,
    "securitytrails": _securitytrails,
    "crtsh": _crtsh,
    "searxng": _searxng,
    "sherlock": _sherlock,
    "whatsmyname": _whatsmyname,
    "hibp-account": _hibp_account,
    "hibp-domain": _hibp_domain,
    "hunter-domain": _hunter_domain,
    "censys-host": _censys_host,
    "companies-house": _companies_house,
}


def probe_provider(provider: str, options: dict[str, str] | None = None) -> dict[str, Any]:
    provider = provider.lower()
    options = options or {}
    if provider not in PROVIDERS:
        raise ValueError(f"Unknown provider: {provider}")
    if provider in provider_profiles() and provider_profiles()[provider]["mode"] == "api":
        profile = provider_profiles()[provider]
        configured = bool(os.environ.get(profile["credential_env"], "").strip())
        return {
            "provider": provider, "status": "configured-unprobed" if configured else "unconfigured",
            "endpoint": profile["docs_url"], "latency_ms": 0, "response_bytes": 0,
            "checked_at_utc": utc_now(),
            "error": "Credential present; no target or charged API request was made." if configured else
                     f"Set {profile['credential_env']} in an approved secret manager; no request was made.",
        }
    if provider == "sherlock":
        executable = shutil.which("sherlock")
        if not executable:
            return {
                "provider": provider, "status": "unconfigured", "endpoint": "", "latency_ms": 0,
                "response_bytes": 0, "checked_at_utc": utc_now(),
                "error": "Install the official sherlock-project package and ensure sherlock is on PATH.",
            }
        started = time.monotonic()
        version = _sherlock_version(executable)
        return {
            "provider": provider,
            "status": "healthy" if version != "unknown" else "degraded",
            "endpoint": executable,
            "latency_ms": round((time.monotonic() - started) * 1000),
            "response_bytes": 0,
            "checked_at_utc": utc_now(),
            "error": "" if version != "unknown" else "Sherlock version could not be determined.",
            "version": version,
        }
    probe_headers: dict[str, str] | None = None
    if provider == "searxng":
        base = options.get("base_url") or os.environ.get("OSINT_SEARXNG_URL", "")
        if not base:
            return {
                "provider": provider, "status": "unconfigured", "endpoint": "", "latency_ms": 0,
                "response_bytes": 0, "checked_at_utc": utc_now(),
                "error": "Set base_url or OSINT_SEARXNG_URL before probing SearXNG.",
            }
        endpoint = base.rstrip("/") + "/config"
    elif provider == "securitytrails":
        api_key = os.environ.get("SECURITYTRAILS_API_KEY", "").strip()
        if not api_key:
            return {
                "provider": provider, "status": "unconfigured", "endpoint": "", "latency_ms": 0,
                "response_bytes": 0, "checked_at_utc": utc_now(),
                "error": "Set SECURITYTRAILS_API_KEY before probing SecurityTrails.",
            }
        if "\r" in api_key or "\n" in api_key:
            return {
                "provider": provider, "status": "unconfigured", "endpoint": "", "latency_ms": 0,
                "response_bytes": 0, "checked_at_utc": utc_now(),
                "error": "SECURITYTRAILS_API_KEY contains an invalid newline.",
            }
        endpoint = f"{SECURITYTRAILS_API_ROOT}/history/example.com/dns/a?page=1"
        probe_headers = {"APIKEY": api_key}
    else:
        endpoints = {
            "wayback": "https://web.archive.org/cdx/search/cdx?" + urlencode({"url": "example.com", "output": "json", "limit": "1"}),
            "commoncrawl": "https://index.commoncrawl.org/collinfo.json",
            "rdap": IANA_RDAP_BOOTSTRAP,
            "dns": "https://dns.google/resolve?" + urlencode({"name": "example.com", "type": "A"}),
            "crtsh": "https://crt.sh/?" + urlencode({"q": "example.com", "output": "json"}),
            "whatsmyname": WHATS_MY_NAME_DATA,
        }
        endpoint = endpoints[provider]
    timeout = _integer(options, "timeout", 15, 5, 60)
    started = time.monotonic()
    try:
        fetched = _fetch(endpoint, timeout=timeout, retries=0, headers=probe_headers)
        _json(fetched)
        return {
            "provider": provider,
            "status": "healthy",
            "endpoint": fetched.final_url,
            "latency_ms": round((time.monotonic() - started) * 1000),
            "response_bytes": len(fetched.content),
            "checked_at_utc": utc_now(),
            "error": "",
        }
    except ValueError as exc:
        return {
            "provider": provider,
            "status": "degraded",
            "endpoint": endpoint,
            "latency_ms": round((time.monotonic() - started) * 1000),
            "response_bytes": 0,
            "checked_at_utc": utc_now(),
            "error": str(exc),
        }


def save_provider_probe(result: dict[str, Any], output: str | Path) -> Path:
    destination = Path(output).expanduser().resolve()
    if destination.exists():
        try:
            registry = read_json(destination)
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"Provider status registry could not be read: {exc}") from exc
        if not isinstance(registry, dict) or registry.get("schema_version") != "1.0":
            raise ValueError("Provider status registry has an unsupported format")
    else:
        registry = {"schema_version": "1.0", "providers": {}, "history": []}
    registry.setdefault("providers", {})[result["provider"]] = result
    history = registry.setdefault("history", [])
    history.append(result)
    registry["history"] = history[-100:]
    write_json(destination, registry)
    return destination


def collect_provider(
    case: str | Path,
    provider: str,
    target: str,
    options: dict[str, str] | None = None,
    collector: str = "operator",
    confirm_external_disclosure: bool = False,
) -> dict[str, Any]:
    provider = provider.lower()
    if provider not in PREPARERS:
        raise ValueError(f"Unknown provider: {provider}")
    case_dir = ensure_case(case)
    assert_case_mutable(case_dir)
    selected_options = options or {}
    try:
        _validate_collection_options(provider, selected_options)
    except Exception as exc:
        add_provider_run(case_dir, provider, target, "failed", "", error=str(exc), collector=collector)
        raise

    disclosure_id = ""
    approval_id = ""
    case_record = read_json(case_dir / "case.json")
    if PROVIDERS[provider]["target_disclosure"] == "external":
        sensitivity = str(case_record.get("sensitivity", "unknown"))
        if not confirm_external_disclosure:
            message = (
                f"{provider} sends the target/query to an external service. Review the case sensitivity "
                f"({sensitivity}) and authority, then pass --confirm-external-disclosure"
            )
            add_provider_run(case_dir, provider, target, "blocked", "", error=message, collector=collector)
            raise ValueError(message)
        disclosure_id = new_id("DSC")
        append_ledger(
            case_dir,
            "provider.external-disclosure-confirmed",
            {
                "confirmation_id": disclosure_id,
                "provider": provider,
                "target": target,
                "case_sensitivity": sensitivity,
                "disclosure_scope": "target-or-query",
                "confirmed_at_utc": utc_now(),
            },
            collector.strip() or "operator",
        )
    if provider in provider_profiles() and provider_profiles()[provider]["mode"] == "api":
        try:
            approval_id = reserve_approved_run(case_dir, provider, target, collector)
        except ValueError as exc:
            add_provider_run(case_dir, provider, target, "blocked", "", error=str(exc), collector=collector)
            raise
    try:
        prepared = PREPARERS[provider](target, selected_options)
        if approval_id:
            prepared.source_notes = " ".join((prepared.source_notes.strip(), f"Approved under {approval_id}."))
        if disclosure_id:
            confirmation_note = (
                f"External target/query disclosure was confirmed under {disclosure_id} for the "
                f"{case_record.get('sensitivity', 'unknown')} case sensitivity."
            )
            prepared.source_notes = " ".join(
                item for item in (prepared.source_notes.strip(), confirmation_note) if item
            )
        source = add_source(
            case_dir, prepared.request_url, prepared.source_title, prepared.topic,
            prepared.reliability, prepared.credibility, prepared.source_notes, collector,
        )
        artifact = add_artifact_bytes(
            case_dir, prepared.raw_content, prepared.raw_name, prepared.request_url, prepared.topic,
            f"Raw {provider} provider response", collector, prepared.content_type,
        )
        observations = [
            add_observation(
                case_dir, source["source_id"], record["kind"], record["value"], target,
                record.get("observed_at", ""), artifact["artifact_id"], record.get("status", "observed"),
                record.get("notes", ""), collector,
            )
            for record in prepared.records
        ]
        run = add_provider_run(
            case_dir, provider, target, "completed", prepared.request_url, source["source_id"], artifact["artifact_id"],
            len(observations), "", collector,
        )
        return {"run": run, "source": source, "artifact": artifact, "observations": observations}
    except Exception as exc:
        error = str(exc)
        if disclosure_id:
            error = f"disclosure_confirmation={disclosure_id}; {error}"
        add_provider_run(case_dir, provider, target, "failed", "", error=error, collector=collector)
        raise
