"""Structural validation for URL scans. No DNS resolution or outbound requests."""
import ipaddress
import re
import unicodedata
from urllib.parse import ParseResult, unquote, urlparse


def parse_scan_url(value: str) -> ParseResult:
    """Accept HTTP(S), scheme-relative URLs and bare hosts without changing input."""
    message = "Enter a valid HTTP(S) URL with a valid host, port and percent encoding."
    try:
        value = value.strip(" ")
        if any(c.isspace() or unicodedata.category(c) in {"Cc", "Cs"} for c in value):
            raise ValueError(message)
        if "\\" in value or re.search(r"%(?![0-9a-fA-F]{2})", value):
            raise ValueError(message)
        decoded = unquote(value, errors="strict")
        if any(unicodedata.category(c) in {"Cc", "Cs"} for c in decoded):
            raise ValueError(message)

        absolute = re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value)
        candidate = value if absolute or value.startswith("//") else "//" + value
        parsed = urlparse(candidate)
        if parsed.scheme and parsed.scheme.lower() not in {"http", "https"}:
            raise ValueError(message)
        host = parsed.hostname
        if not host or "%" in host:
            raise ValueError(message)
        # Accessing .port performs urllib's range/non-numeric validation.
        _ = parsed.port
        authority = parsed.netloc.rsplit("@", 1)[-1]
        if authority.endswith(":"):
            raise ValueError(message)
        if authority.startswith("[") or ":" in host:
            if not re.fullmatch(r"\[[^\]]+\](?::[0-9]+)?", authority):
                raise ValueError(message)
            ipaddress.IPv6Address(host)
        elif re.fullmatch(r"[0-9.]+", host):
            ipaddress.IPv4Address(host)
        else:
            dns = host[:-1] if host.endswith(".") else host
            ascii_host = dns.encode("idna").decode("ascii")
            if len(ascii_host) > 253:
                raise ValueError(message)
            for label in ascii_host.split("."):
                if not re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?", label):
                    raise ValueError(message)
                if label.lower().startswith("xn--"):
                    label.encode("ascii").decode("idna")
        return parsed
    except (ValueError, UnicodeError):
        # Never echo submitted credentials, query strings or raw parser errors.
        raise ValueError(message) from None
