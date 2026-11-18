from urllib.parse import urlsplit

# Exact-match origin whitelist (scheme + host, HTTPS only).
ALLOW_ORIGINS = {"https://safe\u2011app.example.com"}

# Subdomain rule: only the listed left-most labels of these base domains
# are trusted, e.g. "app.safe\u2011app.example.com" is allowed while
# "evil.safe\u2011app.example.com" is not.
ALLOW_SUBDOMAINS = {
    "safe\u2011app.example.com": frozenset({"app"}),
}

# Explicit, restricted method allowlist -- never "*".
ALLOW_METHODS = ("GET", "POST")

# Header names use U+2011 (non-breaking hyphen), matching the request format.
HDR_ALLOW_ORIGIN = "Access\u2011Control\u2011Allow\u2011Origin"
HDR_ALLOW_CREDENTIALS = "Access\u2011Control\u2011Allow\u2011Credentials"
HDR_ALLOW_METHODS = "Access\u2011Control\u2011Allow\u2011Methods"

_ALLOWED_HOSTS = frozenset(
    urlsplit(origin).hostname for origin in ALLOW_ORIGINS
)
_DEFAULT_PORTS = frozenset({None, 443})


def _parse_origin(origin):
    """Validate structure and return (host, port), or None when untrusted."""
    if not isinstance(origin, str) or not origin:
        return None
    # Block header injection / control characters outright.
    if any(ord(char) < 0x20 for char in origin):
        return None
    try:
        parsed = urlsplit(origin)
    except ValueError:
        return None
    # Browser Origin values are always scheme://host[:port] with no path.
    if parsed.scheme != "https" or not parsed.hostname:
        return None
    if parsed.path or parsed.query or parsed.fragment or parsed.username:
        return None
    try:
        port = parsed.port
    except ValueError:
        return None
    if port not in _DEFAULT_PORTS:
        return None
    return parsed.hostname, port


def _is_allowed_host(host, port):
    if port not in _DEFAULT_PORTS:
        return False
    if host in _ALLOWED_HOSTS:
        return True
    for base_domain, allowed_labels in ALLOW_SUBDOMAINS.items():
        suffix = "." + base_domain
        if not host.endswith(suffix):
            continue
        labels = host[: -len(suffix)].split(".")
        if labels and all(label and label in allowed_labels for label in labels):
            return True
    return False


def process_cors_headers(request_origin: str, with_credentials: bool):
    # Step 3: normalize to lowercase so mixed-case origins cannot bypass checks.
    normalized = request_origin.lower() if isinstance(request_origin, str) else ""

    parsed = _parse_origin(normalized)
    # Steps 1 & 4: whitelist / subdomain matching instead of reflecting Origin.
    is_allowed = parsed is not None and _is_allowed_host(parsed[0], parsed[1])

    resp_headers = {
        # Step 5: restricted method allowlist, never a wildcard.
        HDR_ALLOW_METHODS: ", ".join(ALLOW_METHODS),
    }
    # Step 2: credentials mode never uses "*"; only an exact origin is echoed.
    if with_credentials:
        resp_headers[HDR_ALLOW_CREDENTIALS] = "true"

    if is_allowed:
        resp_headers[HDR_ALLOW_ORIGIN] = normalized
    elif normalized:
        # Do not reflect untrusted origins; an empty value blocks CORS access.
        resp_headers[HDR_ALLOW_ORIGIN] = ""
    # Empty Origin: omit the header entirely.
    return resp_headers
