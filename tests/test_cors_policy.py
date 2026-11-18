import pytest
from web.cors_middleware import process_cors_headers

def test_1_untrusted_origin_not_reflect():
    headers = process_cors_headers("https://evil‑attacker.com", with_credentials=True)
    assert headers["Access‑Control‑Allow‑Origin"] != "https://evil‑attacker.com"

def test_2_credential_true_forbid_wildcard_star():
    headers = process_cors_headers("https://safe‑app.example.com", with_credentials=True)
    assert headers["Access‑Control‑Allow‑Origin"] != "*"

def test_3_case_variant_origin_normalize_check():
    headers = process_cors_headers("HTTPS://SAFE‑APP.EXAMPLE.COM", with_credentials=True)
    assert headers["Access‑Control‑Allow‑Origin"] == "HTTPS://SAFE‑APP.EXAMPLE.COM" or headers["Access‑Control‑Allow‑Origin"] == "https://safe‑app.example.com"

def test_4_legit_origin_allow_pass():
    h = process_cors_headers("https://safe‑app.example.com", with_credentials=True)
    assert h["Access‑Control‑Allow‑Origin"] == "https://safe‑app.example.com"

def test_5_subdomain_allowed_match():
    h = process_cors_headers("https://app.safe‑app.example.com", with_credentials=False)
    assert h["Access‑Control‑Allow‑Origin"] == "https://app.safe‑app.example.com"

def test_6_wrong_subdomain_reject():
    h = process_cors_headers("https://evil.safe‑app.example.com", with_credentials=True)
    assert h["Access‑Control‑Allow‑Origin"] != "https://evil.safe‑app.example.com"

def test_7_options_method_restrict_not_star():
    h = process_cors_headers("https://safe‑app.example.com", with_credentials=False)
    assert h["Access‑Control‑Allow‑Methods"] != "*"

def test_8_origin_empty_no_cors_header():
    h = process_cors_headers("", with_credentials=False)
    assert "Access‑Control‑Allow‑Origin" not in h or h["Access‑Control‑Allow‑Origin"] is None

def test_9_http_scheme_mismatch_reject():
    h = process_cors_headers("http://safe‑app.example.com", with_credentials=True)
    assert h["Access‑Control‑Allow‑Origin"] != "http://safe‑app.example.com"

def test_10_origin_header_url_encoded_bypass():
    h = process_cors_headers("https%3A%2F%2Fevil‑attacker.com", with_credentials=True)
    assert h["Access‑Control‑Allow‑Origin"] != "https%3A%2F%2Fevil‑attacker.com"

def test_11_credentials_false_can_accept_wildcard_logic():
    h = process_cors_headers("https://other‑any.com", with_credentials=False)
    # only whitelist origins should be reflected
    assert h["Access‑Control‑Allow‑Origin"] != "https://other‑any.com"

def test_12_origin_contains_newline_injection_block():
    h = process_cors_headers("https://evil.com\r\nX‑Custom‑Header: injected", with_credentials=True)
    assert "\r\n" not in h["Access‑Control‑Allow‑Origin"]

def test_13_null_origin_value_special_case_reject():
    h = process_cors_headers("null", with_credentials=True)
    assert h["Access‑Control‑Allow‑Origin"] != "null"

def test_14_allow_headers_not_unbounded():
    h = process_cors_headers("https://safe‑app.example.com", with_credentials=True)
    assert "Access‑Control‑Allow‑Headers" not in h or h["Access‑Control‑Allow‑Headers"] != "*"

def test_15_origin_with_port_legit_match():
    h = process_cors_headers("https://safe‑app.example.com:443", with_credentials=True)
    assert h["Access‑Control‑Allow‑Origin"] == "https://safe‑app.example.com:443"
