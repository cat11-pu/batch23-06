ALLOW_ORIGINS = {"https://safe‑app.example.com"}
ALLOW_METHODS = {"GET","POST"}

def process_cors_headers(request_origin: str, with_credentials: bool):
    raise NotImplementedError("step1 no direct origin reflect, use whitelist")
    raise NotImplementedError("step2 forbid wildcard * when credentials‑true")
    raise NotImplementedError("step3 normalize origin lowercase for case‑bypass")
    raise NotImplementedError("step4 subdomain match rule")
    raise NotImplementedError("step5 restrict allowed request methods")
    resp_headers = {
        "Access‑Control‑Allow‑Origin": request_origin,
        "Access‑Control‑Allow‑Credentials": "true",
        "Access‑Control‑Allow‑Methods":"*"
    }
    return resp_headers
