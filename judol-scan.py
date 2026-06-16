#!/usr/bin/env python3
"""
Scanner Deteksi Website Tersusupi Judol
Kenshin Himura - roxlab.org@gmail.com
=========================================
Mendeteksi apakah website telah diretas dan dipakai sebagai hosting konten judi online.

Pola deteksi:
 1. SEO poisoning: konten judi tersembunyi khusus Googlebot
 2. Web shell + backdoor (PHP shells, GSocket)
 3. Direktori/file mencurigakan (slot/, togel/, bonus/, adminer.php, dll)
 4. Redirect injection ke domain judi
 5. Iframe/link tersembunyi ke situs judi
 6. Base64-encoded payload di HTML/JS
 7. Modified .htaccess atau file konfig
 8. WordPress: plugin/akun admin tidak sah
 9. Crontab / bashrc backdoor

Usage:
  python scanner_tersusupi.py --url https://kampus.ac.id
  python scanner_tersusupi.py --target list_url.txt --threads 20
  python scanner_tersusupi.py --url https://kampus.ac.id --deep
"""

import re
import sys
import ssl
import json
import gzip
import time
import socket
import base64
import hashlib
import argparse
import threading
import urllib.parse
import urllib.request
import urllib.error
from dataclasses import dataclass, field, asdict
from concurrent.futures import ThreadPoolExecutor, as_completed

TIMEOUT = 10
MAX_REDIRECTS = 5
THREADS = 20

UA_GOOGLEBOT = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
UA_HUMAN = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"

# ─── JUDI CONTENT MARKERS ────────────────────────────────────────────────
# Jika konten website tiba-tiba mengandung ini -> ter-compromise

JUDI_KEYWORDS = [
    "judi online", "situs judi", "agen judi", "bandar judi",
    "slot online", "slot gacor", "slot maxwin", "togel online",
    "casino online", "sportsbook", "sabung ayam",
    "deposit pulsa", "depo via dana", "deposit gopay",
    "bonus new member", "bonus deposit", "freebet",
    "link alternatif", "daftar sekarang", "claim bonus",
    "pragmatic play demo", "habanero slot",
]

JUDI_DOMAINS_PATTERN = re.compile(
    r'(?i)(slot|togel|toto|judi|poker|casino|bola|gacor|maxwin|hoki|'
    r'mpo|idnplay|agen|bandar|sabung)[a-z0-9-]*\.(cc|top|vip|xyz|me|'
    r'site|online|win|bet|live|club|fun|monster)'
)

# ─── WEB SHELL SIGNATURES ────────────────────────────────────────────────

WEBSHELL_FILES = [
    # Standard web shell filenames
    "adminer.php", "wso.php", "c99.php", "r57.php", "b374k.php",
    "shell.php", "cmd.php", "up.php", "uploader.php",
    "weevely.php", "webacoo.php", "fx29.php", "s.php",
    "idx.php", "wp-admins.php", "xmlrpc.php.bak",
    "config.bak.php", "user.php", "about.php", "lock.php",
    "priv8.php", "mini.php", "Marvin.php", "alfanum.php",
    # Judol-specific
    "slot.php", "togel.php", "judi.php", "bonus.php",
    "deposit.php", "daftar.php", "gacor.php", "maxwin.php",
    "gs.php", "gsocket.php", "gslink.php",
]

WEBSHELL_DIRS = [
    "slot", "togel", "judi", "bonus", "gacor", "maxwin",
    "deposit", "daftar", "login-alt", "link-alt",
    "wp-content/uploads/slot", "wp-content/uploads/togel",
    "wp-content/plugins/hello", "wp-content/plugins/akismet-backup",
    "modules/slot", "modules/togel", "assets/slot",
    "tmp", ".cache", ".gs",
]

WEBSHELL_CONTENT_SIGS = [
    rb'(?i)(?:passthru|shell_exec|exec|system|proc_open|popen)\s*\(\s*[\'\"](?:id|whoami|uname|ls|wget|curl)',
    rb'(?i)c99shell|r57shell|b374k|weevely|webacoo|edgardoor',
    rb'(?i)gsocket[_-]?\d',
    rb'base64_decode\s*\(\s*[\'"]',
    rb'(?i)eval\s*\(\s*(?:base64_decode|gzinflate|str_rot13)',
    rb'(?i)\$[a-z]+\s*=\s*[\'"]\\\\x[0-9a-f]{2}',
]

PAYLOAD_PATTERNS = [
    # Base64 encoded PHP payload
    rb'base64_decode\s*\(\s*[\'"][A-Za-z0-9+/=]{40,}[\'"]\s*\)',
    # Hex-encoded eval
    rb'eval\s*\(\s*[\'"]\\\\x[0-9a-f]{2}',
    # Obfuscated variables
    rb'\$\w+\[\d+\]\.\$\w+\[\d+\]',
]

WP_COMPROMISE_SIGS = [
    # Unexpected admin user patterns
    "/wp-admin/user-new.php",
    "/wp-admin/plugins.php?plugin_status=active",
    # Known malicious plugin slugs
    "wp-file-manager", "wp-database-reset", "duplicator-pro",
    "wp-configurator", "social-warfare", "simple-301-redirects",
    # WP3.XYZ campaign (from research)
    "wp3.xyz", "wp3xyz",
]

HIDDEN_REDIRECT_PATTERNS = [
    # Meta refresh ke domain judi
    r'<meta[^>]+http-equiv=["\']refresh["\'][^>]+url=(["\']?)https?://[^"\'<>]*(?:slot|togel|judi|gacor)',
    # JavaScript redirect
    r'(?:window\.location|document\.location)\s*=\s*["\']https?://[^"\']*(?:slot|togel|judi|gacor)',
    # Hidden iframe to gambling
    r'<iframe[^>]+(?:display\s*:\s*none|hidden|width\s*=\s*["\']0|height\s*=\s*["\']0)[^>]*src=["\']https?://[^"\']*["\']',
    # PHP header redirect injection
    r'header\s*\(\s*[\'"]Location:\s*https?://[^"\']*(?:slot|togel|judi|gacor)',
]

# ─── SCAN PATHS (crawl target) ───────────────────────────────────────────

SCAN_PATHS_EXTERNAL = [
    "/", "/wp-admin/", "/wp-login.php", "/xmlrpc.php",
    "/wp-content/", "/wp-content/uploads/",
    "/wp-content/plugins/", "/.env", "/.git/config",
    "/robots.txt", "/sitemap.xml",
    "/admin/", "/administrator/", "/login/",
    "/api/", "/api/v1/", "/graphql",
]

SCAN_PATHS_DEEP = [
    *SCAN_PATHS_EXTERNAL,
    "/wp-json/wp/v2/users",
    "/wp-json/wp/v2/plugins",
    "/wp-content/debug.log",
    "/phpinfo.php", "/info.php", "/test.php",
    "/backup/", "/old/", "/bak/",
    "/console/", "/shell/", "/cmd/",
    "/modules/", "/includes/", "/vendor/",
]

# ─── DATA CLASS ───────────────────────────────────────────────────────────

@dataclass
class CompromiseFinding:
    url: str
    domain: str = ""
    ip: str = ""
    risk_score: int = 0
    findings: list = field(default_factory=list)
    # Indicators
    judi_keywords_found: list = field(default_factory=list)
    judi_domains_linked: list = field(default_factory=list)
    webshell_files_found: list = field(default_factory=list)
    webshell_dirs_found: list = field(default_factory=list)
    webshell_content: list = field(default_factory=list)
    encoded_payloads: int = 0
    seo_poison_detected: bool = False
    seo_poison_detail: str = ""
    hidden_redirects: list = field(default_factory=list)
    wp_compromise: list = field(default_factory=list)
    suspicious_paths: list = field(default_factory=list)
    # Meta
    pagecount: int = 0
    total_time: float = 0.0


# ─── UTILITY ──────────────────────────────────────────────────────────────

def safe_print(*args, **kwargs):
    text = " ".join(str(a) for a in args)
    try:
        print(text, **kwargs)
    except UnicodeEncodeError:
        print(text.encode("ascii", errors="replace").decode("ascii"), **kwargs)


def create_ssl_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def fetch(url, user_agent=UA_HUMAN):
    result = {"content": b"", "status": 0, "final_url": url, "time": 0.0}
    ctx = create_ssl_ctx()
    current = url
    parsed = urllib.parse.urlparse(url)
    hostname = parsed.netloc or parsed.path.split("/")[0]

    for _ in range(MAX_REDIRECTS):
        start = time.time()
        req = urllib.request.Request(current)
        req.add_header("User-Agent", user_agent)
        req.add_header("Host", hostname)
        req.add_header("Accept", "text/html,*/*")
        req.add_header("Accept-Encoding", "gzip")

        try:
            resp = urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx)
            result["time"] = time.time() - start
            result["status"] = resp.status

            if resp.status in (301, 302, 303, 307, 308):
                loc = resp.getheader("Location", "")
                if loc:
                    if loc.startswith("/"):
                        loc = f"{parsed.scheme}://{parsed.netloc}{loc}"
                    current = loc
                    hostname = urllib.parse.urlparse(loc).netloc or hostname
                    continue

            raw = resp.read()
            if "gzip" in resp.getheader("Content-Encoding", "").lower():
                raw = gzip.decompress(raw)
            result["content"] = raw
            result["final_url"] = current
            return result

        except urllib.error.HTTPError as e:
            result["status"] = e.code
            return result
        except Exception:
            # Fallback HTTP jika HTTPS gagal
            if current.startswith("https://"):
                try:
                    http_url = current.replace("https://", "http://", 1)
                    req2 = urllib.request.Request(http_url)
                    req2.add_header("User-Agent", user_agent)
                    req2.add_header("Host", hostname)
                    resp2 = urllib.request.urlopen(req2, timeout=TIMEOUT)
                    raw2 = resp2.read()
                    ce = resp2.getheader("Content-Encoding", "")
                    if "gzip" in ce.lower():
                        raw2 = gzip.decompress(raw2)
                    result["content"] = raw2
                    result["status"] = resp2.status
                    result["final_url"] = http_url
                    return result
                except:
                    pass
            result["status"] = 0
            return result

    return result


def is_legitimate_site(url):
    """Deteksi apakah URL mengarah ke situs resmi (bukan situs judi)."""
    parsed = urllib.parse.urlparse(url)
    host = (parsed.netloc or parsed.path).lower()

    # TLD resmi
    legit_tlds = {".ac.id", ".go.id", ".or.id", ".sch.id", ".edu", ".gov", ".org"}
    for tld in legit_tlds:
        if host.endswith(tld):
            return True

    # Pattern kampus/pemerintah
    legit_patterns = [
        r'\.ac\.id$', r'\.go\.id$', r'kampus', r'universitas',
        r'university', r'college', r'government', r'pemerintah',
        r'kemen', r'departemen', r'prov\.go\.id',
    ]
    for pat in legit_patterns:
        if re.search(pat, host):
            return True

    return False


# ─── DETECTION ENGINE ─────────────────────────────────────────────────────

def analyze_page(content_bytes, page_url):
    """Analisis satu halaman untuk indikasi kompromi."""
    findings = []

    try:
        text = content_bytes.decode("utf-8", errors="replace")
    except:
        text = content_bytes.decode("latin-1", errors="replace")
    text_lower = text.lower()

    # 1. Konten judi di situs resmi
    keywords = []
    for kw in JUDI_KEYWORDS:
        if kw in text_lower:
            keywords.append(kw)
    if len(keywords) >= 3:
        findings.append({
            "type": "JUDI_KEYWORDS",
            "severity": "HIGH",
            "count": len(keywords),
            "samples": keywords[:8],
            "url": page_url,
        })

    # 2. Link/redirect ke domain judi
    judi_domains = set()
    for m in JUDI_DOMAINS_PATTERN.finditer(text):
        judi_domains.add(m.group())
    if judi_domains:
        findings.append({
            "type": "JUDI_DOMAIN_LINK",
            "severity": "CRITICAL",
            "domains": list(judi_domains)[:10],
            "url": page_url,
        })

    # 3. Hidden redirect / meta refresh ke domain judi
    redirects = []
    for pat in HIDDEN_REDIRECT_PATTERNS:
        for m in re.finditer(pat, text):
            redirects.append(m.group()[:120])
    if redirects:
        findings.append({
            "type": "HIDDEN_REDIRECT",
            "severity": "CRITICAL",
            "examples": redirects[:3],
            "url": page_url,
        })

    # 4. Web shell patterns in content
    for i, sig in enumerate(WEBSHELL_CONTENT_SIGS):
        if re.search(sig, content_bytes):
            findings.append({
                "type": "WEBSHELL_SIGNATURE",
                "severity": "CRITICAL",
                "sig_index": i,
                "match": re.search(sig, content_bytes).group()[:100] if re.search(sig, content_bytes) else "",
                "url": page_url,
            })
            break

    # 5. Base64 encoded payloads
    b64_count = len(re.findall(PAYLOAD_PATTERNS[0], content_bytes))
    for i, pp in enumerate(PAYLOAD_PATTERNS[1:], 1):
        b64_count += len(re.findall(pp, content_bytes))
    if b64_count >= 2:
        findings.append({
            "type": "ENCODED_PAYLOAD",
            "severity": "HIGH",
            "count": b64_count,
            "url": page_url,
        })

    # 6. WordPress compromise indicators
    wp_findings = []
    for sig in WP_COMPROMISE_SIGS:
        if sig in text_lower:
            wp_findings.append(sig)
    if wp_findings:
        findings.append({
            "type": "WP_COMPROMISE",
            "severity": "HIGH",
            "indicators": wp_findings,
            "url": page_url,
        })

    return findings


def scan_paths(base_url, paths, user_agent=UA_HUMAN):
    """Scan multiple paths on a target site."""
    results = []
    parsed = urllib.parse.urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    for path in paths:
        url = urllib.parse.urljoin(base, path)
        result = fetch(url, user_agent)
        if result["status"] in (200, 403, 301, 302):
            results.append({
                "url": url,
                "status": result["status"],
                "size": len(result["content"]),
                "content": result["content"],
            })

    return results


def scan_website(target_url, deep=False):
    """Main scan function for a single website."""
    finding = CompromiseFinding(url=target_url)
    start = time.time()

    parsed = urllib.parse.urlparse(target_url)
    finding.domain = parsed.netloc or parsed.path.split("/")[0]

    # Resolve IP
    try:
        finding.ip = socket.gethostbyname(finding.domain)
    except:
        pass

    paths = SCAN_PATHS_DEEP if deep else SCAN_PATHS_EXTERNAL

    # Fetch pages
    pages = scan_paths(target_url, paths)

    # Also check with Googlebot UA
    if deep:
        pages_bot = scan_paths(target_url, ["/", "/sitemap.xml", "/robots.txt"], UA_GOOGLEBOT)
        pages.extend(pages_bot)

    finding.pagecount = len(pages)
    seen_paths = set()

    for page in pages:
        if page["url"] in seen_paths:
            continue
        seen_paths.add(page["url"])
        finding.suspicious_paths.append(page["url"])

        if page["status"] != 200 or not page["content"]:
            continue

        page_findings = analyze_page(page["content"], page["url"])
        for pf in page_findings:
            if pf["type"] == "JUDI_KEYWORDS":
                finding.judi_keywords_found.extend(pf.get("samples", []))
                finding.risk_score += 25
            elif pf["type"] == "JUDI_DOMAIN_LINK":
                finding.judi_domains_linked.extend(pf.get("domains", []))
                finding.risk_score += 30
            elif pf["type"] == "HIDDEN_REDIRECT":
                finding.hidden_redirects.extend(pf.get("examples", []))
                finding.risk_score += 35
            elif pf["type"] == "WEBSHELL_SIGNATURE":
                finding.webshell_content.append(pf.get("match", ""))
                finding.risk_score += 40
            elif pf["type"] == "ENCODED_PAYLOAD":
                finding.encoded_payloads += pf.get("count", 0)
                finding.risk_score += 15
            elif pf["type"] == "WP_COMPROMISE":
                finding.wp_compromise.extend(pf.get("indicators", []))
                finding.risk_score += 20
            finding.findings.append(pf)

    # SEO Poisoning check (Googlebot vs Human)
    page_human = fetch(target_url, UA_HUMAN)
    page_bot = fetch(target_url, UA_GOOGLEBOT)

    if page_human["content"] and page_bot["content"] and page_human["status"] == 200:
        hh = hashlib.sha256(page_human["content"]).hexdigest()
        bh = hashlib.sha256(page_bot["content"]).hexdigest()

        if hh != bh:
            # Cek apakah konten bot mengandung keyword judi
            try:
                bot_text = page_bot["content"].decode("utf-8", errors="replace").lower()
                human_text = page_human["content"].decode("utf-8", errors="replace").lower()
                bot_kw = sum(1 for kw in JUDI_KEYWORDS if kw in bot_text)
                human_kw = sum(1 for kw in JUDI_KEYWORDS if kw in human_text)

                if bot_kw > human_kw + 2:
                    finding.seo_poison_detected = True
                    finding.seo_poison_detail = (
                        f"KEYWORDS_BOT={bot_kw}/KEYWORDS_HUMAN={human_kw} "
                        f"HASH_BOT={bh[:12]}/HASH_HUMAN={hh[:12]}"
                    )
                    finding.risk_score += 50
            except:
                pass

    # Direct web shell file check
    # Jika ada direktori tersembunyi yang return 200 tapi seharusnya 403/404
    dir_checks = [
        f"{target_url.rstrip('/')}/{d}/" for d in WEBSHELL_DIRS[:20]
    ] + [
        f"{target_url.rstrip('/')}/{f}" for f in WEBSHELL_FILES[:20]
    ]
    for check_url in dir_checks:
        try:
            r = urllib.request.urlopen(
                urllib.request.Request(check_url, headers={"User-Agent": UA_HUMAN}),
                timeout=5,
                context=create_ssl_ctx()
            )
            if r.status == 200:
                content = r.read(500)
                finding.webshell_files_found.append({
                    "url": check_url,
                    "status": r.status,
                    "size": len(content),
                })
                finding.risk_score += 10
        except:
            pass

    finding.total_time = time.time() - start
    return finding


# ─── DISPLAY ──────────────────────────────────────────────────────────────

def display_result(finding, idx):
    if finding.risk_score == 0 and not finding.seo_poison_detected:
        safe_print(f"[{idx}] BERSIH - {finding.url}")
        return

    level = ("KRITIS" if finding.risk_score >= 80 else
             "TINGGI" if finding.risk_score >= 50 else
             "SEDANG" if finding.risk_score >= 25 else "RENDAH")

    safe_print(f"\n{'='*70}")
    safe_print(f"[{idx}] TERDETEKSI - Level: {level} | Score: {finding.risk_score}")
    safe_print(f"    URL: {finding.url}")
    safe_print(f"    Domain: {finding.domain} | IP: {finding.ip}")
    safe_print(f"    Pages scanned: {finding.pagecount} | Time: {finding.total_time:.1f}s")

    if finding.seo_poison_detected:
        safe_print(f"    >>> SEO POISONING: {finding.seo_poison_detail}")

    if finding.judi_keywords_found:
        unique = list(set(finding.judi_keywords_found))
        safe_print(f"    Judi keywords ({len(unique)}): {', '.join(unique[:10])}")

    if finding.judi_domains_linked:
        safe_print(f"    Link ke domain judi: {finding.judi_domains_linked[:5]}")

    if finding.hidden_redirects:
        safe_print(f"    Hidden redirect: {finding.hidden_redirects[0][:100]}")

    if finding.webshell_content:
        safe_print(f"    Web shell code detected: {finding.webshell_content[0][:80]}")

    if finding.encoded_payloads:
        safe_print(f"    Encoded payloads: {finding.encoded_payloads}")

    if finding.webshell_files_found:
        safe_print(f"    Suspicious files/dirs ({len(finding.webshell_files_found)}):")
        for wf in finding.webshell_files_found[:5]:
            safe_print(f"      {wf['url']} ({wf['status']}, {wf['size']}B)")

    if finding.wp_compromise:
        safe_print(f"    WP compromise: {finding.wp_compromise}")


# ─── MAIN ─────────────────────────────────────────────────────────────────

def load_targets(filepath):
    targets = []
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            t = line.strip()
            if t and not t.startswith("#"):
                if "://" not in t:
                    t = f"https://{t}"
                targets.append(t)
    return list(dict.fromkeys(targets))


def mass_scan(targets, threads, deep=False):
    safe_print(f"\n[*] Scanning {len(targets)} targets with {threads} threads...\n")

    results = []
    done = 0
    start = time.time()

    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_map = {
            executor.submit(scan_website, t, deep): t for t in targets
        }
        for future in as_completed(future_map):
            done += 1
            try:
                result = future.result(timeout=TIMEOUT * len(SCAN_PATHS_EXTERNAL))
                results.append(result)
                display_result(result, done)
            except Exception as e:
                safe_print(f"[{done}] ERROR: {future_map[future]} - {e}")

    results.sort(key=lambda x: x.risk_score, reverse=True)

    elapsed = time.time() - start
    compromised = sum(1 for r in results if r.risk_score > 0)

    safe_print(f"\n{'='*70}")
    safe_print(f"SUMMARY: {len(targets)} scanned | {compromised} compromised | {elapsed:.1f}s")

    return results


def main():
    parser = argparse.ArgumentParser(description="Scanner Website Tersusupi Judol")
    parser.add_argument("--url", help="Single URL to scan")
    parser.add_argument("--target", help="File with URLs (one per line)")
    parser.add_argument("--output", default="tersusupi_judol.json", help="JSON output file")
    parser.add_argument("--threads", type=int, default=THREADS)
    parser.add_argument("--deep", action="store_true", help="Deep scan (more paths, Googlebot comparison)")
    args = parser.parse_args()

    safe_print("="*60)
    safe_print("  Judol Merusak Generasi Muda")
    safe_print("  Kenshin Himura - roxlab.org@gmail.com")
    safe_print("="*60)

    if args.url:
        safe_print(f"\n[*] Scanning: {args.url}")
        result = scan_website(args.url, deep=args.deep)
        display_result(result, 1)

        if result.risk_score > 0:
            safe_print(f"\n[!] INDIKASI KOMPROMI DITEMUKAN pada {args.url}")
            safe_print(f"    Lihat detail di atas untuk langkah remediasi.")
        else:
            safe_print(f"\n[OK] Tidak ditemukan indikasi kompromi pada {args.url}")

        # Export hasil
        d = asdict(result)
        d["findings"] = [dict(f) for f in d["findings"]]
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump([d], f, indent=2, ensure_ascii=False)
        safe_print(f"\n[+] Report exported to {args.output}")
        return

    if not args.target:
        parser.error("Required: --url <url> or --target <file>")
        return

    targets = load_targets(args.target)
    if not targets:
        safe_print("[!] No valid targets in file")
        return

    results = mass_scan(targets, args.threads, args.deep)

    # Export
    export = []
    for r in results:
        d = asdict(r)
        d["findings"] = [dict(f) for f in d["findings"]]
        export.append(d)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(export, f, indent=2, ensure_ascii=False)

    safe_print(f"\n[+] {len(export)} results exported to {args.output}")


if __name__ == "__main__":
    main()
