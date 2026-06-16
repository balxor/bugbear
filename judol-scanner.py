#!/usr/bin/env python3
"""
Judol Merusak Generasi Muda
Kenshin Himura - roxlab.org@gmail.com
========================================================
Metode:
 1. Keyword-based: konten HTML + meta tag + title
 2. SEO poisoning detection: konten berbeda untuk bot vs user
 3. Domain pattern matching: TLD murah + nama generik
 4. Redirect chain ke domain judi dikenal
 5. Web shell + GSocket persistence detection (server korban)
 6. Struktur HTML khas platform judi (iframe embed, game list)

Usage:
  python scanner_judol.py --target domain.txt
  python scanner_judol.py --url https://example.com
  python scanner_judol.py --cidr 103.0.0.0/8 --ports 80,443
  python scanner_judol.py --mass-scan from-shodan-export.json
"""

import re
import sys
import ssl
import json
import time
import gzip
import socket
import hashlib
import argparse
import threading
import urllib.parse
import urllib.request
import urllib.error
from dataclasses import dataclass, field, asdict
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

# ─── CONFIG ───────────────────────────────────────────────────────────

TIMEOUT = 10
MAX_REDIRECTS = 5
THREADS = 50
USER_AGENT_BOT = (
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
)
USER_AGENT_HUMAN = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)

# ─── JUDI KEYWORD CORPUS ──────────────────────────────────────────────

JUDI_KEYWORDS = [
    # Umum
    "judi online", "situs judi", "agen judi", "bandar judi",
    "judi slot", "judi bola", "sportsbook", "live casino",
    "slot online", "slot gacor", "slot maxwin", "slot rtp",
    "togel online", "toto online", "togel hk", "togel sgp",
    "casino online", "live casino", "sicbo", "baccarat", "roulette",
    "poker online", "dominoqq", "bandarq", "ceme",
    "sabung ayam", "cockfight",
    # Deposit / Withdraw
    "deposit pulsa", "depo via dana", "depo via ovo",
    "deposit gopay", "deposit linkaja", "depo qris",
    "minimal deposit", "minimal depo", "deposit terjangkau",
    "withdraw", "wd", "penarikan dana",
    # Bonus / Promosi khas judi
    "bonus new member", "bonus deposit", "bonus cashback",
    "bonus rollingan", "bonus turnover", "bonus mingguan",
    "promo terbaru", "event slot", "turnamen slot",
    "freebet", "free chip", "garansi kekalahan",
    # Klaim lisensi
    "lisensi resmi", "lisensi pagcor", "lisensi bmm",
    "lisensi international", "diawasi oleh",
    "sertifikat resmi",
    # Domain / redirect
    "link alternatif", "login alternatif", "situs alternatif",
    "daftar sekarang", "daftar di sini", "klik untuk daftar",
    "claim bonus",
]

JUDI_KEYWORDS_NEGATIVE = [
    # Untuk mengurangi false positive
    "kemenkominfo", "polri", "ojk", "bank indonesia",
    "berita", "artikel", "penelitian",
]

JUDI_TLDS = {
    ".cc", ".top", ".vip", ".xyz", ".me", ".site", ".online",
    ".club", ".live", ".guru", ".win", ".bet", ".casino",
    ".buzz", ".monster", ".fun", ".art",
}

JUDI_DOMAIN_PATTERNS = [
    r"(?i)(slot|togel|toto|judi|poker|casino|bola|sabung)[a-z0-9-]*\.[a-z]+",
    r"(?i)(gacor|maxwin|hoki|jackpot|mpo|idn|pragmatic)[a-z0-9-]*\.[a-z]+",
    r"(?i)(login|daftar|alternatif|link)[0-9]*\.[a-z]+",
]

JUDI_STRUCTURAL_MARKERS = [
    # iframe embed dari provider game judi
    r'(?i)(?:src|href)=["\']https?://[^"\']*(?:pragmatic|habanero|spadegaming|pgsoft|microgaming|playtech|evolution|idnplay|idnpoker)[^"\']*["\']',
    # Game list dengan jumlah (khas situs slot)
    r'<span[^>]*>\d{2,4}\s*</span>\s*permainan',
    # List deposit method
    r'(?i)(dana|ovo|gopay|linkaja|qris|shopeepay)\s*(?:</td>|</li>|</span>|<br)',
    # WhatsApp floating button
    r'(?i)api\.whatsapp\.com/send.*?(?:judi|slot|togel|casino|depo|bonus)',
]

# ─── WEB SHELL + BACKDOOR SIGNATURES ───────────────────────────────────
# Menandakan server korban yang dipakai untuk hosting konten judi

WEBSHELL_SIGNATURES = [
    # PHP shells umum
    rb'(?i)(?:passthru|shell_exec|exec|system|proc_open|popen)\s*\(\s*[\'"](?:id|whoami|uname|ls|wget|curl)',
    rb'(?i)(?:c99shell|r57shell|b374k|weevely|webacoo|edgardoor)',
    # GSocket presence
    rb'(?i)gsocket[_-]?\d',
    rb'(?i)/tmp/\.gs-',
    # PHP file dengan user-agent check + konten judi
    rb'(?i)Googlebot.*?(?:slot|judi|togel|casino|situs)',
    # Suspicious crontab entries
    rb'(?i)\*/\d+\s+\*\s+\*\s+\*.*?(?:gsocket|wget|curl).*?\.php',
]

# ─── DATA CLASSES ──────────────────────────────────────────────────────

@dataclass
class JudolFinding:
    url: str
    score: int = 0
    title: str = ""
    meta_desc: str = ""
    keywords_hits: list = field(default_factory=list)
    domain_flags: list = field(default_factory=list)
    redirect_chain: list = field(default_factory=list)
    final_url: str = ""
    seo_poison_detected: bool = False
    seo_poison_detail: str = ""
    structural_markers: list = field(default_factory=list)
    webshell_detected: bool = False
    webshell_detail: str = ""
    page_size: int = 0
    response_time: float = 0.0
    status_code: int = 0
    ip_address: str = ""


@dataclass
class ScanStats:
    scanned: int = 0
    alive: int = 0
    detected: int = 0
    errors: int = 0
    start_time: float = 0.0


# ─── HTTP REQUEST ENGINE ───────────────────────────────────────────────

def create_ssl_context():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def fetch_url(url, user_agent=USER_AGENT_HUMAN, follow_redirects=True):
    findings = {
        "content": b"",
        "redirect_chain": [],
        "final_url": url,
        "status_code": 0,
        "response_time": 0.0,
    }
    ctx = create_ssl_context()
    current_url = url
    parsed_orig = urllib.parse.urlparse(url)
    hostname = parsed_orig.netloc or parsed_orig.path.split("/")[0]

    for _ in range(MAX_REDIRECTS):
        start = time.time()
        req = urllib.request.Request(current_url)
        req.add_header("User-Agent", user_agent)
        req.add_header("Accept", "text/html,application/xhtml+xml,*/*")
        req.add_header("Accept-Language", "id-ID,id;q=0.9,en;q=0.8")
        req.add_header("Accept-Encoding", "gzip, deflate")
        req.add_header("Host", hostname)

        try:
            resp = urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx)
            findings["response_time"] = time.time() - start
            findings["status_code"] = resp.status

            if resp.status in (301, 302, 303, 307, 308):
                new_url = resp.getheader("Location")
                if not new_url:
                    break
                if new_url.startswith("/"):
                    parsed = urllib.parse.urlparse(current_url)
                    new_url = f"{parsed.scheme}://{parsed.netloc}{new_url}"
                findings["redirect_chain"].append(current_url)
                current_url = new_url
                hostname = urllib.parse.urlparse(new_url).netloc or hostname
                continue

            # Read body
            raw = resp.read()
            content_encoding = resp.getheader("Content-Encoding", "")
            if "gzip" in content_encoding.lower():
                raw = gzip.decompress(raw)
            findings["content"] = raw
            findings["final_url"] = current_url
            return findings

        except urllib.error.HTTPError as e:
            findings["status_code"] = e.code
            return findings
        except (urllib.error.URLError, ssl.SSLError, socket.timeout, ConnectionResetError) as e:
            # Fallback: retry with HTTP if HTTPS fails
            if current_url.startswith("https://"):
                http_url = current_url.replace("https://", "http://", 1)
                try:
                    req2 = urllib.request.Request(http_url)
                    req2.add_header("User-Agent", user_agent)
                    req2.add_header("Host", hostname)
                    resp2 = urllib.request.urlopen(req2, timeout=TIMEOUT, context=ctx)
                    findings["response_time"] = time.time() - start
                    findings["status_code"] = resp2.status
                    raw = resp2.read()
                    ce = resp2.getheader("Content-Encoding", "")
                    if "gzip" in ce.lower():
                        raw = gzip.decompress(raw)
                    findings["content"] = raw
                    findings["final_url"] = http_url
                    return findings
                except:
                    pass
            findings["status_code"] = 0
            return findings

    return findings


# ─── ANALYSIS ENGINE ───────────────────────────────────────────────────

def extract_title(html_bytes):
    try:
        text = html_bytes.decode("utf-8", errors="replace")
    except Exception:
        text = html_bytes.decode("latin-1", errors="replace")
    m = re.search(r"(?i)<title[^>]*>(.+?)</title>", text)
    return m.group(1).strip()[:300] if m else ""


def extract_meta_description(html_bytes):
    try:
        text = html_bytes.decode("utf-8", errors="replace")
    except Exception:
        text = html_bytes.decode("latin-1", errors="replace")
    for pattern in [
        r'(?i)<meta\s+name=["\']description["\']\s+content=["\'](.+?)["\']',
        r'(?i)<meta\s+content=["\'](.+?)["\']\s+name=["\']description["\']',
    ]:
        m = re.search(pattern, text)
        if m:
            return m.group(1).strip()[:500]
    return ""


def check_seo_poisoning(url):
    result_bot = fetch_url(url, user_agent=USER_AGENT_BOT)
    result_human = fetch_url(url, user_agent=USER_AGENT_HUMAN)

    if not result_bot["content"] or not result_human["content"]:
        return False, ""

    # Compare content hashes
    hash_bot = hashlib.sha256(result_bot["content"]).hexdigest()
    hash_human = hashlib.sha256(result_human["content"]).hexdigest()

    if hash_bot != hash_human:
        # One serves gambling, other redirects
        site_bot = extract_title(result_bot["content"])
        site_human = extract_title(result_human["content"])
        diff_url = result_bot["final_url"] != result_human["final_url"]

        detail = (
            f"HASH_DIFF={hash_bot[:8]}/{hash_human[:8]} "
            f"TITLE_BOT='{site_bot}' TITLE_HUMAN='{site_human}' "
            f"FINAL_URL_BOT={result_bot['final_url']} "
            f"FINAL_URL_HUMAN={result_human['final_url']} "
            f"STATUS_BOT={result_bot['status_code']} "
            f"STATUS_HUMAN={result_human['status_code']}"
        )
        return True, detail

    return False, ""


def score_domain(domain):
    flags = []
    score = 0
    parsed = urllib.parse.urlparse(domain if "//" in domain else f"http://{domain}")
    host = parsed.netloc or parsed.path

    # TLD check
    tld = host[host.rfind("."):] if "." in host else ""
    if tld in JUDI_TLDS:
        flags.append(f"TLD_MENcurigakan:{tld}")
        score += 10

    # Pattern check
    for pattern in JUDI_DOMAIN_PATTERNS:
        if re.search(pattern, host):
            flags.append(f"DOMAIN_PATTERN:{pattern}")
            score += 15
            break

    # Length suspicious?
    if len(host.split(".")[0]) <= 6 and tld in JUDI_TLDS:
        flags.append("DOMAIN_SINGKAT_MENcurigakan")
        score += 5

    return score, flags


def analyze_content(html_bytes):
    try:
        text = html_bytes.decode("utf-8", errors="replace").lower()
    except Exception:
        text = html_bytes.decode("latin-1", errors="replace").lower()

    keyword_hits = []
    for kw in JUDI_KEYWORDS:
        if kw.lower() in text:
            keyword_hits.append(kw)

    structural_markers = []
    for pattern in JUDI_STRUCTURAL_MARKERS:
        try:
            decoded = html_bytes.decode("utf-8", errors="replace")
        except Exception:
            decoded = html_bytes.decode("latin-1", errors="replace")
        if re.search(pattern, decoded, re.IGNORECASE):
            structural_markers.append(pattern[:80])

    return keyword_hits, structural_markers


def check_webshell_signatures(html_bytes):
    for i, sig in enumerate(WEBSHELL_SIGNATURES):
        m = re.search(sig, html_bytes)
        if m:
            return True, f"SIGNATURE_{i}:{m.group(0)[:100]}"
    return False, ""


def analyze_url(target_url):
    finding = JudolFinding(url=target_url)
    score = 0

    # 1. Domain scoring
    domain_score, domain_flags = score_domain(target_url)
    score += domain_score
    finding.domain_flags = domain_flags

    # 2. Fetch page as human
    result = fetch_url(target_url)

    if not result["content"] and result["status_code"] == 0:
        return None  # Dead

    finding.status_code = result["status_code"]
    finding.redirect_chain = result["redirect_chain"]
    finding.final_url = result["final_url"]
    finding.response_time = result["response_time"]
    finding.page_size = len(result["content"])

    # Resolve IP
    try:
        parsed = urllib.parse.urlparse(result["final_url"])
        host = parsed.netloc or parsed.hostname
        finding.ip_address = socket.gethostbyname(host)
    except Exception:
        pass

    # 3. Redirect to gambling domain?
    for url_in_chain in result["redirect_chain"]:
        rs, rf = score_domain(url_in_chain)
        score += rs
        finding.domain_flags.extend(rf)
    if result["redirect_chain"]:
        rs, rf = score_domain(result["final_url"])
        score += rs
        finding.domain_flags.extend(rf)

    if not result["content"]:
        return finding

    # 4. Content analysis
    keyword_hits, structural = analyze_content(result["content"])
    finding.keywords_hits = keyword_hits
    finding.structural_markers = structural
    score += len(keyword_hits) * 5
    score += len(structural) * 8

    # 5. Title & meta
    finding.title = extract_title(result["content"])
    finding.meta_desc = extract_meta_description(result["content"])
    if finding.title:
        for kw in JUDI_KEYWORDS:
            if kw.lower() in finding.title.lower():
                score += 8
                finding.keywords_hits.append(f"TITLE:{kw}")

    # 6. Web shell check
    ws_detected, ws_detail = check_webshell_signatures(result["content"])
    finding.webshell_detected = ws_detected
    finding.webshell_detail = ws_detail
    if ws_detected:
        score += 20

    # 7. SEO poisoning check (double fetch)
    seo_detected, seo_detail = check_seo_poisoning(target_url)
    finding.seo_poison_detected = seo_detected
    finding.seo_poison_detail = seo_detail
    if seo_detected:
        score += 25

    finding.score = score
    return finding


# ─── OUTPUT ─────────────────────────────────────────────────────────────

def print_banner():
    print("""
=============================================================
    Judol Merusak Generasi Muda
    Kenshin Himura - roxlab.org@gmail.com
=============================================================
""")


def safe_print(*args, **kwargs):
    text = " ".join(str(a) for a in args)
    try:
        print(text, **kwargs)
    except UnicodeEncodeError:
        print(text.encode("ascii", errors="replace").decode("ascii"), **kwargs)


def print_result(finding, idx):
    if finding.score < 10:
        return

    status = f"[AKTIF {finding.status_code}]" if finding.status_code == 200 else f"[{finding.status_code}]"
    label = "JUDOL" if finding.score >= 50 else ("SUSPECT" if finding.score >= 20 else "LOW")

    safe_print(f"\n{'-'*70}")
    safe_print(f"[{idx}] {label} | Score: {finding.score} | {status}")
    safe_print(f"    URL: {finding.url}")
    safe_print(f"    Final: {finding.final_url}")
    safe_print(f"    IP: {finding.ip_address} | Time: {finding.response_time:.2f}s | Size: {finding.page_size/1024:.1f}KB")
    if finding.title:
        safe_print(f"    Title: {finding.title[:180]}")

    if finding.keywords_hits:
        kws = list(set(finding.keywords_hits))
        safe_print(f"    Keywords ({len(kws)}): {', '.join(kws[:15])}")
    if finding.structural_markers:
        safe_print(f"    Structural: {len(finding.structural_markers)} markers")
    if finding.domain_flags:
        safe_print(f"    Domain flags: {finding.domain_flags}")
    if finding.redirect_chain:
        safe_print(f"    Redirect: {' -> '.join(finding.redirect_chain[-2:])} -> {finding.final_url}")
    if finding.seo_poison_detected:
        detail = finding.seo_poison_detail[:200]
        safe_print(f"    SEO POISON detected: {detail}")
    if finding.webshell_detected:
        safe_print(f"    WEB SHELL: {finding.webshell_detail}")


def export_json(findings, output_path):
    results = [asdict(f) for f in findings if f and f.score >= 10]
    with open(output_path, "w", encoding="utf-8") as fp:
        json.dump(results, fp, indent=2, ensure_ascii=False)
    print(f"\n[+] {len(results)} results exported to {output_path}")


# ─── MASS SCANNER ──────────────────────────────────────────────────────

def ensure_scheme(url):
    url = url.strip()
    if not url:
        return None
    if "://" not in url:
        return f"https://{url}"
    return url


def load_targets(target_file):
    targets = []
    with open(target_file, "r", encoding="utf-8") as f:
        for line in f:
            target = ensure_scheme(line.strip())
            if target:
                targets.append(target)
    return list(dict.fromkeys(targets))  # deduplicate


def mass_scan(targets, threads=THREADS):
    stats = ScanStats(start_time=time.time())
    stats.scanned = len(targets)
    findings = []

    print(f"[*] Scanning {len(targets)} targets with {threads} threads...\n")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_map = {executor.submit(analyze_url, t): t for t in targets}
        done = 0
        for future in as_completed(future_map):
            done += 1
            try:
                result = future.result(timeout=TIMEOUT * 2)
                if result is None:
                    stats.errors += 1
                else:
                    stats.alive += 1
                    if result.score >= 10:
                        stats.detected += 1
                    findings.append(result)
            except Exception as e:
                stats.errors += 1

            if done % 100 == 0:
                el = time.time() - stats.start_time
                print(f"    {done}/{len(targets)} scanned | {stats.detected} detected | {el:.0f}s")

    elapsed = time.time() - stats.start_time
    print(f"\n[*] Done. {stats.scanned} scanned, {stats.alive} alive, "
          f"{stats.detected} detected, {stats.errors} errors in {elapsed:.1f}s")

    # Sort by score descending
    findings.sort(key=lambda f: f.score if f else 0, reverse=True)
    return findings, stats


# ─── MAIN ──────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Judol Scanner")
    parser.add_argument("--target", help="File with URLs/domains (one per line)")
    parser.add_argument("--url", help="Single URL to scan")
    parser.add_argument("--output", default="judol_findings.json", help="JSON output file")
    parser.add_argument("--threads", type=int, default=THREADS, help="Concurrent threads")
    parser.add_argument("--min-score", type=int, default=10, help="Minimum score to display")
    parser.add_argument("--show-all", action="store_true", help="Show all results including clean ones")
    args = parser.parse_args()

    print_banner()

    if args.url:
        print(f"[*] Single URL scan: {args.url}\n")
        result = analyze_url(args.url)
        if result:
            print_result(result, 1)
        else:
            print("[!] Target unreachable")
        return

    if not args.target:
        parser.error("Required: --target <file> or --url <url>")
        return

    targets = load_targets(args.target)
    if not targets:
        print("[!] No valid targets found")
        return

    findings, stats = mass_scan(targets, args.threads)

    # Display
    shown = 0
    for i, f in enumerate(findings, 1):
        if f and (args.show_all or f.score >= args.min_score):
            print_result(f, i)
            shown += 1

    # Export
    export_json(findings, args.output)
    print(f"\n[+] Shown {shown}/{stats.detected} detected")
    print(f"[+] Summary: {stats.scanned} scanned | {stats.alive} alive | "
          f"{stats.detected} suspicious (score>={args.min_score})")


if __name__ == "__main__":
    main()
