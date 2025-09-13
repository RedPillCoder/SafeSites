import asyncio, csv, datetime as dt, json, re, socket, sqlite3, ssl, sys, textwrap, time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import aiohttp, tldextract, streamlit as st
from bs4 import BeautifulSoup
from duckduckgo_search import DDGS

# ---------------- CONFIG ---------------- #
APP_DIR = Path.home() / ".safe_sites_repo"
DB_PATH, CACHE_DIR = APP_DIR / "repository.sqlite", APP_DIR / "cache"
APP_DIR.mkdir(parents=True, exist_ok=True); CACHE_DIR.mkdir(parents=True, exist_ok=True)

USER_AGENT = "SafeSitesRepo/4.1 (+https://example.local)"
MAX_REDIRECTS, CONCURRENCY, REQUEST_TIMEOUT = 5, 8, 30

BLOCKLIST_SOURCES = {
    "phishtank": "https://data.phishtank.com/data/online-valid.csv",
    "urlhaus": "https://urlhaus.abuse.ch/downloads/csv/",
    "openphish": "https://openphish.com/feed.txt",
}

CATEGORY_KEYWORDS = {
    "Educational": ["university","college","course","tutorial","curriculum","learn","education","lectures","mooc","syllabus"],
    "News and Media": ["news","press","breaking","journalism","headline","report","magazine","newspaper"],
    "Entertainment": ["entertainment","music","movie","film","tv","series","stream","game","comedy","podcast","anime"],
    "Productivity": ["productivity","notes","todo","tasks","calendar","project","kanban","planner","docs","organize"],
    "Health and Wellness": ["health","wellness","fitness","nutrition","mental health","therapy","medical","exercise"],
    "Science and Technology": ["science","research","paper","developer","api","open source","engineering","technology","docs"],
    "Arts and Culture": ["museum","gallery","art","culture","exhibit","theatre","literature"],
    "Government and Public Services": ["government","public service","council","ministry","department","city","state","federal","gov"]
}
HTML_MIME_TYPES = ("text/html","application/xhtml+xml")

# ---------------- DATA MODEL ---------------- #
@dataclass
class SiteRecord:
    url: str; domain: str; category: str; safe: bool; reasons: List[str]; checked_at: str
    title: Optional[str]=None; description: Optional[str]=None; final_url: Optional[str]=None
    http_status: Optional[int]=None; https: Optional[bool]=None; tls_ok: Optional[bool]=None
    tls_expired: Optional[bool]=None; hsts: Optional[bool]=None
    security_headers: Optional[Dict[str,bool]]=None; blocklisted: Optional[bool]=None

# ---------------- DATABASE ---------------- #
def db_connect():
    con = sqlite3.connect(DB_PATH)
    con.execute("""CREATE TABLE IF NOT EXISTS sites(
        url TEXT PRIMARY KEY, domain TEXT, category TEXT, safe INTEGER, reasons TEXT, checked_at TEXT,
        title TEXT, description TEXT, final_url TEXT, http_status INTEGER, https INTEGER, tls_ok INTEGER,
        tls_expired INTEGER, hsts INTEGER, security_headers TEXT, blocklisted INTEGER)""")
    return con

def save_record(rec: SiteRecord):
    con = db_connect()
    with con:
        con.execute("""INSERT OR REPLACE INTO sites VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
            rec.url, rec.domain, rec.category, int(rec.safe),
            json.dumps(rec.reasons,ensure_ascii=False), rec.checked_at, rec.title, rec.description,
            rec.final_url, rec.http_status, int(bool(rec.https)) if rec.https is not None else None,
            int(bool(rec.tls_ok)) if rec.tls_ok is not None else None,
            int(bool(rec.tls_expired)) if rec.tls_expired is not None else None,
            int(bool(rec.hsts)) if rec.hsts is not None else None,
            json.dumps(rec.security_headers or {},ensure_ascii=False),
            int(bool(rec.blocklisted)) if rec.blocklisted is not None else None))
    con.close()

def export_repo(path: Path):
    con = db_connect()
    cur = con.execute("SELECT * FROM sites WHERE safe=1 ORDER BY category, domain")
    cols = [d[0] for d in cur.description]
    rows = [dict(zip(cols,r)) for r in cur.fetchall()]
    con.close()
    for r in rows:
        r["reasons"]=json.loads(r.get("reasons") or "[]")
        r["security_headers"]=json.loads(r.get("security_headers") or "{}")
    path.write_text(json.dumps(rows,indent=2,ensure_ascii=False),encoding="utf-8")
    return rows

# ---------------- BLOCKLISTS ---------------- #
async def _fetch_text(session,url):
    try:
        async with session.get(url,headers={"User-Agent":USER_AGENT},timeout=REQUEST_TIMEOUT) as r:
            return await r.text()
    except:
        return ""

async def load_blocklists_async(force_refresh=False)->Dict[str,set]:
    cache_file = CACHE_DIR/"blocklists.json"
    fresh = cache_file.exists() and (time.time()-cache_file.stat().st_mtime)<86400
    if fresh and not force_refresh:
        return {k:set(v) for k,v in json.load(open(cache_file)).items()}
    async with aiohttp.ClientSession() as s:
        texts = await asyncio.gather(*[_fetch_text(s,u) for u in BLOCKLIST_SOURCES.values()])
    lists={"domains":set(),"urls":set()}
    try:
        for row in csv.DictReader(texts[0].splitlines()):
            u=row.get("url")
            if u and u.startswith("http"):
                lists["urls"].add(u.strip())
                lists["domains"].add(tldextract.extract(u).registered_domain)
    except: pass
    try:
        for line in texts[1].splitlines():
            if line and not line.startswith("#") and line.startswith("http"):
                u=line.split(",")[0].strip()
                lists["urls"].add(u)
                lists["domains"].add(tldextract.extract(u).registered_domain)
    except: pass
    try:
        for line in texts[2].splitlines():
            if line.startswith("http"):
                lists["urls"].add(line.strip())
                lists["domains"].add(tldextract.extract(line.strip()).registered_domain)
    except: pass
    json.dump({k:sorted(v) for k,v in lists.items()},open(cache_file,"w"))
    return lists

# ---------------- HELPERS ---------------- #
_dns_cache={}
async def dns_resolves(host):
    if not host: return False
    if host in _dns_cache: return _dns_cache[host]
    try:
        await asyncio.get_event_loop().getaddrinfo(host,443)
        _dns_cache[host]=True
        return True
    except:
        _dns_cache[host]=False
        return False

def _parse_cert_not_after(cert):
    try:
        return dt.datetime.strptime(cert.get("notAfter"),"%b %d %H:%M:%S %Y %Z") if cert.get("notAfter") else None
    except:
        return None

def get_tls_info(hostname: str) -> Tuple[bool, Optional[bool]]:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                exp = _parse_cert_not_after(cert)
                expired = (exp is not None) and (exp < dt.datetime.utcnow())
                return True, expired
    except:
        return False, None

def is_html_content_type(ct: Optional[str]) -> bool:
    return bool(ct and any(m in ct.lower() for m in HTML_MIME_TYPES))

def extract_title_desc(html: bytes) -> Tuple[Optional[str], Optional[str]]:
    if not html:
        return None, None
    try:
        soup = BeautifulSoup(html, "html.parser")
        title = soup.title.string.strip() if soup.title and soup.title.string else None
        desc = None
        m = soup.find("meta", attrs={"name": "description"})
        if m and m.get("content"):
            desc = m["content"].strip()
        if not desc:
            og = soup.find("meta", property="og:description")
            if og and og.get:
                desc = og["content"].strip()
        return title, desc
    except:
        return None, None

def score_security_headers(headers: Dict[str, str]) -> Dict[str, bool]:
    lower = {k.lower(): v for k, v in headers.items()}
    return {
        "csp": "content-security-policy" in lower,
        "x_content_type_options": lower.get("x-content-type-options", "").lower() == "nosniff",
        "x_frame_options": "x-frame-options" in lower,
        "referrer_policy": "referrer-policy" in lower,
        "permissions_policy": "permissions-policy" in lower or "feature-policy" in lower,
        "hsts": "strict-transport-security" in lower
    }

def infer_category(domain: str, title: Optional[str], desc: Optional[str]) -> str:
    ext = tldextract.extract(domain)
    tld = ext.suffix.lower()
    registered = ext.registered_domain
    text = " ".join([title or "", desc or "", registered or ""]).lower()
    if tld in ("gov", "gov.au", "gov.uk", "gouv.fr", "govt.nz"):
        return "Government and Public Services"
    if tld in ("edu", "edu.au", "ac.uk"):
        return "Educational"
    scores = {k: 0 for k in CATEGORY_KEYWORDS}
    for cat, kws in CATEGORY_KEYWORDS.items():
        for kw in kws:
            if re.search(rf"\b{re.escape(kw)}\b", text):
                scores[cat] += 1
    if "museum" in registered or "gallery" in registered:
        scores["Arts and Culture"] += 2
    if "news" in registered:
        scores["News and Media"] += 2
    best_cat, best_score = max(scores.items(), key=lambda x: x[1])
    return best_cat if best_score > 0 else "Science and Technology"

# ---------------- SEARCH ---------------- #
def search_web(query: str, max_results: int = 30) -> List[str]:
    urls = []
    with DDGS() as ddgs:
        for r in ddgs.text(query, region="wt-wt", safesearch="moderate", max_results=max_results):
            u = r.get("href") or r.get("url")
            if u and u.startswith("http"):
                urls.append(u)
    seen, uniq = set(), []
    for u in urls:
        rd = tldextract.extract(u).registered_domain
        path = urlparse(u).path.rstrip("/")
        key = (rd, path)
        if key not in seen:
            seen.add(key)
            uniq.append(u)
    return uniq

# ---------------- SITE CHECK ---------------- #
async def check_site(url: str, blocklists: Dict[str, set], sem: asyncio.Semaphore) -> SiteRecord:
    async with sem:
        now = dt.datetime.utcnow().isoformat() + "Z"
        original = url.strip()
        p = urlparse(original)
        domain = tldextract.extract(p.netloc).registered_domain
        reasons = []
        if domain in blocklists["domains"] or original in blocklists["urls"]:
            return SiteRecord(original, domain, "Science and Technology", False, ["Listed on public blocklists"], now, blocklisted=True)
        if not await dns_resolves(p.hostname or ""):
            return SiteRecord(original, domain, "Science and Technology", False, ["DNS resolution failed"], now)
        timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT)
        async with aiohttp.ClientSession(headers={"User-Agent": USER_AGENT}, timeout=timeout) as session:
            try:
                async with session.get(original, allow_redirects=True, max_redirects=MAX_REDIRECTS) as resp:
                    body = await resp.read()
                    status = resp.status
                    headers = dict(resp.headers)
                    https = original.startswith("https://")
                    title, desc = extract_title_desc(body)
                    category = infer_category(domain, title, desc)
                    tls_ok, tls_expired = await asyncio.get_event_loop().run_in_executor(None, lambda: get_tls_info(p.hostname or ""))
                    sec = score_security_headers(headers)
                    hsts = bool(sec.get("hsts"))
                    if status >= 400:
                        reasons.append(f"HTTP status {status}")
                    if tls_expired:
                        reasons.append("TLS certificate expired")
                    safe = (status < 400) and tls_ok and not tls_expired
                    return SiteRecord(original, domain, category, safe, reasons, now, title, desc, str(resp.url), status, https, tls_ok, tls_expired, hsts, sec, False)
            except:
                return SiteRecord(original, domain, "Science and Technology", False, ["Fetch failed"], now)

# ---------------- PIPELINE ---------------- #
async def pipeline(query: str, limit: int = 30) -> List[SiteRecord]:
    blocklists = await load_blocklists_async()
    urls = search_web(query, max_results=limit)
    sem = asyncio.Semaphore(CONCURRENCY)
    tasks = [check_site(u, blocklists, sem) for u in urls]
    results = await asyncio.gather(*tasks)
    for rec in results:
        save_record(rec)
    return results

# ---------------- STREAMLIT UI ---------------- #
def run_ui():
    st.title("🔍 Safe Sites Repository")
    query = st.text_input("Enter search query")
    limit = st.slider("Number of results", 5, 50, 25)
    if st.button("Search"):
        with st.spinner("Searching and verifying..."):
            results = asyncio.run(pipeline(query, limit))
        safe_sites = [r for r in results if r.safe]
        if safe_sites:
            st.success(f"Found {len(safe_sites)} SAFE sites")
            st.table([{"Category": r.category, "Domain": r.domain, "Title": r.title, "URL": r.final_url or r.url} for r in safe_sites])
            if st.button("Export to JSON"):
                export_path = APP_DIR / "safe_sites_export.json"
                export_repo(export_path)
                st.info(f"Exported to {export_path}")
        else:
            st.warning("No safe sites found.")

# ---------------- CLI ---------------- #
def print_help():
    print("""
    Safe Sites Repository

    Commands:
      search "<query>" --limit N   Search and verify sites
      review                       Show safe sites
      export --out file.json       Export safe sites
      ui                           Launch web interface
    """)

def main():
    if len(sys.argv) == 1:
        print_help()
        return
    cmd = sys.argv[1].lower()
    if cmd == "search":
        query = sys.argv[2]
        limit = 30
        if "--limit" in sys.argv:
            limit = int(sys.argv[sys.argv.index("--limit") + 1])
        results = asyncio.run(pipeline(query, limit))
        for r in results:
            if r.safe:
                print(f"[SAFE] {r.domain} - {r.title or ''} - {r.final_url or r.url}")
    elif cmd == "review":
        con = db_connect()
        cur = con.execute("SELECT domain,title,url FROM sites WHERE safe=1 ORDER BY category,domain")
        for d, t, u in cur.fetchall():
            print(f"{d} - {t or ''} - {u}")
        con.close()
    elif cmd == "export":
        out = Path(sys.argv[sys.argv.index("--out") + 1]) if "--out" in sys.argv else Path("safe_sites.json")
        export_repo(out)
        print(f"Exported to {out}")
    elif cmd == "ui":
        run_ui()
    else:
        print_help()

if __name__ == "__main__":
    main()
