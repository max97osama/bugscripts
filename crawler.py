#!/usr/bin/env python3
"""
Security Learning Material Crawler
====================================
Universal web crawler for security/learning sites.

Usage:
    python security_crawler.py -u <URL> -o <output_file.txt>

Examples:
    python security_crawler.py -u https://portswigger.net/web-security/all-materials -o portswigger.txt
    python security_crawler.py -u https://hacktricks.wiki/en/index.html -o hacktricks.txt
    python security_crawler.py -u https://adsecurity.org/ -o adsecurity.txt
    python security_crawler.py -u https://ippsec.rocks/ -o ippsec.txt
    python security_crawler.py -u https://packetstorm.news/ -o packetstorm.txt
    python security_crawler.py -u https://any-other-site.com/blog -o output.txt

Optional flags:
    --delay      Seconds between requests (default: 1.5)
    --max-pages  Max pages to crawl per run (default: 500)

Requirements:
    pip install requests beautifulsoup4 trafilatura lxml
"""

import os
import re
import time
import argparse
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import trafilatura

# ── Defaults ──────────────────────────────────────────────────────────────────
DELAY     = 1.5
TIMEOUT   = 20
MAX_PAGES = 500
MIN_TEXT  = 80
HEADERS   = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    )
}

session = requests.Session()
session.headers.update(HEADERS)


# ── Helpers ───────────────────────────────────────────────────────────────────

def fetch(url):
    try:
        r = session.get(url, timeout=TIMEOUT)
        r.raise_for_status()
        return r.text, r.status_code
    except requests.RequestException as e:
        code = getattr(getattr(e, "response", None), "status_code", 0)
        print(f"    [!] Failed {url} — {e}")
        return None, code


def extract_text(html, url):
    return trafilatura.extract(
        html,
        url=url,
        include_tables=True,
        include_links=False,
        include_images=False,
        no_fallback=False,
    ) or ""


def get_title(html):
    soup = BeautifulSoup(html, "lxml")
    if soup.title and soup.title.string:
        return soup.title.string.strip()
    h1 = soup.find("h1")
    return h1.get_text(strip=True) if h1 else "Untitled"


def same_domain(url, base):
    return urlparse(url).netloc == urlparse(base).netloc


def collect_links(html, base_url, path_prefix=""):
    soup  = BeautifulSoup(html, "lxml")
    links = set()
    for a in soup.find_all("a", href=True):
        full   = urljoin(base_url, a["href"])
        parsed = urlparse(full)
        clean  = parsed._replace(fragment="", query="").geturl()
        if same_domain(clean, base_url):
            if not path_prefix or parsed.path.startswith(path_prefix):
                links.add(clean)
    return links


def write_article(f, url, title, text):
    f.write("=" * 80 + "\n")
    f.write(f"URL   : {url}\n")
    f.write(f"TITLE : {title}\n")
    f.write("=" * 80 + "\n\n")
    f.write(text.strip() + "\n\n\n")


def get_domain(url):
    return urlparse(url).netloc.lower()


# ── Site-Specific Crawlers ────────────────────────────────────────────────────

def crawl_portswigger(url, f):
    """PortSwigger Web Security Academy."""
    base  = "https://portswigger.net"
    html, _ = fetch(url)
    if not html:
        return 0

    links = set()
    for a in BeautifulSoup(html, "lxml").find_all("a", href=True):
        if a["href"].startswith("/web-security/"):
            clean = urlparse(urljoin(base, a["href"]))._replace(fragment="", query="").geturl()
            links.add(clean)

    # Second-level discovery
    second = set()
    for link in list(links)[:MAX_PAGES]:
        time.sleep(DELAY)
        h, _ = fetch(link)
        if h:
            for a in BeautifulSoup(h, "lxml").find_all("a", href=True):
                if a["href"].startswith("/web-security/"):
                    clean = urlparse(urljoin(base, a["href"]))._replace(fragment="", query="").geturl()
                    second.add(clean)

    all_links = links | second
    print(f"  → {len(all_links)} article URLs found")

    count = 0
    for link in sorted(all_links):
        if count >= MAX_PAGES:
            break
        time.sleep(DELAY)
        html, _ = fetch(link)
        if not html:
            continue
        text = extract_text(html, link)
        if not text or len(text) < MIN_TEXT:
            continue
        title = get_title(html)
        write_article(f, link, title, text)
        count += 1
        print(f"  [{count}] {title[:70]}")
    return count


def crawl_ippsec(url, f):
    """IppSec.rocks — fetch dataset.json for all video metadata."""
    try:
        r    = session.get("https://ippsec.rocks/dataset.json", timeout=TIMEOUT)
        r.raise_for_status()
        data = r.json()
    except Exception as e:
        print(f"  [!] Could not fetch dataset.json: {e}")
        return 0

    count = 0
    for entry in (data if isinstance(data, list) else []):
        f.write("=" * 80 + "\n")
        name = entry.get("name",  entry.get("title", "Unknown"))
        link = entry.get("url",   entry.get("link",  "N/A"))
        tags = entry.get("tags",  entry.get("chapters", []))
        desc = entry.get("description", "")
        ts   = entry.get("timestamp", "")
        f.write(f"VIDEO : {name}\n")
        f.write(f"URL   : {link}\n")
        if ts:
            f.write(f"TIME  : {ts}\n")
        if tags:
            tag_strs = []
            for t in tags:
                if isinstance(t, dict):
                    label = t.get("name", t.get("tag", str(t)))
                    tts   = t.get("timestamp", "")
                    tag_strs.append(f"{label} @ {tts}" if tts else label)
                else:
                    tag_strs.append(str(t))
            f.write(f"TAGS  : {', '.join(tag_strs)}\n")
        if desc:
            f.write(f"DESC  : {desc}\n")
        f.write("=" * 80 + "\n\n")
        count += 1
        if count % 50 == 0:
            print(f"  [{count}] {name[:70]}")
    return count


def crawl_hacktricks(url, f):
    """HackTricks Wiki — BFS over all /en/ pages."""
    base    = "https://hacktricks.wiki"
    prefix  = "/en/"
    visited = set()
    html, _ = fetch(url)
    if not html:
        return 0

    queue = list(collect_links(html, base, path_prefix=prefix))
    visited.add(url)
    print(f"  → {len(queue)} seed links")

    count = 0
    while queue and count < MAX_PAGES:
        link = queue.pop(0)
        if link in visited:
            continue
        visited.add(link)
        time.sleep(DELAY)
        html, _ = fetch(link)
        if not html:
            continue
        for new in collect_links(html, base, path_prefix=prefix):
            if new not in visited:
                queue.append(new)
        text = extract_text(html, link)
        if not text or len(text) < MIN_TEXT:
            continue
        title = get_title(html)
        write_article(f, link, title, text)
        count += 1
        print(f"  [{count}] {title[:70]}")
    return count


def crawl_adsecurity(url, f):
    """ADSecurity.org — WordPress paginated archive."""
    base       = "https://adsecurity.org"
    post_links = set()

    for page in range(1, 31):
        page_url = base if page == 1 else f"{base}/?paged={page}"
        html, status = fetch(page_url)
        if not html or status == 404:
            break
        soup  = BeautifulSoup(html, "lxml")
        posts = (
            soup.select("h1.entry-title a, h2.entry-title a, .post-title a, article h2 a")
            or soup.select("a[rel='bookmark']")
        )
        if not posts:
            break
        for a in posts:
            post_links.add(urljoin(base, a["href"]))
        print(f"  Archive page {page}: {len(posts)} posts (total {len(post_links)})")
        time.sleep(DELAY)

    print(f"  → {len(post_links)} post URLs found")
    count = 0
    for link in sorted(post_links):
        if count >= MAX_PAGES:
            break
        time.sleep(DELAY)
        html, _ = fetch(link)
        if not html:
            continue
        text = extract_text(html, link)
        if not text or len(text) < MIN_TEXT:
            continue
        title = get_title(html)
        write_article(f, link, title, text)
        count += 1
        print(f"  [{count}] {title[:70]}")
    return count


def crawl_packetstorm(url, f):
    """PacketStorm News — paginated news index."""
    base          = "https://packetstorm.news"
    article_links = set()

    for page in range(1, 21):
        page_url = f"{base}/news/" if page == 1 else f"{base}/news/page/{page}/"
        html, status = fetch(page_url)
        if not html or status == 404:
            break
        for a in BeautifulSoup(html, "lxml").find_all("a", href=True):
            if re.match(r"^/news/view/\d+/", a["href"]):
                article_links.add(urljoin(base, a["href"]))
        print(f"  News page {page}: {len(article_links)} total links")
        time.sleep(DELAY)

    print(f"  → {len(article_links)} article URLs found")
    count = 0
    for link in sorted(article_links):
        if count >= MAX_PAGES:
            break
        time.sleep(DELAY)
        html, _ = fetch(link)
        if not html:
            continue
        text = extract_text(html, link)
        if not text or len(text) < MIN_TEXT:
            continue
        title = get_title(html)
        write_article(f, link, title, text)
        count += 1
        print(f"  [{count}] {title[:70]}")
    return count


def crawl_generic(url, f):
    """
    Generic BFS crawler — works on any site.
    Stays within the same domain and path prefix.
    """
    parsed  = urlparse(url)
    base    = f"{parsed.scheme}://{parsed.netloc}"
    prefix  = parsed.path.rsplit("/", 1)[0] + "/"
    visited = set()
    queue   = [url]
    print(f"  → Generic BFS crawl | domain: {parsed.netloc} | prefix: {prefix}")

    count = 0
    while queue and count < MAX_PAGES:
        link = queue.pop(0)
        if link in visited:
            continue
        visited.add(link)
        time.sleep(DELAY)
        html, _ = fetch(link)
        if not html:
            continue
        for new in collect_links(html, base, path_prefix=prefix):
            if new not in visited:
                queue.append(new)
        text = extract_text(html, link)
        if not text or len(text) < MIN_TEXT:
            continue
        title = get_title(html)
        write_article(f, link, title, text)
        count += 1
        print(f"  [{count}] {title[:70]}")
    return count


# ── Router ────────────────────────────────────────────────────────────────────

SITE_HANDLERS = {
    "portswigger.net" : crawl_portswigger,
    "ippsec.rocks"    : crawl_ippsec,
    "hacktricks.wiki" : crawl_hacktricks,
    "adsecurity.org"  : crawl_adsecurity,
    "packetstorm.news": crawl_packetstorm,
}


def route(url):
    domain = get_domain(url)
    for key, handler in SITE_HANDLERS.items():
        if key in domain:
            return handler
    return crawl_generic


# ── CLI ───────────────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        prog="security_crawler.py",
        description="Crawl security/learning sites and save articles to a text file.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python security_crawler.py -u https://portswigger.net/web-security/all-materials -o portswigger.txt
  python security_crawler.py -u https://hacktricks.wiki/en/index.html -o hacktricks.txt
  python security_crawler.py -u https://adsecurity.org/ -o adsecurity.txt
  python security_crawler.py -u https://ippsec.rocks/ -o ippsec.txt
  python security_crawler.py -u https://packetstorm.news/ -o packetstorm.txt
  python security_crawler.py -u https://any-other-site.com/blog -o custom.txt
  python security_crawler.py -u https://example.com -o out.txt --delay 2.0 --max-pages 200
        """
    )
    parser.add_argument("-u", "--url",       required=True,  help="Target site URL to crawl")
    parser.add_argument("-o", "--output",    required=True,  help="Output .txt file path")
    parser.add_argument("--delay",     type=float, default=DELAY,     help=f"Seconds between requests (default: {DELAY})")
    parser.add_argument("--max-pages", type=int,   default=MAX_PAGES, help=f"Max pages to crawl (default: {MAX_PAGES})")
    return parser.parse_args()


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    args = parse_args()

    global DELAY, MAX_PAGES
    DELAY     = args.delay
    MAX_PAGES = args.max_pages

    url     = args.url.rstrip("/")
    out     = args.output
    handler = route(url)

    print("=" * 60)
    print(f"  Target   : {url}")
    print(f"  Output   : {os.path.abspath(out)}")
    print(f"  Handler  : {handler.__name__}")
    print(f"  Delay    : {DELAY}s  |  Max pages: {MAX_PAGES}")
    print("=" * 60)

    out_dir = os.path.dirname(out)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    with open(out, "w", encoding="utf-8") as f:
        f.write(f"CRAWLED FROM : {url}\n")
        f.write("=" * 80 + "\n\n\n")
        count = handler(url, f)

    size_mb = os.path.getsize(out) / (1024 * 1024)
    print("\n" + "=" * 60)
    print(f"  ✓ Done!  {count} articles saved")
    print(f"  ✓ File : {os.path.abspath(out)}  ({size_mb:.1f} MB)")
    print("=" * 60)


if __name__ == "__main__":
    main()