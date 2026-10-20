"""Threat Intel Monitor v4.

Collects threat intelligence from configured RSS/JSON sources, scores items
against the Company operating profile, and writes a daily Excel workbook with
Critical, Review, and Low/Archive sheets.
"""

import json
import logging
import os
import re
import smtplib
import socket
import sys
import time
import ipaddress
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import feedparser
import pandas as pd
import requests
from bs4 import BeautifulSoup
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter

# Workbook tabs reflect operational priority:
# CRITICAL = likely same-day Company action
# REVIEW   = analyst review or exposure validation
# LOW      = archive/no immediate action

SCRIPT_DIR = Path(__file__).resolve().parent
RUNTIME_DIR = SCRIPT_DIR / "runtime_logs"
RUNTIME_DIR.mkdir(exist_ok=True)

OUTPUT_PREFIX = "threat_intel"
USER_AGENT = "ThreatIntelMonitor/4.3 (+InfoSec)"
REQUEST_TIMEOUT = 12
SOURCE_TIMEOUT = 45
RUN_TIMEOUT = 240
MAX_WORKERS = 10
ARTICLE_FETCH_ENABLED = True
MAX_ARTICLE_TEXT_CHARS = 18000
DEFAULT_FIRST_RUN_HOURS = 24
MAX_CATCHUP_HOURS = 72
RETENTION_DAYS = 90

# Main runtime log for run status, source warnings, and summaries.
RUN_LOG_FILE = RUNTIME_DIR / "monitor_run_activity.log"
SEEN_ITEMS_FILE = RUNTIME_DIR / "seen_items.json"
LAST_RUN_STATE_FILE = RUNTIME_DIR / "last_run_state.json"
RUN_HISTORY_FILE = RUNTIME_DIR / "run_history.jsonl"

ENABLE_EMAIL_ALERTS = False
SMTP_CONFIG = {
    "server": "smtp.example.com",
    "port": 587,
    "use_tls": True,
    "username": "sender@example.com",
    "password": "replace_me",
    "sender": "sender@example.com",
    "recipients": ["soc@example.com"],
}

COMPANY_PROFILE = {
    "technologies": [
        "microsoft 365", "office 365", "sharepoint", "exchange online", "exchange server", "entra id", "azure ad", "azure",
        "microsoft defender", "microsoft intune", "microsoft sentinel", "bitlocker", "windows", "linux", "macos",
        "oracle", "oracle ebs", "oracle fusion", "oracle retail", "oracle cloud", "oracle financials", "oracle iam",
        "cisco", "fortinet", "fortigate", "fortios", "palo alto", "pan-os", "citrix", "netscaler", "netScaler adc", "netScaler gateway",
        "cloudflare", "cloudflare waf", "fastly", "waf", "proofpoint", "sentinelone", "edr", "siem", "qualys", "picus",
        "aws", "amazon web services", "amazon bedrock", "ec2", "s3", "iam", "azure devops", "github", "bitbucket", "jenkins", "postman",
        "docker", "kubernetes", "wordpress", "drupal", "cms", "magento", "adobe commerce", "shopify", "salesforce", "netsuite",
        "point of sale", "pos", "mpos", "payment gateway", "checkout.com", "adyen", "knet", "benefit pay", "tabby", "tamara", "epaysafe",
        "nuget", "npm", "pypi", ".net", "java", "python", "node.js", "android", "mobile app",
        "braintree", "paypal braintree", "braintree.net", "litellm", "litellm-proxy", "ai gateway", "llm gateway", "langflow",
        "google chrome", "chrome", "wireshark", "roundcube", "u-boot", "zimbra", "xquic", "http/3", "quic",
        "datadog", "rabbitmq", "teamviewer", "beyondtrust", "lastpass", "vpn", "ssl-vpn",
    ],
    "vendors": [
        "microsoft", "oracle", "cisco", "fortinet", "palo alto", "adobe", "vmware", "sap", "okta", "crowdstrike", "aws", "azure", "google",
        "cloudflare", "proofpoint", "sentinelone", "qualys", "github", "atlassian", "datadog", "teamviewer", "citrix", "zimbra",
        "shopify", "salesforce", "netsuite", "magento", "drupal", "adyen", "checkout.com", "tabby", "tamara", "paypal", "braintree", "socket", "npm", "nuget", "pypi",
        "roundcube", "wireshark", "amazon", "meta", "instagram", "whatsapp", "openai", "fastnetmon",
    ],
    "brands": ["6thstreet", "bath and body works", "victoria secret", "pottery barn", "west elm", "boots", "mothercare", "muji", "american eagle", "new balance", "nike", "footlocker", "charlotte tilbury", "harvey nichols", "h&m", "starbucks", "shake shack", "kidzania"],
    "regions": ["middle east", "mena", "gcc", "gulf", "uae", "united arab emirates", "dubai", "abu dhabi", "ksa", "saudi", "saudi arabia", "kuwait", "qatar", "bahrain", "oman", "egypt", "jordan", "turkey", "india"],
    "industry": ["retail", "e-commerce", "ecommerce", "payment", "payments", "merchant", "point of sale", "pos", "supply chain", "cloud security", "identity", "identity management", "endpoint security", "email security", "application security", "appsec", "source code", "repository", "ci/cd", "devops", "vulnerability management", "waf", "siem", "edr", "brand abuse", "phishing", "fraud", "third party", "vendor", "payment gateway", "microsoft 365", "cloud", "iam"],
}

CONFIRMED_ACTIONABLE_TERMS = {
    "microsoft 365", "office 365", "sharepoint", "exchange online", "exchange server", "entra id", "azure ad", "azure", "microsoft defender", "microsoft intune", "microsoft sentinel",
    "oracle", "oracle ebs", "oracle fusion", "oracle retail", "cisco", "fortinet", "fortigate", "fortios", "palo alto", "pan-os", "citrix", "netscaler", "netscaler adc", "netscaler gateway",
    "cloudflare", "waf", "proofpoint", "sentinelone", "aws", "amazon web services", "amazon bedrock", "ec2", "iam", "github", "bitbucket", "jenkins", "azure devops",
    "adobe commerce", "magento", "shopify", "drupal", "cms", "wordpress", "pos", "point of sale", "payment gateway", "checkout.com", "adyen", "braintree", "nuget", "langflow",
}
POSSIBLE_ACTIONABLE_TERMS = {"npm", "pypi", "roundcube", "wireshark", "chrome", "google chrome", "u-boot", "linux", "windows", "macos", "zimbra", "xquic", "http/3", "quic", "teamviewer", "vpn", "ssl-vpn", "python", "node.js", "java", "android", "mobile app"}
WEAK_ONLY_TERMS = {"linux", "windows", "github", "python", "google", "amazon", "whatsapp", "instagram", "facebook", "meta", "linkedin", "edr", "siem", "picus", "teamviewer", "retail", "ecommerce", "e-commerce", "marketing", "delivery", "search", "warehouse", "tracking", "cloud security", "email security", "application security", "vulnerability management"}

RELATIONSHIP_TERMS = {"affects", "affected", "impact", "impacts", "target", "targets", "targeting", "compromise", "compromised", "abuse", "abuses", "abused", "exploit", "exploited", "exploitation", "patch", "patched", "vulnerability", "flaw", "bug", "security update", "malware", "ransomware", "phishing", "credential", "credentials", "token", "secret", "exposed", "exposure", "bypass", "remote code", "privilege", "attack", "backdoor", "rat", "stealer", "wiper", "cryptominer", "webshell", "injection", "xss", "ssrf", "rce", "dos", "payload", "c2", "command and control", "mining pool", "attacker-controlled", "ioc", "indicator"}

THREAT_TYPE_KEYWORDS = {
    "Vulnerability": ["cve", "vulnerability", "vulnerabilities", "security update", "security advisory", "patch", "patched", "patches", "flaw", "flaws", "zero-day", "zero day", "rce", "remote code execution", "privilege escalation", "lpe", "auth bypass", "authentication bypass", "xss", "ssrf", "command injection", "code execution", "denial-of-service", "denial of service", "dos", "critical vulnerability", "poc", "proof-of-concept", "unpatched"],
    "Ransomware / Wiper": ["ransomware", "wiper", "disk wiping", "destructive", "extortion", "encryptor", "blackcat", "alphv", "lockbit", "cl0p", "dragonforce"],
    "Phishing": ["phishing", "vishing", "smishing", "aitm", "adversary-in-the-middle", "device code", "device-code", "credential lure", "callback phishing", "fake sign-in", "phishing-as-a-service", "phaas", "passkey enrollment", "login pages"],
    "Supply Chain": ["malicious package", "typosquat", "typosquatting", "npm", "nuget", "pypi", "package manager", "dependency", "maintainer", "install script", "ci/cd", "repository compromise", "sdk", "go module"],
    "Cloud Intrusion": ["aws", "azure", "cloud", "iam", "access key", "bedrock", "ec2", "s3", "cloud compromise", "cryptomining", "ai gateway", "litellm"],
    "Malware": ["malware", "trojan", "backdoor", "stealer", "infostealer", "rat", "botnet", "loader", "dropper", "spyware", "banker", "cryptominer", "xmrig", "implant", "webshell", "process injection", "shellcode"],
    "Data Breach": ["data breach", "breach", "leak", "leaked", "stolen data", "data theft", "exposed records", "customer data", "patient data"],
    "APT / Intrusion": ["apt", "nation state", "state-sponsored", "espionage", "webshell", "intrusion", "compromised servers", "hijacked web servers", "backdooring", "wp-shellstorm"],
    "AI / Identity Security": ["ai agents", "ai agent", "service account", "api token", "identity", "passkey", "agentic", "ai coding", "mcp gateway"]
}
CYBER_SUPPLY_CHAIN_TERMS = {"npm", "nuget", "pypi", "package", "dependency", "repository", "maintainer", "install script", "ci/cd", "token", "malicious package", "typosquat", "sdk", "go module"}
ACTIVE_EXPLOIT_PHRASES = ["actively exploited", "exploited in the wild", "known exploited", "under active exploitation", "mass exploitation", "in-the-wild"]
SECURITY_CONTEXT_TERMS = sorted(set().union(*[set(v) for v in THREAT_TYPE_KEYWORDS.values()]) | {"ioc", "indicator", "c2", "payload", "credential", "advisory", "psirt", "webshell", "oauth", "personal access token"})
LEGAL_ONLY_TERMS = ["sentenced", "prison", "gets 70 months", "jail", "jailed", "former ransomware negotiator", "security expert sentenced", "pleaded guilty", "sentencing"]
PRODUCT_ANNOUNCEMENT_TERMS = ["launches", "announced", "introducing", "new platform", "self-hosted", "press release", "cyberwire", "cybernewswire"]

COMMON_TLDS = {"com", "net", "org", "io", "co", "pro", "dev", "info", "biz", "cloud", "app", "ai", "me", "tv", "ae", "sa", "kw", "qa", "bh", "om", "eg", "jo", "tr", "in", "ru", "jp", "cn", "de", "fr", "pl", "ro", "cz"}
ARTIFACT_SUFFIXES = {"json", "yaml", "yml", "dat", "php", "exe", "dll", "sys", "bat", "cmd", "ps1", "vbs", "jar", "zip", "rar", "7z", "pdf", "doc", "docx", "xls", "xlsx", "main", "create", "privatekey"}
BENIGN_DOMAINS = {
    "socket.dev", "nuget.org", "npmjs.com", "github.com", "twitter.com", "x.com", "microsoft.com", "google.com", "amazon.com", "aws.amazon.com", "cloudflare.com", "openai.com",
    "gbhackers.com", "cybersecuritynews.com", "bleepingcomputer.com", "securityweek.com", "thehackernews.com", "darkreading.com", "theregister.com", "hackread.com", "socradar.io", "cisa.gov", "cve.org", "reddit.com", "linkedin.com", "facebook.com", "instagram.com", "youtube.com",
    "archive.ubuntu.com", "ports.ubuntu.com", "ubuntu.com", "redhat.com", "kernel.org", "mozilla.org", "chrome.com", "robinhood.com", "fastnetmon.com", "infratech.com.sa", "originality.ai", "163.com",
}
MALWARE_FAMILIES = ["xmrig", "gigawiper", "goddamn", "poisonx", "redhook", "asyncrat", "blackcat", "alphv", "lockbit", "forg365", "jadepuffer", "helix", "modbeacon", "dragonforce", "odyssey"]

RSS_SOURCES = {
    "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
    "The Hacker News": "https://feeds.feedburner.com/TheHackersNews",
    "SecurityWeek": "https://securityweek.com/feed",
    "CyberSecurityNews": "https://cybersecuritynews.com/feed/",
    "HackRead": "https://www.hackread.com/feed/",
    "Information Security Buzz": "https://informationsecuritybuzz.com/feed/",
    "CyberWire": "https://www.thecyberwire.com/feeds/rss.xml",
    "The Register Security": "https://www.theregister.com/security/headlines.atom",
    "The Register All Tech": "https://www.theregister.com/headlines.atom",
    "KrebsOnSecurity": "https://krebsonsecurity.com/feed/",
    "Dark Reading": "https://www.darkreading.com/rss.xml",
    "ITSecForU (RU)": "https://itsecforu.ru/feed/",
    "Retail Design Blog": "https://retaildesignblog.net/feed/",
    "Retail Dive": "https://www.retaildive.com/feeds/news/",
    "Retail Gazette": "https://www.retailgazette.co.uk/feed/",
    "Retail Times": "https://retailtimes.co.uk/feed/",
    "SOCRadar": "https://socradar.io/feed/",
    "GBHackers": "https://gbhackers.com/feed/",
    "Cisco PSIRT": "https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml",
    "Cisco Event Responses": "https://sec.cloudapps.cisco.com/security/center/eventResponses_20.xml",
    "Fortinet PSIRT": "https://filestore.fortinet.com/fortiguard/rss/ir.xml",
    "CrowdStrike Blog": "https://www.crowdstrike.com/en-us/blog/feed",
    "Exploit-DB": "https://www.exploit-db.com/rss.xml",
}
JSON_SOURCES = {
    "CISA KEV JSON": {"type": "cisa_kev", "url": "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"},
}

ACTION_MAP = {
    "Vulnerability": "Validate exposure, check vendor advisory, patch or mitigate, and verify internet exposure.",
    "Malware": "Review detections, hunt impacted endpoints, and block related malicious infrastructure where validated.",
    "Ransomware / Wiper": "Review ransomware/wiper TTPs, validate backups/detections, and hunt/block confirmed IOCs where relevant.",
    "Phishing": "Block malicious domains or URLs, review email controls, and search telemetry for delivery or user interaction.",
    "Data Breach": "Assess exposure, review affected accounts or tokens, and search monitoring data for related access or abuse.",
    "Supply Chain": "Review impacted package/vendor use, validate exposure, rotate affected secrets, and inspect CI/CD pipelines.",
    "Cloud Intrusion": "Validate cloud exposure, review IAM activity, rotate affected keys, and hunt for unusual cloud resource usage.",
    "APT / Intrusion": "Escalate to threat hunting, map TTPs, search telemetry, and review privileged access and segmentation.",
    "AI / Identity Security": "Review identity, token, and AI-agent access controls; validate exposed credentials and delegated permissions where relevant.",
    "Threat Roundup": "Review individual items in the roundup only if relevant to Company technologies or controls.",
    "Other": "Analyst review recommended if business or technology context indicates possible relevance.",
}

# Runtime and state helpers
def utc_now() -> datetime:
    return datetime.now(timezone.utc)

def normalize_space(text: str) -> str:
    return re.sub(r"\s+", " ", str(text or "")).strip()

def parse_line_datetime(line: str) -> Optional[datetime]:
    for pattern in [r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", r"^(\d{4}-\d{2}-\d{2}T[^\s|]+)"]:
        m = re.search(pattern, line)
        if m:
            raw = m.group(1)
            try:
                if "T" in raw:
                    return datetime.fromisoformat(raw.replace("Z", "+00:00")).astimezone(timezone.utc)
                return datetime.strptime(raw, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
            except Exception:
                return None
    return None

def prune_text_log(path: Path, retention_days: int = RETENTION_DAYS):
    if not path.exists():
        return
    cutoff = utc_now() - timedelta(days=retention_days)
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines(True)
        kept = []
        for line in lines:
            dt = parse_line_datetime(line)
            if dt is None or dt >= cutoff:
                kept.append(line)
        path.write_text("".join(kept), encoding="utf-8")
    except Exception:
        pass

def setup_logging():
    prune_text_log(RUN_LOG_FILE)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s", handlers=[logging.FileHandler(RUN_LOG_FILE, encoding="utf-8"), logging.StreamHandler(sys.stdout)], force=True)

setup_logging()
logger = logging.getLogger("threat_intel_monitor")
session = requests.Session()
session.headers.update({"User-Agent": USER_AGENT})

def append_jsonl(path: Path, obj: dict):
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(obj, ensure_ascii=False) + "\n")
    except Exception:
        pass

def log_feed_error(source: str, url: str, error: Exception):
    # Source issues are written to the main runtime log.
    logger.warning(f"Source fetch/parser issue | source={source} | url={url} | error={repr(error)}")

def output_excel_name() -> Path:
    return SCRIPT_DIR / f"{OUTPUT_PREFIX}_{datetime.now().strftime('%Y-%m-%d')}.xlsx"

def load_last_run_time() -> Optional[datetime]:
    if not LAST_RUN_STATE_FILE.exists():
        return None
    try:
        raw = json.loads(LAST_RUN_STATE_FILE.read_text(encoding="utf-8")).get("last_successful_run_utc")
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).astimezone(timezone.utc) if raw else None
    except Exception:
        return None

def save_last_run_time(dt: datetime):
    LAST_RUN_STATE_FILE.write_text(json.dumps({"last_successful_run_utc": dt.astimezone(timezone.utc).isoformat()}, indent=2), encoding="utf-8")

def get_collection_window() -> Tuple[datetime, datetime, str]:
    end = utc_now()
    last = load_last_run_time()
    if not last:
        return end - timedelta(hours=DEFAULT_FIRST_RUN_HOURS), end, "first_run_24h"
    return max(last, end - timedelta(hours=MAX_CATCHUP_HOURS)), end, "incremental_since_last_run_capped_72h"

def prune_run_history():
    if not RUN_HISTORY_FILE.exists():
        return
    cutoff = utc_now() - timedelta(days=RETENTION_DAYS)
    kept = []
    for line in RUN_HISTORY_FILE.read_text(encoding="utf-8", errors="ignore").splitlines():
        try:
            obj = json.loads(line)
            dt = datetime.fromisoformat((obj.get("run_end_utc") or obj.get("run_start_utc")).replace("Z", "+00:00")).astimezone(timezone.utc)
            if dt >= cutoff:
                kept.append(json.dumps(obj, ensure_ascii=False))
        except Exception:
            kept.append(line)
    RUN_HISTORY_FILE.write_text("\n".join(kept) + ("\n" if kept else ""), encoding="utf-8")

def append_run_history(obj: dict):
    prune_run_history()
    append_jsonl(RUN_HISTORY_FILE, obj)

def is_excel_locked(path: Path) -> bool:
    if not path.exists():
        return False
    try:
        if os.name == "nt":
            import msvcrt
            with open(path, "a+b") as f:
                try:
                    msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
                    msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
                except OSError:
                    return True
        else:
            with open(path, "a+b"):
                pass
        return False
    except PermissionError:
        return True
    except Exception:
        return False

# Text, URL, and article extraction helpers
def source_host(link: str) -> str:
    try:
        return urlparse(link).netloc.lower().replace("www.", "")
    except Exception:
        return ""

def canonical_link(link: str) -> str:
    if not link:
        return ""
    try:
        p = urlparse(link)
        return f"{p.scheme.lower()}://{p.netloc.lower().replace('www.', '')}{p.path.rstrip('/')}"
    except Exception:
        return str(link).strip().lower()

def clean_html(text: str) -> str:
    if not text:
        return ""
    return normalize_space(BeautifulSoup(text, "html.parser").get_text(" ", strip=True))

NOISE_SELECTORS = ["script", "style", "noscript", "svg", "header", "footer", "nav", "form", "aside", "iframe", "figure", "figcaption", ".related", ".related-posts", ".recommended", ".popular", ".trending", ".latest", ".more-stories", ".comments", "#comments", ".author", ".bio", ".share", ".social", ".newsletter", ".advertisement", ".ad", ".ads", ".sidebar", ".widget", ".tags", ".tag", ".breadcrumb", ".menu", ".post-navigation", ".read-more", "[class*='related']", "[class*='popular']", "[class*='sidebar']", "[class*='share']", "[class*='author']", "[class*='newsletter']", "[class*='advert']", ".td_block_wrap", ".td_block_related_posts", ".td-related-title", ".td-post-next-prev", ".td-post-sharing", ".td-a-rec", ".td_block_template_1"]
STOP_MARKERS = ["the post ", "tags", "tagged", "related", "related articles", "read more", "also read", "latest articles", "latest news", "popular posts", "recommended", "author", "about the author", "follow us", "subscribe", "advertisement", "share this", "more from", "you may also like", "#1 globally trusted", "globally trusted cyber security news platform", "appeared first on", "with gbhackers security we cover", "recent news", "most popular", "trending now"]

def remove_noise(soup: BeautifulSoup):
    for sel in NOISE_SELECTORS:
        for t in soup.select(sel):
            t.decompose()

def find_main_article_node(soup: BeautifulSoup):
    candidates = []
    for sel in ["article", "main article", "main", ".article-content", ".entry-content", ".post-content", ".td-post-content", ".single-post-content", ".story-content", ".article-body", ".content-area", ".post", ".entry", "[itemprop='articleBody']"]:
        for node in soup.select(sel):
            txt = normalize_space(node.get_text(" ", strip=True))
            if len(txt) > 250:
                candidates.append((len(txt), node))
    return sorted(candidates, key=lambda x: x[0], reverse=True)[0][1] if candidates else None

def line_is_stop_marker(txt: str) -> bool:
    low = txt.lower().strip(" :|-/")
    return any(low == m or low.startswith(m) for m in STOP_MARKERS)

def line_is_noise(txt: str) -> bool:
    low = txt.lower()
    if any(m in low for m in ["advertisement", "subscribe", "follow us", "share this", "all rights reserved"]):
        return True
    if len(txt) < 20 and not re.search(r"\b(CVE-|\d+\.\d+\.\d+\.\d+|\[\.\]|[a-fA-F0-9]{64})\b", txt):
        return True
    return False

def extract_clean_article_text_from_html(html: str, url: str = "") -> str:
    soup = BeautifulSoup(html, "html.parser")
    remove_noise(soup)
    host = source_host(url)
    if "gbhackers.com" in host:
        for sel in [".td_block_wrap", ".td_block_related_posts", ".td-related-title", ".td-main-sidebar", ".td-footer-wrapper", ".td-post-sharing", ".td-post-next-prev", ".td-a-rec", ".td-category", ".td-post-author-name", ".td-module-container"]:
            for t in soup.select(sel):
                t.decompose()
    node = find_main_article_node(soup)
    if node is None:
        return ""
    parts = []
    for el in node.find_all(["h1", "h2", "h3", "p", "li", "td", "th", "caption", "pre", "code", "blockquote"], recursive=True):
        txt = normalize_space(el.get_text(" ", strip=True))
        if not txt:
            continue
        if line_is_stop_marker(txt):
            break
        if "gbhackers.com" in host and any(m in txt.lower() for m in ["the post ", "appeared first on", "gbhackers security | #1", "globally trusted cyber security news platform"]):
            break
        if line_is_noise(txt):
            continue
        parts.append(txt)
        if len(" ".join(parts)) >= MAX_ARTICLE_TEXT_CHARS:
            break
    out, seen = [], set()
    for p in parts:
        key = re.sub(r"\W+", " ", p.lower())[:180]
        if key not in seen:
            seen.add(key)
            out.append(p)
    joined = normalize_space(" ".join(out))[:MAX_ARTICLE_TEXT_CHARS]
    for marker in [" The post ", " Tags ", " Related Articles ", " Related: ", " Also Read ", " Latest Articles ", " Author "]:
        idx = joined.find(marker)
        if idx > 600:
            joined = joined[:idx]
    return normalize_space(joined)

def fetch_article_text(url: str) -> str:
    if not ARTICLE_FETCH_ENABLED or not url:
        return ""
    try:
        r = session.get(url, timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
        return extract_clean_article_text_from_html(r.text, url)
    except Exception as e:
        logger.debug(f"Article fetch failed for {url}: {e}")
        return ""

# Profile matching and IOC extraction
def term_pattern(term: str):
    parts = [re.escape(x) for x in term.lower().split() if x]
    if not parts:
        return None
    return re.compile(r"(?<!\w)" + r"\s+".join(parts) + r"(?!\w)", re.IGNORECASE)

def contains_term(text: str, term: str) -> bool:
    pat = term_pattern(term)
    return bool(pat.search(text or "")) if pat else False

def match_terms(text: str, terms: List[str]) -> List[str]:
    return sorted({t for t in terms if contains_term(text, t)})

def has_any(text: str, terms: List[str]) -> bool:
    low = (text or "").lower()
    return any(contains_term(low, t) for t in terms)

def has_cyber_context(text: str) -> bool:
    return has_any(text, SECURITY_CONTEXT_TERMS)

def local_context(text: str, term: str, window_words: int = 15) -> List[str]:
    words = re.findall(r"\w+(?:[-.]\w+)*", (text or "").lower())
    tw = term.lower().split()
    contexts = []
    if not tw:
        return contexts
    for i in range(0, len(words) - len(tw) + 1):
        if words[i:i + len(tw)] == tw:
            contexts.append(" ".join(words[max(0, i - window_words): min(len(words), i + len(tw) + window_words)]))
    return contexts

def appears_near_relationship(text: str, term: str) -> bool:
    return any(any(rel in ctx for rel in RELATIONSHIP_TERMS) for ctx in local_context(text, term))

def defang_to_normal(text: str) -> str:
    out = text or ""
    for k, v in {"hxxps://": "https://", "hxxp://": "http://", "[.]": ".", "(.)": ".", "{.}": ".", "[dot]": ".", "(dot)": "."}.items():
        out = re.sub(re.escape(k), v, out, flags=re.IGNORECASE)
    out = re.sub(r"(?<=\d)\s*\.\s*(?=\d)", ".", out)
    return out

def is_public_ip(ip: str) -> bool:
    try:
        obj = ipaddress.ip_address(ip)
        return not (obj.is_private or obj.is_loopback or obj.is_link_local or obj.is_multicast or obj.is_unspecified or obj.is_reserved)
    except Exception:
        return False

def value_has_malicious_context(text: str, value: str) -> bool:
    low = (text or "").lower()
    val = value.lower()
    idx = low.find(val)
    if idx == -1:
        return False
    nearby = low[max(0, idx - 260): idx + len(val) + 260]
    return any(x in nearby for x in ["ioc", "indicator", "c2", "command and control", "payload", "downloaded", "connects to", "mining pool", "pool", "attacker", "malicious", "phishing", "beacon", "exfil", "block", "sinkhole", "compromised", "callback", "credential", "backdoor", "trojan", "rat", "cryptomining", "cryptominer", "infrastructure", "domain", "ip address", "server"])

def is_reference_context(text: str, value: str) -> bool:
    low = (text or "").lower()
    val = value.lower()
    idx = low.find(val)
    if idx == -1:
        return False
    nearby = low[max(0, idx - 180): idx + len(val) + 180]
    return any(x in nearby for x in ["press release", "cyberwire", "contact", "media@", "top 10", "launches", "announced", "introducing", "website", "company", "vendor", "platform", "official", "brand store", "home page"])

def is_probable_domain(domain: str, src_host: str, text: str) -> bool:
    d = domain.lower().strip(". ,;:()[]{}<>\"'")
    if d.startswith("www."):
        d = d[4:]
    if not d or d == src_host or d in BENIGN_DOMAINS:
        return False
    parts = d.split(".")
    if len(parts) < 2 or any(not p for p in parts):
        return False
    if parts[-1] not in COMMON_TLDS or parts[-1] in ARTIFACT_SUFFIXES:
        return False
    if is_reference_context(text, d):
        return False
    return value_has_malicious_context(text, d)

def malware_has_local_context(text: str, family: str, primary_text: str) -> bool:
    if contains_term(primary_text, family):
        return True
    for ctx in local_context(text, family, 12):
        if any(x in ctx for x in ["malware", "ransomware", "backdoor", "family", "tracked", "known as", "variant", "payload", "uses", "deploy", "detected", "rat"]):
            return True
    return False

def extract_iocs(text: str, src_link: str = "", primary_text: str = "") -> Dict[str, List[str]]:
    src_host = source_host(src_link)
    normalized = defang_to_normal(text or "")
    primary_norm = defang_to_normal(primary_text or "")
    cves = sorted({x.upper() for x in re.findall(r"\bCVE-\d{4}-\d{4,7}\b", normalized, re.IGNORECASE)})
    ips_all = sorted(set(re.findall(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b", normalized)))
    ips = [ip for ip in ips_all if is_public_ip(ip) and value_has_malicious_context(normalized, ip)]
    if not ips and has_any(primary_norm, THREAT_TYPE_KEYWORDS["Cloud Intrusion"] + THREAT_TYPE_KEYWORDS["Ransomware / Wiper"] + THREAT_TYPE_KEYWORDS["Malware"] + THREAT_TYPE_KEYWORDS["Phishing"]):
        ips = [ip for ip in ips_all if is_public_ip(ip)]
    urls_raw = sorted(set(re.findall(r"https?://[^\s\]\)>'\"}]+", normalized, re.IGNORECASE)))
    urls = []
    for u in urls_raw:
        h = source_host(u)
        if h and h != src_host and h not in BENIGN_DOMAINS and value_has_malicious_context(normalized, h) and not is_reference_context(normalized, h):
            urls.append(u)
    sha256 = sorted({x.upper() for x in re.findall(r"\b[a-fA-F0-9]{64}\b", normalized)})
    emails = sorted(set(re.findall(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", normalized)))
    emails = [e for e in emails if value_has_malicious_context(normalized, e) and not is_reference_context(normalized, e)]
    filename_candidates = re.findall(r"\b[\w.-]{1,80}\.(?:exe|dll|sys|js|vbs|ps1|bat|cmd|zip|rar|7z|docm|xlsm|hta|apk|iso|jar|lnk|appref-ms)\b", normalized, re.IGNORECASE)
    filenames = sorted({f.strip(".,;:()[]{}<>\"'") for f in filename_candidates if len(f) <= 90})
    raw_domains = set(re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", normalized))
    domains = sorted({d.lower().lstrip("www.") for d in raw_domains if is_probable_domain(d, src_host, normalized)})
    malware = sorted({m for m in MALWARE_FAMILIES if malware_has_local_context(normalized, m, primary_norm)})
    cloud_assets_raw = re.findall(r"\b(?:LiteLLM-Proxy|LiteLLM|EC2 instance|S3 bucket|IAM user|IAM role|Amazon Bedrock|Azure OpenAI|AI gateway|MCP Gateway)\b", normalized, re.IGNORECASE)
    cloud_map = {}
    for x in cloud_assets_raw:
        nx = normalize_space(x)
        cloud_map.setdefault(nx.lower(), nx)
    cloud_assets = [cloud_map[k] for k in sorted(cloud_map)]
    return {"cves": cves, "ips": ips, "domains": domains, "urls": urls[:15], "sha256": sha256, "emails": emails, "filenames": filenames, "malware_families": malware, "cloud_assets": cloud_assets}

# Classification and scoring


NON_CYBER_BUSINESS_SOURCES = {
    "Retail Dive", "Retail Gazette", "Retail Times", "Retail Design Blog", "The Register All Tech"
}


def has_explicit_security_threat_signal(title: str, summary: str) -> bool:
    """Strict gate for allowing non-cyber/product/business articles into REVIEW.
    Intentionally excludes generic words like attack, risk, security, technology, AI, platform, retail, future.
    """
    primary = f"{title} {summary}".lower()
    if re.search(r"\bCVE-\d{4}-\d{4,7}\b", primary, re.IGNORECASE):
        return True
    strong_phrases = [
        "critical vulnerability", "security vulnerability", "vulnerabilities allow", "unpatched", "zero-day", "zero day",
        "remote code execution", "privilege escalation", "root privileges", "root shell", "xss", "ssrf", "rce",
        "phishing", "vishing", "smishing", "malware", "ransomware", "wiper", "backdoor", "trojan", " rat ", "remote access trojan",
        "stealer", "infostealer", "botnet", "loader", "dropper", "shellcode", "process injection", "cryptominer", "xmrig",
        "credential theft", "stolen credentials", "token theft", "oauth token", "personal access token", "webshell",
        "threat actors", "threat actor", "actively exploited", "exploited in the wild", "malicious package", "typosquat",
        "citrixbleed", "wp-shellstorm", "github repositories used for malware", "microsoft 365 accounts", "entra passkey",
        "ai gateway", "cloud compromise", "hijacked for cryptomining", "agentic ransomware", "langflow instance"
    ]
    return any(x in primary for x in strong_phrases)


def should_force_low_by_source_or_topic(source: str, title: str, summary: str) -> bool:
    primary = f"{title} {summary}".lower()
    # Business feeds require explicit security language before analyst review.
    if source in NON_CYBER_BUSINESS_SOURCES and not has_explicit_security_threat_signal(title, summary):
        return True
    # Product or market content remains archive-only unless it includes a clear threat signal.
    non_threat_markers = [
        "top 10", "market", "mssp", "ctem", "exposure management platforms", "launches netomics", "self-hosted routing intelligence platform",
        "announced", "introducing", "launches", "press release", "cyberwire", "cybernewswire", "case study", "rebuilt exposure management",
        "ai slop", "font bug", "grocers", "customer satisfaction", "restaurant design", "scoops major win", "collaboration", "fashion partnership",
        "football portrait", "renames nordpak", "manned guarding", "family business of the year", "new store", "emissions"
    ]
    if any(x in primary for x in non_threat_markers) and not has_explicit_security_threat_signal(title, summary):
        return True
    return False

def is_product_or_market_awareness(title: str, summary: str) -> bool:
    primary = f"{title} {summary}".lower()
    product_words = [
        "launches", "launch", "announced", "introducing", "introduces", "new platform", "product", "self-hosted", "top 10", "report", "survey", "market", "partnership", "press release", "cyberwire", "cybernewswire", "award", "awards", "collaboration", "store", "restaurant design", "emissions", "customer satisfaction", "shopping", "productivity gains", "case study", "blueprint", "how lumen", "exposure management at scale", "mssp", "ctem", "penetration testing tool", "testing tool", "platform", "tool with", "managed service", "gateway secures", "launches netomics", "ai slop", "font bug", "grocers", "manned guarding", "scoops major win", "unveils new restaurant", "designer collaboration", "fashion partnership", "football portrait", "finance team of the year"
    ]
    hard_threat_words = [
        "cve", "actively exploited", "exploited in the wild", "known exploited", "vulnerability", "malware", "ransomware", "phishing", "vishing", "webshell", "backdoor", "trojan", "stealer", "rat", "botnet", "credential theft", "compromised", "threat actors", "remote code execution", "privilege escalation", "citrixbleed", "wp-shellstorm", "malicious package", "process injection", "shellcode"
    ]
    return any(w in primary for w in product_words) and not any(w in primary for w in hard_threat_words)

def is_legal_or_law_enforcement_awareness(title: str, summary: str) -> bool:
    primary = f"{title} {summary}".lower()
    return any(x in primary for x in LEGAL_ONLY_TERMS) and not any(x in primary for x in ["ioc", "indicator", "campaign", "new malware", "active campaign", "exploiting", "targets", "targeting"])


def is_primary_threat_intel(title: str, summary: str) -> bool:
    primary = f"{title} {summary}".lower()
    if should_force_low_by_source_or_topic("", title, summary) or is_product_or_market_awareness(title, summary) or is_legal_or_law_enforcement_awareness(title, summary):
        return False
    threat_anchors = [
        "cve", "vulnerability", "vulnerabilities", "xss", "ssrf", "rce", "remote code execution", "privilege escalation", "unpatched", "patch", "patched",
        "phishing", "vishing", "smishing", "aitm", "passkey", "credential theft", "stolen credentials", "oauth token", "personal access token",
        "malware", "ransomware", "wiper", "backdoor", "trojan", "rat", "stealer", "infostealer", "botnet", "loader", "dropper", "shellcode", "process injection", "cryptominer", "xmrig",
        "compromised", "hijacked", "exploit", "exploited", "webshell", "backdooring", "wp-shellstorm", "threat actor", "threat actors", "ioc",
        "cloud compromise", "access key", "ai gateway", "litellm", "citrixbleed", "netscaler", "github organization", "repository enumeration", "malicious package", "typosquat", "modbeacon", "xring", "hallusquatting", "gigaWiper".lower(), "goddamn", "jadepuffer", "langflow"
    ]
    return any(t in primary for t in threat_anchors)

def classify_threat_type(title: str, summary: str, body: str, iocs: Dict[str, List[str]]) -> str:
    primary = f"{title} {summary}".lower()
    clean = f"{primary} {body[:1800].lower()}"

    # Exclude non-threat content before article-body inference is used.
    if is_legal_or_law_enforcement_awareness(title, summary):
        return "Other"
    if is_product_or_market_awareness(title, summary):
        return "Other"

    # Apply specific categories before generic malware classification.
    if any(x in primary for x in ["threatsday", "roundup", "+ 17 more stories", "more stories"]):
        return "Threat Roundup"
    if has_any(primary, THREAT_TYPE_KEYWORDS["Phishing"]):
        return "Phishing"
    if any(x in primary for x in ["citrixbleed", "netscaler", "zimbra", "wireshark", "xquic", "http/3", "chrome", "fuse vulnerability", "linux kernel", "palo alto", "pan-os"]):
        if any(x in primary for x in ["cve", "vulnerability", "flaw", "patch", "patched", "unpatched", "xss", "ssrf", "crash", "privilege", "exploit"]):
            return "Vulnerability"
    if has_any(primary, THREAT_TYPE_KEYWORDS["Cloud Intrusion"]) and any(x in primary for x in ["compromise", "compromised", "hijack", "hijacked", "cryptomining", "stolen credential", "access key", "attack surface"]):
        return "Cloud Intrusion"
    if any(x in primary for x in ["webshell", "web shell", "cms exploitation", "content management systems", "web servers hijacked", "wp-shellstorm", "backdooring wordpress", "wordpress sites"]):
        return "APT / Intrusion"
    if ((any(x in primary for x in ["ai agents", "ai agent", "service account", "api token", "passkey", "agent credential", "mcp gateway", "non-human identities"]) or ("identity" in primary and "ai" in primary)) and not any(x in primary for x in ["malicious package", "npm", "pypi", "nuget"])):
        return "AI / Identity Security"
    if any(x in primary for x in ["github organization", "corporate github", "github api", "oauth tokens", "personal access", "ghost accounts", "repositories used for malware", "github repositories used"]):
        return "Supply Chain"
    if any(contains_term(primary, x) for x in CYBER_SUPPLY_CHAIN_TERMS):
        return "Supply Chain"
    if iocs["cves"] or has_any(primary, THREAT_TYPE_KEYWORDS["Vulnerability"]):
        if "bug" in primary and not any(x in primary for x in ["security", "cve", "privilege", "execution", "xss", "ssrf", "patch", "vulnerability", "flaw", "malicious", "unpatched"]):
            return "Other"
        return "Vulnerability"
    if has_any(primary, THREAT_TYPE_KEYWORDS["Ransomware / Wiper"]):
        return "Ransomware / Wiper"
    if has_any(primary, THREAT_TYPE_KEYWORDS["Data Breach"]):
        return "Data Breach"
    if any(x in primary for x in ["infostealer", "stealer", "rat", "modbeacon", "odyssey stealer", "process injection", "shellcode", "botnet", "backdoor", "malware"]):
        return "Malware"

    # Use body text only when the title/summary is already security-relevant.
    if is_primary_threat_intel(title, summary):
        if any(x in clean for x in ["cms exploitation", "content management systems", "webshell", "web servers hijacked", "wp-shellstorm", "backdooring wordpress"]):
            return "APT / Intrusion"
        if any(x in clean for x in ["github organization", "repository enumeration", "oauth token", "personal access token", "ghost accounts"]):
            return "Supply Chain"
        if has_any(clean, THREAT_TYPE_KEYWORDS["Cloud Intrusion"]) and any(x in clean for x in ["compromise", "compromised", "cryptomining", "stolen credential"]):
            return "Cloud Intrusion"
        if has_any(clean, THREAT_TYPE_KEYWORDS["Malware"]):
            return "Malware"
    return "Other"

def assess_profile_matches(title: str, summary: str, body: str) -> Dict[str, List[str]]:
    primary = f"{title} {summary}"
    clean_body = body[:6000]
    all_text = f"{primary} {clean_body}"
    cyber = has_cyber_context(primary) or has_cyber_context(clean_body[:2200])
    result: Dict[str, List[str]] = {}
    for key in ["technologies", "vendors", "brands", "regions", "industry"]:
        matches = match_terms(all_text, COMPANY_PROFILE.get(key, []))
        strong, moderate, weak = [], [], []
        for term in matches:
            in_title = contains_term(title, term)
            in_primary = contains_term(primary, term)
            contextual = cyber and appears_near_relationship(clean_body, term)
            tl = term.lower()
            if key == "regions":
                (moderate if in_primary and cyber else weak).append(term)
            elif tl in WEAK_ONLY_TERMS:
                if in_title and cyber and tl in CONFIRMED_ACTIONABLE_TERMS:
                    moderate.append(term)
                elif contextual and tl in CONFIRMED_ACTIONABLE_TERMS:
                    moderate.append(term)
                else:
                    weak.append(term)
            else:
                if in_title and cyber and tl in CONFIRMED_ACTIONABLE_TERMS:
                    strong.append(term)
                elif in_primary and cyber:
                    moderate.append(term)
                elif contextual:
                    moderate.append(term)
                else:
                    weak.append(term)
        result[key] = sorted(set(matches))
        result[f"{key}_strong"] = sorted(set(strong))
        result[f"{key}_moderate"] = sorted(set(moderate))
        result[f"{key}_weak"] = sorted(set(weak))
    return result

def threat_importance_score(threat_type: str, title: str, summary: str, body: str, iocs: Dict[str, List[str]], source: str) -> Tuple[int, List[str]]:
    primary = f"{title} {summary}".lower()
    trusted_body = body[:1800].lower()
    score, reasons = 0, []
    legal_only = any(x in primary for x in LEGAL_ONLY_TERMS) and not (iocs["ips"] or iocs["domains"] or iocs["sha256"] or iocs["cves"])
    product_only = any(x in primary for x in PRODUCT_ANNOUNCEMENT_TERMS) and threat_type == "Other"
    active = source == "CISA KEV JSON" or any(p in primary for p in ACTIVE_EXPLOIT_PHRASES) or any(p in trusted_body for p in ["actively exploited", "exploited in the wild", "known exploited", "under active exploitation", "mass exploitation"])
    if active:
        score += 30; reasons.append("active exploitation signal")
    if threat_type in ["Ransomware / Wiper", "Cloud Intrusion", "Phishing"]:
        score += 30; reasons.append(threat_type)
    elif threat_type in ["Vulnerability", "Supply Chain", "Malware", "APT / Intrusion", "AI / Identity Security", "Threat Roundup"]:
        score += 25; reasons.append(threat_type)
    elif threat_type == "Data Breach":
        score += 15; reasons.append("data breach")
    if iocs["cves"]:
        score += 15; reasons.append("CVE(s) present")
    if iocs["ips"] or iocs["domains"] or iocs["urls"] or iocs["sha256"]:
        score += 20; reasons.append("reliable IOCs present")
    if any(x in f"{primary} {trusted_body}" for x in ["webshell", "cms exploitation", "wp-shellstorm", "backdooring wordpress", "github organization", "oauth token", "personal access token", "ai gateway", "credential theft", "stolen credentials", "developer machine", "outside workspaces", "agentic ransomware", "langflow", "modbeacon", "xring", "unpatched", "remote privilege escalation", "privilege escalation", "arbitrary files", "overwrite arbitrary", "man-in-the-middle", "suid", "root shell"]):
        score += 15; reasons.append("campaign/TTP has high analyst value")
    if legal_only:
        score = min(score, 18); reasons = [r for r in reasons if r not in ["Ransomware / Wiper", "Malware"]] or ["legal/cybercrime awareness only"]
    if product_only:
        score = min(score, 12)
    return score, reasons

def relevance_confidence(matches: Dict[str, List[str]], threat_type: str, title: str, summary: str) -> Tuple[str, List[str]]:
    primary = f"{title} {summary}"
    strong_terms = sorted(set(matches.get("technologies_strong", []) + matches.get("vendors_strong", []) + matches.get("brands_strong", [])))
    moderate_terms = sorted(set(matches.get("technologies_moderate", []) + matches.get("vendors_moderate", []) + matches.get("brands_moderate", []) + matches.get("regions_moderate", [])))
    weak_terms = sorted(set(matches.get("technologies_weak", []) + matches.get("vendors_weak", []) + matches.get("brands_weak", []) + matches.get("industry_weak", [])))
    if strong_terms:
        return "strong", [f"direct Company profile match: {', '.join(strong_terms[:8])}"]
    if moderate_terms:
        return "moderate", [f"contextual Company profile match: {', '.join(moderate_terms[:8])}"]
    if weak_terms and (threat_type != "Other" or has_cyber_context(primary)):
        return "weak", [f"weak/out-of-context profile match: {', '.join(weak_terms[:8])}"]
    return "none", []

def actionability_score(threat_type: str, iocs: Dict[str, List[str]], matches: Dict[str, List[str]], rel_conf: str, title: str, summary: str) -> Tuple[int, List[str]]:
    primary = f"{title} {summary}".lower()
    action_terms = sorted(set(matches.get("technologies_strong", []) + matches.get("technologies_moderate", []) + matches.get("vendors_strong", []) + matches.get("vendors_moderate", []) + matches.get("brands_strong", []) + matches.get("brands_moderate", [])))
    action_terms_l = [t.lower() for t in action_terms]
    confirmed_terms = [t for t in action_terms_l if t in CONFIRMED_ACTIONABLE_TERMS]
    possible_terms = [t for t in action_terms_l if t in POSSIBLE_ACTIONABLE_TERMS]
    score, reasons = 0, []
    relevant = rel_conf in ["strong", "moderate"]
    if not relevant:
        return 0, []
    if iocs["cves"] and threat_type == "Vulnerability" and any(x in primary for x in ["defender", "rogueplanet", "mpengine"]):
        score += 35; reasons.append("Microsoft Defender/RoguePlanet patch or exposure validation may be required")
    elif iocs["cves"] and threat_type == "Vulnerability" and confirmed_terms:
        score += 35; reasons.append("patch/exposure validation required for confirmed Company-relevant technology")
    elif iocs["cves"] and threat_type == "Vulnerability" and possible_terms:
        score += 18; reasons.append("patch/exposure validation may be required for possible Company-relevant technology")
    if iocs["ips"] or iocs["domains"] or iocs["sha256"] or iocs["urls"]:
        if confirmed_terms:
            score += 35; reasons.append("IOC hunting/blocking possible for Company-relevant threat")
        else:
            score += 18; reasons.append("IOC review may be useful if exposure is confirmed")
    if threat_type == "Phishing" and any(x in action_terms_l for x in ["microsoft 365", "office 365", "sharepoint", "entra id", "proofpoint", "cloudflare"]):
        score += 35; reasons.append("email/IAM/M365 monitoring or advisory may be required")
    if threat_type == "Cloud Intrusion" and any(x in action_terms_l for x in ["aws", "amazon web services", "amazon bedrock", "ec2", "iam", "azure"]):
        score += 35; reasons.append("cloud IAM/exposure validation may be required")
    if threat_type == "Supply Chain":
        malicious_sc = any(x in primary for x in ["malicious package", "infected", "compromised", "typosquat", "typosquatting", "steals", "stealer", "credential", "secret", "pan", "cvv", "malware infection"])
        defensive = any(x in primary for x in ["disables", "disabled by default", "reduce risk", "hardening", "deprecating", "release", "announced"]) and not malicious_sc
        payment = any(x in action_terms_l for x in ["payment gateway", "braintree", "paypal", "checkout.com", "adyen", "pos", "point of sale"])
        dev_platform = any(x in action_terms_l for x in ["github", "bitbucket", "jenkins", "azure devops", "nuget"])
        generic_package = any(x in action_terms_l for x in ["npm", "pypi"])
        github_recon = any(x in primary for x in ["github organizations", "corporate github", "github api", "oauth tokens", "personal access", "ghost accounts", "mapping corporate orgs"])
        if payment and malicious_sc:
            score += 40; reasons.append("payment/AppSec dependency validation may be required")
        elif github_recon and dev_platform:
            score += 35; reasons.append("GitHub organization/token exposure review may be required")
        elif dev_platform and malicious_sc:
            score += 22; reasons.append("developer platform dependency review may be useful if exposure is confirmed")
        elif generic_package and malicious_sc:
            score += 18; reasons.append("package ecosystem awareness; validate dependency exposure if used")
        elif defensive:
            score += 0
        elif dev_platform or generic_package:
            score += 12; reasons.append("AppSec dependency awareness; action depends on exposure")
    if threat_type in ["Ransomware / Wiper", "Malware", "APT / Intrusion"]:
        if iocs["ips"] or iocs["domains"] or iocs["sha256"]:
            score += 30 if confirmed_terms else 18; reasons.append("SOC/EDR detection review and hunting may be required")
        elif threat_type == "APT / Intrusion" and any(x in primary for x in ["cms", "webshell", "web shell", "content management", "wordpress", "wp-shellstorm"]):
            score += 35; reasons.append("web/CMS exposure validation may be required")
    if threat_type == "AI / Identity Security" and any(x in action_terms_l for x in ["github", "aws", "azure", "iam", "microsoft 365", "entra id"]):
        score += 25; reasons.append("AI/identity/token exposure review may be required")
    if confirmed_terms and any(x in primary for x in ["defender", "microsoft 365", "sharepoint", "exchange", "oracle", "fortinet", "palo alto", "citrix", "netscaler", "cisco", "aws", "azure", "payment", "cms", "wordpress", "github"]):
        score += 8; reasons.append("asset owner or control owner follow-up may be useful")
    return score, reasons

def decide_sheet(threat_score: int, rel_conf: str, action_score: int, threat_type: str, title: str, summary: str) -> Tuple[str, str]:
    primary = f"{title} {summary}"
    if rel_conf in ["strong", "moderate"] and action_score >= 30 and threat_score >= 25:
        return "CRITICAL - Full Review", "CRITICAL"
    if threat_score >= 55:
        return "REVIEW - Analyst Check", "HIGH"
    if threat_score >= 35:
        return "REVIEW - Analyst Check", "MEDIUM"
    if threat_score >= 25 and rel_conf in ["strong", "moderate", "weak"]:
        return "REVIEW - Analyst Check", "MEDIUM"
    if has_cyber_context(primary) and rel_conf == "weak":
        return "LOW - Archive", "Unsure"
    return "LOW - Archive", "LOW"

def build_relevance_reason(rel_reasons: List[str], threat_reasons: List[str], action_reasons: List[str], iocs: Dict[str, List[str]]) -> str:
    parts = []
    if rel_reasons: parts.extend(rel_reasons)
    if threat_reasons: parts.append("Threat signals: " + ", ".join(threat_reasons[:6]))
    if action_reasons: parts.append("Actionability: " + "; ".join(action_reasons[:4]))
    if iocs["cves"]: parts.append("CVEs: " + ", ".join(iocs["cves"][:6]))
    if iocs["ips"] or iocs["domains"] or iocs["sha256"] or iocs["urls"]: parts.append("Reliable IOCs extracted")
    return "; ".join(parts) if parts else "No direct action or strong relevance identified."

def build_action_required(threat_type: str, iocs: Dict[str, List[str]], action_reasons: List[str], text: str, source: str) -> str:
    actions = []
    actions.extend(action_reasons)
    actions.append(ACTION_MAP.get(threat_type, ACTION_MAP["Other"]))
    if iocs["cves"]: actions.append(f"Validate exposure to: {', '.join(iocs['cves'][:6])}.")
    if iocs["ips"]: actions.append(f"Review/block confirmed IP indicators where appropriate: {', '.join(iocs['ips'][:6])}.")
    if iocs["domains"]: actions.append(f"Review/block confirmed malicious domains where appropriate: {', '.join(iocs['domains'][:6])}.")
    if iocs["urls"]: actions.append("Review suspicious URLs in proxy, email, and endpoint telemetry.")
    if iocs["sha256"]: actions.append("Search SHA256 indicators across EDR, detonation, and malware repositories.")
    if iocs["malware_families"]: actions.append(f"Review detections for malware families/tools: {', '.join(iocs['malware_families'][:5])}.")
    if source == "CISA KEV JSON":
        actions.append("Treat as CISA KEV/active exploitation signal and verify patch or mitigation status urgently if exposure exists.")
    return " ".join(dict.fromkeys(actions))

@dataclass
class ThreatRecord:
    sheet: str
    source: str
    title: str
    link: str
    published_utc: str
    threat_type: str
    severity: str
    summary: str
    relevance_reason: str
    cves: str
    ips: str
    domains: str
    urls: str
    sha256: str
    emails: str
    filenames: str
    malware_families: str
    cloud_assets: str
    vendors_matched: str
    regions_matched: str
    applications_matched: str
    brands_matched: str
    action_required: str
    record_key: str
    critical_email: bool

def build_record_key(source: str, title: str, link: str) -> str:
    cve = re.search(r"\bCVE-\d{4}-\d{4,7}\b", f"{title} {link}", re.IGNORECASE)
    if source.lower().startswith("cisa") and cve:
        return f"cisa_cve::{cve.group(0).upper()}"
    cl = canonical_link(link)
    return f"link::{cl}" if cl else f"title::{source.lower()}::{normalize_space(title).lower()}"

def create_record(source: str, title: str, link: str, summary: str, published: datetime, body_text: str) -> ThreatRecord:
    clean_summary = clean_html(summary)
    primary_text = f"{title} {clean_summary}"
    # Keep non-threat business/product items in archive even if weak profile terms appear.
    if should_force_low_by_source_or_topic(source, title, clean_summary):
        empty = {"cves": [], "ips": [], "domains": [], "urls": [], "sha256": [], "emails": [], "filenames": [], "malware_families": [], "cloud_assets": []}
        matches = assess_profile_matches(title, clean_summary, "")
        vendors_shown = sorted(set(matches.get("vendors_strong", []) + matches.get("vendors_moderate", [])))
        apps_shown = sorted(set(matches.get("technologies_strong", []) + matches.get("technologies_moderate", [])))
        brands_shown = sorted(set(matches.get("brands_strong", []) + matches.get("brands_moderate", [])))
        regions_shown = sorted(set(matches.get("regions_moderate", [])))
        return ThreatRecord("LOW - Archive", source, title, link, published.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"), "Other", "LOW", (clean_summary or title)[:500], "No direct action or strong relevance identified.", "", "", "", "", "", "", "", "", "", ", ".join(vendors_shown), ", ".join(regions_shown), ", ".join(apps_shown), ", ".join(brands_shown), "No immediate action. Archive only.", build_record_key(source, title, link), False)
    # Ignore article body for non-threat primary text.
    analysis_body = body_text if is_primary_threat_intel(title, clean_summary) else ""
    full_text = normalize_space(f"{primary_text} {analysis_body}")
    iocs = extract_iocs(full_text, link, primary_text)
    threat_type = classify_threat_type(title, clean_summary, analysis_body, iocs)
    # Prevent non-threat primary text from being promoted by noisy body content.
    if not is_primary_threat_intel(title, clean_summary) and threat_type not in ["Data Breach"]:
        threat_type = "Other"
        iocs = {"cves": [], "ips": [], "domains": [], "urls": [], "sha256": [], "emails": [], "filenames": [], "malware_families": [], "cloud_assets": []}
    matches = assess_profile_matches(title, clean_summary, analysis_body if is_primary_threat_intel(title, clean_summary) else "")
    score, threat_reasons = threat_importance_score(threat_type, title, clean_summary, analysis_body, iocs, source)
    rel_conf, rel_reasons = relevance_confidence(matches, threat_type, title, clean_summary)
    act_score, act_reasons = actionability_score(threat_type, iocs, matches, rel_conf, title, clean_summary)
    sheet, severity = decide_sheet(score, rel_conf, act_score, threat_type, title, clean_summary)
    if is_product_or_market_awareness(title, clean_summary) and not iocs.get("cves"):
        sheet, severity, threat_type = "LOW - Archive", "LOW", "Other"
        act_reasons = []
        threat_reasons = []
    # Final guard for weak non-threat rows.
    if (should_force_low_by_source_or_topic(source, title, clean_summary) or ((not is_primary_threat_intel(title, clean_summary) or is_product_or_market_awareness(title, clean_summary)) and not iocs.get("cves") and not iocs.get("ips") and not iocs.get("domains") and not iocs.get("sha256"))):
        sheet, severity, threat_type = "LOW - Archive", "LOW", "Other"
        threat_reasons, act_reasons = [], []
        iocs = {"cves": [], "ips": [], "domains": [], "urls": [], "sha256": [], "emails": [], "filenames": [], "malware_families": [], "cloud_assets": []}
    # Generic malicious package items require exposure confirmation before Critical priority.
    if sheet == "CRITICAL - Full Review" and threat_type == "Supply Chain" and any(x in f"{title} {clean_summary}".lower() for x in ["npm", "pypi", "package manager"]) and not any(x in f"{title} {clean_summary}".lower() for x in ["braintree", "payment", "cvv", "pan", "corporate github", "github organization", "oauth", "personal access", "ghost accounts"]):
        sheet, severity = "REVIEW - Analyst Check", "HIGH"
    reason = build_relevance_reason(rel_reasons, threat_reasons, act_reasons, iocs)
    if threat_type == "AI / Identity Security" and any(x in f"{title} {clean_summary}".lower() for x in ["service account", "api token", "non-human", "identity", "ai agents", "ai agent"]):
        if sheet == "LOW - Archive":
            sheet, severity = "REVIEW - Analyst Check", "MEDIUM"
            reason = build_relevance_reason(rel_reasons, threat_reasons, act_reasons, iocs)
    if threat_type == "Vulnerability" and any(x in f"{title} {clean_summary}".lower() for x in ["defender", "rogueplanet", "mpengine"]) and iocs.get("cves"):
        sheet, severity = "CRITICAL - Full Review", "CRITICAL"
        if not any("Defender" in r or "RoguePlanet" in r for r in act_reasons):
            act_reasons.append("Microsoft Defender/RoguePlanet patch or exposure validation may be required")
        reason = build_relevance_reason(rel_reasons, threat_reasons, act_reasons, iocs)
    if sheet == "LOW - Archive":
        action = "Optional analyst review if time allows; no immediate Company action identified." if severity == "Unsure" else "No immediate action. Archive only."
    else:
        action = build_action_required(threat_type, iocs, act_reasons, full_text, source)
    vendors_shown = sorted(set(matches.get("vendors_strong", []) + matches.get("vendors_moderate", [])))
    apps_shown = sorted(set(matches.get("technologies_strong", []) + matches.get("technologies_moderate", [])))
    brands_shown = sorted(set(matches.get("brands_strong", []) + matches.get("brands_moderate", [])))
    regions_shown = sorted(set(matches.get("regions_moderate", [])))
    return ThreatRecord(sheet, source, title, link, published.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"), threat_type, severity, (clean_summary or body_text or title)[:500], reason, ", ".join(iocs["cves"]), ", ".join(iocs["ips"]), ", ".join(iocs["domains"]), ", ".join(iocs["urls"]), ", ".join(iocs["sha256"]), ", ".join(iocs["emails"]), ", ".join(iocs["filenames"]), ", ".join(iocs["malware_families"]), ", ".join(iocs["cloud_assets"]), ", ".join(vendors_shown), ", ".join(regions_shown), ", ".join(apps_shown), ", ".join(brands_shown), action, build_record_key(source, title, link), sheet == "CRITICAL - Full Review")

# Source collection
def parse_datetime(entry) -> datetime:
    for attr in ["published_parsed", "updated_parsed", "created_parsed"]:
        struct = getattr(entry, attr, None)
        if struct:
            try: return datetime(*struct[:6], tzinfo=timezone.utc)
            except Exception: pass
    if isinstance(entry, dict):
        for key in ["published", "updated", "dateAdded"]:
            raw = entry.get(key)
            if raw:
                try: return datetime.fromisoformat(str(raw).replace("Z", "+00:00")).astimezone(timezone.utc)
                except Exception: pass
    return utc_now()

def in_window(dt: datetime, start: datetime, end: datetime) -> bool:
    return start <= dt <= end

def safe_get_title(entry) -> str:
    return normalize_space(entry.get("title", "")) if isinstance(entry, dict) else normalize_space(getattr(entry, "title", ""))

def safe_get_link(entry) -> str:
    return normalize_space(entry.get("link", "")) if isinstance(entry, dict) else normalize_space(getattr(entry, "link", ""))

def safe_get_summary(entry) -> str:
    if isinstance(entry, dict): return normalize_space(entry.get("summary", ""))
    return normalize_space(getattr(entry, "summary", "") or getattr(entry, "description", ""))

def fetch_feed_bytes(source_name: str, feed_url: str):
    # Fetch feed content with requests so network timeouts are enforced.
    try:
        resp = session.get(feed_url, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        return resp.content, None
    except requests.exceptions.SSLError as e:
        # Limited fallback for RSS feeds behind SSL-inspecting proxies.
        try:
            resp = session.get(feed_url, timeout=REQUEST_TIMEOUT, verify=False)
            resp.raise_for_status()
            return resp.content, f"SSL verify failed, used verify=False fallback: {e}"
        except Exception as e2:
            return None, e2
    except Exception as e:
        return None, e

def parse_entry_to_record(source_name: str, entry, start: datetime, end: datetime) -> Optional[ThreatRecord]:
    published = parse_datetime(entry)
    if not in_window(published, start, end): return None
    title, link, summary = safe_get_title(entry), safe_get_link(entry), safe_get_summary(entry)
    if not title or not link: return None
    body = fetch_article_text(link) if ARTICLE_FETCH_ENABLED else ""
    return create_record(source_name, title, link, summary, published, body)

def scrape_rss_source(source_name: str, feed_url: str, start: datetime, end: datetime) -> List[ThreatRecord]:
    logger.info(f"Scraping RSS source: {source_name}")
    t0 = time.time()
    stats = {"time_utc": utc_now().isoformat(), "source": source_name, "url": feed_url, "status": "STARTED", "records": 0, "elapsed_seconds": None, "warning": None, "error": None}
    records = []
    try:
        content, err = fetch_feed_bytes(source_name, feed_url)
        if err:
            stats["warning"] = str(err)
            logger.warning(f"RSS fetch warning for {source_name}: {err}")
        if not content:
            stats["status"] = "FAILED_FETCH"
            stats["error"] = str(err)
            log_feed_error(source_name, feed_url, Exception(str(err)))
            return []
        feed = feedparser.parse(content)
        if getattr(feed, "bozo", 0):
            warning = str(getattr(feed, "bozo_exception", ""))
            stats["warning"] = (stats.get("warning") or "") + (" | " if stats.get("warning") else "") + warning
            logger.warning(f"RSS parser warning for {source_name}: {warning}")
        for entry in getattr(feed, "entries", []):
            try:
                rec = parse_entry_to_record(source_name, entry, start, end)
                if rec: records.append(rec)
            except Exception as e:
                logger.warning(f"Entry parse failed from {source_name}: {e}")
        stats["status"] = "OK"
        stats["records"] = len(records)
        return records
    except Exception as e:
        stats["status"] = "FAILED_RUNTIME"
        stats["error"] = repr(e)
        log_feed_error(source_name, feed_url, e)
        logger.error(f"RSS feed failed: {source_name} | {e}")
        return []
    finally:
        stats["elapsed_seconds"] = round(time.time() - t0, 2)
        logger.debug(f"Source stats: {stats}")

def fetch_cisa_kev_json(source_name: str, url: str, start: datetime, end: datetime) -> List[ThreatRecord]:
    logger.info(f"Fetching JSON source: {source_name}")
    records = []
    try:
        r = session.get(url, timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
        for item in r.json().get("vulnerabilities", []):
            date_added = item.get("dateAdded")
            published = datetime.fromisoformat(date_added).replace(tzinfo=timezone.utc) if date_added else utc_now()
            if not in_window(published, start, end): continue
            cve = item.get("cveID", "")
            title = normalize_space(f"{cve} | {item.get('vendorProject','')} {item.get('product','')} | {item.get('vulnerabilityName','')}")
            link = f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog#{cve}" if cve else "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
            summary = normalize_space(f"{item.get('shortDescription','')} Action: {item.get('requiredAction','')} Notes: {item.get('notes','')}")
            if str(item.get("knownRansomwareCampaignUse", "")).lower() == "known": summary += " Known to be used in ransomware campaigns."
            body = f"{title} {summary} known exploited actively exploited vulnerability KEV"
            records.append(create_record(source_name, title, link, summary, published, body))
    except Exception as e:
        log_feed_error(source_name, url, e)
        logger.error(f"JSON source failed: {source_name} | {e}")
    logger.debug(f"Source stats: source={source_name} status=OK records={len(records)}")
    return records

def collect_all_sources(start: datetime, end: datetime) -> List[ThreatRecord]:
    all_records = []
    futures = {}
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        for n, u in RSS_SOURCES.items():
            futures[executor.submit(scrape_rss_source, n, u, start, end)] = n
        for n, meta in JSON_SOURCES.items():
            if meta.get("type") == "cisa_kev":
                futures[executor.submit(fetch_cisa_kev_json, n, meta["url"], start, end)] = n
        pending = set(futures.keys())
        deadline = time.time() + RUN_TIMEOUT
        while pending and time.time() < deadline:
            done = []
            for fut in list(pending):
                if fut.done(): done.append(fut)
            if not done:
                time.sleep(0.5); continue
            for fut in done:
                pending.remove(fut)
                name = futures.get(fut, "unknown")
                try: all_records.extend(fut.result(timeout=1))
                except Exception as e: logger.error(f"Source future failed: {name} | {e}")
        for fut in pending:
            name = futures.get(fut, "unknown")
            logger.error(f"Source timed out and was skipped: {name}")
            logger.debug(f"Source stats: source={name} status=SOURCE_TIMEOUT records=0")
            fut.cancel()
    return all_records

# Excel output and state management
def load_existing_workbook_keys(excel_path: Path) -> set:
    if not excel_path.exists(): return set()
    keys = set()
    try:
        xls = pd.ExcelFile(excel_path, engine="openpyxl")
        for sheet in xls.sheet_names:
            df = pd.read_excel(excel_path, sheet_name=sheet, engine="openpyxl")
            if "link" in df.columns:
                for link in df["link"].dropna().astype(str): keys.add(f"link::{canonical_link(link)}")
    except Exception as e: logger.warning(f"Failed to read existing workbook for keys: {e}")
    return keys

def deduplicate_for_excel(records: List[ThreatRecord], excel_path: Path) -> List[ThreatRecord]:
    # De-duplicate records within the current collection run.
    seen, out = set(), []
    for r in records:
        key, link_key = r.record_key, f"link::{canonical_link(r.link)}"
        if key in seen or link_key in seen:
            continue
        seen.add(key); seen.add(link_key); out.append(r)
    return out

def records_to_frames(records: List[ThreatRecord]) -> Dict[str, pd.DataFrame]:
    rows = {"CRITICAL - Full Review": [], "REVIEW - Analyst Check": [], "LOW - Archive": []}
    cols = ["source", "title", "link", "published_utc", "threat_type", "severity", "summary", "relevance_reason", "cves", "ips", "domains", "urls", "sha256", "emails", "filenames", "malware_families", "cloud_assets", "vendors_matched", "regions_matched", "applications_matched", "brands_matched", "action_required"]
    for r in records:
        d = asdict(r); d.pop("record_key", None); d.pop("critical_email", None); d.pop("sheet", None); rows[r.sheet].append(d)
    return {sheet: (pd.DataFrame(vals)[cols] if vals else pd.DataFrame(columns=cols)) for sheet, vals in rows.items()}

def merge_with_existing(frames: Dict[str, pd.DataFrame], excel_path: Path) -> Dict[str, pd.DataFrame]:
    if not excel_path.exists(): return frames
    merged = {}
    xls = pd.ExcelFile(excel_path, engine="openpyxl")
    for sheet, new_df in frames.items():
        combined = pd.concat([pd.read_excel(excel_path, sheet_name=sheet, engine="openpyxl") if sheet in xls.sheet_names else pd.DataFrame(), new_df], ignore_index=True)
        if not combined.empty and "link" in combined.columns:
            combined["_k"] = combined["link"].fillna("").astype(str).apply(canonical_link)
            combined = combined.drop_duplicates(subset=["_k"], keep="last").drop(columns=["_k"])
        merged[sheet] = combined
    return merged

def style_workbook(excel_path: Path):
    from openpyxl import load_workbook
    wb = load_workbook(excel_path)
    colors = {"CRITICAL - Full Review": "FFC7CE", "REVIEW - Analyst Check": "FFEB9C", "LOW - Archive": "C6EFCE"}
    for ws in wb.worksheets:
        fill = PatternFill("solid", fgColor=colors.get(ws.title, "D9EAD3"))
        for cell in ws[1]:
            cell.fill = fill; cell.font = Font(bold=True); cell.alignment = Alignment(vertical="top", wrap_text=True)
        for row in ws.iter_rows(min_row=2):
            for cell in row: cell.alignment = Alignment(vertical="top", wrap_text=True)
        ws.freeze_panes = "A2"; ws.auto_filter.ref = ws.dimensions
        for col in ws.columns:
            letter = get_column_letter(col[0].column)
            max_len = max((len(str(c.value)) if c.value is not None else 0 for c in col), default=12)
            ws.column_dimensions[letter].width = min(max(max_len + 2, 12), 60)
    wb.save(excel_path)

def export_excel(records: List[ThreatRecord], excel_path: Path, merge_existing: bool = True):
    frames = records_to_frames(records)
    if merge_existing: frames = merge_with_existing(frames, excel_path)
    tmp = excel_path.with_suffix(".tmp.xlsx")
    if tmp.exists(): tmp.unlink()
    with pd.ExcelWriter(tmp, engine="openpyxl", mode="w") as writer:
        for sheet, df in frames.items(): df.to_excel(writer, sheet_name=sheet[:31], index=False)
    style_workbook(tmp); os.replace(tmp, excel_path)

def load_seen_items() -> Dict[str, dict]:
    if not SEEN_ITEMS_FILE.exists(): return {"items": {}}
    try:
        data = json.loads(SEEN_ITEMS_FILE.read_text(encoding="utf-8")); return {"items": data.get("items", {})}
    except Exception: return {"items": {}}

def save_seen_items_for_records(records: List[ThreatRecord]):
    data = load_seen_items(); items = data.setdefault("items", {}); now = utc_now().isoformat(); cutoff = utc_now() - timedelta(days=RETENTION_DAYS)
    for key, meta in list(items.items()):
        try:
            last = datetime.fromisoformat(meta.get("last_seen", meta.get("first_seen", now)).replace("Z", "+00:00")).astimezone(timezone.utc)
            if last < cutoff: items.pop(key, None)
        except Exception: items.pop(key, None)
    for r in records:
        meta = items.setdefault(r.record_key, {"first_seen": now, "alerted": False}); meta["last_seen"] = now
        if r.critical_email: meta["alerted"] = True
    SEEN_ITEMS_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

# Alerts and main run flow
def send_email_alert(records: List[ThreatRecord]):
    if not ENABLE_EMAIL_ALERTS or not records: return
    try:
        body = "\n".join([f"{i+1}. {r.title}\nSource: {r.source}\nAction: {r.action_required}\nLink: {r.link}\n" for i, r in enumerate(records[:10])])
        msg = MIMEMultipart(); msg["From"] = SMTP_CONFIG["sender"]; msg["To"] = ", ".join(SMTP_CONFIG["recipients"]); msg["Subject"] = f"[IMMEDIATE ACTION] {len(records)} Company-actionable threat intel item(s)"; msg.attach(MIMEText(body, "plain", "utf-8"))
        server = smtplib.SMTP(SMTP_CONFIG["server"], SMTP_CONFIG["port"], timeout=20)
        if SMTP_CONFIG["use_tls"]: server.starttls()
        server.login(SMTP_CONFIG["username"], SMTP_CONFIG["password"]); server.sendmail(SMTP_CONFIG["sender"], SMTP_CONFIG["recipients"], msg.as_string()); server.quit()
    except Exception as e: logger.error(f"Email alert failed: {e}")

def summarize_counts(records: List[ThreatRecord]) -> Dict[str, int]:
    return {"critical": sum(1 for r in records if r.sheet == "CRITICAL - Full Review"), "review": sum(1 for r in records if r.sheet == "REVIEW - Analyst Check"), "low": sum(1 for r in records if r.sheet == "LOW - Archive"), "total": len(records)}

def run_once():
    start_time = utc_now(); start_clock = time.time(); excel_path = output_excel_name(); run_status = "FAILED_UNKNOWN"; raw_count = 0; written_records: List[ThreatRecord] = []
    window_start, window_end, mode = get_collection_window()
    logger.info("Starting threat intel collection run..."); logger.info(f"Collection window mode: {mode}"); logger.info(f"Collection window UTC: {window_start.isoformat()} to {window_end.isoformat()}"); logger.info(f"Daily workbook target: {excel_path.name}")
    if is_excel_locked(excel_path):
        run_status = "FAILED_EXCEL_LOCKED"; logger.error(f"Excel file appears to be open/locked: {excel_path.name}. Close it and rerun. State was not updated."); append_run_history({"run_start_utc": start_time.isoformat(), "run_end_utc": utc_now().isoformat(), "status": run_status, "excel_file": excel_path.name}); return
    try:
        raw_records = collect_all_sources(window_start, window_end); raw_count = len(raw_records); logger.info(f"Collected raw records: {raw_count}")
        if raw_count == 0:
            run_status = "FAILED_EMPTY_RUN"; logger.error("0 raw records collected. This run is unsafe; Excel/state/seen-items will NOT be updated."); append_run_history({"run_start_utc": start_time.isoformat(), "run_end_utc": utc_now().isoformat(), "status": run_status, "raw_records": raw_count, "excel_file": excel_path.name}); return
        written_records = deduplicate_for_excel(raw_records, excel_path); logger.info(f"New unique records after Excel de-duplication: {len(written_records)}")
        export_excel(written_records, excel_path, merge_existing=True); logger.info(f"Writing Excel output: {excel_path.name}")
        save_seen_items_for_records(raw_records); save_last_run_time(window_end); run_status = "SUCCESS"
        counts = summarize_counts(written_records); logger.info("Run Summary"); logger.info(f"  Critical: {counts['critical']}"); logger.info(f"  Review  : {counts['review']}"); logger.info(f"  Low     : {counts['low']}"); logger.info(f"  Total   : {counts['total']}"); logger.info(f"  Workbook: {excel_path.name}")
        critical_records = [r for r in written_records if r.critical_email]
        if critical_records: logger.warning(f"Immediate critical threat count: {len(critical_records)}"); send_email_alert(critical_records)
        else: logger.info("No immediate critical email alert conditions met.")
    except Exception as e:
        run_status = "FAILED_EXCEL_WRITE" if "Excel" in str(e) or "workbook" in str(e).lower() else "FAILED_RUNTIME_ERROR"; logger.error(f"Run failed safely. State was not updated after failure. Error: {e}"); raise
    finally:
        elapsed = round(time.time() - start_clock, 2); append_run_history({"run_start_utc": start_time.isoformat(), "run_end_utc": utc_now().isoformat(), "status": run_status, "window_start_utc": window_start.isoformat(), "window_end_utc": window_end.isoformat(), "raw_records": raw_count, "written_records": len(written_records), "excel_file": excel_path.name, "elapsed_seconds": elapsed, "host": socket.gethostname()}); logger.info(f"Run completed with status={run_status} in {elapsed} seconds | Host={socket.gethostname()}")

if __name__ == "__main__":
    run_once()
