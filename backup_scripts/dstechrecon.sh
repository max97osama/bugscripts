#!/bin/bash

if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <ips.txt|subdomains.txt>"
    exit 1
fi

INPUT="$1"
TECH_OUT="tech.txt"
TECHSTACK_OUT="techstack.txt"
RAW_ALL="/tmp/tech_raw_$$.txt"
TARGETS="/tmp/tech_targets_$$.txt"
HTTP_TARGETS="/tmp/tech_http_$$.txt"

> "$RAW_ALL"
> "$TARGETS"
> "$HTTP_TARGETS"

touch "$TECH_OUT"
touch "$TECHSTACK_OUT"

while IFS= read -r line; do
    line=$(echo "$line" | tr -d '[:space:]')
    [ -z "$line" ] && continue
    echo "$line" >> "$TARGETS"
    if echo "$line" | grep -qE "^https?://"; then
        echo "$line" >> "$HTTP_TARGETS"
    elif echo "$line" | grep -qE "^[a-zA-Z]"; then
        echo "https://$line" >> "$HTTP_TARGETS"
    fi
done < "$INPUT"

sort -u "$TARGETS" -o "$TARGETS"
sort -u "$HTTP_TARGETS" -o "$HTTP_TARGETS"

echo "[*] Total targets: $(wc -l < "$TARGETS")"

CURATED_PORTS="21,22,23,25,53,67,68,69,80,110,139,143,161,162,443,445,465,587,853,993,995,1433,1521,2049,2181,2375,2376,2379,2380,3000,3100,3306,3389,4243,4444,4848,5432,5601,5672,5900,5901,5984,6379,6443,7070,7474,7990,8000,8008,8080,8086,8088,8090,8443,8888,9000,9090,9092,9100,9200,9300,10250,10255,11211,15672,27017,27018,50000"

while IFS= read -r TARGET; do
    echo "[*] Nmap scanning: $TARGET"

    echo "=== NMAP: $TARGET ===" >> "$RAW_ALL"

    SCAN_PORTS="$CURATED_PORTS"

    if command -v naabu >/dev/null 2>&1; then
        NAABU_OUT="/tmp/naabu_tech_$$.json"
        echo "[*] naabu pre-scan on curated port list for $TARGET..."
        timeout 180 naabu -host "$TARGET" -p "$CURATED_PORTS" \
            -rate 200 -c 25 -silent -json -o "$NAABU_OUT" 2>/dev/null

        FOUND_PORTS=$(python3 -c "
import json
ports = set()
try:
    with open('$NAABU_OUT') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                p = data.get('port')
                if p:
                    ports.add(int(p))
            except Exception:
                continue
except FileNotFoundError:
    pass
print(','.join(str(p) for p in sorted(ports)))
")
        rm -f "$NAABU_OUT"

        if [ -z "$FOUND_PORTS" ]; then
            echo "[*] naabu found no open ports on $TARGET out of the curated list, skipping nmap."
            echo "[*] No open ports found by naabu pre-scan." >> "$RAW_ALL"
            sleep 3
            continue
        fi

        echo "[+] naabu found open ports on $TARGET: $FOUND_PORTS"
        SCAN_PORTS="$FOUND_PORTS"
    else
        echo "[-] naabu not found, nmap will discover ports itself from the curated list (slower)."
    fi

    timeout 600 nmap -sV -sC -O --osscan-guess --max-os-tries 1 \
        -T3 \
        -n \
        -p "$SCAN_PORTS" \
        --host-timeout 8m \
        --script-timeout 45s \
        --script banner,http-server-header,http-generator,http-title,http-auth-finder,http-headers,ssh-hostkey,ftp-anon,ssl-cert,http-robots.txt,snmp-info,smb-os-discovery,redis-info,mongodb-info,mysql-info,ms-sql-info \
        -oN /tmp/nmap_tech_$$.txt \
        "$TARGET" 2>/dev/null

    if [ $? -eq 124 ]; then
        echo "[!] $TARGET nmap scan hit its time limit, killed"
    fi

    cat /tmp/nmap_tech_$$.txt >> "$RAW_ALL"
    rm -f /tmp/nmap_tech_$$.txt

    sleep 5

done < "$TARGETS"

CMS_DETECTED_FILE="/tmp/cms_detected_$$.txt"
> "$CMS_DETECTED_FILE"

while IFS= read -r TARGET; do
    echo "[*] Web scanning: $TARGET"

    echo "=== WHATWEB: $TARGET ===" >> "$RAW_ALL"
    timeout 30 whatweb "$TARGET" \
        --color=never \
        -a 1 \
        2>/dev/null >> "$RAW_ALL"

    sleep 5

    echo "=== WEBANALYZE: $TARGET ===" >> "$RAW_ALL"
    timeout 30 webanalyze -host "$TARGET" \
        -crawl 1 \
        2>/dev/null >> "$RAW_ALL"

    sleep 5

    echo "=== CURL HEADERS: $TARGET ===" >> "$RAW_ALL"
    curl -skI "$TARGET" \
        --max-time 10 \
        -A "Mozilla/5.0" \
        2>/dev/null >> "$RAW_ALL"

    sleep 3

    echo "=== WAFW00F: $TARGET ===" >> "$RAW_ALL"
    timeout 30 wafw00f "$TARGET" \
        2>/dev/null >> "$RAW_ALL"

    sleep 5

    echo "=== HTTPX TECH: $TARGET ===" >> "$RAW_ALL"
    echo "$TARGET" | httpx \
        -tech-detect \
        -status-code \
        -title \
        -server \
        -silent \
        -threads 1 \
        -timeout 10 \
        2>/dev/null >> "$RAW_ALL"

    sleep 5

    echo "=== CMSEEK: $TARGET ===" >> "$RAW_ALL"
    CMSEEK_OUT=$(timeout 60 cmseek -u "$TARGET" \
        --follow-redirect \
        -r \
        2>/dev/null)
    echo "$CMSEEK_OUT" >> "$RAW_ALL"

    if echo "$CMSEEK_OUT" | grep -qi "wordpress"; then
        echo "wordpress $TARGET" >> "$CMS_DETECTED_FILE"
    elif echo "$CMSEEK_OUT" | grep -qiE "drupal|joomla|magento|prestashop|typo3|opencart|concrete5|ghost|october|craft|umbraco|moodle|vbulletin|phpbb|xenforo|modx|textpattern|silverstripe"; then
        CMS_NAME=$(echo "$CMSEEK_OUT" | grep -ioE "drupal|joomla|magento|prestashop|typo3|opencart|concrete5|ghost|october|craft|umbraco|moodle|vbulletin|phpbb|xenforo|modx|textpattern|silverstripe" | head -1 | tr '[:upper:]' '[:lower:]')
        echo "other $CMS_NAME $TARGET" >> "$CMS_DETECTED_FILE"
    fi

    WHATWEB_OUT=$(timeout 30 whatweb "$TARGET" --color=never -a 1 2>/dev/null)
    if [ -z "$(grep "wordpress $TARGET" "$CMS_DETECTED_FILE" 2>/dev/null)" ]; then
        if echo "$WHATWEB_OUT" | grep -qi "wordpress"; then
            echo "wordpress $TARGET" >> "$CMS_DETECTED_FILE"
        fi
    fi

    sleep 5

done < "$HTTP_TARGETS"

while IFS= read -r cms_line; do
    CMS_TYPE=$(echo "$cms_line" | awk '{print $1}')
    TARGET=$(echo "$cms_line" | awk '{print $NF}')
    CMS_NAME=$(echo "$cms_line" | awk '{print $2}')

    if [ "$CMS_TYPE" = "wordpress" ]; then
        echo "[*] WordPress detected on $TARGET - running wpscan..."
        echo "=== WPSCAN: $TARGET ===" >> "$RAW_ALL"
        timeout 300 wpscan --url "$TARGET" \
            --no-banner \
            --disable-tls-checks \
            --throttle 2000 \
            --request-timeout 10 \
            --enumerate vp,vt,u,tt,cb,dbe \
            2>/dev/null >> "$RAW_ALL"
        sleep 10

    elif [ "$CMS_TYPE" = "other" ]; then
        echo "[*] $CMS_NAME detected on $TARGET - running cmsmap..."
        echo "=== CMSMAP ($CMS_NAME): $TARGET ===" >> "$RAW_ALL"
        timeout 180 cmsmap "$TARGET" \
            -t 1 \
            2>/dev/null >> "$RAW_ALL"
        sleep 10
    fi

done < "$CMS_DETECTED_FILE"

echo "[*] Building tech.txt and techstack.txt..."

python3 - <<PYEOF
import re
from datetime import datetime

PORT_TOOLS = {
    "21":    ("FTP", "vsftpd / ProFTPD / FileZilla Server"),
    "22":    ("SSH", "OpenSSH / Dropbear"),
    "23":    ("Telnet", "Telnet daemon - CRITICAL: plaintext credentials"),
    "25":    ("SMTP", "Postfix / Sendmail / Exim"),
    "53":    ("DNS", "BIND / Unbound / PowerDNS / dnsmasq"),
    "67":    ("DHCP", "ISC DHCP Server / dnsmasq"),
    "68":    ("DHCP Client", "DHCP client port"),
    "69":    ("TFTP", "TFTP server - unauthenticated file transfer"),
    "80":    ("HTTP", "Apache / Nginx / IIS / LiteSpeed / Caddy"),
    "110":   ("POP3", "Dovecot / Courier / Cyrus"),
    "139":   ("NetBIOS", "Samba / Windows File Sharing"),
    "143":   ("IMAP", "Dovecot / Courier / Cyrus"),
    "161":   ("SNMP", "Net-SNMP - CRITICAL: leaks OS, hardware, network info"),
    "162":   ("SNMP Trap", "Net-SNMP trap receiver"),
    "443":   ("HTTPS", "Apache / Nginx / IIS / LiteSpeed with SSL"),
    "445":   ("SMB", "Samba / Windows SMB - check for EternalBlue"),
    "465":   ("SMTPS", "Postfix / Exim with SSL"),
    "587":   ("SMTP Submission", "Postfix / Exim submission port"),
    "853":   ("DNS over TLS", "Unbound / BIND / PowerDNS with TLS"),
    "993":   ("IMAPS", "Dovecot / Courier with SSL"),
    "995":   ("POP3S", "Dovecot / Courier with SSL"),
    "1433":  ("MSSQL", "Microsoft SQL Server"),
    "1521":  ("Oracle DB", "Oracle Database"),
    "2049":  ("NFS", "NFS server - check for unauthenticated mount"),
    "2181":  ("Zookeeper", "Apache Zookeeper"),
    "2375":  ("Docker", "Docker daemon UNENCRYPTED - CRITICAL: full container takeover"),
    "2376":  ("Docker TLS", "Docker daemon with TLS"),
    "2379":  ("etcd", "etcd key-value store - Kubernetes control plane"),
    "2380":  ("etcd cluster", "etcd cluster communication"),
    "3000":  ("Dev Server", "Node.js / Grafana / React dev server / Gitea"),
    "3100":  ("Loki", "Grafana Loki log aggregation"),
    "3306":  ("MySQL", "MySQL / MariaDB"),
    "3389":  ("RDP", "Windows Remote Desktop - check for BlueKeep"),
    "4243":  ("Docker alt", "Docker daemon alternate port"),
    "4444":  ("Metasploit / WildFly", "Metasploit listener or JBoss WildFly"),
    "4848":  ("GlassFish", "GlassFish admin console"),
    "5432":  ("PostgreSQL", "PostgreSQL database"),
    "5601":  ("Kibana", "Kibana log visualization"),
    "5672":  ("RabbitMQ", "RabbitMQ AMQP"),
    "5900":  ("VNC", "VNC remote desktop - check for no-auth"),
    "5901":  ("VNC display 1", "VNC remote desktop display 1"),
    "5984":  ("CouchDB", "Apache CouchDB"),
    "6379":  ("Redis", "Redis - CRITICAL: often unauthenticated RCE"),
    "6443":  ("Kubernetes API", "Kubernetes API server"),
    "7070":  ("Jira alt / RealServer", "Jira alternate or RealNetworks RealServer"),
    "7474":  ("Neo4j", "Neo4j graph database browser"),
    "7990":  ("Bitbucket", "Atlassian Bitbucket"),
    "8000":  ("Dev HTTP", "Python Django / Flask / Twisted dev server"),
    "8008":  ("HTTP alt", "HTTP alternate / Confluence"),
    "8080":  ("Tomcat / Jenkins", "Apache Tomcat / Jenkins / Squid proxy / dev server"),
    "8086":  ("InfluxDB", "InfluxDB time-series database"),
    "8088":  ("Hadoop", "Apache Hadoop HDFS HTTP"),
    "8090":  ("Confluence", "Atlassian Confluence"),
    "8443":  ("Tomcat HTTPS", "Apache Tomcat HTTPS / Kubernetes API alt"),
    "8888":  ("Jupyter", "Jupyter Notebook - CRITICAL: often unauthenticated RCE"),
    "9000":  ("SonarQube / Portainer", "SonarQube / Portainer / PHP-FPM"),
    "9090":  ("Prometheus / Cockpit", "Prometheus metrics / Cockpit web admin"),
    "9092":  ("Kafka", "Apache Kafka"),
    "9100":  ("Prometheus exporter", "Prometheus node exporter - leaks system metrics"),
    "9200":  ("Elasticsearch", "Elasticsearch - CRITICAL: often unauthenticated data dump"),
    "9300":  ("Elasticsearch cluster", "Elasticsearch cluster communication"),
    "10250": ("Kubelet API", "Kubernetes Kubelet - CRITICAL: node-level container access"),
    "10255": ("Kubelet readonly", "Kubernetes Kubelet read-only API"),
    "11211": ("Memcached", "Memcached - CRITICAL: unauthenticated data exposure + DDoS amplification"),
    "15672": ("RabbitMQ UI", "RabbitMQ management web UI"),
    "27017": ("MongoDB", "MongoDB - CRITICAL: often unauthenticated DB access"),
    "27018": ("MongoDB shard", "MongoDB shard server"),
    "50000": ("Jenkins agent", "Jenkins agent port - CRITICAL: potential RCE"),
}

CRITICAL_PORTS = {"23","2375","6379","8888","9200","10250","11211","27017","27018","50000","161","2379","4444"}

with open('$RAW_ALL', 'r', errors='ignore') as f:
    content = f.read()

version_pattern = re.compile(
    r'(v?\d+\.\d+[\.\d]*|/\d+\.\d+[\.\d]*|\d+\.\d+[\.\d]*[a-zA-Z]\w*)',
    re.IGNORECASE
)

skip_patterns = re.compile(
    r'^\s*$|^Starting Nmap|^Host is up|Nmap done|^#|^SF:'
    r'|latency|Not shown|^PORT\s+STATE'
    r'|Warning:|^Initiating|^Completed|^NSE:|^Scanning'
    r'|^Sending|^Increasing|^Stats:|^Read data',
    re.IGNORECASE
)

tech_keywords = re.compile(
    r'apache|nginx|iis|litespeed|caddy|tomcat'
    r'|php|python|ruby|java|node|perl|asp\.net|golang|rust'
    r'|wordpress|drupal|joomla|magento|prestashop|typo3|opencart|concrete5|ghost|october|craft|umbraco|moodle|vbulletin|phpbb|xenforo|modx|silverstripe'
    r'|laravel|django|flask|rails|spring|express|symfony|codeigniter|yii|zend'
    r'|mysql|mariadb|postgresql|mssql|oracle|mongodb|redis|elasticsearch|cassandra|sqlite|couchdb|memcached|influxdb'
    r'|react|angular|vue|jquery|bootstrap|svelte|ember|backbone'
    r'|ubuntu|debian|centos|redhat|fedora|windows server|freebsd|unix'
    r'|openssl|openssh|mod_ssl|cloudflare|akamai|fastly|varnish|squid|haproxy'
    r'|docker|kubernetes|jenkins|gitlab|jira|confluence|grafana|kibana|prometheus|zookeeper|kafka|rabbitmq'
    r'|x-powered-by|server:|x-generator|x-aspnet|x-runtime|x-framework'
    r'|cpanel|plesk|directadmin|webmin|glassfish|wildfly|jetty'
    r'|waf|firewall|load.balancer|cdn|cache'
    r'|plugin|theme|version|banner|product|service|open|filtered'
    r'|vulnerability|vulnerabilities|CVE-|outdated|admin|user|enumerat',
    re.IGNORECASE
)

open_filtered_pattern = re.compile(
    r'(\d+)/tcp\s+(open|filtered|open\|filtered)',
    re.IGNORECASE
)

sections = re.split(r'(=== .+ ===)', content)

seen = set()
findings_by_section = {}
port_findings_by_target = {}

current_section = 'GENERAL'
for part in sections:
    if re.match(r'=== .+ ===', part.strip()):
        current_section = part.strip()
        continue

    target_match = re.search(r'===\s+\w[\w\s]*:\s+(\S+)\s+===', current_section)
    target = target_match.group(1) if target_match else 'unknown'

    port_matches = open_filtered_pattern.findall(part)
    if port_matches:
        if target not in port_findings_by_target:
            port_findings_by_target[target] = []
        for port, state in port_matches:
            if port in PORT_TOOLS:
                service, tools = PORT_TOOLS[port]
                flag = " *** CRITICAL ***" if port in CRITICAL_PORTS else ""
                entry = f"  PORT {port} ({state.upper()}): {service} -> Possibly: {tools}{flag}"
                if entry not in port_findings_by_target[target]:
                    port_findings_by_target[target].append(entry)

    for line in part.splitlines():
        line_stripped = line.strip()
        if skip_patterns.search(line_stripped):
            continue
        if not version_pattern.search(line_stripped) and not tech_keywords.search(line_stripped):
            continue
        if line_stripped in seen:
            continue
        seen.add(line_stripped)
        if current_section not in findings_by_section:
            findings_by_section[current_section] = []
        findings_by_section[current_section].append(line_stripped)

with open('$TECH_OUT', 'a') as out:
    if port_findings_by_target:
        out.write('\n')
        out.write('=' * 60 + '\n')
        out.write('PORT-BASED TOOL DETECTION\n')
        out.write('=' * 60 + '\n')
        for target, entries in port_findings_by_target.items():
            out.write(f'\nTarget: {target}\n')
            out.write('-' * 40 + '\n')
            for entry in entries:
                out.write(f'{entry}\n')

    total = 0
    for section, lines in findings_by_section.items():
        out.write(f'\n{section}\n')
        out.write('-' * len(section) + '\n')
        for line in lines:
            out.write(f'{line}\n')
            total += 1

os_by_target = {}
os_pattern = re.compile(r'(OS details:|Running:|Aggressive OS guesses:|OS CPE:)\s*(.+)')
target_marker = re.compile(r'===\s+NMAP:\s+(\S+)\s+===')

current_target = None
for line in content.splitlines():
    tmatch = target_marker.match(line.strip())
    if tmatch:
        current_target = tmatch.group(1)
        continue
    omatch = os_pattern.search(line)
    if omatch and current_target:
        label, value = omatch.groups()
        os_by_target.setdefault(current_target, [])
        entry = f"{label} {value.strip()}"
        if entry not in os_by_target[current_target]:
            os_by_target[current_target].append(entry)

confirmed_tech_pattern = re.compile(
    r'\b([A-Za-z][A-Za-z0-9_.+-]{1,30})[\[/]v?(\d+(?:\.\d+){0,3}[a-zA-Z0-9]*)\]?'
)

confirmed_by_target = {}
current_target = None
for line in content.splitlines():
    tmatch = re.match(r'===\s+\w[\w\s]*:\s+(\S+)\s+===', line.strip())
    if tmatch:
        current_target = tmatch.group(1)
        continue
    if current_target is None:
        continue
    for m in confirmed_tech_pattern.finditer(line):
        name, version = m.groups()
        if name.lower() in ('http', 'https', 'tcp', 'udp', 'cve'):
            continue
        confirmed_by_target.setdefault(current_target, set())
        confirmed_by_target[current_target].add(f"{name} {version}")

with open('$TECHSTACK_OUT', 'a') as out:
    out.write('================================================================\n')
    out.write('TECH STACK SUMMARY\n')
    out.write(f'Date: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}\n')
    out.write('================================================================\n\n')

    out.write('OS DETECTION\n')
    out.write('------------\n')
    if os_by_target:
        for target, entries in os_by_target.items():
            out.write(f'\nTarget: {target}\n')
            for e in entries:
                out.write(f'  {e}\n')
    else:
        out.write('No OS details confirmed by nmap on any target.\n')
    out.write('\n')

    out.write('CONFIRMED TOOLS/VERSIONS\n')
    out.write('------------------------\n')
    if confirmed_by_target:
        for target, entries in confirmed_by_target.items():
            out.write(f'\nTarget: {target}\n')
            for e in sorted(entries):
                out.write(f'  {e}\n')
    else:
        out.write('No confirmed tool versions extracted.\n')
    out.write('\n')

    out.write('POSSIBLE (PORT-INFERRED, UNCONFIRMED)\n')
    out.write('--------------------------------------\n')
    if port_findings_by_target:
        for target, entries in port_findings_by_target.items():
            out.write(f'\nTarget: {target}\n')
            for entry in entries:
                out.write(f'{entry}\n')
    else:
        out.write('No port-based candidates identified.\n')
    out.write('\n')

print(f'[+] Port-based detections for {len(port_findings_by_target)} targets')
print(f'[+] tech.txt findings written')
print(f'[+] techstack.txt written')
PYEOF

echo "[+] Done."
echo "[+] tech.txt total lines: $(wc -l < "$TECH_OUT")"
echo "[+] techstack.txt total lines: $(wc -l < "$TECHSTACK_OUT")"

rm -f "$RAW_ALL" "$TARGETS" "$HTTP_TARGETS" "$CMS_DETECTED_FILE" /tmp/nmap_tech_$$.txt