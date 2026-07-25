#!/bin/bash
# ============================================================================
# origin-ip-finder-advanced.sh — v3 (High-Precision, Content-Verified)
# ============================================================================
# Finds the REAL origin IPv4 addresses of an organization / domain that sit
# behind CDN/WAF (CloudFront, Cloudflare, Akamai, Fastly, Incapsula, ...).
#
# v3 focus: DRASTICALLY reduce false positives via a multi-signal confidence
# engine. Every candidate IP is independently verified and scored using:
#   • TLS certificate SAN / Subject-O matching (parsed from the live IP)
#   • HTTP content fingerprint vs a baseline of the real site
#     (page <title>, favicon hash, org name & apex string in body)
#   • RDAP / WHOIS netblock owner matching the organization
#   • Reverse-DNS (PTR) matching the domain or org
#   • Provenance weighting (IPs that ARE the domain's live DNS score higher
#     than stale passive-DNS / broad ASN dumps)
# Only IPs whose combined score >= threshold are emitted as true positives.
#
# Outputs:
#   <domain>_ips.txt              confirmed true-positive origin IPs (naabu-ready)
#   <domain>_ips_scored.tsv       every candidate with score/tier/signals (audit)
#   <domain>_subdomains.txt       all discovered subdomains
#   <domain>_live_subdomains.txt  subdomains that resolve to an A record
#
# Usage:
#   ./origin-ip-finder-advanced.sh -d example.com -o "Example Inc"
#   ./origin-ip-finder-advanced.sh -d example.com -o "Example Inc" -b -D -t 45 \
#       -k <shodan> -c <censys_id:secret> -s <securitytrails>
#
# For authorized security research / bug bounty use only.
# ============================================================================

set -uo pipefail

# ── Colors ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

# ── Globals ─────────────────────────────────────────────────────────────────
DOMAIN=""
APEX=""
ORG_NAME=""
SHODAN_KEY=""
CENSYS_CREDS=""
SECURITYTRAILS_KEY=""
VIEWDNS_KEY=""
OUTPUT_FILE=""
THRESHOLD=45          # minimum confidence score to be a "true positive"
WORKERS=25            # verifier concurrency
DO_BRUTE=0            # -b : DNS brute force
DO_DEEP=0            # -D : deep/permutation enumeration
MAX_CANDIDATES=4000   # safety cap on IPs sent to verification
VERBOSE=0
WORDLIST=""

TMPDIR_BASE=$(mktemp -d /tmp/origin-ip-finder.XXXXXX)
ALL_IPS_FILE="$TMPDIR_BASE/all_ips.txt"          # ip only (dedup helper)
CAND_TSV="$TMPDIR_BASE/candidates.tsv"           # ip<TAB>source  (provenance)
CONFIRMED_FILE="$TMPDIR_BASE/confirmed.txt"       # verified true positives
SCORED_TSV="$TMPDIR_BASE/scored.tsv"              # full audit table
CDN_RANGES_FILE="$TMPDIR_BASE/cdn_ranges.txt"
SUBS_FILE="$TMPDIR_BASE/all_subdomains.txt"
LIVE_SUBS_FILE="$TMPDIR_BASE/live_subdomains.txt"
VERIFY_SCRIPT="$TMPDIR_BASE/verify.py"

trap 'rm -rf "$TMPDIR_BASE"' EXIT

# ── CDN / WAF CIDR ranges (edge IPs only — never origin hosting) ───────────
declare -a KNOWN_CDN_PREFIXES=(
    # Cloudflare
    "173.245.48.0/20" "103.21.244.0/22" "103.22.200.0/22" "103.31.4.0/22"
    "141.101.64.0/18" "108.162.192.0/18" "190.93.240.0/20" "188.114.96.0/20"
    "197.234.240.0/22" "198.41.128.0/17" "162.158.0.0/15" "104.16.0.0/13"
    "104.24.0.0/14" "172.64.0.0/13" "131.0.72.0/22"
    # AWS CloudFront ONLY
    "52.84.0.0/14" "54.182.0.0/16" "54.192.0.0/16" "54.230.0.0/16"
    "54.239.128.0/18" "54.239.192.0/19" "54.240.128.0/18" "99.84.0.0/16"
    "143.204.0.0/16" "204.246.164.0/22" "204.246.168.0/22" "205.251.249.0/24"
    "205.251.250.0/23" "205.251.252.0/23" "205.251.254.0/24"
    "216.137.32.0/19" "13.32.0.0/15" "13.35.0.0/16" "13.224.0.0/14"
    "13.249.0.0/16" "18.64.0.0/14" "18.68.0.0/16" "18.154.0.0/15"
    "18.160.0.0/15" "18.164.0.0/15" "18.172.0.0/15" "18.238.0.0/15"
    "3.160.0.0/14" "3.164.0.0/18" "3.168.0.0/14" "3.172.0.0/18"
    # Fastly
    "23.235.32.0/20" "43.249.72.0/22" "103.244.50.0/24" "103.245.222.0/23"
    "103.245.224.0/24" "104.156.80.0/20" "140.248.64.0/18" "140.248.128.0/17"
    "146.75.0.0/17" "151.101.0.0/16" "157.52.64.0/18" "167.82.0.0/17"
    "167.82.128.0/20" "167.82.160.0/20" "167.82.224.0/20" "172.111.64.0/18"
    "185.31.16.0/22" "199.27.72.0/21" "199.232.0.0/16"
    # Akamai (edge blocks)
    "72.246.0.0/15" "96.16.0.0/15" "96.6.0.0/15"
    "184.24.0.0/13" "184.50.0.0/15" "184.84.0.0/14"
    "2.16.0.0/13" "95.100.0.0/15" "92.122.0.0/15"
    "23.0.0.0/12" "23.32.0.0/11" "23.64.0.0/14" "23.72.0.0/13"
    # Sucuri
    "192.88.134.0/23" "185.93.228.0/22" "66.248.200.0/22"
    # StackPath / Highwinds
    "151.139.0.0/16" "199.250.192.0/18"
    # Incapsula / Imperva
    "199.83.128.0/21" "198.143.32.0/19" "149.126.72.0/21" "103.28.248.0/22"
    "45.64.64.0/22" "107.154.0.0/16" "45.60.0.0/16"
    # Limelight
    "68.232.32.0/20" "117.18.232.0/21"
    # BunnyCDN
    "116.206.186.0/24" "199.247.16.0/21"
    # Vercel / Netlify edge
    "76.76.21.0/24" "104.198.14.0/24"
)

# ── Logging helpers ─────────────────────────────────────────────────────────
log()  { echo -e "${CYAN}[*]${RESET} $*"; }
ok()   { echo -e "${GREEN}[+]${RESET} $*"; }
warn() { echo -e "${YELLOW}[!]${RESET} $*"; }
err()  { echo -e "${RED}[-]${RESET} $*" >&2; }
vlog() { [[ $VERBOSE -eq 1 ]] && echo -e "${CYAN}[v]${RESET} $*" || true; }

usage() {
    cat <<EOF
${BOLD}Origin IP Finder — Advanced Content-Verified Enumerator v3${RESET}

Usage: $0 -d <domain> [options]

Required:
  -d  Target domain (e.g., example.com)

Optional:
  -o  Organization name (auto-detected from whois if omitted)
  -t  Confidence threshold 0-100 (default: $THRESHOLD; raise to cut FPs further)
  -b  Enable DNS brute-force of common subdomains
  -D  Deep mode: permutation enumeration of discovered subdomains
  -j  Verifier concurrency (default: $WORKERS)
  -w  Custom subdomain wordlist file (for -b)
  -k  Shodan API key
  -c  Censys credentials (API_ID:API_SECRET)
  -s  SecurityTrails API key
  -v  ViewDNS API key
  -f  IP output file (default: <domain>_ips.txt)
  -V  Verbose
  -h  Help

Scoring signals (each independent; IP must reach threshold):
  TLS cert SAN matches domain ....... +45   Favicon hash matches baseline .. +35
  Live DNS provenance ............... +35   HTTP <title> matches baseline .. +25
  RDAP/WHOIS org matches ............ +30   PTR contains apex domain ....... +25
  TLS cert Subject-O matches org .... +30   Org name string in HTML body ... +20
  Apex domain string in body ........ +15   PTR contains org token ......... +15
  Responds to Host: <domain> ........  +5

Example:
  $0 -d example.com -o "Example Inc" -b -D -t 50 -k \$SHODAN_KEY
EOF
    exit 0
}

# ── Candidate recording (with provenance) ──────────────────────────────────
add_ip() {
    local ip="$1"; local source="${2:-unknown}"
    if [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        echo "$ip" >> "$ALL_IPS_FILE"
        printf '%s\t%s\n' "$ip" "$source" >> "$CAND_TSV"
        vlog "  candidate: $ip ($source)"
    fi
}
add_ips_from_var() {
    local ips="$1"; local source="$2"; local ip
    for ip in $ips; do add_ip "$ip" "$source"; done
}
add_sub() { # record a discovered subdomain
    local h="$1"
    [[ -n "$h" ]] && echo "$h" | grep -qiE "\\.?${APEX//./\\.}$" && echo "${h,,}" >> "$SUBS_FILE"
}

# ── Dependency installer ───────────────────────────────────────────────────
install_deps() {
    log "Checking dependencies..."
    local PKG=""
    if command -v apt-get &>/dev/null; then PKG="apt-get"
    elif command -v yum &>/dev/null; then PKG="yum"
    elif command -v dnf &>/dev/null; then PKG="dnf"
    elif command -v pacman &>/dev/null; then PKG="pacman"
    elif command -v brew &>/dev/null; then PKG="brew"; fi

    for cmd in dig whois curl jq python3 openssl; do
        if ! command -v "$cmd" &>/dev/null; then
            case "$cmd" in
                dig) case "$PKG" in
                        apt-get) sudo apt-get install -y dnsutils 2>/dev/null || true ;;
                        yum|dnf) sudo $PKG install -y bind-utils 2>/dev/null || true ;;
                        pacman) sudo pacman -S --noconfirm bind-tools 2>/dev/null || true ;;
                        brew) brew install bind 2>/dev/null || true ;;
                     esac ;;
                *) [[ -n "$PKG" ]] && sudo $PKG install -y "$cmd" 2>/dev/null || true ;;
            esac
        fi
    done

    if command -v go &>/dev/null; then
        for tool in subfinder dnsx httpx; do
            if ! command -v "$tool" &>/dev/null; then
                warn "Installing $tool..."
                case "$tool" in
                    subfinder) go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null || true ;;
                    dnsx) go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest 2>/dev/null || true ;;
                    httpx) go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest 2>/dev/null || true ;;
                esac
            fi
        done
    else
        warn "Go not found — subfinder/dnsx/httpx unavailable (fallbacks used)."
    fi

    if command -v pip3 &>/dev/null; then
        pip3 install mmh3 --quiet --break-system-packages 2>/dev/null || \
        pip3 install mmh3 --quiet 2>/dev/null || true
    fi
    ok "Dependency check complete."
}

# ── Auto-detect org name ───────────────────────────────────────────────────
detect_org_name() {
    if [[ -n "$ORG_NAME" ]]; then return; fi
    log "Auto-detecting organization name from whois..."
    if command -v whois &>/dev/null; then
        ORG_NAME=$(whois "$DOMAIN" 2>/dev/null | grep -iE "^(Org(anization)?(-Name)?|OrgName|Registrant Organization)" | head -1 | sed 's/^[^:]*:\s*//' | xargs 2>/dev/null || true)
        [[ -n "$ORG_NAME" ]] && ok "Detected org: $ORG_NAME" || warn "No org name found. Use -o for best precision."
    fi
}

# ── CDN range database ─────────────────────────────────────────────────────
build_cdn_ranges() {
    log "Building CDN/WAF IP range database..."
    printf '%s\n' "${KNOWN_CDN_PREFIXES[@]}" > "$CDN_RANGES_FILE"
    curl -sf --max-time 10 "https://www.cloudflare.com/ips-v4" >> "$CDN_RANGES_FILE" 2>/dev/null || true
    local aws_json
    aws_json=$(curl -sf --max-time 15 "https://ip-ranges.amazonaws.com/ip-ranges.json" 2>/dev/null || echo "")
    if [[ -n "$aws_json" ]] && command -v jq &>/dev/null; then
        echo "$aws_json" | jq -r '.prefixes[] | select(.service=="CLOUDFRONT") | .ip_prefix' >> "$CDN_RANGES_FILE" 2>/dev/null || true
    fi
    local fastly_json
    fastly_json=$(curl -sf --max-time 10 "https://api.fastly.com/public-ip-list" 2>/dev/null || echo "")
    if [[ -n "$fastly_json" ]] && command -v jq &>/dev/null; then
        echo "$fastly_json" | jq -r '.addresses[]' >> "$CDN_RANGES_FILE" 2>/dev/null || true
    fi
    sort -u -o "$CDN_RANGES_FILE" "$CDN_RANGES_FILE"
    ok "Loaded $(wc -l < "$CDN_RANGES_FILE" | xargs) CDN/WAF CIDR ranges."
}

# ============================================================================
# ENUMERATION MODULES
# ============================================================================

# ── Module 1: Direct DNS (host is literally the domain's record) ───────────
module_dns_direct() {
    log "Module: Direct DNS resolution..."
    command -v dig &>/dev/null || return
    local subs=("" "www" "mail" "ftp" "direct" "origin" "origin-www"
        "direct-connect" "server" "host" "cpanel" "webmail" "smtp" "pop"
        "imap" "mx" "ns1" "ns2" "api" "dev" "staging" "stage" "test" "uat"
        "admin" "panel" "old" "legacy" "backup" "bak" "real" "orig" "vpn"
        "remote" "ssh" "portal" "crm" "erp" "intranet" "internal" "gateway"
        "proxy" "app" "web" "ns" "dns" "mail2" "email" "exchange" "owa"
        "autodiscover" "git" "gitlab" "jenkins" "jira" "confluence" "docker"
        "registry" "vpn2" "monitor" "grafana" "kibana" "db" "sql" "mysql")
    for sub in "${subs[@]}"; do
        local target; [[ -z "$sub" ]] && target="$DOMAIN" || target="${sub}.${DOMAIN}"
        local ips
        ips=$(dig +short +time=3 +tries=1 A "$target" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' || true)
        if [[ -n "$ips" ]]; then
            [[ -n "$sub" ]] && add_sub "$target"
            add_ips_from_var "$ips" "dns:$target"
        fi
    done
}

# ── Module 2: MX / SPF / TXT / NS / SOA ─────────────────────────────────────
module_dns_records() {
    log "Module: MX/SPF/TXT/NS/SOA record analysis..."
    command -v dig &>/dev/null || return
    local mx_hosts
    mx_hosts=$(dig +short MX "$DOMAIN" 2>/dev/null | awk '{print $2}' | sed 's/\.$//' || true)
    for mxh in $mx_hosts; do
        echo "$mxh" | grep -qiE '(google|outlook|microsoft|protonmail|zoho|mimecast|pphosted|messagelabs)' && continue
        local ips; ips=$(dig +short A "$mxh" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' || true)
        add_ips_from_var "$ips" "mx:$mxh"
    done
    local spf
    spf=$(dig +short TXT "$DOMAIN" 2>/dev/null | tr -d '"' | grep -i 'v=spf1' || true)
    if [[ -n "$spf" ]]; then
        local spf_ips; spf_ips=$(echo "$spf" | grep -oE 'ip4:[0-9.]+(/[0-9]+)?' | cut -d: -f2 || true)
        for entry in $spf_ips; do
            [[ "$entry" == */* ]] && add_ip "${entry%/*}" "spf-cidr:$entry" || add_ip "$entry" "spf"
        done
        local includes; includes=$(echo "$spf" | grep -oE 'include:[^ ]+' | cut -d: -f2 || true)
        for inc in $includes; do
            echo "$inc" | grep -qiE '(google|amazonses|sendgrid|mailgun|outlook|microsoft|spf\.protection|mailchimp|postmarkapp|zendesk)' && continue
            local inc_ips; inc_ips=$(dig +short TXT "$inc" 2>/dev/null | tr -d '"' | grep -oE 'ip4:[0-9.]+' | cut -d: -f2 || true)
            add_ips_from_var "$inc_ips" "spf-include:$inc"
        done
    fi
    local soa_ns; soa_ns=$(dig +short SOA "$DOMAIN" 2>/dev/null | awk '{print $1}' | sed 's/\.$//' || true)
    if [[ -n "$soa_ns" ]]; then
        echo "$soa_ns" | grep -qiE '(cloudflare|awsdns|ultradns|route53)' || {
            local ips; ips=$(dig +short A "$soa_ns" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' || true)
            add_ips_from_var "$ips" "soa:$soa_ns"; }
    fi
    local ns_hosts; ns_hosts=$(dig +short NS "$DOMAIN" 2>/dev/null | sed 's/\.$//' || true)
    for nsh in $ns_hosts; do
        echo "$nsh" | grep -qiE '(cloudflare|awsdns|ultradns|akamai|dynect|nsone|route53|domaincontrol|registrar)' && continue
        local ips; ips=$(dig +short A "$nsh" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' || true)
        add_ips_from_var "$ips" "ns:$nsh"
    done
}

# ── Module 3: Deep passive subdomain enumeration ────────────────────────────
module_subdomains() {
    log "Module: Deep subdomain enumeration..."
    local sf="$TMPDIR_BASE/subs_raw.txt"; touch "$sf"
    local d="$DOMAIN"

    command -v subfinder &>/dev/null && subfinder -d "$d" -silent -all >> "$sf" 2>/dev/null || true

    log "  crt.sh..."
    curl -sf --max-time 30 "https://crt.sh/?q=%25.$d&output=json" 2>/dev/null | \
        jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//g' >> "$sf" || true

    log "  certspotter..."
    curl -sf --max-time 20 "https://api.certspotter.com/v1/issuances?domain=$d&include_subdomains=true&expand=dns_names" 2>/dev/null | \
        jq -r '.[].dns_names[]?' 2>/dev/null | sed 's/\*\.//g' >> "$sf" || true

    log "  anubis (jldc.me)..."
    curl -sf --max-time 15 "https://jldc.me/anubis/subdomains/$d" 2>/dev/null | \
        jq -r '.[]?' 2>/dev/null >> "$sf" || true

    log "  HackerTarget..."
    curl -sf --max-time 15 "https://api.hackertarget.com/hostsearch/?q=$d" 2>/dev/null | cut -d',' -f1 >> "$sf" || true

    log "  RapidDNS..."
    curl -sf --max-time 15 "https://rapiddns.io/subdomain/$d?full=1" 2>/dev/null | \
        grep -oP "[a-zA-Z0-9._-]+\\.${d//./\\.}" >> "$sf" || true

    log "  AlienVault OTX..."
    curl -sf --max-time 15 "https://otx.alienvault.com/api/v1/indicators/domain/$d/passive_dns" 2>/dev/null | \
        jq -r '.passive_dns[].hostname' 2>/dev/null >> "$sf" || true

    log "  ThreatCrowd..."
    curl -sf --max-time 15 "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=$d" 2>/dev/null | \
        jq -r '.subdomains[]?' 2>/dev/null >> "$sf" || true

    log "  URLScan.io..."
    curl -sf --max-time 15 "https://urlscan.io/api/v1/search/?q=domain:$d&size=100" 2>/dev/null | \
        jq -r '.results[].page.domain' 2>/dev/null >> "$sf" || true

    log "  Wayback Machine..."
    curl -sf --max-time 20 "http://web.archive.org/cdx/search/cdx?url=*.$d/*&output=text&fl=original&collapse=urlkey&limit=5000" 2>/dev/null | \
        awk -F/ '{print $3}' | sed 's/:.*//' | grep -oP "[a-zA-Z0-9._-]+\\.${d//./\\.}" >> "$sf" || true

    # Normalize: lowercase, strip ports, keep only in-scope
    grep -oiE "[a-z0-9._-]+\.${d//./\\.}" "$sf" 2>/dev/null | tr 'A-Z' 'a-z' | sort -u >> "$SUBS_FILE" || true
    sort -u -o "$SUBS_FILE" "$SUBS_FILE"
    ok "  Passive subdomains: $(wc -l < "$SUBS_FILE" | xargs)"
}

# ── Module 3b: Brute force + permutation depth ─────────────────────────────
module_subdomain_depth() {
    [[ $DO_BRUTE -eq 0 && $DO_DEEP -eq 0 ]] && return
    log "Module: Subdomain depth (brute / permutation)..."
    local gen="$TMPDIR_BASE/gen.txt"; touch "$gen"

    if [[ $DO_BRUTE -eq 1 ]]; then
        local words
        if [[ -n "$WORDLIST" && -f "$WORDLIST" ]]; then
            words=$(cat "$WORDLIST")
        else
            words="www mail webmail smtp imap pop ftp sftp ssh vpn remote portal
api api2 api-dev apidev dev dev2 develop development staging stage test testing
qa uat sandbox demo preprod prod production admin adminpanel administrator panel
cpanel whm plesk dashboard console manage management internal intranet corp
corporate gateway gw proxy edge lb loadbalancer origin origin-www backend
back office app apps application mobile m web web1 web2 www2 secure ssl
auth login sso oauth id identity account accounts user users customer
crm erp sap oracle db database mysql postgres mssql mongo redis cache
git gitlab github bitbucket jenkins ci cd build deploy jira confluence wiki
docs support help helpdesk status monitor monitoring grafana kibana
prometheus nagios zabbix elk splunk log logs syslog metrics
ns ns1 ns2 ns3 dns dns1 dns2 mx mx1 mx2 mail1 mail2 email
static assets cdn img images media video files download uploads storage s3
blog news shop store cart checkout payment pay billing invoice
old legacy new beta alpha v1 v2 v3 temp tmp bak backup archive
partner partners vendor vendors b2b b2c client clients extranet"
        fi
        log "  Brute-forcing $(echo "$words" | wc -w | xargs) prefixes..."
        for w in $words; do echo "${w}.${DOMAIN}" >> "$gen"; done
    fi

    if [[ $DO_DEEP -eq 1 && -s "$SUBS_FILE" ]]; then
        log "  Generating permutations of discovered subdomains..."
        local prefixes="dev test stage staging uat qa prod admin internal api old new backup"
        # take first labels of known subs and permute
        head -300 "$SUBS_FILE" | while IFS= read -r host; do
            local label="${host%%.$DOMAIN}"
            [[ "$label" == "$host" ]] && continue
            for p in $prefixes; do
                echo "${p}-${label}.${DOMAIN}" >> "$gen"
                echo "${p}.${label}.${DOMAIN}" >> "$gen"
            done
        done
    fi

    sort -u -o "$gen" "$gen"
    cat "$gen" >> "$SUBS_FILE"
    sort -u -o "$SUBS_FILE" "$SUBS_FILE"
    ok "  Candidate hostlist now: $(wc -l < "$SUBS_FILE" | xargs)"
}

# ── Module 3c: Resolve all subdomains (records provenance + live subs) ──────
module_resolve_subs() {
    log "Module: Resolving all subdomains (live-DNS provenance)..."
    [[ ! -s "$SUBS_FILE" ]] && { warn "  No subdomains to resolve."; return; }

    if command -v dnsx &>/dev/null; then
        # dnsx prints: host [1.2.3.4]
        dnsx -l "$SUBS_FILE" -a -resp -silent 2>/dev/null | while IFS= read -r line; do
            local host ip
            host=$(echo "$line" | awk '{print $1}')
            ip=$(echo "$line" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1)
            [[ -z "$host" || -z "$ip" ]] && continue
            echo "$host" >> "$LIVE_SUBS_FILE"
            printf '%s\t%s\n' "$ip" "subdomain:$host" >> "$CAND_TSV"
            echo "$ip" >> "$ALL_IPS_FILE"
        done
    else
        head -1500 "$SUBS_FILE" | while IFS= read -r host; do
            [[ -z "$host" ]] && continue
            local ips; ips=$(dig +short +time=2 +tries=1 A "$host" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' || true)
            [[ -z "$ips" ]] && continue
            echo "$host" >> "$LIVE_SUBS_FILE"
            for ip in $ips; do
                printf '%s\t%s\n' "$ip" "subdomain:$host" >> "$CAND_TSV"
                echo "$ip" >> "$ALL_IPS_FILE"
            done
        done
    fi
    [[ -f "$LIVE_SUBS_FILE" ]] && sort -u -o "$LIVE_SUBS_FILE" "$LIVE_SUBS_FILE"
    ok "  Live subdomains: $( [[ -f "$LIVE_SUBS_FILE" ]] && wc -l < "$LIVE_SUBS_FILE" | xargs || echo 0 )"
}

# ── Module 4: Historical DNS (passive — NOT auto-trusted, must verify) ─────
module_dns_history() {
    log "Module: Historical DNS records..."
    if [[ -n "$SECURITYTRAILS_KEY" ]]; then
        curl -sf --max-time 15 -H "APIKEY: $SECURITYTRAILS_KEY" \
            "https://api.securitytrails.com/v1/history/$DOMAIN/dns/a" 2>/dev/null | \
            jq -r '.records[].values[].ip' 2>/dev/null | while read -r ip; do
                printf '%s\t%s\n' "$ip" "history-securitytrails" >> "$CAND_TSV"; echo "$ip" >> "$ALL_IPS_FILE"; done || true
    fi
    if [[ -n "$VIEWDNS_KEY" ]]; then
        curl -sf --max-time 15 "https://api.viewdns.info/iphistory/?domain=$DOMAIN&apikey=$VIEWDNS_KEY&output=json" 2>/dev/null | \
            jq -r '.response.records[].ip' 2>/dev/null | while read -r ip; do
                printf '%s\t%s\n' "$ip" "history-viewdns" >> "$CAND_TSV"; echo "$ip" >> "$ALL_IPS_FILE"; done || true
    fi
}

# ── Module 5: Certificate Transparency → IPs (Censys) ──────────────────────
module_cert_transparency() {
    [[ -z "$CENSYS_CREDS" ]] && return
    log "Module: Censys certificate → host search..."
    local id="${CENSYS_CREDS%%:*}" sec="${CENSYS_CREDS#*:}"
    curl -sf --max-time 20 -u "$id:$sec" -H "Content-Type: application/json" \
        -d "{\"q\":\"services.tls.certificates.leaf.names: $DOMAIN\",\"per_page\":100}" \
        "https://search.censys.io/api/v2/hosts/search" 2>/dev/null | \
        jq -r '.result.hits[].ip' 2>/dev/null | while read -r ip; do
            printf '%s\t%s\n' "$ip" "censys-cert" >> "$CAND_TSV"; echo "$ip" >> "$ALL_IPS_FILE"; done || true
}

# ── Module 6: Shodan ────────────────────────────────────────────────────────
module_shodan() {
    [[ -z "$SHODAN_KEY" ]] && return
    log "Module: Shodan search..."
    local queries=("ssl:$DOMAIN" "hostname:$DOMAIN" "http.title:%22$DOMAIN%22")
    [[ -n "$ORG_NAME" ]] && queries+=("org:%22${ORG_NAME// /%20}%22")
    for q in "${queries[@]}"; do
        curl -sf --max-time 20 "https://api.shodan.io/shodan/host/search?key=$SHODAN_KEY&query=$q" 2>/dev/null | \
            jq -r '.matches[].ip_str' 2>/dev/null | while read -r ip; do
                printf '%s\t%s\n' "$ip" "shodan" >> "$CAND_TSV"; echo "$ip" >> "$ALL_IPS_FILE"; done || true
    done
}

# ── Module 7: Censys host search ────────────────────────────────────────────
module_censys() {
    [[ -z "$CENSYS_CREDS" ]] && return
    log "Module: Censys host search..."
    local id="${CENSYS_CREDS%%:*}" sec="${CENSYS_CREDS#*:}"
    curl -sf --max-time 20 -u "$id:$sec" -H "Content-Type: application/json" \
        -d "{\"q\":\"dns.names: $DOMAIN\",\"per_page\":100}" \
        "https://search.censys.io/api/v2/hosts/search" 2>/dev/null | \
        jq -r '.result.hits[].ip' 2>/dev/null | while read -r ip; do
            printf '%s\t%s\n' "$ip" "censys-host" >> "$CAND_TSV"; echo "$ip" >> "$ALL_IPS_FILE"; done || true
}

# ── Module 8: ASN / Netblock (GATED by strict org-name match) ──────────────
module_whois_asn() {
    [[ -z "$ORG_NAME" ]] && return
    log "Module: ASN / Netblock (org-name gated)..."
    command -v jq &>/dev/null || return

    # Build normalized org tokens for strict matching
    local org_norm; org_norm=$(echo "$ORG_NAME" | tr 'A-Z' 'a-z' | sed -E 's/\b(inc|llc|ltd|corp|corporation|company|co|gmbh|sa|ag|plc|group|holdings|technologies|technology|systems|solutions)\b//g' | tr -cd 'a-z0-9 ')
    local main_token; main_token=$(echo "$org_norm" | tr ' ' '\n' | awk 'length>=4' | head -1)
    [[ -z "$main_token" ]] && { warn "  Org token too short — skipping ASN dump to avoid FPs."; return; }

    local bgp; bgp=$(curl -sf --max-time 15 "https://api.bgpview.io/search?query_term=${ORG_NAME// /%20}" 2>/dev/null || echo "")
    [[ -z "$bgp" ]] && return

    # Only accept ASNs whose name/description actually contains the org token
    local asns
    asns=$(echo "$bgp" | jq -r --arg t "$main_token" \
        '.data.asns[]? | select((.name+" "+.description|ascii_downcase) | contains($t)) | .asn' 2>/dev/null || true)

    local pcount=0
    for asn in $asns; do
        vlog "  Org-matched ASN: AS$asn"
        local prefixes
        prefixes=$(curl -sf --max-time 15 "https://api.bgpview.io/asn/$asn/prefixes" 2>/dev/null | \
            jq -r --arg t "$main_token" \
            '.data.ipv4_prefixes[]? | select(((.name//"")+" "+(.description//"")+" "+((.parent.name)//"")|ascii_downcase)|contains($t)) | .prefix' 2>/dev/null || true)
        # If no per-prefix org text, fall back to all prefixes of the matched ASN
        [[ -z "$prefixes" ]] && prefixes=$(curl -sf --max-time 15 "https://api.bgpview.io/asn/$asn/prefixes" 2>/dev/null | jq -r '.data.ipv4_prefixes[]?.prefix' 2>/dev/null || true)
        for prefix in $prefixes; do
            # Only add gateway candidates; verification will confirm real ownership
            local net_ip="${prefix%/*}"
            IFS='.' read -r a b c d <<< "$net_ip"
            add_ip "$a.$b.$c.1" "asn-$asn:$prefix"
            ((pcount++)); [[ $pcount -ge 400 ]] && { warn "  ASN prefix cap reached"; break 2; }
        done
    done
}

# ── Module 9: HTTP header IP leaks ─────────────────────────────────────────
module_http_headers() {
    log "Module: HTTP header leak analysis..."
    for scheme in https http; do
        curl -sI --max-time 10 -L "$scheme://$DOMAIN" 2>/dev/null | \
            grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | while read -r ip; do
                printf '%s\t%s\n' "$ip" "header-leak" >> "$CAND_TSV"; echo "$ip" >> "$ALL_IPS_FILE"; done || true
    done
}

# ── Module 10: SecurityTrails current + associated ─────────────────────────
module_securitytrails_org() {
    [[ -z "$SECURITYTRAILS_KEY" ]] && return
    log "Module: SecurityTrails current/associated..."
    local st
    st=$(curl -sf --max-time 15 -H "APIKEY: $SECURITYTRAILS_KEY" "https://api.securitytrails.com/v1/domain/$DOMAIN" 2>/dev/null || echo "")
    if [[ -n "$st" ]] && command -v jq &>/dev/null; then
        echo "$st" | jq -r '.current_dns.a.values[].ip' 2>/dev/null | while read -r ip; do
            printf '%s\t%s\n' "$ip" "securitytrails-current" >> "$CAND_TSV"; echo "$ip" >> "$ALL_IPS_FILE"; done || true
    fi
}

# ── Module 11: Passive DNS (stale — verification mandatory) ─────────────────
module_passive_dns() {
    log "Module: Passive DNS sources..."
    curl -sf --max-time 15 "https://www.virustotal.com/ui/domains/$DOMAIN/resolutions?limit=40" 2>/dev/null | \
        jq -r '.data[]?.attributes?.ip_address // empty' 2>/dev/null | while read -r ip; do
            printf '%s\t%s\n' "$ip" "vt-pdns" >> "$CAND_TSV"; echo "$ip" >> "$ALL_IPS_FILE"; done || true
    curl -sf --max-time 15 "https://otx.alienvault.com/api/v1/indicators/domain/$DOMAIN/passive_dns" 2>/dev/null | \
        jq -r '.passive_dns[].address // empty' 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | while read -r ip; do
            printf '%s\t%s\n' "$ip" "otx-pdns" >> "$CAND_TSV"; echo "$ip" >> "$ALL_IPS_FILE"; done || true
}

# ============================================================================
# CONFIDENCE VERIFIER (Python) — the false-positive killer
# ============================================================================
write_verifier() {
    cat > "$VERIFY_SCRIPT" << 'PYEOF'
#!/usr/bin/env python3
"""
Multi-signal origin-IP confidence verifier.
Reads candidate IPs (with aggregated provenance sources), establishes a
baseline fingerprint of the real site, then scores each IP on independent
evidence that it truly belongs to the target domain/org. Emits confirmed IPs.
"""
import sys, os, re, ssl, socket, subprocess, ipaddress, hashlib, json
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import mmh3
    HAVE_MMH3 = True
except Exception:
    HAVE_MMH3 = False

# ---- args ----
DOMAIN   = sys.argv[1]
APEX     = sys.argv[2]
ORG      = sys.argv[3]
CDN_FILE = sys.argv[4]
CAND_TSV = sys.argv[5]
SCORED   = sys.argv[6]
THRESH   = int(sys.argv[7])
WORKERS  = int(sys.argv[8])

# ---- helpers ----
def run(cmd, inp=None, timeout=10):
    try:
        p = subprocess.run(cmd, input=inp, capture_output=True, timeout=timeout)
        return p.stdout
    except Exception:
        return b""

def load_cdn(path):
    nets = []
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line:
                    try: nets.append(ipaddress.ip_network(line, strict=False))
                    except ValueError: pass
    except FileNotFoundError:
        pass
    return nets

CDN = load_cdn(CDN_FILE)

def is_cdn(ip):
    try: a = ipaddress.ip_address(ip)
    except ValueError: return True
    if a.is_private or a.is_reserved or a.is_loopback or a.is_multicast or a.is_link_local:
        return True
    for n in CDN:
        if a in n: return True
    return False

def norm_tokens(s):
    s = (s or "").lower()
    s = re.sub(r'\b(inc|llc|ltd|corp|corporation|company|co|gmbh|sa|ag|plc|group|holdings|technologies|technology|systems|solutions|the|and)\b', ' ', s)
    return [t for t in re.split(r'[^a-z0-9]+', s) if len(t) >= 4]

ORG_TOKENS = set(norm_tokens(ORG)) if ORG else set()
# also treat the apex label as an org token (e.g. "example" from example.com)
apex_label = APEX.split('.')[0] if APEX else ""
if len(apex_label) >= 3:
    ORG_TOKENS.add(apex_label.lower())

def favhash(data):
    if not data: return None
    if HAVE_MMH3:
        import base64
        return str(mmh3.hash(base64.encodebytes(data)))
    return hashlib.md5(data).hexdigest()

def get_title(html):
    m = re.search(r'<title[^>]*>(.*?)</title>', html, re.I | re.S)
    return re.sub(r'\s+', ' ', m.group(1)).strip().lower() if m else ""

# ---- baseline fingerprint of the REAL site ----
def build_baseline():
    b = {"title": "", "fav": None, "sans": set(), "subj_o": "", "ok": False}
    html = run(["curl","-sk","-L","--max-time","15","https://"+DOMAIN+"/"], timeout=20).decode("utf-8","ignore")
    if not html:
        html = run(["curl","-s","-L","--max-time","15","http://"+DOMAIN+"/"], timeout=20).decode("utf-8","ignore")
    b["title"] = get_title(html)
    fav = run(["curl","-sk","-L","--max-time","10","https://"+DOMAIN+"/favicon.ico"], timeout=15)
    if fav and len(fav) > 60:
        b["fav"] = favhash(fav)
    sans, o = cert_of(DOMAIN, DOMAIN)
    b["sans"], b["subj_o"] = set(sans), o
    b["ok"] = bool(b["title"] or b["fav"] or b["sans"])
    return b

# ---- TLS cert grab from an endpoint (IP or host) via openssl ----
def cert_of(target, sni):
    out = run(["openssl","s_client","-connect",f"{target}:443","-servername",sni],
              inp=b"", timeout=9)
    if not out:
        return [], ""
    txt = run(["openssl","x509","-noout","-text"], inp=out, timeout=6).decode("utf-8","ignore")
    sans = [s.lower() for s in re.findall(r'DNS:([^,\s]+)', txt)]
    mo = re.search(r'Subject:.*?\bO\s*=\s*([^,/\n]+)', txt)
    subj_o = mo.group(1).strip().lower() if mo else ""
    return sans, subj_o

def san_matches(sans):
    dl = DOMAIN.lower(); al = APEX.lower()
    for s in sans:
        s = s.strip().lstrip('*.').lower()
        if s == dl or s == al or s.endswith('.'+al) or al.endswith('.'+s):
            return True
    return False

# ---- HTTP fetch of a candidate IP with Host header ----
def http_probe(ip):
    for scheme in ("https","http"):
        body = run(["curl","-s","-k","-L","--max-time","8","--connect-timeout","4",
                    "-H","Host: "+DOMAIN, f"{scheme}://{ip}/"], timeout=12)
        if body and body.strip():
            fav = run(["curl","-s","-k","-L","--max-time","8","--connect-timeout","4",
                       "-H","Host: "+DOMAIN, f"{scheme}://{ip}/favicon.ico"], timeout=12)
            return body.decode("utf-8","ignore"), (favhash(fav) if fav and len(fav)>60 else None), scheme
    return "", None, ""

def rdap_org(ip):
    txt = run(["whois", ip], timeout=10).decode("utf-8","ignore").lower()
    if not txt or "no match" in txt:
        j = run(["curl","-s","--max-time","8","https://rdap.org/ip/"+ip], timeout=10).decode("utf-8","ignore").lower()
        txt += " " + j
    return txt

def ptr_of(ip):
    return run(["dig","+short","+time=2","+tries=1","-x",ip], timeout=6).decode("utf-8","ignore").strip().lower()

# ---- score one IP ----
def score_ip(ip, sources, base):
    sig = []
    score = 0

    src_join = " ".join(sources)
    live_dns = re.search(r'(^|\s)(dns:|subdomain:|mx:|ns:|soa:|spf|securitytrails-current)', src_join) is not None
    if live_dns:
        score += 35; sig.append("live-dns+35")

    # TLS certificate
    sans, subj_o = cert_of(ip, DOMAIN)
    if sans and san_matches(sans):
        score += 45; sig.append("cert-san+45")
    if subj_o and ORG_TOKENS and any(t in subj_o for t in ORG_TOKENS):
        score += 30; sig.append("cert-org+30")

    # HTTP content
    html, fav, scheme = http_probe(ip)
    if scheme:
        score += 5; sig.append("alive+5")
        low = html.lower()
        if base["title"] and get_title(html) == base["title"]:
            score += 25; sig.append("title+25")
        if base["fav"] and fav and fav == base["fav"]:
            score += 35; sig.append("favicon+35")
        if ORG_TOKENS and any(t in low for t in ORG_TOKENS):
            score += 20; sig.append("body-org+20")
        if APEX.lower() in low:
            score += 15; sig.append("body-apex+15")

    # RDAP / WHOIS owner
    who = rdap_org(ip)
    if ORG_TOKENS and any(t in who for t in ORG_TOKENS):
        score += 30; sig.append("whois-org+30")

    # PTR
    ptr = ptr_of(ip)
    if ptr:
        if APEX.lower() in ptr:
            score += 25; sig.append("ptr-apex+25")
        elif ORG_TOKENS and any(t in ptr for t in ORG_TOKENS):
            score += 15; sig.append("ptr-org+15")

    tier = "HIGH" if score >= 80 else ("MEDIUM" if score >= THRESH else "REJECT")
    return ip, score, tier, sig

def main():
    # aggregate sources per ip
    cand = {}
    try:
        with open(CAND_TSV) as f:
            for line in f:
                parts = line.rstrip("\n").split("\t")
                if not parts or not parts[0]: continue
                ip = parts[0].strip()
                src = parts[1].strip() if len(parts) > 1 else "unknown"
                try: ipaddress.ip_address(ip)
                except ValueError: continue
                cand.setdefault(ip, set()).add(src)
    except FileNotFoundError:
        pass

    # drop CDN/private up front
    cand = {ip:s for ip,s in cand.items() if not is_cdn(ip)}
    sys.stderr.write(f"[*] Verifying {len(cand)} non-CDN candidates (threshold {THRESH})...\n")

    base = build_baseline()
    if not base["ok"]:
        sys.stderr.write("[!] Warning: could not fully fingerprint baseline site; relying on cert/whois/ptr.\n")

    results = []
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futs = {ex.submit(score_ip, ip, list(srcs), base): ip for ip, srcs in cand.items()}
        for fut in as_completed(futs):
            try:
                results.append(fut.result())
            except Exception:
                pass

    results.sort(key=lambda r: r[1], reverse=True)
    with open(SCORED, "w") as out:
        out.write("ip\tscore\ttier\tsignals\tsources\n")
        for ip, score, tier, sig in results:
            out.write(f"{ip}\t{score}\t{tier}\t{','.join(sig)}\t{','.join(sorted(cand[ip]))}\n")

    for ip, score, tier, sig in results:
        if score >= THRESH:
            print(ip)

if __name__ == "__main__":
    main()
PYEOF
    chmod +x "$VERIFY_SCRIPT"
}

run_verifier() {
    log "Running content-verification confidence engine..."
    if [[ ! -s "$CAND_TSV" ]]; then
        err "No candidates collected."
        return 1
    fi
    # Safety cap
    local ccount; ccount=$(cut -f1 "$CAND_TSV" | sort -u | wc -l | xargs)
    if [[ "$ccount" -gt "$MAX_CANDIDATES" ]]; then
        warn "Candidate count ($ccount) exceeds cap ($MAX_CANDIDATES); keeping DNS-derived + highest-signal first."
        # Prioritize live-dns provenance rows, then others, cap unique ips
        { grep -E $'\t'"(dns:|subdomain:|mx:|ns:|soa:|spf|securitytrails-current)" "$CAND_TSV";
          grep -vE $'\t'"(dns:|subdomain:|mx:|ns:|soa:|spf|securitytrails-current)" "$CAND_TSV"; } \
          > "$TMPDIR_BASE/cand_pri.tsv" 2>/dev/null || cp "$CAND_TSV" "$TMPDIR_BASE/cand_pri.tsv"
        awk -F'\t' -v cap="$MAX_CANDIDATES" '{ if(!seen[$1]){seen[$1]=1;n++} if(n<=cap) print }' \
          "$TMPDIR_BASE/cand_pri.tsv" > "$TMPDIR_BASE/cand_capped.tsv"
        cp "$TMPDIR_BASE/cand_capped.tsv" "$CAND_TSV"
    fi

    python3 "$VERIFY_SCRIPT" "$DOMAIN" "$APEX" "$ORG_NAME" "$CDN_RANGES_FILE" \
        "$CAND_TSV" "$SCORED_TSV" "$THRESHOLD" "$WORKERS" > "$CONFIRMED_FILE" 2>>"$TMPDIR_BASE/verify.log"
    cat "$TMPDIR_BASE/verify.log" 2>/dev/null | sed 's/^/    /' || true
    sort -u -o "$CONFIRMED_FILE" "$CONFIRMED_FILE"
}

# ============================================================================
# MAIN
# ============================================================================
main() {
    echo ""
    echo -e "${BOLD}╔══════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${BOLD}║  Origin IP Finder — Advanced Content-Verified v3         ║${RESET}"
    echo -e "${BOLD}╚══════════════════════════════════════════════════════════╝${RESET}"
    echo ""

    while getopts "d:o:t:j:w:k:c:s:v:f:bDVh" opt; do
        case "$opt" in
            d) DOMAIN="$OPTARG" ;;
            o) ORG_NAME="$OPTARG" ;;
            t) THRESHOLD="$OPTARG" ;;
            j) WORKERS="$OPTARG" ;;
            w) WORDLIST="$OPTARG" ;;
            k) SHODAN_KEY="$OPTARG" ;;
            c) CENSYS_CREDS="$OPTARG" ;;
            s) SECURITYTRAILS_KEY="$OPTARG" ;;
            v) VIEWDNS_KEY="$OPTARG" ;;
            f) OUTPUT_FILE="$OPTARG" ;;
            b) DO_BRUTE=1 ;;
            D) DO_DEEP=1 ;;
            V) VERBOSE=1 ;;
            h) usage ;;
            *) usage ;;
        esac
    done

    [[ -z "$DOMAIN" ]] && { err "Domain is required. Use -d <domain>"; usage; }

    DOMAIN=$(echo "$DOMAIN" | sed 's|https\?://||;s|/.*||;s|^www\.||')
    # crude apex (last two labels) — override with -o awareness not needed
    APEX=$(echo "$DOMAIN" | awk -F. '{if(NF>=2) print $(NF-1)"."$NF; else print $0}')
    [[ -z "$OUTPUT_FILE" ]] && OUTPUT_FILE="${DOMAIN//\./_}_ips.txt"
    local SCORED_OUT="${OUTPUT_FILE%.txt}_scored.tsv"
    local SUBS_OUTPUT="${DOMAIN//\./_}_subdomains.txt"
    local LIVE_OUTPUT="${DOMAIN//\./_}_live_subdomains.txt"

    log "Target domain : $DOMAIN"
    log "Apex domain   : $APEX"
    [[ -n "$ORG_NAME" ]] && log "Organization  : $ORG_NAME"
    log "Threshold     : $THRESHOLD   Concurrency: $WORKERS   Brute:$DO_BRUTE Deep:$DO_DEEP"
    echo ""

    touch "$ALL_IPS_FILE" "$CAND_TSV" "$SUBS_FILE" "$LIVE_SUBS_FILE"
    install_deps
    detect_org_name
    build_cdn_ranges
    write_verifier

    echo ""
    log "Phase 1 — Enumeration"
    echo "──────────────────────────────────────────────────────────"
    module_dns_direct
    module_dns_records
    module_subdomains
    module_subdomain_depth
    module_resolve_subs
    module_dns_history
    module_cert_transparency
    module_shodan
    module_censys
    module_whois_asn
    module_http_headers
    module_securitytrails_org
    module_passive_dns
    echo "──────────────────────────────────────────────────────────"
    echo ""

    if [[ ! -s "$CAND_TSV" ]]; then
        err "No candidate IPs collected — check connectivity / domain validity."
        exit 1
    fi
    log "Phase 2 — Verification"
    echo "──────────────────────────────────────────────────────────"
    run_verifier
    echo "──────────────────────────────────────────────────────────"
    echo ""

    # ── Save subdomains ──
    if [[ -s "$SUBS_FILE" ]]; then
        sort -u -o "$SUBS_FILE" "$SUBS_FILE"; cp "$SUBS_FILE" "$SUBS_OUTPUT"
    fi
    if [[ -s "$LIVE_SUBS_FILE" ]]; then
        sort -u -o "$LIVE_SUBS_FILE" "$LIVE_SUBS_FILE"; cp "$LIVE_SUBS_FILE" "$LIVE_OUTPUT"
    fi
    [[ -s "$SCORED_TSV" ]] && cp "$SCORED_TSV" "$SCORED_OUT"

    # ── Report ──
    local total_cand; total_cand=$(cut -f1 "$CAND_TSV" | sort -u | wc -l | xargs)
    if [[ -s "$CONFIRMED_FILE" ]]; then
        local n; n=$(wc -l < "$CONFIRMED_FILE" | xargs)
        cp "$CONFIRMED_FILE" "$OUTPUT_FILE"
        echo -e "${BOLD}══════════════════════════════════════════════════════════${RESET}"
        echo -e "${GREEN}${BOLD} CONFIRMED TRUE-POSITIVE ORIGIN IPs ($n / $total_cand candidates):${RESET}"
        echo -e "${BOLD}══════════════════════════════════════════════════════════${RESET}"
        echo ""
        # show with score/tier from scored table
        while IFS= read -r ip; do
            local row; row=$(grep -P "^${ip//./\\.}\t" "$SCORED_TSV" 2>/dev/null | head -1)
            local sc tier sigs
            sc=$(echo "$row" | cut -f2); tier=$(echo "$row" | cut -f3); sigs=$(echo "$row" | cut -f4)
            printf "  %-16s  score=%-3s  %-6s  %s\n" "$ip" "$sc" "$tier" "$sigs"
        done < "$CONFIRMED_FILE"
        echo ""
        ok "Confirmed IPs      : $OUTPUT_FILE  (naabu-ready)"
        ok "Full scored audit  : $SCORED_OUT"
        [[ -s "$SUBS_OUTPUT" ]]  && ok "All subdomains     : $SUBS_OUTPUT ($(wc -l < "$SUBS_OUTPUT" | xargs))"
        [[ -s "$LIVE_OUTPUT" ]]  && ok "Live subdomains    : $LIVE_OUTPUT ($(wc -l < "$LIVE_OUTPUT" | xargs))"
        echo ""
        ok "Next: naabu -list $OUTPUT_FILE -top-ports 1000 -silent"
    else
        warn "No candidates reached the confidence threshold ($THRESHOLD)."
        warn "Review the full scored table to lower the bar or inspect near-misses:"
        [[ -s "$SCORED_TSV" ]] && { echo ""; head -20 "$SCORED_TSV" | column -t -s $'\t' 2>/dev/null || head -20 "$SCORED_TSV"; }
        [[ -s "$SCORED_TSV" ]] && cp "$SCORED_TSV" "$SCORED_OUT" && { echo ""; ok "Scored audit saved: $SCORED_OUT"; }
        echo ""
        warn "Tip: lower -t (e.g. -t 30), or add -k/-c/-s API keys for more evidence."
    fi
    echo ""
}

main "$@"
