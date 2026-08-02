#!/bin/bash
# ============================================================================
# origin-ip-finder-pro.sh — v4 (Evidence-Verified, High-Precision)
# ============================================================================
# Discovers the REAL origin IPv4 addresses of a domain / organization that sit
# behind CDN/WAF, with an aggressive false-positive-elimination engine.
#
# WHY v4 beats naive origin finders:
#   Most tools confirm an origin on a single weak signal (matching <title>,
#   favicon, or "the domain string appears on the page"). Those produce heavy
#   false positives. v4 instead demands *site-specific* proof that the IP
#   serves THIS application, using an evidence-tiered decision engine:
#
#   DEFINITIVE proof (any one confirms):
#     • Candidate presents the SAME TLS certificate (SHA-256 fingerprint) as
#       the CDN edge — origins reuse their cert.
#     • Candidate page contains the SAME unique build artifacts as the real
#       site: analytics IDs (UA-/G-/GTM-), content-hashed JS/CSS bundle names.
#     • Cert SAN matches the domain AND the IP serves matching live content.
#     • Structural content similarity (shingled Jaccard) is very high AND the
#       page is not a default/parking page.
#
#   Anti-false-positive guards:
#     • Default-server / parking-page detection (nginx/apache/IIS/"for sale").
#     • Catch-all vhost detection (serves identical content for a random Host).
#     • Word-boundary org matching (not loose substring).
#     • Shared-hoster awareness (WHOIS "Amazon/OVH/DO" never confirms alone).
#     • Synthetic ASN IPs removed — org netblocks become a *scoring booster*
#       and a separate scannable CIDR file, not injected fake candidates.
#     • DNS wildcard detection prunes brute-force noise.
#     • TCP pre-liveness skips dead IPs for speed.
#
# Outputs:
#   <domain>_ips.txt              CONFIRMED origin IPs (high precision, naabu-ready)
#   <domain>_ips_likely.txt       LIKELY IPs (needs a human glance)
#   <domain>_ips_scored.tsv       full audit: score / verdict / evidence / sources
#   <domain>_subdomains.txt       all discovered subdomains
#   <domain>_live_subdomains.txt  subdomains resolving to an A record
#   <domain>_org_ranges.txt       org-owned CIDRs (optional: naabu -cidr these)
#
# Authorized security research / bug bounty use only.
# ============================================================================

set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

# ── Config / globals ────────────────────────────────────────────────────────
DOMAIN=""; APEX=""; ORG_NAME=""
SHODAN_KEY=""; CENSYS_CREDS=""; SECURITYTRAILS_KEY=""; VIEWDNS_KEY=""
OUTPUT_FILE=""; WORDLIST=""
WORKERS=30
DO_BRUTE=0; DO_DEEP=0
MAX_CANDIDATES=6000
VERBOSE=0

TMPDIR_BASE=$(mktemp -d /tmp/originpro.XXXXXX)
ALL_IPS_FILE="$TMPDIR_BASE/all_ips.txt"
CAND_TSV="$TMPDIR_BASE/candidates.tsv"
CONFIRMED_FILE="$TMPDIR_BASE/confirmed.txt"
LIKELY_FILE="$TMPDIR_BASE/likely.txt"
SCORED_TSV="$TMPDIR_BASE/scored.tsv"
CDN_RANGES_FILE="$TMPDIR_BASE/cdn_ranges.txt"
ORG_PREFIXES="$TMPDIR_BASE/org_prefixes.txt"
WILDCARD_FILE="$TMPDIR_BASE/wildcard_ips.txt"
SUBS_FILE="$TMPDIR_BASE/all_subdomains.txt"
LIVE_SUBS_FILE="$TMPDIR_BASE/live_subdomains.txt"
VERIFY_SCRIPT="$TMPDIR_BASE/verify.py"

trap 'rm -rf "$TMPDIR_BASE"' EXIT

declare -a KNOWN_CDN_PREFIXES=(
    "173.245.48.0/20" "103.21.244.0/22" "103.22.200.0/22" "103.31.4.0/22"
    "141.101.64.0/18" "108.162.192.0/18" "190.93.240.0/20" "188.114.96.0/20"
    "197.234.240.0/22" "198.41.128.0/17" "162.158.0.0/15" "104.16.0.0/13"
    "104.24.0.0/14" "172.64.0.0/13" "131.0.72.0/22"
    "52.84.0.0/14" "54.182.0.0/16" "54.192.0.0/16" "54.230.0.0/16"
    "54.239.128.0/18" "54.239.192.0/19" "54.240.128.0/18" "99.84.0.0/16"
    "143.204.0.0/16" "204.246.164.0/22" "204.246.168.0/22" "205.251.249.0/24"
    "205.251.250.0/23" "205.251.252.0/23" "205.251.254.0/24"
    "216.137.32.0/19" "13.32.0.0/15" "13.35.0.0/16" "13.224.0.0/14"
    "13.249.0.0/16" "18.64.0.0/14" "18.68.0.0/16" "18.154.0.0/15"
    "18.160.0.0/15" "18.164.0.0/15" "18.172.0.0/15" "18.238.0.0/15"
    "3.160.0.0/14" "3.164.0.0/18" "3.168.0.0/14" "3.172.0.0/18"
    "23.235.32.0/20" "43.249.72.0/22" "103.244.50.0/24" "103.245.222.0/23"
    "103.245.224.0/24" "104.156.80.0/20" "140.248.64.0/18" "140.248.128.0/17"
    "146.75.0.0/17" "151.101.0.0/16" "157.52.64.0/18" "167.82.0.0/17"
    "167.82.128.0/20" "167.82.160.0/20" "167.82.224.0/20" "172.111.64.0/18"
    "185.31.16.0/22" "199.27.72.0/21" "199.232.0.0/16"
    "72.246.0.0/15" "96.16.0.0/15" "96.6.0.0/15" "184.24.0.0/13"
    "184.50.0.0/15" "184.84.0.0/14" "2.16.0.0/13" "95.100.0.0/15"
    "92.122.0.0/15" "23.0.0.0/12" "23.32.0.0/11" "23.64.0.0/14" "23.72.0.0/13"
    "192.88.134.0/23" "185.93.228.0/22" "66.248.200.0/22"
    "151.139.0.0/16" "199.250.192.0/18"
    "199.83.128.0/21" "198.143.32.0/19" "149.126.72.0/21" "103.28.248.0/22"
    "45.64.64.0/22" "107.154.0.0/16" "45.60.0.0/16"
    "68.232.32.0/20" "117.18.232.0/21" "116.206.186.0/24" "199.247.16.0/21"
    "76.76.21.0/24" "104.198.14.0/24"
)

log()  { echo -e "${CYAN}[*]${RESET} $*"; }
ok()   { echo -e "${GREEN}[+]${RESET} $*"; }
warn() { echo -e "${YELLOW}[!]${RESET} $*"; }
err()  { echo -e "${RED}[-]${RESET} $*" >&2; }
vlog() { [[ $VERBOSE -eq 1 ]] && echo -e "${CYAN}[v]${RESET} $*" || true; }

usage() {
    cat <<EOF
${BOLD}Origin IP Finder PRO v4 — Evidence-Verified True-Positive Enumerator${RESET}

Usage: $0 -d <domain> [options]

Required:
  -d  Target domain

Optional:
  -o  Organization name (auto-detected from whois if omitted)
  -b  DNS brute-force common subdomains
  -D  Deep permutation enumeration
  -j  Verifier concurrency (default $WORKERS)
  -w  Custom brute wordlist
  -k  Shodan API key      -c Censys ID:SECRET
  -s  SecurityTrails key   -v ViewDNS key
  -f  Confirmed IP output file (default <domain>_ips.txt)
  -V  Verbose      -h Help

Verdicts:
  CONFIRMED  site-specific proof (cert-fp / unique build assets / cert-SAN+content
             / very-high content similarity). Goes to <domain>_ips.txt.
  LIKELY     one strong-but-not-conclusive signal. Goes to <domain>_ips_likely.txt.
  REJECT     no site-specific evidence, default/parking page, or different site.

Example:
  $0 -d example.com -o "Example Inc" -b -D -k \$SHODAN_KEY
  naabu -list example_com_ips.txt -top-ports 1000 -silent
EOF
    exit 0
}

# ── Candidate recording ─────────────────────────────────────────────────────
add_ip() {
    local ip="$1"; local source="${2:-unknown}"
    if [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        echo "$ip" >> "$ALL_IPS_FILE"
        printf '%s\t%s\n' "$ip" "$source" >> "$CAND_TSV"
        vlog "  candidate: $ip ($source)"
    fi
}
add_ips_from_var() { local ips="$1" source="$2" ip; for ip in $ips; do add_ip "$ip" "$source"; done; }

install_deps() {
    log "Checking dependencies..."
    local PKG=""
    command -v apt-get &>/dev/null && PKG="apt-get"
    [[ -z "$PKG" ]] && command -v dnf &>/dev/null && PKG="dnf"
    [[ -z "$PKG" ]] && command -v yum &>/dev/null && PKG="yum"
    [[ -z "$PKG" ]] && command -v pacman &>/dev/null && PKG="pacman"
    [[ -z "$PKG" ]] && command -v brew &>/dev/null && PKG="brew"
    for cmd in dig whois curl jq python3 openssl; do
        command -v "$cmd" &>/dev/null && continue
        case "$cmd" in
            dig) case "$PKG" in
                    apt-get) sudo apt-get install -y dnsutils 2>/dev/null||true;;
                    dnf|yum) sudo $PKG install -y bind-utils 2>/dev/null||true;;
                    pacman) sudo pacman -S --noconfirm bind-tools 2>/dev/null||true;;
                    brew) brew install bind 2>/dev/null||true;; esac;;
            *) [[ -n "$PKG" ]] && sudo $PKG install -y "$cmd" 2>/dev/null||true;;
        esac
    done
    if command -v go &>/dev/null; then
        for t in subfinder dnsx httpx; do
            command -v "$t" &>/dev/null && continue
            warn "Installing $t..."
            case "$t" in
                subfinder) go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null||true;;
                dnsx) go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest 2>/dev/null||true;;
                httpx) go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest 2>/dev/null||true;;
            esac
        done
    fi
    command -v pip3 &>/dev/null && { pip3 install mmh3 --quiet --break-system-packages 2>/dev/null || pip3 install mmh3 --quiet 2>/dev/null || true; }
    ok "Dependencies ready."
}

detect_org_name() {
    [[ -n "$ORG_NAME" ]] && return
    command -v whois &>/dev/null || return
    log "Auto-detecting org from whois..."
    ORG_NAME=$(whois "$DOMAIN" 2>/dev/null | grep -iE "^(Org(anization)?(-Name)?|OrgName|Registrant Organization)" | head -1 | sed 's/^[^:]*:\s*//' | xargs 2>/dev/null || true)
    [[ -n "$ORG_NAME" ]] && ok "Org: $ORG_NAME" || warn "No org name; pass -o for best precision."
}

build_cdn_ranges() {
    log "Building CDN/WAF range DB..."
    printf '%s\n' "${KNOWN_CDN_PREFIXES[@]}" > "$CDN_RANGES_FILE"
    curl -sf --max-time 10 "https://www.cloudflare.com/ips-v4" >> "$CDN_RANGES_FILE" 2>/dev/null||true
    local aws; aws=$(curl -sf --max-time 15 "https://ip-ranges.amazonaws.com/ip-ranges.json" 2>/dev/null||echo "")
    [[ -n "$aws" ]] && command -v jq &>/dev/null && echo "$aws" | jq -r '.prefixes[]|select(.service=="CLOUDFRONT")|.ip_prefix' >> "$CDN_RANGES_FILE" 2>/dev/null||true
    local fa; fa=$(curl -sf --max-time 10 "https://api.fastly.com/public-ip-list" 2>/dev/null||echo "")
    [[ -n "$fa" ]] && command -v jq &>/dev/null && echo "$fa" | jq -r '.addresses[]' >> "$CDN_RANGES_FILE" 2>/dev/null||true
    sort -u -o "$CDN_RANGES_FILE" "$CDN_RANGES_FILE"
    ok "Loaded $(wc -l < "$CDN_RANGES_FILE"|xargs) CDN/WAF ranges."
}

# ── Wildcard DNS detection (prunes brute-force noise) ───────────────────────
detect_wildcard() {
    command -v dig &>/dev/null || return
    log "Detecting DNS wildcard..."
    local r1 r2
    r1=$(dig +short A "zzq7x9nope-$RANDOM.$DOMAIN" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' || true)
    r2=$(dig +short A "qqw31mnope-$RANDOM.$DOMAIN" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' || true)
    { echo "$r1"; echo "$r2"; } | grep -E '[0-9]' | sort -u > "$WILDCARD_FILE" 2>/dev/null || true
    if [[ -s "$WILDCARD_FILE" ]]; then
        warn "Wildcard DNS present ($(wc -l < "$WILDCARD_FILE"|xargs) IPs) — brute hits to these are downweighted."
    fi
}

# ============================================================================
# ENUMERATION
# ============================================================================
module_dns_direct() {
    log "Direct DNS resolution..."; command -v dig &>/dev/null || return
    local subs=("" "www" "mail" "ftp" "direct" "origin" "origin-www" "server"
        "host" "cpanel" "webmail" "smtp" "imap" "mx" "api" "dev" "staging"
        "stage" "test" "uat" "admin" "panel" "old" "legacy" "backup" "vpn"
        "remote" "portal" "crm" "erp" "intranet" "internal" "gateway" "proxy"
        "app" "web" "ns1" "ns2" "mail2" "exchange" "owa" "autodiscover" "git"
        "gitlab" "jenkins" "jira" "confluence" "monitor" "grafana" "db")
    for sub in "${subs[@]}"; do
        local target; [[ -z "$sub" ]] && target="$DOMAIN" || target="${sub}.${DOMAIN}"
        local ips; ips=$(dig +short +time=3 +tries=1 A "$target" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' || true)
        [[ -z "$ips" ]] && continue
        [[ -n "$sub" ]] && echo "${target,,}" >> "$SUBS_FILE"
        # apex/www get stronger provenance tag
        if [[ -z "$sub" || "$sub" == "www" ]]; then
            add_ips_from_var "$ips" "dns-apex:$target"
        else
            add_ips_from_var "$ips" "dns:$target"
        fi
    done
}

module_dns_records() {
    log "MX/SPF/NS/SOA analysis..."; command -v dig &>/dev/null || return
    local mx; mx=$(dig +short MX "$DOMAIN" 2>/dev/null | awk '{print $2}' | sed 's/\.$//' || true)
    for h in $mx; do
        echo "$h" | grep -qiE '(google|outlook|microsoft|protonmail|zoho|mimecast|pphosted|messagelabs)' && continue
        add_ips_from_var "$(dig +short A "$h" 2>/dev/null | grep -oE '[0-9.]+' || true)" "mx:$h"
    done
    local spf; spf=$(dig +short TXT "$DOMAIN" 2>/dev/null | tr -d '"' | grep -i 'v=spf1' || true)
    if [[ -n "$spf" ]]; then
        for e in $(echo "$spf" | grep -oE 'ip4:[0-9.]+(/[0-9]+)?' | cut -d: -f2); do
            [[ "$e" == */* ]] && add_ip "${e%/*}" "spf-cidr:$e" || add_ip "$e" "spf"
        done
    fi
    local soa; soa=$(dig +short SOA "$DOMAIN" 2>/dev/null | awk '{print $1}' | sed 's/\.$//' || true)
    [[ -n "$soa" ]] && ! echo "$soa" | grep -qiE '(cloudflare|awsdns|ultradns|route53)' && \
        add_ips_from_var "$(dig +short A "$soa" 2>/dev/null | grep -oE '[0-9.]+' || true)" "soa:$soa"
}

module_subdomains() {
    log "Deep passive subdomain enumeration..."
    local sf="$TMPDIR_BASE/subs_raw.txt"; touch "$sf"; local d="$DOMAIN"
    command -v subfinder &>/dev/null && subfinder -d "$d" -silent -all >> "$sf" 2>/dev/null||true
    log "  crt.sh"; curl -sf --max-time 30 "https://crt.sh/?q=%25.$d&output=json" 2>/dev/null | jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//g' >> "$sf"||true
    log "  certspotter"; curl -sf --max-time 20 "https://api.certspotter.com/v1/issuances?domain=$d&include_subdomains=true&expand=dns_names" 2>/dev/null | jq -r '.[].dns_names[]?' 2>/dev/null | sed 's/\*\.//g' >> "$sf"||true
    log "  anubis"; curl -sf --max-time 15 "https://jldc.me/anubis/subdomains/$d" 2>/dev/null | jq -r '.[]?' 2>/dev/null >> "$sf"||true
    log "  hackertarget"; curl -sf --max-time 15 "https://api.hackertarget.com/hostsearch/?q=$d" 2>/dev/null | cut -d',' -f1 >> "$sf"||true
    log "  rapiddns"; curl -sf --max-time 15 "https://rapiddns.io/subdomain/$d?full=1" 2>/dev/null | grep -oP "[a-zA-Z0-9._-]+\\.${d//./\\.}" >> "$sf"||true
    log "  otx"; curl -sf --max-time 15 "https://otx.alienvault.com/api/v1/indicators/domain/$d/passive_dns" 2>/dev/null | jq -r '.passive_dns[].hostname' 2>/dev/null >> "$sf"||true
    log "  wayback"; curl -sf --max-time 20 "http://web.archive.org/cdx/search/cdx?url=*.$d/*&output=text&fl=original&collapse=urlkey&limit=5000" 2>/dev/null | awk -F/ '{print $3}' | sed 's/:.*//' | grep -oP "[a-zA-Z0-9._-]+\\.${d//./\\.}" >> "$sf"||true
    log "  threatcrowd"; curl -sf --max-time 15 "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=$d" 2>/dev/null | jq -r '.subdomains[]?' 2>/dev/null >> "$sf"||true
    log "  urlscan"; curl -sf --max-time 15 "https://urlscan.io/api/v1/search/?q=domain:$d&size=1000" 2>/dev/null | jq -r '.results[].page.domain' 2>/dev/null >> "$sf"||true
    log "  threatminer"; curl -sf --max-time 15 "https://api.threatminer.org/v2/domain.php?q=$d&rt=5" 2>/dev/null | jq -r '.results[]?' 2>/dev/null >> "$sf"||true
    log "  commoncrawl"; local ccidx; ccidx=$(curl -sf --max-time 15 "https://index.commoncrawl.org/collinfo.json" 2>/dev/null | jq -r '.[0].id' 2>/dev/null||echo ""); \
        [[ -n "$ccidx" ]] && curl -sf --max-time 30 "https://index.commoncrawl.org/${ccidx}-index?url=*.$d&output=json" 2>/dev/null | jq -r '.url' 2>/dev/null | awk -F/ '{print $3}' | sed 's/:.*//' >> "$sf"||true
    if [[ -n "${FULLHUNT_KEY:-}" ]]; then
        log "  fullhunt"; curl -sf --max-time 15 -H "X-API-KEY: $FULLHUNT_KEY" "https://fullhunt.io/api/v1/domain/$d/subdomains" 2>/dev/null | jq -r '.hosts[]?' 2>/dev/null >> "$sf"||true
    fi
    grep -oiE "[a-z0-9._-]+\.${d//./\\.}" "$sf" 2>/dev/null | tr 'A-Z' 'a-z' >> "$SUBS_FILE"||true
    sort -u -o "$SUBS_FILE" "$SUBS_FILE"
    ok "  Passive subdomains: $(wc -l < "$SUBS_FILE"|xargs)"
}

module_subdomain_depth() {
    [[ $DO_BRUTE -eq 0 && $DO_DEEP -eq 0 ]] && return
    log "Brute / permutation depth..."
    local gen="$TMPDIR_BASE/gen.txt"; touch "$gen"
    if [[ $DO_BRUTE -eq 1 ]]; then
        local words
        if [[ -n "$WORDLIST" && -f "$WORDLIST" ]]; then words=$(cat "$WORDLIST")
        else words="www mail webmail smtp imap ftp sftp ssh vpn remote portal api api2
apidev dev dev2 develop development staging stage test qa uat sandbox demo preprod
prod production admin panel cpanel dashboard console manage internal intranet corp
gateway proxy edge lb origin origin-www backend office app apps mobile secure ssl
auth login sso oauth id account crm erp db database mysql postgres mongo redis git
gitlab jenkins ci jira confluence wiki docs support status monitor grafana kibana
ns ns1 ns2 dns mx mx1 mx2 mail1 mail2 static assets cdn img media files storage
blog news shop store old legacy new beta v1 v2 temp bak backup partner vendor b2b extranet"; fi
        for w in $words; do echo "${w}.${DOMAIN}" >> "$gen"; done
    fi
    if [[ $DO_DEEP -eq 1 && -s "$SUBS_FILE" ]]; then
        local pre="dev test stage staging uat qa prod admin internal api old new"
        head -300 "$SUBS_FILE" | while IFS= read -r host; do
            local label="${host%%.$DOMAIN}"; [[ "$label" == "$host" ]] && continue
            for p in $pre; do echo "${p}-${label}.${DOMAIN}" >> "$gen"; echo "${p}.${label}.${DOMAIN}" >> "$gen"; done
        done
    fi
    sort -u "$gen" >> "$SUBS_FILE"; sort -u -o "$SUBS_FILE" "$SUBS_FILE"
    ok "  Hostlist now: $(wc -l < "$SUBS_FILE"|xargs)"
}

module_resolve_subs() {
    log "Resolving subdomains (live-DNS provenance)..."; [[ -s "$SUBS_FILE" ]] || { warn "  none"; return; }
    local mapfile_="$TMPDIR_BASE/host_ip.txt"; : > "$mapfile_"
    if command -v dnsx &>/dev/null; then
        dnsx -l "$SUBS_FILE" -a -resp -silent 2>/dev/null | while IFS= read -r line; do
            local host ip; host=$(echo "$line"|awk '{print $1}'); ip=$(echo "$line"|grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'|head -1)
            [[ -z "$host" || -z "$ip" ]] && continue
            printf '%s\t%s\n' "$host" "$ip" >> "$mapfile_"
        done
    else
        head -2000 "$SUBS_FILE" | while IFS= read -r host; do
            [[ -z "$host" ]] && continue
            for ip in $(dig +short +time=2 +tries=1 A "$host" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'); do
                printf '%s\t%s\n' "$host" "$ip" >> "$mapfile_"
            done
        done
    fi
    # record live subs + candidates (wildcard-only hosts downweighted)
    while IFS=$'\t' read -r host ip; do
        [[ -z "$host" || -z "$ip" ]] && continue
        echo "$host" >> "$LIVE_SUBS_FILE"
        if [[ -s "$WILDCARD_FILE" ]] && grep -qx "$ip" "$WILDCARD_FILE"; then
            printf '%s\t%s\n' "$ip" "wildcard:$host" >> "$CAND_TSV"
        else
            printf '%s\t%s\n' "$ip" "subdomain:$host" >> "$CAND_TSV"
        fi
        echo "$ip" >> "$ALL_IPS_FILE"
    done < "$mapfile_"
    [[ -f "$LIVE_SUBS_FILE" ]] && sort -u -o "$LIVE_SUBS_FILE" "$LIVE_SUBS_FILE"
    ok "  Live subdomains: $([[ -f "$LIVE_SUBS_FILE" ]] && wc -l < "$LIVE_SUBS_FILE"|xargs || echo 0)"
}

module_dns_history() {
    log "Historical DNS..."
    [[ -n "$SECURITYTRAILS_KEY" ]] && curl -sf --max-time 15 -H "APIKEY: $SECURITYTRAILS_KEY" "https://api.securitytrails.com/v1/history/$DOMAIN/dns/a" 2>/dev/null | jq -r '.records[].values[].ip' 2>/dev/null | while read -r ip; do printf '%s\thistory-st\n' "$ip">>"$CAND_TSV"; echo "$ip">>"$ALL_IPS_FILE"; done||true
    [[ -n "$VIEWDNS_KEY" ]] && curl -sf --max-time 15 "https://api.viewdns.info/iphistory/?domain=$DOMAIN&apikey=$VIEWDNS_KEY&output=json" 2>/dev/null | jq -r '.response.records[].ip' 2>/dev/null | while read -r ip; do printf '%s\thistory-viewdns\n' "$ip">>"$CAND_TSV"; echo "$ip">>"$ALL_IPS_FILE"; done||true
}

module_cert_transparency() {
    [[ -z "$CENSYS_CREDS" ]] && return; log "Censys cert→host..."
    local id="${CENSYS_CREDS%%:*}" sec="${CENSYS_CREDS#*:}"
    curl -sf --max-time 20 -u "$id:$sec" -H "Content-Type: application/json" -d "{\"q\":\"services.tls.certificates.leaf.names: $DOMAIN\",\"per_page\":100}" "https://search.censys.io/api/v2/hosts/search" 2>/dev/null | jq -r '.result.hits[].ip' 2>/dev/null | while read -r ip; do printf '%s\tcensys-cert\n' "$ip">>"$CAND_TSV"; echo "$ip">>"$ALL_IPS_FILE"; done||true
}

module_shodan() {
    [[ -z "$SHODAN_KEY" ]] && return; log "Shodan..."
    local qs=("ssl:$DOMAIN" "hostname:$DOMAIN" "http.title:%22$DOMAIN%22")
    [[ -n "$ORG_NAME" ]] && qs+=("org:%22${ORG_NAME// /%20}%22")
    for q in "${qs[@]}"; do
        curl -sf --max-time 20 "https://api.shodan.io/shodan/host/search?key=$SHODAN_KEY&query=$q" 2>/dev/null | jq -r '.matches[].ip_str' 2>/dev/null | while read -r ip; do printf '%s\tshodan\n' "$ip">>"$CAND_TSV"; echo "$ip">>"$ALL_IPS_FILE"; done||true
    done
}

module_censys() {
    [[ -z "$CENSYS_CREDS" ]] && return; log "Censys host..."
    local id="${CENSYS_CREDS%%:*}" sec="${CENSYS_CREDS#*:}"
    curl -sf --max-time 20 -u "$id:$sec" -H "Content-Type: application/json" -d "{\"q\":\"dns.names: $DOMAIN\",\"per_page\":100}" "https://search.censys.io/api/v2/hosts/search" 2>/dev/null | jq -r '.result.hits[].ip' 2>/dev/null | while read -r ip; do printf '%s\tcensys-host\n' "$ip">>"$CAND_TSV"; echo "$ip">>"$ALL_IPS_FILE"; done||true
}

# ── Org ASN ranges → scoring booster + scannable CIDRs (NO synthetic IPs) ───
module_org_ranges() {
    [[ -z "$ORG_NAME" ]] && return; command -v jq &>/dev/null || return
    log "Org ASN / netblock discovery (booster, not candidates)..."
    local org_norm; org_norm=$(echo "$ORG_NAME"|tr 'A-Z' 'a-z'|sed -E 's/\b(inc|llc|ltd|corp|corporation|company|co|gmbh|sa|ag|plc|group|holdings|technologies|technology|systems|solutions)\b//g'|tr -cd 'a-z0-9 ')
    local tok; tok=$(echo "$org_norm"|tr ' ' '\n'|awk 'length>=4'|head -1)
    [[ -z "$tok" ]] && { warn "  org token <4 chars — skipping ASN to avoid noise."; return; }
    local bgp; bgp=$(curl -sf --max-time 15 "https://api.bgpview.io/search?query_term=${ORG_NAME// /%20}" 2>/dev/null||echo "")
    [[ -z "$bgp" ]] && return
    local asns; asns=$(echo "$bgp"|jq -r --arg t "$tok" '.data.asns[]?|select((.name+" "+.description|ascii_downcase)|contains($t))|.asn' 2>/dev/null||true)
    for asn in $asns; do
        vlog "  org ASN AS$asn"
        curl -sf --max-time 15 "https://api.bgpview.io/asn/$asn/prefixes" 2>/dev/null | jq -r '.data.ipv4_prefixes[]?.prefix' 2>/dev/null >> "$ORG_PREFIXES"||true
    done
    # also the prefixes directly owned per BGPView search
    echo "$bgp"|jq -r --arg t "$tok" '.data.ipv4_prefixes[]?|select(((.name//"")+" "+(.description//"")|ascii_downcase)|contains($t))|.prefix' 2>/dev/null >> "$ORG_PREFIXES"||true
    [[ -f "$ORG_PREFIXES" ]] && sort -u -o "$ORG_PREFIXES" "$ORG_PREFIXES"
    ok "  Org-owned CIDRs: $([[ -f "$ORG_PREFIXES" ]] && wc -l < "$ORG_PREFIXES"|xargs || echo 0)"
}

module_passive_dns() {
    log "Passive DNS..."
    curl -sf --max-time 15 "https://www.virustotal.com/ui/domains/$DOMAIN/resolutions?limit=40" 2>/dev/null | jq -r '.data[]?.attributes?.ip_address // empty' 2>/dev/null | while read -r ip; do printf '%s\tvt-pdns\n' "$ip">>"$CAND_TSV"; echo "$ip">>"$ALL_IPS_FILE"; done||true
    curl -sf --max-time 15 "https://otx.alienvault.com/api/v1/indicators/domain/$DOMAIN/passive_dns" 2>/dev/null | jq -r '.passive_dns[].address // empty' 2>/dev/null | grep -oE '[0-9.]+' | while read -r ip; do printf '%s\totx-pdns\n' "$ip">>"$CAND_TSV"; echo "$ip">>"$ALL_IPS_FILE"; done||true
    # ThreatMiner passive DNS (rt=2 returns historically resolved IPs)
    curl -sf --max-time 15 "https://api.threatminer.org/v2/domain.php?q=$DOMAIN&rt=2" 2>/dev/null | jq -r '.results[]?' 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | while read -r ip; do printf '%s\tthreatminer\n' "$ip">>"$CAND_TSV"; echo "$ip">>"$ALL_IPS_FILE"; done||true
}

# ── SecurityTrails organization pivot: current DNS + MX + associated domains ─
module_securitytrails_org() {
    [[ -z "$SECURITYTRAILS_KEY" ]] && return; command -v jq &>/dev/null || return
    log "SecurityTrails current DNS + associated domains..."
    local st
    st=$(curl -sf --max-time 15 -H "APIKEY: $SECURITYTRAILS_KEY" "https://api.securitytrails.com/v1/domain/$DOMAIN" 2>/dev/null||echo "")
    if [[ -n "$st" ]]; then
        echo "$st"|jq -r '.current_dns.a.values[].ip' 2>/dev/null | while read -r ip; do printf '%s\tst-current\n' "$ip">>"$CAND_TSV"; echo "$ip">>"$ALL_IPS_FILE"; done||true
        echo "$st"|jq -r '.current_dns.mx.values[].hostname' 2>/dev/null | while read -r h; do
            echo "$h"|grep -qiE '(google|outlook|microsoft|pphosted|mimecast)' && continue
            for ip in $(dig +short A "$h" 2>/dev/null|grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'); do printf '%s\tst-mx\n' "$ip">>"$CAND_TSV"; echo "$ip">>"$ALL_IPS_FILE"; done
        done||true
    fi
    # Associated domains (same registrant) — org-related; verifier decides relevance
    curl -sf --max-time 15 -H "APIKEY: $SECURITYTRAILS_KEY" "https://api.securitytrails.com/v1/domain/$DOMAIN/associated" 2>/dev/null | jq -r '.records[]?.hostname' 2>/dev/null | head -100 | while read -r h; do
        for ip in $(dig +short +time=2 +tries=1 A "$h" 2>/dev/null|grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'); do printf '%s\tst-associated:%s\n' "$ip" "$h">>"$CAND_TSV"; echo "$ip">>"$ALL_IPS_FILE"; done
    done||true
}

# ============================================================================
# EVIDENCE VERIFIER
# ============================================================================
write_verifier() {
    cat > "$VERIFY_SCRIPT" << 'PYEOF'
#!/usr/bin/env python3
"""
Evidence-tiered origin verifier. Confirms an IP only on site-specific proof.
Args: DOMAIN APEX ORG CDN_FILE ORG_PREFIXES WILDCARD_FILE CAND_TSV \
      SCORED_OUT CONFIRMED_OUT LIKELY_OUT WORKERS
"""
import sys, re, socket, subprocess, ipaddress, hashlib, base64
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import mmh3; HAVE_MMH3 = True
except Exception:
    HAVE_MMH3 = False

(DOMAIN, APEX, ORG, CDN_FILE, ORG_PREFIXES, WILDCARD_FILE,
 CAND_TSV, SCORED_OUT, CONFIRMED_OUT, LIKELY_OUT, WORKERS) = sys.argv[1:12]
WORKERS = int(WORKERS)

def run(cmd, inp=None, timeout=10):
    try:
        return subprocess.run(cmd, input=inp, capture_output=True, timeout=timeout).stdout
    except Exception:
        return b""

def load_nets(path):
    nets = []
    try:
        for line in open(path):
            line = line.strip()
            if line:
                try: nets.append(ipaddress.ip_network(line, strict=False))
                except ValueError: pass
    except FileNotFoundError: pass
    return nets

CDN = load_nets(CDN_FILE)
ORGNETS = load_nets(ORG_PREFIXES)
WILDCARD = set()
try:
    WILDCARD = set(l.strip() for l in open(WILDCARD_FILE) if l.strip())
except FileNotFoundError: pass

def in_nets(ip, nets):
    try: a = ipaddress.ip_address(ip)
    except ValueError: return False
    return any(a in n for n in nets)

def is_cdn(ip):
    try: a = ipaddress.ip_address(ip)
    except ValueError: return True
    if a.is_private or a.is_reserved or a.is_loopback or a.is_multicast or a.is_link_local:
        return True
    return in_nets(ip, CDN)

def org_tokens(s):
    s = (s or "").lower()
    s = re.sub(r'\b(inc|llc|ltd|corp|corporation|company|co|gmbh|sa|ag|plc|group|holdings|technologies|technology|systems|solutions|the|and)\b', ' ', s)
    return set(t for t in re.split(r'[^a-z0-9]+', s) if len(t) >= 4)

ORG_TOKENS = org_tokens(ORG)
al = APEX.split('.')[0] if APEX else ""
if len(al) >= 3: ORG_TOKENS.add(al.lower())

def word_match(token_set, text):
    for t in token_set:
        if re.search(r'\b' + re.escape(t) + r'\b', text):
            return True
    return False

def favhash(data):
    if not data or len(data) < 60: return None
    return str(mmh3.hash(base64.encodebytes(data))) if HAVE_MMH3 else hashlib.md5(data).hexdigest()

def get_title(h):
    m = re.search(r'<title[^>]*>(.*?)</title>', h, re.I | re.S)
    return re.sub(r'\s+', ' ', m.group(1)).strip().lower() if m else ""

DEFAULT_SIGS = ["apache2 ubuntu default page", "welcome to nginx", "iis windows",
    "test page for the apache", "http server test page", "it works!",
    "default web page for this server", "under construction",
    "domain is for sale", "sedoparking", "this domain is parked", "buy this domain",
    "future home of something", "directory listing for /", "403 forbidden",
    "404 not found", "welcome to centos", "welcome to your website"]
def is_default(h):
    l = h.lower()
    return any(s in l for s in DEFAULT_SIGS)

HOSTER_SIGS = ["amazonaws", "googleusercontent", "google cloud", "azure", "microsoft",
    "digitalocean", "ovh", "hetzner", "linode", "vultr", "contabo", "leaseweb",
    "godaddy", "namecheap", "unifiedlayer", "hostgator", "bluehost", "cloudflare",
    "fastly", "akamai", "oracle cloud", "alibaba", "tencent"]
def hoster_owned(text):
    return any(s in text for s in HOSTER_SIGS)

def norm_html(h):
    h = re.sub(r'(?is)<script.*?</script>', ' ', h)
    h = re.sub(r'(?is)<style.*?</style>', ' ', h)
    h = re.sub(r'(?is)<!--.*?-->', ' ', h)
    tags = re.findall(r'<\s*([a-zA-Z0-9]+)', h)
    text = re.sub(r'(?s)<[^>]+>', ' ', h)
    text = re.sub(r'\s+', ' ', text).strip().lower()
    return tags, text.split()

def shingles(tokens, k=4):
    if len(tokens) < k:
        return set(tuple(tokens)) if tokens else set()
    return set(tuple(tokens[i:i+k]) for i in range(len(tokens)-k+1))

def jaccard(a, b):
    if not a or not b: return 0.0
    return len(a & b) / len(a | b)

def build_shingles(h):
    tags, toks = norm_html(h)
    return shingles(toks) | set(("TAG", t) for t in tags)

def asset_fps(h):
    s = set()
    for m in re.findall(r'\b(UA-\d{4,}-\d+|G-[A-Z0-9]{6,}|GTM-[A-Z0-9]{5,})\b', h):
        s.add(("an", m))
    for m in re.findall(r'([a-zA-Z0-9_-]+\.[0-9a-f]{6,20}\.(?:js|css|mjs))', h):
        s.add(("as", m.lower()))
    for m in re.findall(r'([a-zA-Z0-9_-]+\.(?:js|css))\?(?:v|ver|id)?=?[0-9a-f]{6,}', h, re.I):
        s.add(("as", m.lower()))
    m = re.search(r'og:site_name["\']?\s*content=["\']([^"\']+)', h, re.I)
    if m: s.add(("site", m.group(1).strip().lower()))
    return s

def asset_paths(h):
    """Same-origin JS/CSS paths — preferring content-hashed bundles.
    These are fetched byte-for-byte from candidate IPs as definitive proof."""
    raw = re.findall(r'(?:src|href)=["\']([^"\']+\.(?:js|css|mjs)(?:\?[^"\']*)?)["\']', h, re.I)
    paths = []
    for u in raw:
        u = u.strip()
        if u.startswith("//"):
            continue  # protocol-relative → usually third-party CDN, skip
        if u.startswith("http"):
            low = u.lower()
            if DOMAIN.lower() in low or APEX.lower() in low:
                try: u = "/" + u.split("/", 3)[3]
                except IndexError: continue
            else:
                continue  # cross-origin asset, skip
        if not u.startswith("/"):
            u = "/" + u
        paths.append(u)
    hashed = [p for p in paths if re.search(r'[._-][0-9a-f]{6,}\.(?:js|css|mjs)(?:\?|$)', p)]
    ordered, seen, out = hashed + paths, set(), []
    for p in ordered:
        if p not in seen:
            seen.add(p); out.append(p)
        if len(out) >= 3: break
    return out

def fetch_asset_hash(target, host, path, scheme):
    data = run(["curl", "-s", "-k", "-L", "--max-time", "8", "--connect-timeout", "4",
                "-H", "Host: " + host, f"{scheme}://{target}{path}"], timeout=12)
    return hashlib.md5(data).hexdigest() if data and len(data) > 32 else None

def cookie_names(hdr):
    return set(re.findall(r'(?im)^set-cookie:\s*([^=;\s]+)=', hdr))
def server_of(hdr):
    m = re.search(r'(?im)^server:\s*(.+)$', hdr)
    return m.group(1).strip().lower() if m else ""
def location_of(hdr):
    m = re.search(r'(?im)^location:\s*(.+)$', hdr)
    return m.group(1).strip().lower() if m else ""

def port_open(ip, port, t=2.0):
    try:
        s = socket.create_connection((ip, port), t); s.close(); return True
    except Exception:
        return False

def cert_raw(target, sni):
    return run(["openssl", "s_client", "-connect", f"{target}:443", "-servername", sni],
               inp=b"", timeout=9)
def parse_cert(out):
    if not out: return [], "", ""
    txt = run(["openssl", "x509", "-noout", "-text"], inp=out, timeout=6).decode("utf-8", "ignore")
    sans = [s.lower() for s in re.findall(r'DNS:([^,\s]+)', txt)]
    mo = re.search(r'Subject:.*?\bO\s*=\s*([^,/\n]+)', txt)
    o = mo.group(1).strip().lower() if mo else ""
    fpo = run(["openssl", "x509", "-noout", "-fingerprint", "-sha256"], inp=out, timeout=6).decode("utf-8", "ignore")
    m = re.search(r'Fingerprint=([0-9A-Fa-f:]+)', fpo)
    fp = m.group(1).replace(':', '').lower() if m else ""
    return sans, o, fp

def san_match(sans):
    dl, aa = DOMAIN.lower(), APEX.lower()
    for s in sans:
        s = s.strip().lstrip('*.').lower()
        if s == dl or s == aa or s.endswith('.' + aa):
            return True
    return False

def http_get(ip, host, scheme):
    return run(["curl", "-s", "-k", "-L", "--max-time", "8", "--connect-timeout", "4",
                "-H", "Host: " + host, f"{scheme}://{ip}/"], timeout=12).decode("utf-8", "ignore")
def http_head(ip, host, scheme):
    return run(["curl", "-sI", "-k", "-L", "--max-time", "8", "--connect-timeout", "4",
                "-H", "Host: " + host, f"{scheme}://{ip}/"], timeout=12).decode("utf-8", "ignore")
def http_code(ip, host, scheme):
    return run(["curl", "-s", "-k", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "8",
                "--connect-timeout", "4", "-H", "Host: " + host, f"{scheme}://{ip}/"], timeout=12).decode().strip()

def owner_text(ip):
    txt = run(["whois", ip], timeout=10).decode("utf-8", "ignore").lower()
    if not txt or "no match" in txt:
        txt += " " + run(["curl", "-s", "--max-time", "8", "https://rdap.org/ip/" + ip], timeout=10).decode("utf-8", "ignore").lower()
    return txt

def ptr_of(ip):
    return run(["dig", "+short", "+time=2", "+tries=1", "-x", ip], timeout=6).decode("utf-8", "ignore").strip().lower()

# ── baseline of the REAL site ──
def baseline():
    html = ""
    for sch in ("https", "http"):
        html = run(["curl", "-sk", "-L", "--max-time", "15", f"{sch}://{DOMAIN}/"], timeout=20).decode("utf-8", "ignore")
        if html.strip(): break
    hdr = run(["curl", "-sIk", "-L", "--max-time", "12", f"https://{DOMAIN}/"], timeout=16).decode("utf-8", "ignore")
    fav = run(["curl", "-sk", "-L", "--max-time", "10", f"https://{DOMAIN}/favicon.ico"], timeout=15)
    sans, o, fp = parse_cert(cert_raw(DOMAIN, DOMAIN))
    # Byte-hash of same-origin hashed asset bundles → definitive origin proof
    abod = {}
    for p in asset_paths(html):
        h = fetch_asset_hash(DOMAIN, DOMAIN, p, "https")
        if h: abod[p] = h
    return dict(title=get_title(html), fav=favhash(fav),
                sh=build_shingles(html), assets=asset_fps(html),
                cookies=cookie_names(hdr), server=server_of(hdr),
                sans=set(sans), fp=fp, abod=abod,
                ok=bool(html.strip() or sans or fp))

def probe(ip, host):
    for sch in ("https", "http"):
        p = 443 if sch == "https" else 80
        if not port_open(ip, p):
            continue
        code = http_code(ip, host, sch)
        if code and code != "000":
            body = http_get(ip, host, sch)
            hdr = http_head(ip, host, sch)
            return body, code, hdr, sch
    return "", "000", "", ""

def evaluate(ip, sources, B):
    ev = []; score = 0
    src = " ".join(sources)
    live_apex = ("dns-apex:" in src) or ("mx:" in src) or ("soa:" in src) or ("spf" in src)
    live_sub = ("subdomain:" in src) or ("dns:" in src)
    wildcard_only = ("wildcard:" in src) and not (live_apex or live_sub)

    # TLS
    sans, subj_o, fp = parse_cert(cert_raw(ip, DOMAIN))
    cert_san = bool(sans) and san_match(sans)
    cert_fp  = bool(fp) and bool(B["fp"]) and fp == B["fp"]
    cert_org = bool(subj_o) and word_match(ORG_TOKENS, subj_o)
    if cert_fp:  score += 60; ev.append("cert-fp")
    if cert_san: score += 45; ev.append("cert-san")
    if cert_org: score += 25; ev.append("cert-org")

    # HTTP content
    body, code, hdr, sch = probe(ip, DOMAIN)
    alive = bool(sch)
    default_pg = alive and is_default(body)
    sim = 0.0; uniq = set(); title_m = fav_m = cookie_m = False; redirect_canon = False
    catchall = False; asset_body = False
    if alive:
        score += 5; ev.append("alive:" + code)
        loc = location_of(hdr)
        if APEX.lower() in loc: redirect_canon = True; ev.append("redir-canonical")
        csh = build_shingles(body)
        sim = jaccard(B["sh"], csh)
        uniq = B["assets"] & asset_fps(body)
        title_m = bool(B["title"]) and get_title(body) == B["title"]
        cfav = favhash(run(["curl","-sk","-L","--max-time","8","-H","Host: "+DOMAIN,f"{sch}://{ip}/favicon.ico"], timeout=12))
        fav_m = bool(B["fav"]) and cfav == B["fav"]
        cc = cookie_names(hdr)
        cookie_m = bool(B["cookies"] & cc) and any(len(c) >= 5 for c in (B["cookies"] & cc))
        # DEFINITIVE: fetch the site's own hashed JS/CSS bundle from this IP and
        # byte-compare. A random host in the same ASN cannot reproduce it.
        for p, h in list(B.get("abod", {}).items())[:2]:
            ch = fetch_asset_hash(ip, DOMAIN, p, sch)
            if ch and ch == h:
                asset_body = True; break
        # catch-all: identical content for a bogus Host
        rnd = http_get(ip, "zzq9notreal-x." + APEX, sch)
        if rnd.strip():
            if jaccard(build_shingles(rnd), csh) > 0.97:
                catchall = True; ev.append("catch-all")
        if asset_body: score += 60; ev.append("asset-body")
        if uniq:      score += 55; ev.append("uniq-asset(%d)" % len(uniq))
        if sim >= 0.85: score += 45; ev.append("sim-high:%.2f" % sim)
        elif sim >= 0.5: score += 22; ev.append("sim-med:%.2f" % sim)
        if fav_m:     score += 40; ev.append("favicon")
        if title_m:   score += 22; ev.append("title")
        if cookie_m:  score += 15; ev.append("cookie")
        if default_pg: score -= 45; ev.append("DEFAULT-PAGE")

    # ownership
    who = owner_text(ip)
    whois_org = word_match(ORG_TOKENS, who) and not hoster_owned(who[:400])
    if whois_org: score += 25; ev.append("whois-org")
    ptr = ptr_of(ip)
    ptr_apex = APEX.lower() in ptr
    if ptr_apex: score += 20; ev.append("ptr-apex")
    elif ptr and word_match(ORG_TOKENS, ptr): score += 12; ev.append("ptr-org")

    in_prefix = in_nets(ip, ORGNETS)
    if in_prefix: score += 15; ev.append("in-org-cidr")
    if live_apex: score += 18; ev.append("live-apex")
    elif live_sub and not wildcard_only: score += 8; ev.append("live-sub")

    # different-site negative
    if alive and not default_pg and sim < 0.1 and not cert_san and not uniq and not title_m and not fav_m:
        score -= 15; ev.append("different-site")

    # ── DECISION (rule-based, evidence-tiered) ──
    definitive = (cert_fp or asset_body or (uniq and alive)
                  or (cert_san and alive and not default_pg)
                  or (sim >= 0.9 and not default_pg and not catchall))
    strong2 = sum([cert_san, fav_m, (sim >= 0.7), title_m, whois_org, redirect_canon]) >= 2
    confirmed = definitive or (strong2 and not default_pg) \
                or (cert_san and (whois_org or in_prefix)) \
                or (fav_m and (title_m or sim >= 0.5 or cert_san or whois_org))

    likely = (not confirmed) and (
        cert_san or fav_m or (sim >= 0.5 and not default_pg)
        or (title_m and (whois_org or in_prefix or ptr_apex))
        or (whois_org and alive and not default_pg and not catchall)
        or (live_apex and alive and not default_pg and (sim >= 0.3 or title_m or ptr_apex))
    )

    # hard guards
    if default_pg and not (cert_fp or asset_body or uniq):
        confirmed = False; likely = False
    if catchall and not (cert_fp or asset_body or uniq or cert_san or fav_m):
        confirmed = False  # generic server matching baseline isn't proof

    verdict = "CONFIRMED" if confirmed else ("LIKELY" if likely else "REJECT")
    return ip, score, verdict, ev

def main():
    cand = {}
    try:
        for line in open(CAND_TSV):
            p = line.rstrip("\n").split("\t")
            if not p or not p[0]: continue
            ip = p[0].strip()
            try: ipaddress.ip_address(ip)
            except ValueError: continue
            cand.setdefault(ip, set()).add(p[1].strip() if len(p) > 1 else "unknown")
    except FileNotFoundError:
        pass
    cand = {ip: s for ip, s in cand.items() if not is_cdn(ip)}
    sys.stderr.write(f"[*] Verifying {len(cand)} non-CDN candidates...\n")

    B = baseline()
    if not B["ok"]:
        sys.stderr.write("[!] Baseline fingerprint incomplete; relying on cert/whois.\n")

    # fast pre-liveness to skip dead IPs
    def alive_pre(ip):
        return port_open(ip, 443, 1.5) or port_open(ip, 80, 1.5)
    live = []
    with ThreadPoolExecutor(max_workers=min(WORKERS*2, 80)) as ex:
        for ip, ok in zip(cand, ex.map(alive_pre, list(cand))):
            if ok: live.append(ip)
    sys.stderr.write(f"[*] {len(live)} candidates have an open web port; deep-verifying.\n")

    results = []
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futs = {ex.submit(evaluate, ip, list(cand[ip]), B): ip for ip in live}
        for f in as_completed(futs):
            try: results.append(f.result())
            except Exception: pass
    # dead IPs recorded as REJECT for the audit
    for ip in cand:
        if ip not in live:
            results.append((ip, 0, "REJECT", ["dead"]))

    results.sort(key=lambda r: r[1], reverse=True)
    with open(SCORED_OUT, "w") as o:
        o.write("ip\tscore\tverdict\tevidence\tsources\n")
        for ip, sc, v, ev in results:
            o.write(f"{ip}\t{sc}\t{v}\t{','.join(ev)}\t{','.join(sorted(cand[ip]))}\n")
    with open(CONFIRMED_OUT, "w") as o:
        for ip, sc, v, ev in results:
            if v == "CONFIRMED": o.write(ip + "\n")
    with open(LIKELY_OUT, "w") as o:
        for ip, sc, v, ev in results:
            if v == "LIKELY": o.write(ip + "\n")

if __name__ == "__main__":
    main()
PYEOF
    chmod +x "$VERIFY_SCRIPT"
}

run_verifier() {
    log "Running evidence verifier (this does live cert+content probing)..."
    [[ -s "$CAND_TSV" ]] || { err "No candidates."; return 1; }
    local ccount; ccount=$(cut -f1 "$CAND_TSV"|sort -u|wc -l|xargs)
    if [[ "$ccount" -gt "$MAX_CANDIDATES" ]]; then
        warn "Candidates ($ccount) > cap ($MAX_CANDIDATES); prioritizing DNS-derived."
        { grep -E $'\t'"(dns-apex:|dns:|subdomain:|mx:|soa:|spf|censys|shodan)" "$CAND_TSV";
          grep -vE $'\t'"(dns-apex:|dns:|subdomain:|mx:|soa:|spf|censys|shodan)" "$CAND_TSV"; } > "$TMPDIR_BASE/pri.tsv" 2>/dev/null || cp "$CAND_TSV" "$TMPDIR_BASE/pri.tsv"
        awk -F'\t' -v cap="$MAX_CANDIDATES" '{if(!s[$1]){s[$1]=1;n++} if(n<=cap)print}' "$TMPDIR_BASE/pri.tsv" > "$CAND_TSV"
    fi
    touch "$ORG_PREFIXES" "$WILDCARD_FILE"
    python3 "$VERIFY_SCRIPT" "$DOMAIN" "$APEX" "$ORG_NAME" "$CDN_RANGES_FILE" "$ORG_PREFIXES" \
        "$WILDCARD_FILE" "$CAND_TSV" "$SCORED_TSV" "$CONFIRMED_FILE" "$LIKELY_FILE" "$WORKERS" \
        2> >(sed 's/^/    /' >&2)
    [[ -f "$CONFIRMED_FILE" ]] && sort -u -o "$CONFIRMED_FILE" "$CONFIRMED_FILE"
    [[ -f "$LIKELY_FILE" ]] && sort -u -o "$LIKELY_FILE" "$LIKELY_FILE"
}

# ============================================================================
# MAIN
# ============================================================================
main() {
    echo ""
    echo -e "${BOLD}╔══════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${BOLD}║  Origin IP Finder PRO v4 — Evidence-Verified            ║${RESET}"
    echo -e "${BOLD}╚══════════════════════════════════════════════════════════╝${RESET}"; echo ""

    while getopts "d:o:j:w:k:c:s:v:f:bDVh" opt; do
        case "$opt" in
            d) DOMAIN="$OPTARG";; o) ORG_NAME="$OPTARG";; j) WORKERS="$OPTARG";;
            w) WORDLIST="$OPTARG";; k) SHODAN_KEY="$OPTARG";; c) CENSYS_CREDS="$OPTARG";;
            s) SECURITYTRAILS_KEY="$OPTARG";; v) VIEWDNS_KEY="$OPTARG";; f) OUTPUT_FILE="$OPTARG";;
            b) DO_BRUTE=1;; D) DO_DEEP=1;; V) VERBOSE=1;; h) usage;; *) usage;;
        esac
    done
    [[ -z "$DOMAIN" ]] && { err "Domain required (-d)."; usage; }

    DOMAIN=$(echo "$DOMAIN"|sed 's|https\?://||;s|/.*||;s|^www\.||')
    APEX=$(echo "$DOMAIN"|awk -F. '{if(NF>=2)print $(NF-1)"."$NF; else print $0}')
    [[ -z "$OUTPUT_FILE" ]] && OUTPUT_FILE="${DOMAIN//\./_}_ips.txt"
    local LIKELY_OUT="${OUTPUT_FILE%.txt}_likely.txt"
    local SCORED_OUT="${OUTPUT_FILE%.txt}_scored.tsv"
    local SUBS_OUT="${DOMAIN//\./_}_subdomains.txt"
    local LIVE_OUT="${DOMAIN//\./_}_live_subdomains.txt"
    local RANGES_OUT="${DOMAIN//\./_}_org_ranges.txt"

    log "Domain: $DOMAIN   Apex: $APEX"
    [[ -n "$ORG_NAME" ]] && log "Org: $ORG_NAME"
    log "Concurrency: $WORKERS   Brute:$DO_BRUTE Deep:$DO_DEEP"; echo ""

    touch "$ALL_IPS_FILE" "$CAND_TSV" "$SUBS_FILE" "$LIVE_SUBS_FILE" "$ORG_PREFIXES" "$WILDCARD_FILE"
    install_deps; detect_org_name; build_cdn_ranges; write_verifier

    echo ""; log "Phase 1 — Enumeration"; echo "──────────────────────────────────────────"
    detect_wildcard
    module_dns_direct
    module_dns_records
    module_subdomains
    module_subdomain_depth
    module_resolve_subs
    module_dns_history
    module_cert_transparency
    module_shodan
    module_censys
    module_securitytrails_org
    module_org_ranges
    module_passive_dns
    echo "──────────────────────────────────────────"; echo ""

    [[ -s "$CAND_TSV" ]] || { err "No candidate IPs collected — check connectivity/domain."; exit 1; }
    log "Phase 2 — Evidence Verification"; echo "──────────────────────────────────────────"
    run_verifier
    echo "──────────────────────────────────────────"; echo ""

    [[ -s "$SUBS_FILE" ]] && { sort -u -o "$SUBS_FILE" "$SUBS_FILE"; cp "$SUBS_FILE" "$SUBS_OUT"; }
    [[ -s "$LIVE_SUBS_FILE" ]] && { sort -u -o "$LIVE_SUBS_FILE" "$LIVE_SUBS_FILE"; cp "$LIVE_SUBS_FILE" "$LIVE_OUT"; }
    [[ -s "$SCORED_TSV" ]] && cp "$SCORED_TSV" "$SCORED_OUT"
    [[ -s "$ORG_PREFIXES" ]] && cp "$ORG_PREFIXES" "$RANGES_OUT"

    local total; total=$(cut -f1 "$CAND_TSV"|sort -u|wc -l|xargs)
    local nconf=0 nlike=0
    [[ -s "$CONFIRMED_FILE" ]] && nconf=$(wc -l < "$CONFIRMED_FILE"|xargs)
    [[ -s "$LIKELY_FILE" ]] && nlike=$(wc -l < "$LIKELY_FILE"|xargs)

    if [[ "$nconf" -gt 0 ]]; then
        cp "$CONFIRMED_FILE" "$OUTPUT_FILE"
        echo -e "${BOLD}══════════════════════════════════════════════════════════${RESET}"
        echo -e "${GREEN}${BOLD} CONFIRMED ORIGIN IPs ($nconf of $total candidates):${RESET}"
        echo -e "${BOLD}══════════════════════════════════════════════════════════${RESET}"; echo ""
        while IFS= read -r ip; do
            local row sc ev; row=$(grep -P "^${ip//./\\.}\t" "$SCORED_TSV" 2>/dev/null|head -1)
            sc=$(echo "$row"|cut -f2); ev=$(echo "$row"|cut -f4)
            printf "  ${GREEN}%-16s${RESET} score=%-3s  %s\n" "$ip" "$sc" "$ev"
        done < "$CONFIRMED_FILE"
        echo ""
    else
        warn "No IPs met the CONFIRMED evidence bar."
    fi

    if [[ "$nlike" -gt 0 ]]; then
        echo -e "${YELLOW}${BOLD} LIKELY (review — one strong signal, $nlike):${RESET}"; echo ""
        while IFS= read -r ip; do
            local row sc ev; row=$(grep -P "^${ip//./\\.}\t" "$SCORED_TSV" 2>/dev/null|head -1)
            sc=$(echo "$row"|cut -f2); ev=$(echo "$row"|cut -f4)
            printf "  ${YELLOW}%-16s${RESET} score=%-3s  %s\n" "$ip" "$sc" "$ev"
        done < "$LIKELY_FILE"
        echo ""
    fi

    ok "Confirmed IPs : $OUTPUT_FILE ($nconf)"
    [[ "$nlike" -gt 0 ]] && ok "Likely IPs    : $LIKELY_OUT ($nlike)"
    ok "Scored audit  : $SCORED_OUT"
    [[ -s "$SUBS_OUT" ]] && ok "Subdomains    : $SUBS_OUT ($(wc -l < "$SUBS_OUT"|xargs))"
    [[ -s "$LIVE_OUT" ]] && ok "Live subs     : $LIVE_OUT ($(wc -l < "$LIVE_OUT"|xargs))"
    [[ -s "$RANGES_OUT" ]] && ok "Org CIDRs     : $RANGES_OUT ($(wc -l < "$RANGES_OUT"|xargs))  (naabu -cidr to hunt more origins)"
    echo ""
    [[ "$nconf" -gt 0 ]] && ok "Next: naabu -list $OUTPUT_FILE -top-ports 1000 -silent"
    [[ "$nconf" -eq 0 && "$nlike" -eq 0 ]] && warn "Inspect $SCORED_OUT for near-misses; add -k/-c/-s API keys for more evidence."
    echo ""
}

main "$@"
