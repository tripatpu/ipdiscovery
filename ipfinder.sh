#!/bin/bash
# ============================================================================
# origin-ip-finder.sh — True-positive origin IP enumerator (v2)
# ============================================================================
# Finds real IPv4 addresses behind CDN/WAF (CloudFront, Cloudflare, Akamai,
# Fastly, Incapsula, Sucuri, StackPath, etc.) for a given domain or org name.
#
# Output: clean list of IPs, one per line — pipe-ready for naabu.
#
# Usage:
#   ./origin-ip-finder.sh -d example.com
#   ./origin-ip-finder.sh -d example.com -o "Example Inc"
#   ./origin-ip-finder.sh -d example.com -o "Example Inc" -k <shodan_key> -c <censys_id:censys_secret> -s <securitytrails_key>
# ============================================================================

# Don't use set -e — we want resilient execution
set -uo pipefail

# ── Colors ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

# ── Globals ─────────────────────────────────────────────────────────────────
DOMAIN=""
ORG_NAME=""
SHODAN_KEY=""
CENSYS_CREDS=""
SECURITYTRAILS_KEY=""
VIEWDNS_KEY=""
OUTPUT_FILE=""
VERBOSE=0
TMPDIR_BASE=$(mktemp -d /tmp/origin-ip-finder.XXXXXX)
ALL_IPS_FILE="$TMPDIR_BASE/all_ips.txt"
FILTERED_IPS_FILE="$TMPDIR_BASE/filtered_ips.txt"
CDN_RANGES_FILE="$TMPDIR_BASE/cdn_ranges.txt"
FILTER_SCRIPT="$TMPDIR_BASE/filter.py"

trap 'rm -rf "$TMPDIR_BASE"' EXIT

# ── CDN / WAF CIDR ranges ──────────────────────────────────────────────────
# ONLY actual CDN/WAF edge IPs — NOT general cloud hosting ranges.
# Key distinction: CloudFront IPs are CDN edges, but EC2/GCP/Azure hosting
# IPs are where real origin servers live — we must NOT filter those.
declare -a KNOWN_CDN_PREFIXES=(
    # ─── Cloudflare (all edge IPs) ───
    "173.245.48.0/20" "103.21.244.0/22" "103.22.200.0/22" "103.31.4.0/22"
    "141.101.64.0/18" "108.162.192.0/18" "190.93.240.0/20" "188.114.96.0/20"
    "197.234.240.0/22" "198.41.128.0/17" "162.158.0.0/15" "104.16.0.0/13"
    "104.24.0.0/14" "172.64.0.0/13" "131.0.72.0/22"
    # ─── AWS CloudFront ONLY (not EC2/general AWS) ───
    "52.84.0.0/14" "54.182.0.0/16" "54.192.0.0/16" "54.230.0.0/16"
    "54.239.128.0/18" "54.239.192.0/19" "54.240.128.0/18" "99.84.0.0/16"
    "143.204.0.0/16" "204.246.164.0/22" "204.246.168.0/22" "205.251.249.0/24"
    "205.251.250.0/23" "205.251.252.0/23" "205.251.254.0/24"
    "216.137.32.0/19" "13.32.0.0/15" "13.35.0.0/16" "13.224.0.0/14"
    "13.249.0.0/16" "18.64.0.0/14" "18.68.0.0/16" "18.154.0.0/15"
    "18.160.0.0/15" "18.164.0.0/15" "18.172.0.0/15" "18.238.0.0/15"
    "3.160.0.0/14" "3.164.0.0/18" "3.168.0.0/14" "3.172.0.0/18"
    # ─── Fastly ───
    "23.235.32.0/20" "43.249.72.0/22" "103.244.50.0/24" "103.245.222.0/23"
    "103.245.224.0/24" "104.156.80.0/20" "140.248.64.0/18" "140.248.128.0/17"
    "146.75.0.0/17" "151.101.0.0/16" "157.52.64.0/18" "167.82.0.0/17"
    "167.82.128.0/20" "167.82.160.0/20" "167.82.224.0/20" "172.111.64.0/18"
    "185.31.16.0/22" "199.27.72.0/21" "199.232.0.0/16"
    # ─── Akamai (CDN edges only — NOT the broad /10 /11 blocks) ───
    "72.246.0.0/15" "96.16.0.0/15" "96.6.0.0/15"
    "184.24.0.0/13" "184.50.0.0/15" "184.84.0.0/14"
    "2.16.0.0/13" "95.100.0.0/15" "92.122.0.0/15"
    "23.0.0.0/12" "23.32.0.0/11" "23.64.0.0/14" "23.72.0.0/13"
    # ─── Sucuri WAF ───
    "192.88.134.0/23" "185.93.228.0/22" "66.248.200.0/22"
    # ─── StackPath / Highwinds ───
    "151.139.0.0/16" "199.250.192.0/18"
    # ─── Incapsula / Imperva ───
    "199.83.128.0/21" "198.143.32.0/19" "149.126.72.0/21" "103.28.248.0/22"
    "45.64.64.0/22" "107.154.0.0/16" "45.60.0.0/16"
    # ─── Limelight ───
    "68.232.32.0/20" "117.18.232.0/21"
    # ─── BunnyCDN ───
    "116.206.186.0/24" "199.247.16.0/21"
    # ─── Vercel (edge) ───
    "76.76.21.0/24"
    # ─── Netlify (edge) ───
    "104.198.14.0/24"
)

# ── Helpers ─────────────────────────────────────────────────────────────────
log()  { echo -e "${CYAN}[*]${RESET} $*"; }
ok()   { echo -e "${GREEN}[+]${RESET} $*"; }
warn() { echo -e "${YELLOW}[!]${RESET} $*"; }
err()  { echo -e "${RED}[-]${RESET} $*" >&2; }
vlog() { [[ $VERBOSE -eq 1 ]] && echo -e "${CYAN}[v]${RESET} $*" || true; }

usage() {
    cat <<EOF
${BOLD}Origin IP Finder — True-Positive Origin IP Enumerator v2${RESET}

Usage: $0 -d <domain> [options]

Required:
  -d  Target domain (e.g., example.com)

Optional:
  -o  Organization name (improves accuracy; auto-detected from whois if omitted)
  -k  Shodan API key
  -c  Censys credentials (format: API_ID:API_SECRET)
  -s  SecurityTrails API key
  -v  ViewDNS API key
  -f  Output file (default: <domain>_ips.txt)
  -V  Verbose mode
  -h  Help

EOF
    exit 0
}

# ── Write IPs to file (safe — no subshell issues) ─────────────────────────
add_ip() {
    local ip="$1"
    local source="${2:-unknown}"
    if [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        echo "$ip" >> "$ALL_IPS_FILE"
        vlog "  Collected: $ip ($source)"
    fi
}

# Bulk-add from a variable (avoids pipe subshells entirely)
add_ips_from_var() {
    local ips="$1"
    local source="$2"
    local ip
    for ip in $ips; do
        add_ip "$ip" "$source"
    done
}

# ── Dependency installer ───────────────────────────────────────────────────
install_deps() {
    log "Checking dependencies..."

    local PKG=""
    if command -v apt-get &>/dev/null; then PKG="apt-get"
    elif command -v yum &>/dev/null; then PKG="yum"
    elif command -v dnf &>/dev/null; then PKG="dnf"
    elif command -v pacman &>/dev/null; then PKG="pacman"
    elif command -v brew &>/dev/null; then PKG="brew"
    fi

    for cmd in dig host whois curl jq python3; do
        if ! command -v "$cmd" &>/dev/null; then
            case "$cmd" in
                dig|host)
                    case "$PKG" in
                        apt-get) sudo apt-get install -y dnsutils 2>/dev/null || true ;;
                        yum|dnf) sudo $PKG install -y bind-utils 2>/dev/null || true ;;
                        pacman) sudo pacman -S --noconfirm bind-tools 2>/dev/null || true ;;
                        brew) brew install bind 2>/dev/null || true ;;
                    esac ;;
                whois)
                    [[ -n "$PKG" ]] && sudo $PKG install -y whois 2>/dev/null || true ;;
                *)
                    [[ -n "$PKG" ]] && sudo $PKG install -y "$cmd" 2>/dev/null || true ;;
            esac
        fi
    done

    # Go-based recon tools
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
    fi

    # Python ipaddress module is built-in; requests is nice-to-have
    if command -v pip3 &>/dev/null; then
        pip3 install requests --quiet --break-system-packages 2>/dev/null || \
        pip3 install requests --quiet 2>/dev/null || true
    fi

    ok "Dependency check complete."
}

# ── Auto-detect org name ───────────────────────────────────────────────────
detect_org_name() {
    if [[ -n "$ORG_NAME" ]]; then return; fi
    log "Auto-detecting organization name from whois..."
    if command -v whois &>/dev/null; then
        ORG_NAME=$(whois "$DOMAIN" 2>/dev/null | grep -iE "^(Org(anization)?(-Name)?|OrgName|Registrant Organization)" | head -1 | sed 's/^[^:]*:\s*//' | xargs 2>/dev/null || true)
        if [[ -n "$ORG_NAME" ]]; then
            ok "Detected org: $ORG_NAME"
        else
            warn "Could not auto-detect org name. Use -o for better results."
        fi
    fi
}

# ── Build CDN range database + Python filter script ───────────────────────
build_cdn_ranges() {
    log "Building CDN/WAF IP range database..."

    # Static ranges
    printf '%s\n' "${KNOWN_CDN_PREFIXES[@]}" > "$CDN_RANGES_FILE"

    # Live Cloudflare ranges
    curl -sf --max-time 10 "https://www.cloudflare.com/ips-v4" >> "$CDN_RANGES_FILE" 2>/dev/null || true

    # Live AWS CloudFront ranges (ONLY CloudFront service)
    local aws_json
    aws_json=$(curl -sf --max-time 15 "https://ip-ranges.amazonaws.com/ip-ranges.json" 2>/dev/null || echo "")
    if [[ -n "$aws_json" ]] && command -v jq &>/dev/null; then
        echo "$aws_json" | jq -r '.prefixes[] | select(.service=="CLOUDFRONT") | .ip_prefix' >> "$CDN_RANGES_FILE" 2>/dev/null || true
    fi

    # Live Fastly ranges
    local fastly_json
    fastly_json=$(curl -sf --max-time 10 "https://api.fastly.com/public-ip-list" 2>/dev/null || echo "")
    if [[ -n "$fastly_json" ]] && command -v jq &>/dev/null; then
        echo "$fastly_json" | jq -r '.addresses[]' >> "$CDN_RANGES_FILE" 2>/dev/null || true
    fi

    sort -u -o "$CDN_RANGES_FILE" "$CDN_RANGES_FILE"
    local count
    count=$(wc -l < "$CDN_RANGES_FILE" | xargs)
    ok "Loaded $count CDN/WAF CIDR ranges for filtering."

    # ── Python CIDR filter (fast + reliable) ──────────────────────────────
    cat > "$FILTER_SCRIPT" << 'PYEOF'
#!/usr/bin/env python3
"""Filter IPs: remove private, reserved, and CDN/WAF addresses."""
import sys
import ipaddress

def load_cdn_ranges(path):
    nets = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                nets.append(ipaddress.ip_network(line, strict=False))
            except ValueError:
                pass
    return nets

def is_private_or_reserved(ip):
    return ip.is_private or ip.is_reserved or ip.is_loopback or ip.is_multicast or ip.is_link_local

def main():
    if len(sys.argv) < 3:
        print("Usage: filter.py <cdn_ranges_file> <ips_file>", file=sys.stderr)
        sys.exit(1)

    cdn_nets = load_cdn_ranges(sys.argv[1])
    seen = set()

    with open(sys.argv[2]) as f:
        for line in f:
            raw = line.strip()
            if not raw:
                continue
            try:
                ip = ipaddress.ip_address(raw)
            except ValueError:
                continue

            if raw in seen:
                continue
            seen.add(raw)

            if is_private_or_reserved(ip):
                continue

            is_cdn = False
            for net in cdn_nets:
                if ip in net:
                    is_cdn = True
                    break

            if not is_cdn:
                print(raw)

if __name__ == "__main__":
    main()
PYEOF
    chmod +x "$FILTER_SCRIPT"
}

# ============================================================================
# ENUMERATION MODULES
# ============================================================================

# ── Module 1: Direct DNS resolution ───────────────────────────────────────
module_dns_direct() {
    log "Module: Direct DNS resolution..."
    if ! command -v dig &>/dev/null; then return; fi

    local subs=("" "www" "mail" "ftp" "direct" "origin" "origin-www"
        "direct-connect" "server" "host" "cpanel" "webmail"
        "smtp" "pop" "imap" "mx" "ns1" "ns2" "api" "dev"
        "staging" "stage" "test" "uat" "admin" "panel"
        "old" "legacy" "backup" "bak" "real" "true"
        "actual" "unfiltered" "orig" "vpn" "remote"
        "ssh" "ftp2" "portal" "crm" "erp" "intranet"
        "internal" "gateway" "proxy" "app" "web" "cdn-origin"
        "ns" "dns" "mx1" "mx2" "mail2" "email" "exchange"
        "owa" "autodiscover" "lyncdiscover" "sip")

    for sub in "${subs[@]}"; do
        local target
        if [[ -z "$sub" ]]; then
            target="$DOMAIN"
        else
            target="${sub}.${DOMAIN}"
        fi
        local result
        result=$(dig +short +time=3 +tries=1 A "$target" 2>/dev/null || true)
        local ips
        ips=$(echo "$result" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' || true)
        add_ips_from_var "$ips" "dns:$target"
    done
}

# ── Module 2: MX / SPF / TXT / NS / SOA records ──────────────────────────
module_dns_records() {
    log "Module: MX/SPF/TXT/NS/SOA record analysis..."
    if ! command -v dig &>/dev/null; then return; fi

    # MX records
    local mx_hosts
    mx_hosts=$(dig +short MX "$DOMAIN" 2>/dev/null | awk '{print $2}' | sed 's/\.$//' || true)
    for mxh in $mx_hosts; do
        # Skip cloud mail providers
        echo "$mxh" | grep -qiE '(google|outlook|microsoft|protonmail|zoho|mimecast|pphosted|messagelabs)' && continue
        local ips
        ips=$(dig +short A "$mxh" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' || true)
        add_ips_from_var "$ips" "mx:$mxh"
    done

    # SPF record — extract ip4: directives
    local spf
    spf=$(dig +short TXT "$DOMAIN" 2>/dev/null | tr -d '"' | grep -i 'v=spf1' || true)
    if [[ -n "$spf" ]]; then
        local spf_ips
        spf_ips=$(echo "$spf" | grep -oE 'ip4:[0-9.]+(/[0-9]+)?' | cut -d: -f2 || true)
        for entry in $spf_ips; do
            if [[ "$entry" == */* ]]; then
                # CIDR — take network address
                add_ip "${entry%/*}" "spf-cidr:$entry"
            else
                add_ip "$entry" "spf"
            fi
        done

        # Recursive SPF includes (skip CDN/cloud providers)
        local includes
        includes=$(echo "$spf" | grep -oE 'include:[^ ]+' | cut -d: -f2 || true)
        for inc in $includes; do
            echo "$inc" | grep -qiE '(google|amazonses|sendgrid|mailgun|outlook|microsoft|spf\.protection|mailchimp|postmarkapp|zendesk)' && continue
            local inc_spf
            inc_spf=$(dig +short TXT "$inc" 2>/dev/null | tr -d '"' | grep -i 'v=spf1' || true)
            local inc_ips
            inc_ips=$(echo "$inc_spf" | grep -oE 'ip4:[0-9.]+' | cut -d: -f2 || true)
            add_ips_from_var "$inc_ips" "spf-include:$inc"
        done
    fi

    # SOA
    local soa_ns
    soa_ns=$(dig +short SOA "$DOMAIN" 2>/dev/null | awk '{print $1}' | sed 's/\.$//' || true)
    if [[ -n "$soa_ns" ]]; then
        echo "$soa_ns" | grep -qiE '(cloudflare|awsdns|ultradns|route53)' || {
            local ips
            ips=$(dig +short A "$soa_ns" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' || true)
            add_ips_from_var "$ips" "soa:$soa_ns"
        }
    fi

    # NS records (skip CDN nameservers)
    local ns_hosts
    ns_hosts=$(dig +short NS "$DOMAIN" 2>/dev/null | sed 's/\.$//' || true)
    for nsh in $ns_hosts; do
        echo "$nsh" | grep -qiE '(cloudflare|awsdns|ultradns|akamai|dynect|nsone|route53|domaincontrol|registrar)' && continue
        local ips
        ips=$(dig +short A "$nsh" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' || true)
        add_ips_from_var "$ips" "ns:$nsh"
    done

    # DMARC
    local dmarc_ips
    dmarc_ips=$(dig +short TXT "_dmarc.$DOMAIN" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' || true)
    add_ips_from_var "$dmarc_ips" "dmarc"
}

# ── Module 3: Subdomain enumeration + resolution ─────────────────────────
module_subdomains() {
    log "Module: Subdomain enumeration..."
    local subs_file="$TMPDIR_BASE/subdomains.txt"
    touch "$subs_file"

    # subfinder
    if command -v subfinder &>/dev/null; then
        subfinder -d "$DOMAIN" -silent -all >> "$subs_file" 2>/dev/null || true
    fi

    # crt.sh (Certificate Transparency)
    log "  Querying crt.sh..."
    local crtsh
    crtsh=$(curl -sf --max-time 30 "https://crt.sh/?q=%25.$DOMAIN&output=json" 2>/dev/null || echo "")
    if [[ -n "$crtsh" ]] && command -v jq &>/dev/null; then
        echo "$crtsh" | jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//g' | sort -u >> "$subs_file" || true
    fi

    # HackerTarget
    curl -sf --max-time 15 "https://api.hackertarget.com/hostsearch/?q=$DOMAIN" 2>/dev/null | \
        cut -d',' -f1 >> "$subs_file" || true

    # RapidDNS
    curl -sf --max-time 15 "https://rapiddns.io/subdomain/$DOMAIN?full=1" 2>/dev/null | \
        grep -oP "[a-zA-Z0-9._-]+\\.${DOMAIN//./\\.}" >> "$subs_file" || true

    # AlienVault OTX
    local otx
    otx=$(curl -sf --max-time 15 "https://otx.alienvault.com/api/v1/indicators/domain/$DOMAIN/passive_dns" 2>/dev/null || echo "")
    if [[ -n "$otx" ]] && command -v jq &>/dev/null; then
        echo "$otx" | jq -r '.passive_dns[].hostname' >> "$subs_file" 2>/dev/null || true
    fi

    # URLScan.io
    local urlscan
    urlscan=$(curl -sf --max-time 15 "https://urlscan.io/api/v1/search/?q=domain:$DOMAIN&size=100" 2>/dev/null || echo "")
    if [[ -n "$urlscan" ]] && command -v jq &>/dev/null; then
        echo "$urlscan" | jq -r '.results[].page.domain' 2>/dev/null | sort -u >> "$subs_file" || true
    fi

    # Deduplicate
    sort -u -o "$subs_file" "$subs_file"
    local sub_count
    sub_count=$(wc -l < "$subs_file" | xargs)
    ok "  Found $sub_count unique subdomains."

    # Resolve all subdomains to IPs
    log "  Resolving subdomains to IPs..."
    if command -v dnsx &>/dev/null && [[ "$sub_count" -gt 0 ]]; then
        local dnsx_out
        dnsx_out=$(dnsx -l "$subs_file" -a -resp-only -silent 2>/dev/null || true)
        local ips
        ips=$(echo "$dnsx_out" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' || true)
        add_ips_from_var "$ips" "subdomain-resolve"
    elif [[ "$sub_count" -gt 0 ]] && command -v dig &>/dev/null; then
        # Fallback: dig each (limit to 500 to avoid excessive time)
        head -500 "$subs_file" | while IFS= read -r sub; do
            [[ -z "$sub" ]] && continue
            local ips
            ips=$(dig +short +time=2 +tries=1 A "$sub" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' || true)
            for ip in $ips; do
                echo "$ip" >> "$ALL_IPS_FILE"
            done
        done
    fi
}

# ── Module 4: Historical DNS ─────────────────────────────────────────────
module_dns_history() {
    log "Module: Historical DNS records..."

    # SecurityTrails history
    if [[ -n "$SECURITYTRAILS_KEY" ]]; then
        log "  Querying SecurityTrails history..."
        local st_hist
        st_hist=$(curl -sf --max-time 15 -H "APIKEY: $SECURITYTRAILS_KEY" \
            "https://api.securitytrails.com/v1/history/$DOMAIN/dns/a" 2>/dev/null || echo "")
        if [[ -n "$st_hist" ]] && command -v jq &>/dev/null; then
            local ips
            ips=$(echo "$st_hist" | jq -r '.records[].values[].ip' 2>/dev/null || true)
            add_ips_from_var "$ips" "securitytrails-history"
        fi
    fi

    # ViewDNS history
    if [[ -n "$VIEWDNS_KEY" ]]; then
        log "  Querying ViewDNS history..."
        local vdns
        vdns=$(curl -sf --max-time 15 \
            "https://api.viewdns.info/iphistory/?domain=$DOMAIN&apikey=$VIEWDNS_KEY&output=json" 2>/dev/null || echo "")
        if [[ -n "$vdns" ]] && command -v jq &>/dev/null; then
            local ips
            ips=$(echo "$vdns" | jq -r '.response.records[].ip' 2>/dev/null || true)
            add_ips_from_var "$ips" "viewdns-history"
        fi
    fi

    # HackerTarget DNS lookup
    local dnslookup
    dnslookup=$(curl -sf --max-time 15 "https://api.hackertarget.com/dnslookup/?q=$DOMAIN" 2>/dev/null || echo "")
    local ips
    ips=$(echo "$dnslookup" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' || true)
    add_ips_from_var "$ips" "hackertarget-dns"
}

# ── Module 5: Certificate Transparency → IP mapping ─────────────────────
module_cert_transparency() {
    log "Module: Certificate Transparency deep analysis..."

    if [[ -n "$CENSYS_CREDS" ]]; then
        local censys_id="${CENSYS_CREDS%%:*}"
        local censys_secret="${CENSYS_CREDS#*:}"

        log "  Querying Censys for certs matching $DOMAIN..."
        local censys_result
        censys_result=$(curl -sf --max-time 20 \
            -u "$censys_id:$censys_secret" \
            -H "Content-Type: application/json" \
            -d "{\"q\":\"services.tls.certificates.leaf.names: $DOMAIN\",\"per_page\":100}" \
            "https://search.censys.io/api/v2/hosts/search" 2>/dev/null || echo "")

        if [[ -n "$censys_result" ]] && command -v jq &>/dev/null; then
            local ips
            ips=$(echo "$censys_result" | jq -r '.result.hits[].ip' 2>/dev/null || true)
            add_ips_from_var "$ips" "censys-cert"
        fi
    fi
}

# ── Module 6: Shodan ─────────────────────────────────────────────────────
module_shodan() {
    if [[ -z "$SHODAN_KEY" ]]; then return; fi
    log "Module: Shodan search..."

    # SSL cert search
    local result
    result=$(curl -sf --max-time 20 \
        "https://api.shodan.io/shodan/host/search?key=$SHODAN_KEY&query=ssl:$DOMAIN" 2>/dev/null || echo "")
    if [[ -n "$result" ]] && command -v jq &>/dev/null; then
        local ips
        ips=$(echo "$result" | jq -r '.matches[].ip_str' 2>/dev/null || true)
        add_ips_from_var "$ips" "shodan-ssl"
    fi

    # Hostname search
    result=$(curl -sf --max-time 20 \
        "https://api.shodan.io/shodan/host/search?key=$SHODAN_KEY&query=hostname:$DOMAIN" 2>/dev/null || echo "")
    if [[ -n "$result" ]] && command -v jq &>/dev/null; then
        local ips
        ips=$(echo "$result" | jq -r '.matches[].ip_str' 2>/dev/null || true)
        add_ips_from_var "$ips" "shodan-hostname"
    fi

    # Org search
    if [[ -n "$ORG_NAME" ]]; then
        result=$(curl -sf --max-time 20 \
            "https://api.shodan.io/shodan/host/search?key=$SHODAN_KEY&query=org:%22${ORG_NAME// /%20}%22" 2>/dev/null || echo "")
        if [[ -n "$result" ]] && command -v jq &>/dev/null; then
            local ips
            ips=$(echo "$result" | jq -r '.matches[].ip_str' 2>/dev/null || true)
            add_ips_from_var "$ips" "shodan-org"
        fi
    fi

    # HTTP title search
    result=$(curl -sf --max-time 20 \
        "https://api.shodan.io/shodan/host/search?key=$SHODAN_KEY&query=http.title:%22$DOMAIN%22" 2>/dev/null || echo "")
    if [[ -n "$result" ]] && command -v jq &>/dev/null; then
        local ips
        ips=$(echo "$result" | jq -r '.matches[].ip_str' 2>/dev/null || true)
        add_ips_from_var "$ips" "shodan-title"
    fi
}

# ── Module 7: Censys host search ─────────────────────────────────────────
module_censys() {
    if [[ -z "$CENSYS_CREDS" ]]; then return; fi
    log "Module: Censys host search..."

    local censys_id="${CENSYS_CREDS%%:*}"
    local censys_secret="${CENSYS_CREDS#*:}"

    local result
    result=$(curl -sf --max-time 20 \
        -u "$censys_id:$censys_secret" \
        -H "Content-Type: application/json" \
        -d "{\"q\":\"dns.names: $DOMAIN\",\"per_page\":100}" \
        "https://search.censys.io/api/v2/hosts/search" 2>/dev/null || echo "")

    if [[ -n "$result" ]] && command -v jq &>/dev/null; then
        local ips
        ips=$(echo "$result" | jq -r '.result.hits[].ip' 2>/dev/null || true)
        add_ips_from_var "$ips" "censys-host"
    fi
}

# ── Module 8: WHOIS / ASN / Netblock ─────────────────────────────────────
module_whois_asn() {
    log "Module: WHOIS / ASN / Netblock discovery..."

    if [[ -n "$ORG_NAME" ]]; then
        local org_encoded="${ORG_NAME// /%20}"

        # BGPView: org → ASN → prefixes
        local bgp_result
        bgp_result=$(curl -sf --max-time 15 \
            "https://api.bgpview.io/search?query_term=$org_encoded" 2>/dev/null || echo "")

        if [[ -n "$bgp_result" ]] && command -v jq &>/dev/null; then
            local asns
            asns=$(echo "$bgp_result" | jq -r '.data.asns[]?.asn' 2>/dev/null || true)

            for asn in $asns; do
                vlog "  Found ASN: AS$asn"
                local prefixes_json
                prefixes_json=$(curl -sf --max-time 15 \
                    "https://api.bgpview.io/asn/$asn/prefixes" 2>/dev/null || echo "")
                if [[ -n "$prefixes_json" ]]; then
                    local prefixes
                    prefixes=$(echo "$prefixes_json" | jq -r '.data.ipv4_prefixes[]?.prefix' 2>/dev/null || true)
                    for prefix in $prefixes; do
                        local net_ip="${prefix%/*}"
                        add_ip "$net_ip" "asn-$asn"
                        # Also try .1 and .2
                        IFS='.' read -r a b c d <<< "$net_ip"
                        add_ip "$a.$b.$c.1" "asn-$asn"
                        add_ip "$a.$b.$c.2" "asn-$asn"
                    done
                fi
            done
        fi
    fi
}

# ── Module 9: HTTP header leak detection ─────────────────────────────────
module_http_headers() {
    log "Module: HTTP header analysis..."

    local headers
    headers=$(curl -sI --max-time 10 -L "https://$DOMAIN" 2>/dev/null || true)

    # Extract any raw IPs from headers
    local leaked_ips
    leaked_ips=$(echo "$headers" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' || true)
    add_ips_from_var "$leaked_ips" "http-header-leak"

    # Also try HTTP (non-SSL) — sometimes origin leaks there
    headers=$(curl -sI --max-time 10 -L "http://$DOMAIN" 2>/dev/null || true)
    leaked_ips=$(echo "$headers" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' || true)
    add_ips_from_var "$leaked_ips" "http-header-leak-plain"
}

# ── Module 10: SecurityTrails org + associated domains ───────────────────
module_securitytrails_org() {
    if [[ -z "$SECURITYTRAILS_KEY" ]]; then return; fi
    log "Module: SecurityTrails current + associated domains..."

    # Current DNS
    local st_dns
    st_dns=$(curl -sf --max-time 15 -H "APIKEY: $SECURITYTRAILS_KEY" \
        "https://api.securitytrails.com/v1/domain/$DOMAIN" 2>/dev/null || echo "")
    if [[ -n "$st_dns" ]] && command -v jq &>/dev/null; then
        local ips
        ips=$(echo "$st_dns" | jq -r '.current_dns.a.values[].ip' 2>/dev/null || true)
        add_ips_from_var "$ips" "securitytrails-current"

        # MX from SecurityTrails
        local mx_hosts
        mx_hosts=$(echo "$st_dns" | jq -r '.current_dns.mx.values[].hostname' 2>/dev/null || true)
        for mxh in $mx_hosts; do
            echo "$mxh" | grep -qiE '(google|outlook|microsoft)' && continue
            local mx_ips
            mx_ips=$(dig +short A "$mxh" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' || true)
            add_ips_from_var "$mx_ips" "securitytrails-mx"
        done
    fi

    # Associated domains
    local st_assoc
    st_assoc=$(curl -sf --max-time 15 -H "APIKEY: $SECURITYTRAILS_KEY" \
        "https://api.securitytrails.com/v1/domain/$DOMAIN/associated" 2>/dev/null || echo "")
    if [[ -n "$st_assoc" ]] && command -v jq &>/dev/null; then
        local hostnames
        hostnames=$(echo "$st_assoc" | jq -r '.records[]?.hostname' 2>/dev/null || true)
        for hostname in $hostnames; do
            local ips
            ips=$(dig +short +time=2 +tries=1 A "$hostname" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' || true)
            add_ips_from_var "$ips" "securitytrails-assoc:$hostname"
        done
    fi
}

# ── Module 11: Passive DNS sources ───────────────────────────────────────
module_passive_dns() {
    log "Module: Passive DNS sources..."

    # VirusTotal
    local vt
    vt=$(curl -sf --max-time 15 \
        "https://www.virustotal.com/ui/domains/$DOMAIN/resolutions?limit=40" 2>/dev/null || echo "")
    if [[ -n "$vt" ]] && command -v jq &>/dev/null; then
        local ips
        ips=$(echo "$vt" | jq -r '.data[]?.attributes?.ip_address // empty' 2>/dev/null || true)
        add_ips_from_var "$ips" "virustotal-pdns"
    fi

    # ThreatMiner
    local tm
    tm=$(curl -sf --max-time 15 \
        "https://api.threatminer.org/v2/domain.php?q=$DOMAIN&rt=2" 2>/dev/null || echo "")
    if [[ -n "$tm" ]] && command -v jq &>/dev/null; then
        local ips
        ips=$(echo "$tm" | jq -r '.results[]?' 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' || true)
        add_ips_from_var "$ips" "threatminer"
    fi

    # AlienVault OTX passive DNS IPs
    local otx
    otx=$(curl -sf --max-time 15 \
        "https://otx.alienvault.com/api/v1/indicators/domain/$DOMAIN/passive_dns" 2>/dev/null || echo "")
    if [[ -n "$otx" ]] && command -v jq &>/dev/null; then
        local ips
        ips=$(echo "$otx" | jq -r '.passive_dns[].address // empty' 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' || true)
        add_ips_from_var "$ips" "otx-pdns"
    fi
}

# ── Module 12: Reverse PTR correlation ───────────────────────────────────
module_reverse_dns() {
    log "Module: Reverse DNS PTR correlation..."
    if ! command -v dig &>/dev/null; then return; fi
    if [[ ! -s "$ALL_IPS_FILE" ]]; then return; fi

    local unique_ips
    unique_ips=$(sort -u "$ALL_IPS_FILE")

    for ip in $unique_ips; do
        local ptr
        ptr=$(dig +short +time=2 +tries=1 -x "$ip" 2>/dev/null | head -1 | sed 's/\.$//' || true)
        if [[ -n "$ptr" ]]; then
            # Check if PTR matches our domain
            if echo "$ptr" | grep -qi "${DOMAIN}"; then
                vlog "  PTR match: $ip → $ptr"
                add_ip "$ip" "ptr-match"
            fi
            # Also check if PTR resolves to same IP (consistency check)
            # Skip CDN PTR patterns
            if echo "$ptr" | grep -qiE '(cloudflare|cloudfront|akamai|fastly|incapsula|sucuri|edgecast|cdn)'; then
                vlog "  PTR indicates CDN: $ip → $ptr"
            fi
        fi
    done
}

# ── Module 13: Favicon hash (Shodan) ─────────────────────────────────────
module_favicon_hash() {
    if [[ -z "$SHODAN_KEY" ]]; then return; fi
    if ! command -v python3 &>/dev/null; then return; fi
    log "Module: Favicon hash matching..."

    local fav_hash
    fav_hash=$(python3 -c "
import urllib.request, base64, hashlib, struct, sys
try:
    import mmh3
    data = urllib.request.urlopen('https://$DOMAIN/favicon.ico', timeout=10).read()
    encoded = base64.encodebytes(data).decode()
    print(mmh3.hash(encoded))
except ImportError:
    # No mmh3 — skip
    pass
except:
    pass
" 2>/dev/null || echo "")

    if [[ -n "$fav_hash" && "$fav_hash" != "0" ]]; then
        ok "  Favicon hash: $fav_hash"
        local result
        result=$(curl -sf --max-time 20 \
            "https://api.shodan.io/shodan/host/search?key=$SHODAN_KEY&query=http.favicon.hash:$fav_hash" 2>/dev/null || echo "")
        if [[ -n "$result" ]] && command -v jq &>/dev/null; then
            local ips
            ips=$(echo "$result" | jq -r '.matches[].ip_str' 2>/dev/null || true)
            add_ips_from_var "$ips" "favicon-hash"
        fi
    fi
}

# ── Module 14: Reverse IP verification ───────────────────────────────────
module_reverse_verify() {
    log "Module: Reverse HTTP verification of candidate IPs..."
    if [[ ! -s "$ALL_IPS_FILE" ]]; then return; fi

    # Only verify the filtered (non-CDN) set
    local candidates
    if [[ -s "$FILTERED_IPS_FILE" ]]; then
        candidates=$(cat "$FILTERED_IPS_FILE")
    else
        return
    fi

    local verified_file="$TMPDIR_BASE/verified.txt"
    touch "$verified_file"

    for ip in $candidates; do
        # Send request with Host header to see if IP serves our domain
        local code
        code=$(curl -sf -o /dev/null -w "%{http_code}" \
            --max-time 5 --connect-timeout 3 \
            -H "Host: $DOMAIN" -k "https://$ip/" 2>/dev/null || echo "000")

        if [[ "$code" == "000" ]]; then
            code=$(curl -sf -o /dev/null -w "%{http_code}" \
                --max-time 5 --connect-timeout 3 \
                -H "Host: $DOMAIN" "http://$ip/" 2>/dev/null || echo "000")
        fi

        if [[ "$code" != "000" ]]; then
            vlog "  Verified: $ip (HTTP $code)"
            echo "$ip" >> "$verified_file"
        fi
    done

    if [[ -s "$verified_file" ]]; then
        local verified_count
        verified_count=$(wc -l < "$verified_file" | xargs)
        ok "  $verified_count IPs responded with Host: $DOMAIN"
        # Replace filtered with verified for higher confidence
        cp "$verified_file" "${FILTERED_IPS_FILE}.verified"
    fi
}

# ============================================================================
# FILTERING — Python-based, fast and accurate
# ============================================================================
filter_ips() {
    log "Filtering CDN/WAF IPs for true positives..."

    if [[ ! -s "$ALL_IPS_FILE" ]]; then
        err "No IPs were collected by any module."
        warn "Debug: checking if file exists and has content..."
        ls -la "$ALL_IPS_FILE" 2>/dev/null || true
        return 1
    fi

    local total_before
    total_before=$(sort -u "$ALL_IPS_FILE" | wc -l | xargs)
    log "  Candidate IPs before filtering: $total_before"

    # Use Python for reliable CIDR matching
    if command -v python3 &>/dev/null; then
        python3 "$FILTER_SCRIPT" "$CDN_RANGES_FILE" "$ALL_IPS_FILE" > "$FILTERED_IPS_FILE" 2>/dev/null
    else
        # Fallback: just deduplicate, skip CIDR filtering
        warn "Python3 not available — skipping CDN CIDR filtering (results may include CDN IPs)"
        sort -u "$ALL_IPS_FILE" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' > "$FILTERED_IPS_FILE"
    fi

    # Secondary PTR-based CDN filter
    if command -v dig &>/dev/null && [[ -s "$FILTERED_IPS_FILE" ]]; then
        local ptr_filtered="$TMPDIR_BASE/ptr_filtered.txt"
        touch "$ptr_filtered"
        while IFS= read -r ip; do
            local ptr
            ptr=$(dig +short +time=2 +tries=1 -x "$ip" 2>/dev/null | head -1 || true)
            if echo "$ptr" | grep -qiE '(cloudflare|cloudfront|akamai|fastly|incapsula|sucuri|stackpath|edgecast|limelight|maxcdn|cdn77|bunnycdn|netlify\.com\.|vercel\.com\.|herokuapp\.com\.)'; then
                vlog "  Filtered by PTR: $ip → $ptr"
            else
                echo "$ip" >> "$ptr_filtered"
            fi
        done < "$FILTERED_IPS_FILE"
        mv "$ptr_filtered" "$FILTERED_IPS_FILE"
    fi

    sort -u -o "$FILTERED_IPS_FILE" "$FILTERED_IPS_FILE"
    local total_after
    total_after=$(wc -l < "$FILTERED_IPS_FILE" | xargs)
    ok "Filtering complete: $total_before candidates → $total_after true-positive IPs"
}

# ============================================================================
# MAIN
# ============================================================================
main() {
    echo ""
    echo -e "${BOLD}╔══════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${BOLD}║   Origin IP Finder — True-Positive IP Enumerator v2     ║${RESET}"
    echo -e "${BOLD}╚══════════════════════════════════════════════════════════╝${RESET}"
    echo ""

    while getopts "d:o:k:c:s:v:f:Vh" opt; do
        case "$opt" in
            d) DOMAIN="$OPTARG" ;;
            o) ORG_NAME="$OPTARG" ;;
            k) SHODAN_KEY="$OPTARG" ;;
            c) CENSYS_CREDS="$OPTARG" ;;
            s) SECURITYTRAILS_KEY="$OPTARG" ;;
            v) VIEWDNS_KEY="$OPTARG" ;;
            f) OUTPUT_FILE="$OPTARG" ;;
            V) VERBOSE=1 ;;
            h) usage ;;
            *) usage ;;
        esac
    done

    if [[ -z "$DOMAIN" ]]; then
        err "Domain is required. Use -d <domain>"
        usage
    fi

    # Normalize domain
    DOMAIN=$(echo "$DOMAIN" | sed 's|https\?://||;s|/.*||;s|^www\.||')

    # Default output file
    if [[ -z "$OUTPUT_FILE" ]]; then
        OUTPUT_FILE="${DOMAIN//\./_}_ips.txt"
    fi

    log "Target: $DOMAIN"
    [[ -n "$ORG_NAME" ]] && log "Organization: $ORG_NAME"
    log "Output: $OUTPUT_FILE"
    echo ""

    # Initialize
    touch "$ALL_IPS_FILE"
    install_deps
    detect_org_name
    build_cdn_ranges

    echo ""
    log "Running enumeration modules..."
    echo "──────────────────────────────────────────────────────────"

    module_dns_direct
    module_dns_records
    module_subdomains
    module_dns_history
    module_cert_transparency
    module_shodan
    module_censys
    module_whois_asn
    module_http_headers
    module_securitytrails_org
    module_passive_dns
    module_reverse_dns
    module_favicon_hash

    echo "──────────────────────────────────────────────────────────"
    echo ""

    # Show raw collection stats
    if [[ -s "$ALL_IPS_FILE" ]]; then
        local raw_count
        raw_count=$(sort -u "$ALL_IPS_FILE" | wc -l | xargs)
        log "Raw IPs collected: $raw_count"
    else
        err "No IPs were collected. Possible causes:"
        err "  - Domain doesn't resolve / doesn't exist"
        err "  - Network issues (check connectivity)"
        err "  - All DNS queries timed out"
        echo ""
        exit 1
    fi

    # Filter
    filter_ips

    # Reverse verification (optional — makes results higher confidence)
    module_reverse_verify

    echo ""

    # Output results
    if [[ -s "$FILTERED_IPS_FILE" ]]; then
        local final_count
        final_count=$(wc -l < "$FILTERED_IPS_FILE" | xargs)

        echo -e "${BOLD}══════════════════════════════════════════════════════════${RESET}"
        echo -e "${GREEN}${BOLD} TRUE-POSITIVE ORIGIN IPs ($final_count found):${RESET}"
        echo -e "${BOLD}══════════════════════════════════════════════════════════${RESET}"
        echo ""
        cat "$FILTERED_IPS_FILE"
        echo ""

        # Save to output file
        cp "$FILTERED_IPS_FILE" "$OUTPUT_FILE"
        ok "Saved to: $OUTPUT_FILE"

        # If verified subset exists, mention it
        if [[ -s "${FILTERED_IPS_FILE}.verified" ]]; then
            local v_count
            v_count=$(wc -l < "${FILTERED_IPS_FILE}.verified" | xargs)
            cp "${FILTERED_IPS_FILE}.verified" "${OUTPUT_FILE%.txt}_verified.txt"
            ok "HTTP-verified subset ($v_count IPs): ${OUTPUT_FILE%.txt}_verified.txt"
        fi

        echo ""
        ok "Usage with naabu:"
        echo "  naabu -list $OUTPUT_FILE -top-ports 1000"
        echo "  naabu -list $OUTPUT_FILE -p - -silent"
    else
        warn "No true-positive origin IPs survived filtering."
        warn "Dumping all collected IPs (pre-filter) for manual review:"
        echo ""
        sort -u "$ALL_IPS_FILE" | head -50
        sort -u "$ALL_IPS_FILE" > "${OUTPUT_FILE%.txt}_raw.txt"
        echo ""
        warn "Raw IPs saved to: ${OUTPUT_FILE%.txt}_raw.txt"
        warn "Tips: add API keys (-k, -c, -s) for deeper enumeration."
    fi

    echo ""
}

main "$@"
