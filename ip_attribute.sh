#!/usr/bin/env bash
#
# ip_attribute.sh -- confirm which IPs in a list belong to a target organization.
#
# PURPOSE: scope validation for AUTHORIZED bug bounty / pentest work. Before you
# touch a host, prove it is actually the target org's asset. This script does that
# from OWNERSHIP metadata, so you don't test third-party systems by mistake.
#
# DEFAULT MODE IS PASSIVE: it only queries registries/DNS (whois, RDAP, Team Cymru,
# reverse DNS). It does NOT connect to the target hosts. Add --active to also grab
# TLS cert CN/SAN and HTTP title (those DO touch the host -- use only in scope).
#
# INPUT : a file of IPs (one per line; CIDRs and "ip,anything" also tolerated).
# OUTPUT: <out>_confirmed.txt   -> IPs attributed to the org (one per line)
#         <out>_review.txt      -> IPs with a partial/uncertain match
#         <out>_report.csv      -> full evidence per IP
#
# MATCH SIGNALS (each independent hit raises confidence):
#   * Team Cymru ASN + AS name
#   * RDAP org name / netname / entity (org handle) names
#   * Reverse DNS (PTR) hostname
#   * [--active] TLS certificate CN / SAN
#   * [--active] HTTP redirect host / <title>
#   * Explicit --asn and --domain allowlists you supply
#
# Usage:
#   ./ip_attribute.sh -i ips.txt -o "Acme,Acme Corp,AS12345" \
#        --domain acme.com,acme.net --asn 12345,67890 -o-file acme -p 5
#   ./ip_attribute.sh -i ips.txt -o "Acme" --active        # also fingerprint hosts
#
set -uo pipefail

# ---------------- defaults ----------------
IPFILE=""
ORG_KEYWORDS=""
DOMAINS=""
ASNS=""
OUT="attribution"
PARALLEL=5
ACTIVE=0
MIN_CONFIRM=2          # independent signals needed to mark CONFIRMED
TIMEOUT=8

usage() { grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 1; }

# ---------------- args --------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    -i) IPFILE="$2"; shift 2;;
    -o|--org) ORG_KEYWORDS="$2"; shift 2;;
    --domain) DOMAINS="$2"; shift 2;;
    --asn) ASNS="$2"; shift 2;;
    --out|-o-file) OUT="$2"; shift 2;;
    -p|--parallel) PARALLEL="$2"; shift 2;;
    --active) ACTIVE=1; shift;;
    --min-confirm) MIN_CONFIRM="$2"; shift 2;;
    -h|--help) usage;;
    *) echo "unknown arg: $1"; usage;;
  esac
done

[[ -z "$IPFILE" || -z "$ORG_KEYWORDS" ]] && { echo "ERROR: -i <ipfile> and -o <org keywords> are required."; usage; }
[[ -f "$IPFILE" ]] || { echo "ERROR: file not found: $IPFILE"; exit 1; }

# ---------------- dependency check --------
have() { command -v "$1" >/dev/null 2>&1; }
for t in whois curl awk sed grep sort; do
  have "$t" || echo "WARN: '$t' not found -- some checks will be skipped." >&2
done
JQ=0; have jq && JQ=1
DIG=0; have dig && DIG=1
HOSTC=0; have host && HOSTC=1
OSSL=0; have openssl && OSSL=1

# ---------------- helpers -----------------
# lowercase, strip punctuation to spaces for robust keyword matching
norm() { echo "$1" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9' ' ' | tr -s ' '; }

NORM_KEYS="$(norm "$ORG_KEYWORDS")"
NORM_DOMAINS="$(echo "$DOMAINS" | tr '[:upper:]' '[:lower:]' | tr ',' ' ')"
NORM_ASNS="$(echo "$ASNS" | tr -c '0-9' ' ' | tr -s ' ')"

# does haystack contain any org keyword?
key_hit() {
  local hay; hay="$(norm "$1")"
  local k
  for k in $NORM_KEYS; do
    [[ ${#k} -ge 3 ]] || continue          # skip 1-2 char noise tokens
    if [[ " $hay " == *" $k "* ]]; then echo "$k"; return 0; fi
  done
  # domain match (substring ok, e.g. acme.com in PTR)
  for d in $NORM_DOMAINS; do
    [[ -n "$d" ]] || continue
    if [[ "$(echo "$1" | tr '[:upper:]' '[:lower:]')" == *"$d"* ]]; then echo "$d"; return 0; fi
  done
  return 1
}

asn_hit() {
  local a="$1"
  for want in $NORM_ASNS; do
    [[ "$a" == "$want" ]] && { echo "AS$want"; return 0; }
  done
  return 1
}

# --------- per-IP attribution routine -----
attribute_ip() {
  local ip="$1"
  ip="${ip%%[,/]*}"                              # strip CIDR / trailing csv
  ip="$(echo "$ip" | tr -d '[:space:]')"
  [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "$ip,,,,,,SKIP_INVALID,0"; return; }

  local asn="" asname="" prefix="" cc="" netname="" org="" ptr="" cert="" htitle=""
  local -a signals=()

  # 1) Team Cymru: ASN + AS name + prefix + country (passive, no host contact).
  #    Prefer whois; fall back to Cymru's DNS interface when whois is absent.
  local cymru
  if have whois; then
    cymru="$(whois -h whois.cymru.com " -v $ip" 2>/dev/null | awk 'NR==2')"
    if [[ -n "$cymru" ]]; then
      asn="$(echo    "$cymru" | awk -F'|' '{gsub(/ /,"",$1);print $1}')"
      prefix="$(echo "$cymru" | awk -F'|' '{gsub(/^ +| +$/,"",$3);print $3}')"
      cc="$(echo     "$cymru" | awk -F'|' '{gsub(/ /,"",$4);print $4}')"
      asname="$(echo "$cymru" | awk -F'|' '{gsub(/^ +| +$/,"",$7);print $7}')"
    fi
  fi
  if [[ -z "$asn" && $DIG -eq 1 ]]; then
    # Cymru DNS: d.c.b.a.origin.asn.cymru.com TXT -> "ASN | Prefix | CC | Registry | Alloc"
    local rev; rev="$(echo "$ip" | awk -F. '{print $4"."$3"."$2"."$1}')"
    local otxt; otxt="$(dig +short TXT "${rev}.origin.asn.cymru.com" 2>/dev/null | tr -d '"' | head -1)"
    if [[ -n "$otxt" ]]; then
      asn="$(echo    "$otxt" | awk -F'|' '{gsub(/ /,"",$1);print $1}')"
      prefix="$(echo "$otxt" | awk -F'|' '{gsub(/^ +| +$/,"",$2);print $2}')"
      cc="$(echo     "$otxt" | awk -F'|' '{gsub(/ /,"",$3);print $3}')"
      # AS name: ASxxxx.asn.cymru.com TXT -> "ASN | CC | Registry | Alloc | AS Name"
      if [[ -n "$asn" ]]; then
        asname="$(dig +short TXT "AS${asn}.asn.cymru.com" 2>/dev/null | tr -d '"' | awk -F'|' '{gsub(/^ +| +$/,"",$5);print $5}' | head -1)"
      fi
    fi
  fi

  # 2) RDAP: structured registration data (passive)
  local rdap
  rdap="$(curl -s -m "$TIMEOUT" -H 'Accept: application/json' "https://rdap.org/ip/$ip" 2>/dev/null)"
  if [[ -n "$rdap" ]]; then
    if [[ $JQ -eq 1 ]]; then
      netname="$(echo "$rdap" | jq -r '.name // empty' 2>/dev/null)"
      org="$(echo "$rdap" | jq -r '[.. | objects | select(.roles? and ((.roles|index("registrant")) or (.roles|index("administrative")))) | (.vcardArray[1][]? | select(.[0]=="fn") | .[3])] | first // empty' 2>/dev/null)"
      [[ -z "$org" ]] && org="$(echo "$rdap" | jq -r '[.entities[]?.vcardArray[1][]? | select(.[0]=="fn") | .[3]] | first // empty' 2>/dev/null)"
    else
      netname="$(echo "$rdap" | grep -o '"name":"[^"]*"' | head -1 | cut -d'"' -f4)"
      org="$(echo "$rdap" | grep -o '"fn","text","[^"]*"' | head -1 | awk -F'","' '{print $3}' | tr -d '"')"
    fi
  fi

  # 3) Reverse DNS PTR (passive DNS query, not the host)
  if [[ $DIG -eq 1 ]]; then
    ptr="$(dig +short -x "$ip" 2>/dev/null | head -1 | sed 's/\.$//')"
  elif [[ $HOSTC -eq 1 ]]; then
    ptr="$(host "$ip" 2>/dev/null | awk '/pointer|domain name pointer/{print $NF}' | head -1 | sed 's/\.$//')"
  fi

  # 4) ACTIVE fingerprints (contact the host) -- only with --active
  if [[ $ACTIVE -eq 1 ]]; then
    if [[ $OSSL -eq 1 ]]; then
      cert="$(echo | timeout "$TIMEOUT" openssl s_client -connect "$ip:443" -servername "$ip" 2>/dev/null \
              | openssl x509 -noout -subject -ext subjectAltName 2>/dev/null \
              | tr '\n' ' ' | sed 's/,/ /g')"
    fi
    htitle="$(curl -s -m "$TIMEOUT" -I "http://$ip:80" 2>/dev/null | tr -d '\r' | awk -F': ' 'tolower($1)=="location"{print $2}' | head -1)"
    [[ -z "$htitle" ]] && htitle="$(curl -s -m "$TIMEOUT" "http://$ip" 2>/dev/null | grep -o -i '<title>[^<]*' | head -1 | sed 's/<title>//I')"
  fi

  # ---------- sanitize (never let lookup errors leak into fields) ----------
  [[ "$asn" =~ ^[0-9]+$ ]] || asn=""                      # ASN must be numeric
  # PTR must look like a hostname, not a resolver error string
  if [[ -n "$ptr" ]]; then
    if [[ "$ptr" == *" "* || "$ptr" == *";;"* || ! "$ptr" =~ ^[A-Za-z0-9._-]+$ ]]; then ptr=""; fi
  fi
  # org/netname/asname: blank out obvious error noise
  for v in asname netname org; do
    case "${!v}" in *";; "*|*"network unreachable"*|*"connection timed out"*) printf -v "$v" '%s' "";; esac
  done

  # ---------- scoring ----------
  local m
  if m="$(asn_hit "$asn")";           then signals+=("ASN:$m"); fi
  if m="$(key_hit "$asname")";        then signals+=("ASname:$m"); fi
  if m="$(key_hit "$netname")";       then signals+=("netname:$m"); fi
  if m="$(key_hit "$org")";           then signals+=("rdaporg:$m"); fi
  if [[ -n "$ptr" ]] && m="$(key_hit "$ptr")"; then signals+=("PTR:$m"); fi
  if [[ $ACTIVE -eq 1 ]]; then
    if [[ -n "$cert" ]]  && m="$(key_hit "$cert")";   then signals+=("cert:$m"); fi
    if [[ -n "$htitle" ]] && m="$(key_hit "$htitle")"; then signals+=("http:$m"); fi
  fi

  local score=${#signals[@]}
  local verdict="NO_MATCH"
  if   [[ $score -ge $MIN_CONFIRM ]]; then verdict="CONFIRMED"
  elif [[ $score -ge 1 ]];           then verdict="REVIEW"
  fi

  local sigstr; sigstr="$(IFS=';'; echo "${signals[*]:-}")"
  # CSV-safe fields
  csv() { echo "$1" | sed 's/"/""/g; s/,/;/g' | tr -d '\n'; }
  echo "$ip,$asn,\"$(csv "$asname")\",\"$(csv "$netname")\",\"$(csv "$org")\",\"$(csv "$ptr")\",\"$(csv "$sigstr")\",$verdict,$score"
}
export -f attribute_ip norm key_hit asn_hit have
export NORM_KEYS NORM_DOMAINS NORM_ASNS JQ DIG HOSTC OSSL ACTIVE TIMEOUT MIN_CONFIRM

# ---------------- run ---------------------
echo "[+] Attributing IPs in '$IPFILE' to org keywords: $ORG_KEYWORDS"
[[ -n "$DOMAINS" ]] && echo "    domains: $DOMAINS"
[[ -n "$ASNS" ]]    && echo "    ASNs   : $ASNS"
echo "[+] Mode: $([[ $ACTIVE -eq 1 ]] && echo 'ACTIVE (contacts hosts)' || echo 'PASSIVE (registry/DNS only)') | parallel=$PARALLEL | min-confirm=$MIN_CONFIRM"
echo

REPORT="${OUT}_report.csv"
echo 'ip,asn,as_name,netname,rdap_org,ptr,matched_signals,verdict,score' > "$REPORT"

# clean, unique, valid-ish IP lines -> parallel attribution
grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' "$IPFILE" | sort -u \
  | xargs -P "$PARALLEL" -I{} bash -c 'attribute_ip "$@"' _ {} \
  | sort -t',' -k9,9nr >> "$REPORT"

# split outputs
awk -F',' 'NR>1 && $(NF-1)=="CONFIRMED"{print $1}' "$REPORT" | sort -u > "${OUT}_confirmed.txt"
awk -F',' 'NR>1 && $(NF-1)=="REVIEW"{print $1}'    "$REPORT" | sort -u > "${OUT}_review.txt"

C=$(wc -l < "${OUT}_confirmed.txt" | tr -d ' ')
R=$(wc -l < "${OUT}_review.txt" | tr -d ' ')
T=$(( $(wc -l < "$REPORT" | tr -d ' ') - 1 ))
echo
echo "[=] Processed:  $T IPs"
echo "[=] CONFIRMED:  $C  -> ${OUT}_confirmed.txt   (>= $MIN_CONFIRM independent signals)"
echo "[=] REVIEW:     $R  -> ${OUT}_review.txt      (1 signal -- verify manually)"
echo "[=] Evidence :  $REPORT"
echo
echo "NOTE: CONFIRMED = ownership metadata matches. Still cross-check each IP against the"
echo "      program's explicit in-scope list before testing. Registration data can lag reality."
