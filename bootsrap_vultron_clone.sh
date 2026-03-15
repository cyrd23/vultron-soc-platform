#!/usr/bin/env bash
set -euo pipefail

############################################
# Vultron full clone + deploy bootstrap
############################################

HOSTNAME_TARGET="vultron-01-dev"
SOC_DIR="${HOME}/soc"
VENV_DIR="${SOC_DIR}/.venv"
REPO_SSH_URL="${REPO_SSH_URL:-git@github.com:cyrd23/vultron-soc-platform.git}"
REPO_HTTPS_URL="${REPO_HTTPS_URL:-https://github.com/cyrd23/vultron-soc-platform.git}"
GIT_MODE="${GIT_MODE:-ssh}"   # ssh or https
OVERWRITE_CONFIGS="${OVERWRITE_CONFIGS:-0}"

log() {
  echo
  echo "[+] $1"
}

warn() {
  echo
  echo "[!] $1"
}

write_file_if_missing() {
  local path="$1"
  local content="$2"

  if [[ -f "$path" && "$OVERWRITE_CONFIGS" != "1" ]]; then
    warn "Skipping existing file: $path"
    return
  fi

  mkdir -p "$(dirname "$path")"
  cat > "$path" <<EOF
${content}
EOF
  echo "    wrote: $path"
}

clone_repo() {
  local url
  if [[ "$GIT_MODE" == "https" ]]; then
    url="$REPO_HTTPS_URL"
  else
    url="$REPO_SSH_URL"
  fi

  if [[ -d "${SOC_DIR}/.git" ]]; then
    log "Repo already exists at ${SOC_DIR}; pulling latest changes"
    git -C "${SOC_DIR}" fetch --all || true
    git -C "${SOC_DIR}" pull --ff-only || warn "Git pull failed. Resolve manually."
  else
    if [[ -d "${SOC_DIR}" && "$(ls -A "${SOC_DIR}" 2>/dev/null)" ]]; then
      warn "${SOC_DIR} exists and is not empty. Not cloning over existing files."
      warn "Move it aside or empty it first if you want a clean clone."
      return
    fi

    log "Cloning repo from ${url}"
    rm -rf "${SOC_DIR}"
    git clone "${url}" "${SOC_DIR}"
  fi
}

log "Setting hostname to ${HOSTNAME_TARGET}"
sudo hostnamectl set-hostname "${HOSTNAME_TARGET}"

if ! grep -q "${HOSTNAME_TARGET}" /etc/hosts; then
  echo "127.0.1.1 ${HOSTNAME_TARGET}" | sudo tee -a /etc/hosts >/dev/null
fi

log "Installing OS packages"
sudo apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
  git \
  curl \
  wget \
  jq \
  unzip \
  zip \
  nano \
  vim \
  tmux \
  ca-certificates \
  software-properties-common \
  build-essential \
  python3 \
  python3-pip \
  python3-venv \
  python3-dev \
  libssl-dev \
  libffi-dev

log "Cloning or updating Vultron repo"
clone_repo

log "Ensuring Vultron directory structure exists"
mkdir -p "${SOC_DIR}"/{agents,packs,reports,runs,configs,intel}
mkdir -p "${SOC_DIR}"/intel/{raw,summaries,priorities,hunt_candidates,structured,iocs,enriched,operational}
mkdir -p "${SOC_DIR}"/packs/threat_hunt_pack_library/{identity,endpoint,lateral_movement,network,dns,exposure,compound,intel_ioc,compromise_detection}

log "Creating Python virtual environment"
cd "${SOC_DIR}"
if [[ ! -d "${VENV_DIR}" ]]; then
  python3 -m venv "${VENV_DIR}"
fi

# shellcheck disable=SC1091
source "${VENV_DIR}/bin/activate"

log "Upgrading pip tooling"
python -m pip install --upgrade pip setuptools wheel

log "Installing Python packages used by Vultron"
python -m pip install \
  requests \
  urllib3 \
  feedparser \
  pyyaml \
  python-dateutil \
  elasticsearch \
  pandas \
  tqdm \
  tabulate \
  dnspython

log "Creating Elastic config template"
write_file_if_missing "${SOC_DIR}/configs/elastic.env" 'ELASTIC_URL=https://YOUR_ELASTIC_HOST:9200
ELASTIC_API_KEY=REPLACE_ME
ELASTIC_TLS_SKIP_VERIFY=true

# Intel providers
VIRUSTOTAL_API_KEY=
OTX_API_KEY=
URLVOID_API_KEY=
IPINFO=
'

log "Creating known-good IOC config"
write_file_if_missing "${SOC_DIR}/configs/known_good_iocs.yaml" 'known_good_ips:
  - 96.255.250.253

known_good_internal_ips:
  - 192.168.20.102

known_good_domains:
  - github.com
  - docs.google.com
  - drive.google.com
  - onedrive.live.com
  - cdn.jsdelivr.net
  - res.cloudinary.com
  - adclick.g.doubleclick.net
  - files.constantcontact.com
  - img1.wsimg.com
'

log "Creating intel source template"
write_file_if_missing "${SOC_DIR}/configs/intel_sources.yaml" 'rss_feeds:
  - name: SANS Internet Storm Center
    url: https://isc.sans.edu/rssfeed.xml
  - name: Google Threat Intelligence Blog
    url: https://cloud.google.com/blog/topics/threat-intelligence/rss
  - name: Microsoft Security Blog
    url: https://www.microsoft.com/security/blog/feed/
  - name: Cisco Talos Intelligence
    url: https://blog.talosintelligence.com/feeds/posts/default
  - name: Unit42
    url: https://unit42.paloaltonetworks.com/feed/
  - name: Securelist
    url: https://securelist.com/feed/
  - name: Check Point Research
    url: https://research.checkpoint.com/feed/
  - name: FortiGuard Labs
    url: https://www.fortiguard.com/rss-feeds
  - name: Proofpoint
    url: https://www.proofpoint.com/us/rss.xml
  - name: The Hacker News
    url: https://feeds.feedburner.com/TheHackersNews
  - name: Dark Reading
    url: https://www.darkreading.com/rss.xml
  - name: BleepingComputer
    url: https://www.bleepingcomputer.com/feed
  - name: SecurityWeek
    url: https://www.securityweek.com/feed
  - name: The CyberWire
    url: https://thecyberwire.com/rss
  - name: Krebs on Security
    url: https://krebsonsecurity.com/feed/
'

log "Creating dataset config template"
write_file_if_missing "${SOC_DIR}/configs/datasets.yaml" 'azure_signin: azure.signinlogs
azure_audit: azure.auditlogs
azure_provisioning: azure.provisioning
o365: o365.audit
crowdstrike: crowdstrike.fdr
fortigate: fortinet_fortigate.log
zeek_dns: zeek.dns
zeek_conn: zeek.connection
umbrella: cisco_umbrella.log
tenable_vuln: tenable_io.vulnerability
tenable_asset: tenable_io.asset
'

log "Creating helper env loader"
write_file_if_missing "${SOC_DIR}/load_vultron_env.sh" '#!/usr/bin/env bash
set -euo pipefail
source "${HOME}/soc/.venv/bin/activate"
set -a
source "${HOME}/soc/configs/elastic.env"
set +a
echo "Vultron environment loaded."
'
chmod +x "${SOC_DIR}/load_vultron_env.sh"

log "Adding shell aliases"
if ! grep -q "alias vultron-env=" "${HOME}/.bashrc"; then
  cat >> "${HOME}/.bashrc" <<'EOF'

# Vultron helpers
alias vultron-env='source ~/soc/load_vultron_env.sh'
alias vultron-run='python ~/soc/agents/vultron_orchestrator.py'
alias vultron-fast='python ~/soc/agents/vultron_orchestrator.py --skip-intel --category intel_ioc --category compromise_detection'
EOF
fi

log "Creating reports and runs directories"
mkdir -p "${SOC_DIR}/reports" "${SOC_DIR}/runs"

log "Showing repo status"
git -C "${SOC_DIR}" status || true

cat <<EOF

============================================================
Vultron clone + deploy complete

Hostname:
  $(hostname)

Repo path:
  ${SOC_DIR}

Virtualenv:
  ${VENV_DIR}

Next steps:
  1. Add real values to:
     ${SOC_DIR}/configs/elastic.env

  2. Load environment:
     source ${SOC_DIR}/load_vultron_env.sh

  3. Run a fast test:
     python ${SOC_DIR}/agents/vultron_orchestrator.py --skip-intel --category intel_ioc --category compromise_detection

  4. If SSH clone failed, either:
     - add your SSH key to GitHub and rerun, or
     - rerun with:
       GIT_MODE=https ./bootstrap_vultron_clone.sh

============================================================
EOF
