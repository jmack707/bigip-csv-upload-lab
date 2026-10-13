#!/usr/bin/env bash
# Prepare a Linux VM for the CSV upload lab: rootless Podman for a `csvlab` account, container
# logs readable without the journal, low ports allowed, and a firewall that admits the lab
# ports only from the addresses you name.
#
#   sudo scripts/prepare-host.sh --role app --allow <bigip-self-ip>[,<more>]   # validator + application host
#   sudo scripts/prepare-host.sh --role av  --allow <bigip-self-ip>                    # antivirus host
#   sudo scripts/prepare-host.sh --role app --allow <bigip-self-ip> --check            # show what would change
#
# Tested on Ubuntu 24.04 and Debian 13 (apt). Rocky/Alma 9 (dnf) is supported but was not tested.
# Run it once as root on a fresh VM. Afterwards, as csvlab: clone or unpack the bundle and run the
# compose commands from chapter 4 of the guide.
set -euo pipefail
ROLE=""; ALLOW=""; CHECK=0; USER_NAME=csvlab
while [[ $# -gt 0 ]]; do case "$1" in
  --role) ROLE="$2"; shift 2 ;; --allow) ALLOW="$2"; shift 2 ;; --user) USER_NAME="$2"; shift 2 ;; --check) CHECK=1; shift ;;
  *) echo "unknown option $1" >&2; exit 2 ;; esac; done
case "$ROLE" in app) PORTS="1345, 8080, 8081" ;; av) PORTS="1344" ;; *) echo "--role app|av is required" >&2; exit 2 ;; esac
[[ -n "$ALLOW" ]] || { echo "--allow <BIG-IP self IP[,more]> is required (who may reach the lab ports)" >&2; exit 2; }
[[ $EUID -eq 0 || $CHECK -eq 1 ]] || { echo "run as root (sudo)" >&2; exit 2; }
run() { if [[ $CHECK -eq 1 ]]; then echo "would: $*"; else "$@"; fi; }
say() { printf '\n==> %s\n' "$*"; }

say "packages"
if command -v apt-get >/dev/null; then
  run apt-get update -qq
  run apt-get install -y -qq --no-install-recommends podman podman-compose uidmap slirp4netns catatonit nftables git curl python3 openssl
elif command -v dnf >/dev/null; then
  run dnf install -y -q podman podman-compose shadow-utils slirp4netns nftables git curl python3 openssl
else echo "neither apt-get nor dnf found" >&2; exit 1; fi

say "account $USER_NAME (rootless Podman)"
if id "$USER_NAME" >/dev/null 2>&1; then echo "exists"; else run useradd -m -s /bin/bash "$USER_NAME"; fi
if ! grep -q "^$USER_NAME:" /etc/subuid 2>/dev/null; then
  # useradd normally allocates these; add a free range if it did not.
  START=$(( $(awk -F: '{ if ($2+$3 > m) m=$2+$3 } END { print m+0 }' /etc/subuid /etc/subgid) ))
  [[ $START -lt 100000 ]] && START=100000
  run bash -c "echo '$USER_NAME:$START:65536' >> /etc/subuid; echo '$USER_NAME:$START:65536' >> /etc/subgid"
fi
run loginctl enable-linger "$USER_NAME"
HOME_DIR=$(getent passwd "$USER_NAME" | cut -d: -f6)
run install -d -o "$USER_NAME" -g "$USER_NAME" "$HOME_DIR/.config/containers"
run bash -c "printf '[containers]\nlog_driver = \"k8s-file\"\n' > '$HOME_DIR/.config/containers/containers.conf'; chown $USER_NAME:$USER_NAME '$HOME_DIR/.config/containers/containers.conf'"

say "ports below 1024 for rootless Podman (1344, 1345)"
run bash -c "echo 'net.ipv4.ip_unprivileged_port_start = 1024' > /etc/sysctl.d/90-csvlab.conf && sysctl -q -p /etc/sysctl.d/90-csvlab.conf"

say "firewall: tcp {$PORTS} from {$ALLOW}; ssh from anywhere; the rest dropped"
RULES="#!/usr/sbin/nft -f
# Managed by csv-upload-lab/scripts/prepare-host.sh
flush ruleset
table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    ct state established,related accept
    iif lo accept
    icmp type { echo-request, destination-unreachable, time-exceeded } accept
    tcp dport 22 accept
    ip saddr { $ALLOW } tcp dport { $PORTS } accept
  }
  chain forward { type filter hook forward priority 0; policy accept; }
  chain output  { type filter hook output  priority 0; policy accept; }
}"
if [[ $CHECK -eq 1 ]]; then echo "would write /etc/nftables.conf:"; echo "$RULES" | sed 's/^/    /'; else
  printf '%s\n' "$RULES" > /etc/nftables.conf; nft -c -f /etc/nftables.conf; systemctl enable -q --now nftables; nft -f /etc/nftables.conf; fi

say "done"
cat <<MSG
Next, as the lab account:
  sudo -iu $USER_NAME
  unzip csv-upload-lab-*.zip && cd csv-upload-lab-*   (or git clone)
  role app:  scripts/gen-secret.sh && podman-compose up -d --build
  role av:   cd icap-av && podman-compose up -d --build        (add CLAMAV_DB=test on a small host)
MSG
