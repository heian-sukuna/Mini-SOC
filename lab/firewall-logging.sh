#!/usr/bin/env bash
# Firewall logging for the minisoc lab — makes nmap recon visible to the port-scan rule.
#
# It installs an iptables LOG rule on Docker's DOCKER-USER chain (the chain Docker
# reserves for user rules, so it survives reloads and isn't clobbered). Every NEW inbound
# TCP SYN forwarded to a lab container is logged to the kernel log; we stream those lines
# to a file in syslog format, which minisoc's firewall parser reads. An nmap scan from
# Kali sprays SYNs across many ports — 15+ from one source IP in a minute trips
# `port-scan-001` (MITRE T1046).
#
#   sudo lab/firewall-logging.sh up      # add rule + start kernel-log -> file stream
#   sudo lab/firewall-logging.sh down    # remove rule + stop stream
#
# Then, in another terminal (no --source: minisoc AUTO-DETECTS the firewall format):
#   minisoc watch /tmp/minisoc-fw.log
#
# Requires: root, iptables, journalctl (systemd/Arch/CachyOS).

set -euo pipefail

PREFIX="[IPTABLES SCAN] "          # neutral prefix; parser treats it as "logged"
RULE=(-p tcp --syn -j LOG --log-prefix "$PREFIX" --log-level 4)
LOGFILE="/tmp/minisoc-fw.log"
PIDFILE="/tmp/minisoc-fw-stream.pid"

up() {
  if ! iptables -C DOCKER-USER "${RULE[@]}" 2>/dev/null; then
    iptables -I DOCKER-USER "${RULE[@]}"
  fi
  echo "[+] iptables LOG rule active on DOCKER-USER."

  : > "$LOGFILE"
  # -o short => "Mon DD HH:MM:SS host kernel: <msg>", exactly what the firewall parser wants.
  journalctl -k -f -o short | stdbuf -oL grep "IPTABLES SCAN" >> "$LOGFILE" &
  echo $! > "$PIDFILE"
  echo "[+] streaming firewall log -> $LOGFILE  (stream pid $(cat "$PIDFILE"))"
  echo
  echo "    next:  minisoc watch $LOGFILE       # auto-detects 'firewall'"
  echo "    scan:  nmap -p 1-1000 proxy         # from the Kali container"
}

down() {
  if iptables -D DOCKER-USER "${RULE[@]}" 2>/dev/null; then
    echo "[-] iptables rule removed."
  else
    echo "[-] no iptables rule to remove."
  fi
  if [[ -f "$PIDFILE" ]] && kill "$(cat "$PIDFILE")" 2>/dev/null; then
    rm -f "$PIDFILE"
    echo "[-] stream stopped."
  fi
}

case "${1:-}" in
  up)   up ;;
  down) down ;;
  *)    echo "usage: sudo $0 {up|down}"; exit 2 ;;
esac
