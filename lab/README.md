# minisoc attack lab — DVWA + Juice Shop → live detection

A self-contained, **authorized** lab: Kali attacks two vulnerable web apps through a
logging reverse proxy; minisoc tails the proxy's access log and raises alerts in real
time. Every command below is meant to be run by hand so you can screenshot each stage.

> **Why a reverse proxy?** minisoc detects on *log files*, not the network. The nginx
> proxy writes one combined-format `access.log` containing the full request URL of every
> attack — which is exactly what the SQLi / directory-traversal / web-shell rules match
> on. Detection fires on the *attempt*, whether or not the target is actually exploited.

```
 Kali ──HTTP──> proxy :80 ─> DVWA        (host :8080)
                proxy :81 ─> Juice Shop  (host :8081)
                  │ writes lab/logs/access.log
                  ▼
        minisoc watch  ─> rich console + JSONL store ─> minisoc serve (dashboard :8000)
```

---

## 0. One-time: minisoc on the host

```bash
cd ~/Desktop/Mini-SOC
source .venv/bin/activate.fish     # bash: source .venv/bin/activate
pip install -e ".[dev]"            # if not already installed
minisoc list                       # sanity check: scenarios + loaded rules   [SCREENSHOT]
```

## 1. Bring up the targets  ▸ *victim screenshot*

```bash
docker compose -f lab/docker-compose.yml up -d
docker compose -f lab/docker-compose.yml ps          # all 4 services healthy  [SCREENSHOT]
```

- DVWA       → http://localhost:8080  (browser, optional — for a victim-app screenshot)
- Juice Shop → http://localhost:8081

First boot of DVWA: browse to it once and click **Create / Reset Database**.

## 2. Start the defender  ▸ *minisoc screenshots*

Terminals on the host (venv active):

```bash
# Terminal A — live detection on the proxy log. Leave this running; alerts print here.
minisoc watch lab/logs/access.log --source access.log         # [SCREENSHOT as alerts fire]

# Terminal B — dashboard
minisoc serve                                                 # http://127.0.0.1:8000  [SCREENSHOT]
```

**Optional — catch nmap recon too (firewall / port-scan rule).** minisoc only sees logs,
so network recon is invisible *unless* a firewall feeds it. This helper logs new inbound
connections to the lab containers and streams them to a file minisoc auto-detects as a
firewall log:

```bash
sudo lab/firewall-logging.sh up          # installs an iptables LOG rule + starts the stream

# Terminal C — note: NO --source, minisoc auto-detects the firewall format from line 1.
minisoc watch /tmp/minisoc-fw.log                             # [SCREENSHOT when scan fires]
```
Tear it down when finished: `sudo lab/firewall-logging.sh down`.

> Start `watch` **before** attacking — it processes new lines only. (Add `--from-start`
> to re-scan a log you already captured.)

## 3. Attack from Kali  ▸ *attacker screenshots*

Get a shell in the in-stack Kali (or use your own Kali on the `soclab` network; then the
target host is `proxy`, ports `80`/`81`):

```bash
docker exec -it soclab-kali bash
apt update && apt install -y curl nikto sqlmap   # first time only
```

From here `proxy` = DVWA on :80, Juice Shop on :81. Run these and watch Terminal A light up.

### 3.0 Recon — port scan (rule: *Port Scan*, T1046) — needs firewall logging from §2
```bash
nmap -sC -sV -p 80,81 proxy      # service/version probe (attacker screenshot)
nmap -p 1-1000 proxy             # sweep — 15+ SYNs from one IP trips port-scan-001
```
📸 *Terminal C shows a Port Scan alert once the sweep crosses 15 connections in a minute.*
Without §2's firewall helper running, nmap stays invisible to minisoc — that's expected.

### 3a. SQL injection (rule: *SQL Injection Attempt*, T1190)
```bash
# Boolean tautology, comment-out, union enumeration, time-based blind:
curl -s "http://proxy/login.php?id=1'%20OR%20'1'='1"                                       >/dev/null
curl -s "http://proxy/login.php?id=1'--"                                                   >/dev/null
curl -s "http://proxy/list.php?id=1%20UNION%20SELECT%20null,table_name%20FROM%20information_schema.tables" >/dev/null
curl -s "http://proxy/list.php?id=1';SELECT%20sleep(5)--"                                  >/dev/null
# Juice Shop search SQLi (payload rides in the URL):
curl -s "http://proxy:81/rest/products/search?q=apple'='"                                  >/dev/null
# Realistic, noisy version of the same — fires repeatedly:
sqlmap -u "http://proxy/vulnerabilities/sqli/?id=1&Submit=Submit" --batch --level=2 --risk=1
```

### 3b. Directory traversal (rule: *Directory Traversal Attempt*, T1083)
```bash
curl -s "http://proxy/index.php?page=../../../../etc/passwd"          >/dev/null
curl -s "http://proxy/index.php?page=..%2f..%2f..%2f..%2fetc%2fpasswd" >/dev/null
# Juice Shop's classic /ftp path traversal:
curl -s "http://proxy:81/ftp/quarantine/..%2f..%2f..%2fetc%2fpasswd"   >/dev/null
```

### 3c. Web-shell access (rule: *Web Shell Access*, T1505.003)
```bash
curl -s "http://proxy/hackable/uploads/shell.php"   >/dev/null   # DVWA upload dir
curl -s "http://proxy/files/cmd.jsp?c=whoami"        >/dev/null
```

### 3d. Kitchen-sink scanner — lots of alerts at once
```bash
nikto -h http://proxy:80      # DVWA
nikto -h http://proxy:81      # Juice Shop
```
Nikto sprays traversal, script-path, and injection probes — Terminal A will stream a burst
of SQLi / traversal / web-shell alerts. Great single screenshot of volume detection.

## 4. Portfolio extras  ▸ *more minisoc screenshots*

```bash
minisoc coverage          # MITRE ATT&CK technique coverage table        [SCREENSHOT]
minisoc triage            # open alerts queued for analyst review         [SCREENSHOT]
```

The dashboard (:8000) shows these alerts under **live** origin — split from the synthetic
training scenarios. Screenshot the alert feed, then the per-alert detail.

## 5. Tear down
```bash
docker compose -f lab/docker-compose.yml down
```

---

### Suggested screenshot set for the repo / portfolio
1. `docker compose ps` — the vulnerable stack running.
2. Kali terminal mid-attack (nikto or sqlmap output).
3. `minisoc watch` console streaming live alerts.
4. minisoc dashboard alert feed (live origin) + an alert detail.
5. `minisoc coverage` ATT&CK table.

> Detections key on the attack **URL** in the proxy log, so they fire even when the app
> rejects the request. For richer *attacker-side* screenshots (e.g. sqlmap dumping DVWA's
> database), log into DVWA first and pass `--cookie "PHPSESSID=…; security=low"` to sqlmap.
