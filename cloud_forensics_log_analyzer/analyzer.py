# analyzer.py
import re
import json
from collections import defaultdict

# helper: is IP private/local
def is_private_ip(ip):
    if not ip: 
        return True
    try:
        if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("127."):
            return True
        if re.match(r"^172\.(1[6-9]|2[0-9]|3[0-1])\.", ip):
            return True
    except Exception:
        return True
    return False

def _add(report, name, solution, example_text):
    entry = report.setdefault(name, {"count": 0, "solution": solution, "examples": []})
    entry["count"] += 1
    # keep unique examples up to 5
    if example_text and example_text not in entry["examples"]:
        entry["examples"].append(example_text)
        if len(entry["examples"]) > 5:
            entry["examples"] = entry["examples"][:5]

def analyze_log_file(filepath):
    """
    Analyze a log file and return a report dict:
      { "Activity Name": {"count": n, "solution": "...", "examples":[...]} }
    Works for:
      - JSON array logs (each item a dict with fields like eventName/eventType/command/sourceIPAddress)
      - Plaintext logs (falls back to regex/pattern checks)
    """
    report = {}

    # read file
    try:
        with open(filepath, "r", errors="ignore") as fh:
            raw = fh.read()
    except Exception as e:
        return {"Error": {"count": 1, "solution": "Could not read file", "examples":[str(e)]}}

    # try parse JSON
    parsed = None
    try:
        parsed_json = json.loads(raw)
        # If top-level is a list of events, use that
        if isinstance(parsed_json, list):
            parsed = parsed_json
        elif isinstance(parsed_json, dict):
            # single object -> wrap as list
            parsed = [parsed_json]
    except Exception:
        parsed = None

    if parsed is not None:
        # structured JSON handling
        for item in parsed:
            # canonicalize keys
            event = { (k or "").lower(): (v if v is not None else "") for k, v in item.items() }

            ev_type = event.get("eventtype", "") or event.get("event_type", "")
            ev_name = event.get("eventname", "") or event.get("event_name", "")
            user = event.get("username", "") or event.get("user", "")
            ip = event.get("sourceipaddress", "") or event.get("source_ip_address", "") or event.get("sourceip", "")
            msg = event.get("errormessage", "") or event.get("message", "") or ""
            command = event.get("command", "") or ""
            bucket = event.get("bucketname", "") or event.get("bucket", "") or event.get("objectkey", "")

            # Failed authentication
            if "failed" in msg.lower() or ev_type.lower() in ("authentication",) and "failed" in msg.lower() or "failed" in ev_name.lower():
                _add(report, "Failed Logins", "Investigate repeated failed authentication attempts (possible brute-force).", f"{event.get('eventtime','')}: {user} {ip} {msg or ev_name}")

            # Successful login (useful to cross-check)
            if ev_name.lower().find("consolelogin") >= 0 and "error" not in msg.lower() and "failed" not in msg.lower():
                _add(report, "Successful Logins", "Review successful login events for unusual times or IPs.", f"{event.get('eventtime','')}: {user} {ip} {ev_name}")

            # Privilege escalation events
            if ev_name.lower().find("attachadminpolicy") >= 0 or ev_type.lower() in ("privilegeescalation",) or "administratoraccess" in str(event.get("policyname","")).lower():
                _add(report, "Privilege Escalation", "Privilege escalation detected. Audit IAM/sudoers and recent policy attachments.", f"{event.get('eventtime','')}: {user} {ip} {ev_name} {event.get('policyname','')}")

            # Security policy/config changes
            if ev_name.lower().find("modifysecuritygroup") >= 0 or "security" in ev_type.lower() or "config" in str(event.get("change","")).lower() or ev_name.lower().find("modify") >= 0:
                _add(report, "Security Policy Changes", "Policy/configuration changes detected. Verify whether they were authorized.", f"{event.get('eventtime','')}: {user} {ip} {event.get('change','') or ev_name}")

            # Data access (S3 GetObject or similar)
            if ev_name.lower().find("getobject") >= 0 or "dataaccess" in ev_type.lower() or bucket:
                _add(report, "Large/Unauthorized Data Access", "Large or sensitive data access detected. Verify the object and user's authorization.", f"{event.get('eventtime','')}: {user} {ip} bucket={event.get('bucketname','') or event.get('bucket','')} key={event.get('objectkey','') or event.get('object_key','')}")

            # Dangerous commands / remote shells
            if command and (re.search(r"\bnc\b.*\-e\b", command) or re.search(r"bash -i >& /dev/tcp", command) or "rm -rf" in command or "mkfs" in command):
                _add(report, "Dangerous Commands / Remote Shells", "Remote shell / destructive commands found. Isolate host and investigate the command source.", f"{event.get('eventtime','')}: {user} {ip} command={command}")

            # suspicious external IP
            if ip and not is_private_ip(ip):
                _add(report, "Suspicious IPs", "External IP seen in events. Investigate and check IP reputation.", f"{event.get('eventtime','')}: {user} {ip} {ev_name}")

            # account creation / deletion
            if ev_name.lower().find("create") >= 0 and ("user" in ev_name.lower() or "account" in ev_name.lower()):
                _add(report, "Unauthorized Account Creation/Deletion", "Account creation/deletion events detected. Verify admin actions.", f"{event.get('eventtime','')}: {user} {ip} {ev_name}")

            # resource abuse: look for keywords in eventType or command
            if "dangerouscommand" in ev_type.lower() or "dangerous" in ev_name.lower() or "mining" in command.lower() or "xmrig" in msg.lower():
                _add(report, "Resource Abuse (mining/DoS/high CPU)", "Indicators of resource abuse found. Inspect processes and network traffic.", f"{event.get('eventtime','')}: {user} {ip} {command or msg or ev_name}")

        # done parsing structured events
        return report

    # ---------- FALLBACK: treat as plain text logs ----------
    text = raw.lower()

    # Basic keyword set (examples)
    basic = {
        "Failed Logins": (["failed password", "login failed", "authentication failure", "invalid password"], "Investigate repeated failed logins and consider blocking/alerting"),
        "Privilege Escalation": (["sudo", "su -", "session opened for user root", "administratoraccess"], "Audit privilege escalation and recent sudo commands"),
        "Security Policy Changes": (["iptables", "ufw", "setenforce", "selinux", "policy change", "configuration changed"], "Review policy changes for authorization"),
        "Large/Unauthorized Data Access": (["getobject", "downloaded", "transferred", "bytes", "mb", "gb"], "Investigate large transfers for possible exfiltration"),
        "Malware Activity": (["xmrig", "minerd", "malware", "trojan", "ransomware"], "Run anti-malware scans and isolate host"),
        "Unusual Network Patterns": (["nmap", "port scan", "syn flood", "connection refused", "connection from"], "Check IDS/Firewall and block scanning IPs"),
        "Unauthorized Account Creation/Deletion": (["useradd", "adduser", "userdel", "deluser"], "Verify account management actions"),
        "Resource Abuse (mining/DoS/high CPU)": (["high cpu", "100% cpu", "mining", "ddos"], "Inspect running processes and network traffic"),
        "Dangerous Commands / Remote Shells": (["rm -rf", "mkfs", "nc -e", "curl http", "wget http"], "Investigate potential destructive or remote shell commands"),
        "Suspicious IPs": ([r"\b(?:\d{1,3}\.){3}\d{1,3}\b"], "External IP addresses seen; check reputation and block if malicious")
    }

    for name, (patterns, solution) in basic.items():
        matches = []
        for p in patterns:
            if p.startswith("\\b"):  # regex-style IP pattern
                found = re.findall(p, text)
                matches.extend(found)
            else:
                # simple substring match
                # collect example lines containing it
                for ln in raw.splitlines():
                    if p in ln.lower():
                        matches.append(ln.strip())
        for m in matches:
            _add(report, name, solution, m)

    return report
