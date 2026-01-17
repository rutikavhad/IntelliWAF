from mitmproxy import http  #SERVER
from datetime import datetime 
import csv #LOG FILE
import os 
import math #TO CHECK BODY ENTROPY
import time

import attacks   #attacks.py SIGN ATTACKS


#CSV AS LOG FILE TO DISPLAY ATTACKS
CSVFILE = "traffic_events.csv"
#error_403="WAF_blocked.html"

#html page to redirect to this if attack found
def load_html():
    file_path = "WAF_blocked.html"
    if os.path.exists(file_path):
        with open(file_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>Blocked by SentinelFlow</h1><p>Security Threat Detected.</p>"


HTML_RESPONSE = load_html()
# =========================
# DDOS / RATE LIMIT CONFIG
# =========================
MAX_REQUESTS = 50      # requests
TIME_WINDOW = 60       # seconds (1 minute)
BLOCK_TIME = 120       # seconds (2 minutes)

request_log = {}       # ip -> [timestamps]
blocked_ips = {}       # ip -> unblock_time

# =========================
# BRUTE-FORCE LIMIT CONFIG
# =========================
BRUTE_MAX_ATTEMPTS = 5        # attempts
BRUTE_TIME_WINDOW = 300      # 5 minutes
BRUTE_BLOCK_TIME = 120       # 10 minutes 600

brute_log = {}               # (ip, path) -> [timestamps]
brute_blocked_ips = {}       # ip -> unblock_time

# =========================
# CSV INIT
# =========================
def init_csv():
    if not os.path.exists(CSVFILE):
        with open(CSVFILE, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "timestamp",
                "client_ip",
                "method",
                "url",
                "path",
                "attack_type",
                "body_len",
                "body_entropy"
            ])

# =========================
# ENTROPY =how random / unpredictable string
#Low entropy → predictable, human text
#High entropy → encoded, encrypted, obfuscated, or machine-generated
# =========================
def shannon_entropy(s):
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    probs = [v / len(s) for v in freq.values()]
    return -sum(p * math.log2(p) for p in probs if p > 0)

# =========================
# DDOS CHECK FUNCTION
# =========================
def check_ddos(client_ip):
    now = time.time()

    # Already blocked?
    if client_ip in blocked_ips:
        if now < blocked_ips[client_ip]:
            return True
        else:
            del blocked_ips[client_ip]  # unblock time limit end

    if client_ip not in request_log:
        request_log[client_ip] = []

    # Keep only recent requests 
    request_log[client_ip] = [
        t for t in request_log[client_ip]
        if now - t <= TIME_WINDOW
    ]

    # Add current request
    request_log[client_ip].append(now)

    # Check limit
    if len(request_log[client_ip]) > MAX_REQUESTS:
        blocked_ips[client_ip] = now + BLOCK_TIME
        del request_log[client_ip]
        return True

    return False


# =========================
# BRUTE FORCE CHECK FUNCTION
# =========================
def check_bruteforce(client_ip, path):
    now = time.time()

    # Already blocked check
    if client_ip in brute_blocked_ips:
        if now < brute_blocked_ips[client_ip]:
            return True
        else:
            del brute_blocked_ips[client_ip]

    key = (client_ip, path)

    if key not in brute_log:
        brute_log[key] = []

    # Keep only recent attempts
    brute_log[key] = [
        t for t in brute_log[key]
        if now - t <= BRUTE_TIME_WINDOW
    ]

    # Log attempt
    brute_log[key].append(now)

    # Check limit
    if len(brute_log[key]) >= BRUTE_MAX_ATTEMPTS:
        brute_blocked_ips[client_ip] = now + BRUTE_BLOCK_TIME
        del brute_log[key]
        return True

    return False

# =========================
# MITMPROXY REQUEST
# =========================
def request(flow: http.HTTPFlow):
    if "WAF_blocked.html" in flow.request.path:   #use to avoid loop of WAF_blocked.html if self WAF can block this
        return
    init_csv()
    req = flow.request

    # =========================
    # CLIENT IP 
    # =========================
    client_ip = "(unknown)"
    try:
        addr = flow.client_conn.address
        if addr:
            client_ip = f"{addr[0]}:{addr[1]}"  # IP&PORT
    except:
        pass

    # =========================
    # DDOS CHECK (FIRST)
    # =========================
    if check_ddos(client_ip):
        # =========================
        # WRITE DDOS EVENT TO CSV
        # =========================
        with open(CSVFILE, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                datetime.utcnow().isoformat() + "Z",
                client_ip,
                req.method,
                req.pretty_url,
                req.path,
                "DDOS",        # attack_type
                0,             # body_len
                0.0            # body_entropy
            ])

        # BLOCK REQUEST
        blocked_page = HTML_RESPONSE.replace(
            "{{ATTACK_TYPE}}",'BRUTE_FORCE'
            )
        flow.response = http.Response.make(
            403,
            blocked_page.encode("utf-8"),
            {
                "Content-Type": "text/html"
            }
            )
        return
    
    # =========================
    # BRUTE FORCE CHECK (LOGIN PATHS ONLY)
    # =========================
    login_paths = ["/login", "/signin", "/auth", "/admin"]

    if any(p in req.path.lower() for p in login_paths):
        if check_bruteforce(client_ip, req.path):
            # WRITE BRUTE FORCE EVENT TO CSV
            with open(CSVFILE, "a", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([
                    datetime.utcnow().isoformat() + "Z",
                    client_ip,
                    req.method,
                    req.pretty_url,
                    req.path,
                    "BRUTE_FORCE",
                    0,
                    0.0
                ])

            # BLOCK REQUEST
            blocked_page = HTML_RESPONSE.replace(
            "{{ATTACK_TYPE}}",'BRUTE_FORCE'
            )

            flow.response = http.Response.make(
            403,
            blocked_page.encode("utf-8"),
            {
                "Content-Type": "text/html"
            }
            )
            #TEST OLD
            # flow.response = http.Response.make(
            #     403,
            #     b"Brute Force Detected - Access Temporarily Blocked",
            #     {"Content-Type": "text/plain"}
            # )
            return


    # =========================
    # BODY
    # =========================
    try:
        body = req.get_text(strict=False) or ""
    except:
        body = ""

    body_len = len(body)
    entropy = round(shannon_entropy(body), 3)

    # =========================
    # ATTACK DETECTION
    # =========================
    file_result = attacks.check_file_upload(req)

    if file_result == "FILE_UPLOAD_ABUSE":
        attack_type = "FILE_UPLOAD_ABUSE"

    elif file_result == "NORMAL":
        attack_type = "NORMAL"

    else:
        found = attacks.check_other_attacks(req)
        attack_type = "|".join(found) if found else "NORMAL"

    # =========================
    # WRITE CSV (ALWAYS)
    # =========================
    with open(CSVFILE, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            datetime.utcnow().isoformat() + "Z", #get time & date 
            client_ip,
            req.method,
            req.pretty_url,
            req.path,
            attack_type,
            body_len,
            entropy
        ])

    # =========================
    # BLOCK IF ATTACK & SHOW WEB PAGE
    # =========================
    if attack_type != "NORMAL":
        blocked_page = HTML_RESPONSE.replace(
        "{{ATTACK_TYPE}}",
        attack_type
        )

        flow.response = http.Response.make(
            403,
            blocked_page.encode("utf-8"),
            {
                "Content-Type": "text/html"
            }
        )