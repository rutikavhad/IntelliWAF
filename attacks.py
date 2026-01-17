import re
from urllib.parse import unquote_plus
import html
import unicodedata

# =========================
# NORMALIZATION
# =========================
def normalize(text):
    if not text:
        return ""

    #URL decode (IF MULTI ENCODED PAYLOADS)
    previous = None
    current = text
    for _ in range(5):
        if previous == current:
            break
        previous = current
        current = unquote_plus(current)

    text = current

    #HTML entity decode
    text = html.unescape(text)

    #Unicode normalization (NFKC)
    text = unicodedata.normalize("NFKC", text)

    #Lowercase
    text = text.lower()

    #Remove comments (SQL / JS)
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    text = re.sub(r"--.*?$", "", text, flags=re.MULTILINE)
    text = re.sub(r"#.*?$", "", text, flags=re.MULTILINE)

    
    # Preserve CRLF for detection
    text = text.replace("\r\n", "\\r\\n")
    text = text.replace("\n", "\\n").replace("\r", "\\r")
    #Collapse whitespace (tabs, newlines, spaces)
    text = re.sub(r"\s+", " ", text)

    return text.strip()

# =========================
# SIGNATURES
# =========================
sqli = [" or 1=1", "union select", "sleep(", "benchmark(", "--","order by","union","group by","having","extractvalue", "updatexml"] #SQL INJECTIONS
cmd = [";", "&&", "||", "|", "`", "$(","&>", "<&", "cmd.exe", "/bin/sh"] #COMMAND INJECTION
path = ["../", "..\\", "php://", "file://", "data://", "/etc/passwd","/config/","boot.ini"] #PATH TRAVEL
xss = ["<script", "</script>", "javascript:", "onerror=", "onload=","alert(","onmouseover=", "onfocus=", "<svg", "<iframe"] #SHELL SCRIPTING
nosql = ["$gt", "$ne", "$where", "$regex"] #NOSQL INJECTIONS

allowed_txt = [".png", ".jpg", ".jpeg", ".gif", ".pdf", ".txt","text"]
blocked_txt = [".php", ".py", ".exe", ".jsp", ".sh","js",".bash",".c",".asm",".java",".class","xml"] #FILE INJECTION


# Critical Server Attacks
server_attack = [
"{{", "${", "<%=",                # SSTI 
"<!entity", "<!doctype",          # XXE
"%0d%0a", "\\r\\n",               # CRLF
"__proto__", "constructor.prot",  # Prototype Pollution
"ac ed 00 05"   # Deserialization (PHP/Java)
]
# =========================
# FILE UPLOAD CHECK (ONLY)
# =========================
def check_file_upload(req):
    """
    Returns:
      - "NORMAL" if safe file upload
      - "FILE_UPLOAD_ABUSE" if malicious
      - None if not a file upload
    """
    ct = req.headers.get("Content-Type", "").lower()
    if "multipart/form-data" not in ct:
        return None

    try:
        body = req.get_text(strict=False) or ""
    except:
        return "FILE_UPLOAD_ABUSE"

    matches = re.findall(r'filename="([^"]+)"', body, re.IGNORECASE)

    for fname in matches:
        fname = fname.lower()

        # block dangerous extensions
        for ext in blocked_txt:
            if fname.endswith(ext):
                return "FILE_UPLOAD_ABUSE"

        # block double extensions
        if fname.count(".") >= 2:
            return "FILE_UPLOAD_ABUSE"

        # allow safe extensions
        for ext in allowed_txt:
            if fname.endswith(ext):
                return "NORMAL"

        # unknown extension → block
        return "FILE_UPLOAD_ABUSE"

    return "NORMAL"

# =========================
# NON-FILE ATTACK CHECKS
# =========================
def check_other_attacks(req):
    attacks = []
    inputs = []

    for v in req.query.values():
        inputs.append(v)

    try:
        body = req.get_text(strict=False) or ""
        inputs.append(body)
    except:
        pass

    norm_inputs = [normalize(i) for i in inputs]

    if any(any(s in d for s in sqli) for d in norm_inputs):
        attacks.append("SQL_INJECTION")

    if any(any(s in d for s in cmd) for d in norm_inputs):
        attacks.append("COMMAND_INJECTION")

    if any(any(s in d for s in path) for d in norm_inputs):
        attacks.append("PATH_TRAVERSAL")

    if any(any(s in d for s in xss) for d in norm_inputs):
        attacks.append("XSS")
    if any(any(s in d for s in nosql) for d in norm_inputs):
        attacks.append("NOSQL")
    if any(any(s in d for s in server_attack) for d in norm_inputs):
        attacks.append("SERVER_ATTACKS")
    return attacks
