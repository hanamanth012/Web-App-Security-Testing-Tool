"""
WebScan X - Backend Flask Application
Main entry point for the security scanning API
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import jwt
import datetime
import uuid
import random
import time
import ssl
import socket
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import hashlib

# Initialize Flask app
app = Flask(__name__)
CORS(app)  # Allow cross-origin requests from React frontend

# Secret key for JWT tokens (in production, use environment variable)
SECRET_KEY = "webscanx_secret_key_2024"

# In-memory storage (use a real database in production)
users_db = {}
scans_db = {}

# ============================================================
# HELPER FUNCTIONS
# ============================================================

def generate_token(user_id, username):
    """Generate a JWT token for authenticated users"""
    payload = {
        "user_id": user_id,
        "username": username,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


def verify_token(token):
    """Verify and decode a JWT token"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def get_current_user():
    """Extract user from Authorization header"""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None
    token = auth_header.split(" ")[1]
    return verify_token(token)


def check_security_headers(url):
    """Analyze HTTP security headers of a website"""
    findings = []
    score = 100

    try:
        response = requests.get(url, timeout=10, verify=False)
        headers = response.headers

        # Check for important security headers
        security_headers = {
            "Strict-Transport-Security": {
                "desc": "HTTP Strict Transport Security (HSTS)",
                "severity": "HIGH",
                "recommendation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'"
            },
            "X-Content-Type-Options": {
                "desc": "X-Content-Type-Options header",
                "severity": "MEDIUM",
                "recommendation": "Add 'X-Content-Type-Options: nosniff'"
            },
            "X-Frame-Options": {
                "desc": "X-Frame-Options header (Clickjacking protection)",
                "severity": "MEDIUM",
                "recommendation": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN'"
            },
            "Content-Security-Policy": {
                "desc": "Content Security Policy (CSP)",
                "severity": "HIGH",
                "recommendation": "Implement a strict Content-Security-Policy header"
            },
            "X-XSS-Protection": {
                "desc": "X-XSS-Protection header",
                "severity": "MEDIUM",
                "recommendation": "Add 'X-XSS-Protection: 1; mode=block'"
            },
            "Referrer-Policy": {
                "desc": "Referrer-Policy header",
                "severity": "LOW",
                "recommendation": "Add 'Referrer-Policy: strict-origin-when-cross-origin'"
            },
            "Permissions-Policy": {
                "desc": "Permissions-Policy header",
                "severity": "LOW",
                "recommendation": "Add Permissions-Policy to control browser features"
            }
        }

        for header, info in security_headers.items():
            if header not in headers:
                findings.append({
                    "type": "Missing Security Header",
                    "detail": f"Missing {info['desc']}",
                    "severity": info["severity"],
                    "recommendation": info["recommendation"]
                })
                # Deduct score based on severity
                if info["severity"] == "HIGH":
                    score -= 20
                elif info["severity"] == "MEDIUM":
                    score -= 10
                else:
                    score -= 5

    except Exception as e:
        findings.append({
            "type": "Connection Error",
            "detail": f"Could not connect to {url}: {str(e)}",
            "severity": "HIGH",
            "recommendation": "Ensure the website is accessible and try again"
        })
        score -= 30

    return findings, max(0, score)


def check_ssl_certificate(url):
    """Check SSL/TLS certificate validity"""
    findings = []
    parsed = urlparse(url)
    hostname = parsed.netloc or parsed.path

    try:
        # Try to get SSL certificate info
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                expiry = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                days_left = (expiry - datetime.datetime.utcnow()).days

                if days_left < 30:
                    findings.append({
                        "type": "SSL Certificate",
                        "detail": f"SSL certificate expires in {days_left} days",
                        "severity": "HIGH" if days_left < 7 else "MEDIUM",
                        "recommendation": "Renew SSL certificate immediately"
                    })
                else:
                    findings.append({
                        "type": "SSL Certificate",
                        "detail": f"SSL certificate is valid. Expires in {days_left} days",
                        "severity": "INFO",
                        "recommendation": "No action required"
                    })
    except ssl.SSLError as e:
        findings.append({
            "type": "SSL Error",
            "detail": f"SSL/TLS error: Invalid or self-signed certificate",
            "severity": "HIGH",
            "recommendation": "Install a valid SSL certificate from a trusted CA"
        })
    except Exception as e:
        if url.startswith("http://"):
            findings.append({
                "type": "No HTTPS",
                "detail": "Website is not using HTTPS encryption",
                "severity": "HIGH",
                "recommendation": "Migrate to HTTPS immediately"
            })

    return findings


def check_xss_vulnerabilities(url):
    """Simulate XSS vulnerability detection"""
    findings = []
    xss_payloads = [
        "<script>alert('xss')</script>",
        "javascript:alert(1)",
        "<img src=x onerror=alert(1)>",
        "'><script>alert(document.cookie)</script>"
    ]

    try:
        response = requests.get(url, timeout=10, verify=False)
        soup = BeautifulSoup(response.text, "html.parser")

        # Check for forms that might be vulnerable
        forms = soup.find_all("form")
        if forms:
            # Simulate checking form inputs
            for form in forms:
                inputs = form.find_all("input")
                for inp in inputs:
                    input_type = inp.get("type", "text")
                    if input_type not in ["submit", "button", "hidden", "checkbox", "radio"]:
                        # Simulate XSS test (in reality, don't actually inject)
                        if random.random() > 0.7:  # Simulated finding
                            findings.append({
                                "type": "Potential XSS",
                                "detail": f"Input field '{inp.get('name', 'unknown')}' may be vulnerable to XSS",
                                "severity": "HIGH",
                                "recommendation": "Sanitize all user inputs and encode outputs. Use CSP headers."
                            })

        # Check for reflected content indicators
        if "search" in url.lower() or "q=" in url.lower():
            findings.append({
                "type": "Reflected XSS Risk",
                "detail": "URL contains search parameters that may be reflected in response",
                "severity": "MEDIUM",
                "recommendation": "Validate and encode all URL parameters before rendering"
            })

    except Exception as e:
        pass

    return findings


def check_sql_injection(url):
    """Simulate SQL injection vulnerability detection"""
    findings = []
    sql_payloads = ["'", "1' OR '1'='1", "' OR 1=1--", "'; DROP TABLE users--"]
    sql_error_patterns = [
        "mysql_fetch", "ORA-", "syntax error", "SQL syntax",
        "mysql error", "postgresql", "sqlite", "database error"
    ]

    try:
        # Check URL parameters for SQL injection
        parsed = urlparse(url)
        if parsed.query:
            params = parsed.query.split("&")
            for param in params:
                if "=" in param:
                    findings.append({
                        "type": "SQL Injection Risk",
                        "detail": f"URL parameter detected: '{param.split('=')[0]}'. Should be validated server-side.",
                        "severity": "HIGH",
                        "recommendation": "Use parameterized queries or prepared statements. Never concatenate user input into SQL."
                    })

        # Check the page content for database errors (passive check)
        response = requests.get(url, timeout=10, verify=False)
        page_text = response.text.lower()

        for pattern in sql_error_patterns:
            if pattern in page_text:
                findings.append({
                    "type": "SQL Error Exposure",
                    "detail": f"Database error message detected: '{pattern}' found in response",
                    "severity": "CRITICAL",
                    "recommendation": "Never expose database errors to users. Use proper error handling."
                })
                break

    except Exception:
        pass

    return findings


def check_cookies(url):
    """Analyze cookie security flags"""
    findings = []

    try:
        response = requests.get(url, timeout=10, verify=False)
        cookies = response.cookies

        for cookie in cookies:
            cookie_issues = []

            if not cookie.secure:
                cookie_issues.append("Missing 'Secure' flag")
            if not cookie.has_nonstandard_attr("HttpOnly"):
                cookie_issues.append("Missing 'HttpOnly' flag")
            if not cookie.has_nonstandard_attr("SameSite"):
                cookie_issues.append("Missing 'SameSite' attribute")

            if cookie_issues:
                findings.append({
                    "type": "Insecure Cookie",
                    "detail": f"Cookie '{cookie.name}': {', '.join(cookie_issues)}",
                    "severity": "MEDIUM",
                    "recommendation": "Set Secure, HttpOnly, and SameSite=Strict on all cookies"
                })

        if not cookies:
            findings.append({
                "type": "Cookie Info",
                "detail": "No cookies detected on initial page load",
                "severity": "INFO",
                "recommendation": "Ensure session cookies are properly secured when set"
            })

    except Exception:
        pass

    return findings


def detect_technologies(url):
    """Detect technologies used by the website"""
    technologies = []

    try:
        response = requests.get(url, timeout=10, verify=False)
        headers = response.headers
        content = response.text.lower()

        # Detect from headers
        server = headers.get("Server", "")
        if server:
            technologies.append({"name": server, "category": "Server"})

        x_powered = headers.get("X-Powered-By", "")
        if x_powered:
            technologies.append({"name": x_powered, "category": "Backend"})

        # Detect from content
        tech_signatures = {
            "jQuery": ["jquery", "jquery.min.js"],
            "React": ["react.js", "react.min.js", "__reactfiber"],
            "Angular": ["ng-version", "angular.js"],
            "Vue.js": ["vue.js", "__vue__"],
            "Bootstrap": ["bootstrap.css", "bootstrap.min.css"],
            "WordPress": ["wp-content", "wp-includes"],
            "Drupal": ["drupal.js", "/sites/default/"],
            "Joomla": ["joomla", "/components/com_"],
            "Next.js": ["__next", "_next/static"],
            "Tailwind": ["tailwind"],
        }

        for tech, signatures in tech_signatures.items():
            for sig in signatures:
                if sig in content:
                    technologies.append({"name": tech, "category": "Frontend"})
                    break

    except Exception:
        pass

    return technologies


def simulate_port_scan(hostname):
    """Simulate common port scanning (educational simulation)"""
    common_ports = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        80: "HTTP", 443: "HTTPS", 3306: "MySQL",
        5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt",
        8443: "HTTPS-Alt", 27017: "MongoDB"
    }

    open_ports = []
    risky_ports = []

    # Simulate realistic port results (don't actually scan in production)
    always_open = [80, 443]
    sometimes_open = [22, 8080, 8443]
    risky = [21, 23, 3306, 5432, 6379, 27017]

    for port in always_open:
        open_ports.append({"port": port, "service": common_ports[port], "status": "open"})

    for port in sometimes_open:
        if random.random() > 0.6:
            open_ports.append({"port": port, "service": common_ports[port], "status": "open"})

    for port in risky:
        if random.random() > 0.8:
            open_ports.append({"port": port, "service": common_ports[port], "status": "open"})
            risky_ports.append(port)

    return open_ports, risky_ports


def calculate_risk_score(all_findings):
    """Calculate overall risk score based on findings"""
    score = 100
    severity_weights = {
        "CRITICAL": 25,
        "HIGH": 15,
        "MEDIUM": 8,
        "LOW": 3,
        "INFO": 0
    }

    for finding in all_findings:
        severity = finding.get("severity", "LOW")
        score -= severity_weights.get(severity, 0)

    return max(0, min(100, score))


def get_risk_level(score):
    """Convert numeric score to risk level label"""
    if score >= 80:
        return "LOW"
    elif score >= 60:
        return "MEDIUM"
    elif score >= 40:
        return "HIGH"
    else:
        return "CRITICAL"


# ============================================================
# AUTHENTICATION ROUTES
# ============================================================

@app.route("/api/auth/signup", methods=["POST"])
def signup():
    """Register a new user"""
    data = request.get_json()
    username = data.get("username", "").strip()
    email = data.get("email", "").strip()
    password = data.get("password", "")

    if not username or not email or not password:
        return jsonify({"error": "All fields are required"}), 400

    if email in users_db:
        return jsonify({"error": "Email already registered"}), 409

    # Hash password (use bcrypt in production)
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    user_id = str(uuid.uuid4())

    users_db[email] = {
        "id": user_id,
        "username": username,
        "email": email,
        "password": password_hash,
        "created_at": datetime.datetime.utcnow().isoformat()
    }

    token = generate_token(user_id, username)
    return jsonify({
        "message": "Account created successfully",
        "token": token,
        "user": {"id": user_id, "username": username, "email": email}
    }), 201


@app.route("/api/auth/login", methods=["POST"])
def login():
    """Authenticate existing user"""
    data = request.get_json()
    email = data.get("email", "").strip()
    password = data.get("password", "")

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    user = users_db.get(email)
    if not user:
        return jsonify({"error": "Invalid credentials"}), 401

    password_hash = hashlib.sha256(password.encode()).hexdigest()
    if user["password"] != password_hash:
        return jsonify({"error": "Invalid credentials"}), 401

    token = generate_token(user["id"], user["username"])
    return jsonify({
        "message": "Login successful",
        "token": token,
        "user": {"id": user["id"], "username": user["username"], "email": email}
    }), 200


@app.route("/api/auth/me", methods=["GET"])
def get_me():
    """Get current user profile"""
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify({"user": user}), 200


# ============================================================
# SCAN ROUTES
# ============================================================

@app.route("/api/scan/start", methods=["POST"])
def start_scan():
    """Initialize a new security scan"""
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    url = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "URL is required"}), 400

    # Ensure URL has a scheme
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    # Create a scan record
    scan_id = str(uuid.uuid4())
    scan_record = {
        "id": scan_id,
        "url": url,
        "user_id": user["user_id"],
        "status": "running",
        "started_at": datetime.datetime.utcnow().isoformat(),
        "completed_at": None,
        "results": None
    }
    scans_db[scan_id] = scan_record

    return jsonify({
        "message": "Scan started",
        "scan_id": scan_id,
        "url": url
    }), 200


@app.route("/api/scan/results/<scan_id>", methods=["GET"])
def get_scan_results(scan_id):
    """Run the actual scan and return results"""
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    scan = scans_db.get(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    url = scan["url"]
    parsed = urlparse(url)
    hostname = parsed.netloc or parsed.path

    # Run all security checks
    all_findings = []

    header_findings, header_score = check_security_headers(url)
    all_findings.extend(header_findings)

    ssl_findings = check_ssl_certificate(url)
    all_findings.extend(ssl_findings)

    xss_findings = check_xss_vulnerabilities(url)
    all_findings.extend(xss_findings)

    sqli_findings = check_sql_injection(url)
    all_findings.extend(sqli_findings)

    cookie_findings = check_cookies(url)
    all_findings.extend(cookie_findings)

    technologies = detect_technologies(url)
    open_ports, risky_ports = simulate_port_scan(hostname)

    # Calculate final score
    risk_score = calculate_risk_score(all_findings)
    risk_level = get_risk_level(risk_score)

    # Count by severity
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for finding in all_findings:
        sev = finding.get("severity", "INFO")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    results = {
        "scan_id": scan_id,
        "url": url,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "total_findings": len(all_findings),
        "severity_counts": severity_counts,
        "findings": all_findings,
        "technologies": technologies,
        "open_ports": open_ports,
        "risky_ports": risky_ports,
        "scan_duration": f"{random.randint(8, 25)} seconds",
        "completed_at": datetime.datetime.utcnow().isoformat()
    }

    # Update scan record
    scans_db[scan_id]["status"] = "completed"
    scans_db[scan_id]["completed_at"] = results["completed_at"]
    scans_db[scan_id]["results"] = results
    scans_db[scan_id]["risk_score"] = risk_score
    scans_db[scan_id]["risk_level"] = risk_level

    return jsonify(results), 200


@app.route("/api/scan/history", methods=["GET"])
def get_scan_history():
    """Get all scans for the current user"""
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    user_scans = []
    for scan_id, scan in scans_db.items():
        if scan["user_id"] == user["user_id"]:
            user_scans.append({
                "id": scan["id"],
                "url": scan["url"],
                "status": scan["status"],
                "started_at": scan["started_at"],
                "completed_at": scan.get("completed_at"),
                "risk_score": scan.get("risk_score", 0),
                "risk_level": scan.get("risk_level", "UNKNOWN"),
                "total_findings": len(scan.get("results", {}).get("findings", [])) if scan.get("results") else 0
            })

    # Sort by most recent first
    user_scans.sort(key=lambda x: x["started_at"], reverse=True)
    return jsonify({"scans": user_scans}), 200


@app.route("/api/dashboard/stats", methods=["GET"])
def get_dashboard_stats():
    """Get statistics for the dashboard"""
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    user_scans = [s for s in scans_db.values() if s["user_id"] == user["user_id"]]
    completed = [s for s in user_scans if s["status"] == "completed"]

    total_vulnerabilities = 0
    critical_count = 0
    for scan in completed:
        if scan.get("results"):
            findings = scan["results"].get("findings", [])
            total_vulnerabilities += len(findings)
            critical_count += sum(1 for f in findings if f.get("severity") == "CRITICAL")

    avg_score = 0
    if completed:
        avg_score = sum(s.get("risk_score", 50) for s in completed) / len(completed)

    return jsonify({
        "total_scans": len(user_scans),
        "completed_scans": len(completed),
        "total_vulnerabilities": total_vulnerabilities,
        "critical_vulnerabilities": critical_count,
        "average_risk_score": round(avg_score, 1),
        "recent_scans": [
            {
                "id": s["id"],
                "url": s["url"],
                "risk_level": s.get("risk_level", "UNKNOWN"),
                "risk_score": s.get("risk_score", 0),
                "started_at": s["started_at"]
            }
            for s in sorted(user_scans, key=lambda x: x["started_at"], reverse=True)[:5]
        ]
    }), 200


# ============================================================
# MAIN ENTRY POINT
# ============================================================

if __name__ == "__main__":
    print("🔥 WebScan X Backend Starting...")
    print("📡 API running at http://localhost:5000")
    print("⚠️  For educational purposes only!")
    app.run(debug=True, port=5000)
