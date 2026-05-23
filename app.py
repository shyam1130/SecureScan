from datetime import datetime
import socket
import ssl
from urllib.parse import urlparse
import os
import smtplib
from email.message import EmailMessage

import requests
from requests.exceptions import RequestException, SSLError
from flask import Flask, render_template, request
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
    "Referrer-Policy",
]


def normalize_url(raw_url: str) -> str:
    raw_url = raw_url.strip()
    if not raw_url:
        raise ValueError("Please provide a URL.")

    if not raw_url.startswith(("http://", "https://")):
        raw_url = "https://" + raw_url

    parsed = urlparse(raw_url)
    if not parsed.netloc:
        raise ValueError("Invalid URL format.")

    return parsed.geturl()


def fetch_security_headers(url: str) -> dict:
    result = {
        "status_code": None,
        "final_url": url,
        "headers": {},
        "redirects": [],
        "ssl_verified": None,
        "ssl_error": None,
        "unreachable": False,
    }

    try:
        response = requests.get(url, timeout=10, allow_redirects=True, verify=True)
        result.update({
            "status_code": response.status_code,
            "final_url": response.url,
            "headers": {k: v for k, v in response.headers.items()},
            "redirects": [redirect.url for redirect in response.history],
            "ssl_verified": True,
        })
        return result
    except SSLError as exc:
        result["ssl_verified"] = False
        result["ssl_error"] = str(exc)
        try:
            response = requests.get(url, timeout=10, allow_redirects=True, verify=False)
            result.update({
                "status_code": response.status_code,
                "final_url": response.url,
                "headers": {k: v for k, v in response.headers.items()},
                "redirects": [redirect.url for redirect in response.history],
            })
            return result
        except RequestException:
            result["unreachable"] = True
            return result
    except RequestException:
        result["unreachable"] = True
        return result


def parse_hsts(header_value: str) -> dict:
    result = {"max_age": None, "include_subdomains": False, "preload": False}
    parts = [part.strip().lower() for part in header_value.split(";")]
    for part in parts:
        if part.startswith("max-age="):
            try:
                result["max_age"] = int(part.split("=", 1)[1])
            except ValueError:
                pass
        elif part == "includesubdomains":
            result["include_subdomains"] = True
        elif part == "preload":
            result["preload"] = True
    return result


def check_header_quality(headers: dict) -> tuple[list, dict]:
    issues = []
    header_details = {}

    if "Strict-Transport-Security" in headers:
        hsts = parse_hsts(headers["Strict-Transport-Security"])
        header_details["strict_transport_security"] = hsts
        if hsts["max_age"] is None:
            issues.append("HSTS header is malformed or missing max-age.")
        elif hsts["max_age"] < 10886400:
            issues.append("HSTS max-age is low; use at least 10886400.")
        if not hsts["include_subdomains"]:
            issues.append("HSTS should include includeSubDomains.")
    else:
        header_details["strict_transport_security"] = None

    if "Content-Security-Policy" in headers:
        csp = headers["Content-Security-Policy"]
        header_details["content_security_policy"] = csp
        if "default-src" not in csp:
            issues.append("CSP header is present but does not define default-src.")
    else:
        header_details["content_security_policy"] = None

    xfo = headers.get("X-Frame-Options")
    if xfo:
        header_details["x_frame_options"] = xfo
        normalized = xfo.strip().upper()
        if normalized not in ("DENY", "SAMEORIGIN") and not normalized.startswith("ALLOW-FROM"):
            issues.append("X-Frame-Options header is using a weak or unknown value.")
    else:
        header_details["x_frame_options"] = None

    xcto = headers.get("X-Content-Type-Options")
    if xcto:
        header_details["x_content_type_options"] = xcto
        if xcto.strip().lower() != "nosniff":
            issues.append("X-Content-Type-Options should be 'nosniff'.")
    else:
        header_details["x_content_type_options"] = None

    referrer_policy = headers.get("Referrer-Policy")
    if referrer_policy:
        header_details["referrer_policy"] = referrer_policy
        valid_values = {
            "no-referrer",
            "no-referrer-when-downgrade",
            "same-origin",
            "origin",
            "strict-origin",
            "origin-when-cross-origin",
            "strict-origin-when-cross-origin",
            "unsafe-url",
        }
        if referrer_policy.strip().lower() not in valid_values:
            issues.append("Referrer-Policy has a non-standard value.")
    else:
        header_details["referrer_policy"] = None

    server_banner = headers.get("Server") or headers.get("X-Powered-By")
    header_details["server_banner"] = server_banner
    if server_banner:
        issues.append("Server banner is exposed: " + server_banner)

    return issues, header_details


def assess_security_score(report: dict) -> dict:
    score = 100
    messages = []

    if not report["secure_scheme"]:
        score -= 30
        messages.append("The site does not start with HTTPS.")

    score -= len(report["missing_headers"]) * 10
    if report.get("server_banner"):
        score -= 5

    if report["ssl"].get("valid") is False:
        score -= 25
        messages.append("SSL certificate is invalid or expired.")

    tls_version = report["ssl"].get("tls_version")
    if tls_version in ("SSLv3", "TLSv1", "TLSv1.1"):
        score -= 20
        messages.append(f"Weak TLS version in use: {tls_version}.")

    if report.get("ssl_verified") is False:
        score -= 15
        messages.append("The HTTPS certificate chain could not be verified by requests.")

    if report.get("unreachable"):
        return {
            "score": 0,
            "grade": "Poor",
            "messages": ["URL could not be reached."]
        }

    if score < 0:
        score = 0

    if score >= 80:
        grade = "Good"
    elif score >= 50:
        grade = "Fair"
    else:
        grade = "Poor"

    return {
        "score": score,
        "grade": grade,
        "messages": messages,
    }


def get_ssl_certificate(hostname: str, port: int = 443) -> dict:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((hostname, port), timeout=10) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert = ssock.getpeercert()
            tls_version = ssock.version()
            cipher = ssock.cipher()

    not_after = cert.get("notAfter")
    if not_after:
        expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
    else:
        expires = None

    return {
        "subject": cert.get("subject", []),
        "issuer": cert.get("issuer", []),
        "not_after": not_after,
        "expires": expires,
        "tls_version": tls_version,
        "cipher": cipher,
    }


def analyze_url(raw_url: str) -> dict:
    url = normalize_url(raw_url)
    parsed = urlparse(url)

    report = {
        "url": url,
        "secure_scheme": parsed.scheme == "https",
        "issues": [],
        "headers": {},
        "missing_headers": [],
        "header_quality_issues": [],
        "header_details": {},
        "ssl": {},
        "redirects": [],
        "final_url": None,
        "status_code": None,
        "ssl_verified": None,
        "ssl_error": None,
        "unreachable": False,
        "server_banner": None,
        "security_score": None,
        "security_grade": None,
    }

    response_info = fetch_security_headers(url)
    report["status_code"] = response_info.get("status_code")
    report["final_url"] = response_info.get("final_url")
    report["redirects"] = response_info.get("redirects", [])
    report["headers"] = response_info.get("headers", {})
    report["ssl_verified"] = response_info.get("ssl_verified")
    report["ssl_error"] = response_info.get("ssl_error")
    report["unreachable"] = response_info.get("unreachable", False)

    if report["unreachable"]:
        report["issues"].append("URL is unreachable or does not exist.")
        score_result = assess_security_score(report)
        report["security_score"] = score_result["score"]
        report["security_grade"] = score_result["grade"]
        report["security_comments"] = score_result["messages"]
        return report

    report["missing_headers"] = [h for h in SECURITY_HEADERS if h not in report["headers"]]
    if report["missing_headers"]:
        report["issues"].append("Missing security headers: " + ", ".join(report["missing_headers"]))

    quality_issues, header_details = check_header_quality(report["headers"])
    report["header_quality_issues"] = quality_issues
    report["header_details"] = header_details
    report["server_banner"] = header_details.get("server_banner")

    if not report["secure_scheme"]:
        report["issues"].append("URL is not using HTTPS.")
        if report["final_url"] and report["final_url"].startswith("https://"):
            report["issues"].append("HTTP redirects to HTTPS.")
        else:
            report["issues"].append("No HTTPS redirect detected.")

    if report["final_url"] and not report["final_url"].startswith("https://"):
        report["issues"].append("Final destination is not HTTPS.")

    if report["secure_scheme"]:
        hostname = parsed.hostname
        port = parsed.port or 443
        try:
            cert_info = get_ssl_certificate(hostname, port)
            report["ssl"] = cert_info

            expires = cert_info.get("expires")
            if expires:
                if expires < datetime.utcnow():
                    report["issues"].append("SSL certificate has expired.")
                    report["ssl"]["valid"] = False
                else:
                    report["ssl"]["valid"] = True
            else:
                report["ssl"]["valid"] = None

            tls_version = cert_info.get("tls_version")
            if tls_version in ("SSLv3", "TLSv1", "TLSv1.1"):
                report["issues"].append(f"Weak TLS version in use: {tls_version}.")

            cipher = cert_info.get("cipher")
            if cipher and isinstance(cipher, tuple):
                cipher_name = cipher[0].upper()
                if "RC4" in cipher_name or "3DES" in cipher_name or cipher_name == "DES":
                    report["issues"].append(f"Weak cipher negotiated: {cipher_name}.")
        except Exception:
            report["ssl"] = {"error": True, "valid": None}
            report["issues"].append("Unable to obtain SSL certificate details.")

    score_result = assess_security_score(report)
    report["security_score"] = score_result["score"]
    report["security_grade"] = score_result["grade"]
    report["security_comments"] = score_result["messages"]

    return report


@app.route("/", methods=["GET", "POST"])
def index():
    report = None
    error = None

    if request.method == "POST":
        url = request.form.get("url", "")
        try:
            report = analyze_url(url)
        except ValueError as exc:
            error = str(exc)
        except Exception as exc:
            error = "An unexpected error occurred: " + str(exc)

        # Send notification email (no storage). Best-effort; failures ignored.
        try:
            def get_client_ip(req):
                xff = req.headers.get("X-Forwarded-For")
                if xff:
                    return xff.split(",")[0].strip()
                return req.remote_addr

            def send_alert_email(recipient, url, ip, forwarded_for, user_agent, status_code, ssl_verified, security_score):
                smtp_host = os.getenv("SMTP_HOST")
                if not smtp_host:
                    print("[EMAIL] SMTP_HOST not set. Email notifications disabled.")
                    return

                smtp_port = int(os.getenv("SMTP_PORT", "587"))
                smtp_user = os.getenv("SMTP_USER")
                smtp_pass = os.getenv("SMTP_PASS")
                use_tls = os.getenv("SMTP_USE_TLS", "true").lower() in ("1", "true", "yes")
                use_ssl = os.getenv("SMTP_USE_SSL", "").lower() in ("1", "true", "yes")

                print(f"[EMAIL] Sending notification to {recipient}...")
                print(f"[EMAIL] SMTP: {smtp_host}:{smtp_port}, TLS={use_tls}, SSL={use_ssl}")

                msg = EmailMessage()
                msg["Subject"] = f"Website check: {url}"
                sender = smtp_user or (f"no-reply@{os.getenv('MAIL_DOMAIN','localhost')}")
                msg["From"] = sender
                msg["To"] = recipient
                body = (
                    f"Time: {datetime.utcnow().isoformat()}Z\n"
                    f"URL: {url}\n"
                    f"Client IP: {ip}\n"
                    f"Forwarded-For: {forwarded_for}\n"
                    f"User-Agent: {user_agent}\n"
                    f"Status code: {status_code}\n"
                    f"SSL verified: {ssl_verified}\n"
                    f"Security score: {security_score}\n"
                )
                msg.set_content(body)

                try:
                    if use_ssl:
                        with smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=10) as server:
                            if smtp_user and smtp_pass:
                                server.login(smtp_user, smtp_pass)
                            server.send_message(msg)
                    else:
                        with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
                            if use_tls:
                                server.starttls()
                            if smtp_user and smtp_pass:
                                server.login(smtp_user, smtp_pass)
                            server.send_message(msg)
                    print("[EMAIL] ✓ Email sent successfully!")
                except Exception as e:
                    print(f"[EMAIL] ✗ Failed to send email: {e}")

            recipient = "robert0220814@gmail.com"
            send_alert_email(
                recipient,
                url,
                get_client_ip(request),
                request.headers.get("X-Forwarded-For"),
                request.headers.get("User-Agent"),
                report.get("status_code") if report else None,
                report.get("ssl_verified") if report else None,
                report.get("security_score") if report else None,
            )
        except Exception as exc:
            print(f"[EMAIL] ✗ Notification setup failed: {exc}")

    return render_template("index.html", report=report, error=error)


if __name__ == "__main__":
    app.run(debug=True)
