
import streamlit as st
import pandas as pd
import hashlib
import re
import io
import json
from datetime import datetime, timezone
from urllib.parse import urlparse
from collections import Counter

st.set_page_config(
    page_title="CyberShield AI",
    page_icon="🛡️",
    layout="wide"
)

st.markdown("""
<style>
.stApp {
    background: linear-gradient(145deg, #07111f 0%, #101b30 100%);
}
[data-testid="stSidebar"] {
    background-color: #0a1424;
}
h1, h2, h3 {
    color: #e7f0ff;
}
[data-testid="stMetric"] {
    background: rgba(25, 43, 67, 0.8);
    border: 1px solid #294260;
    padding: 16px;
    border-radius: 12px;
}
div.stButton > button, div.stDownloadButton > button {
    border-radius: 9px;
    font-weight: 600;
}
</style>
""", unsafe_allow_html=True)

if "findings" not in st.session_state:
    st.session_state.findings = []

def add_finding(module, severity, title, details):
    st.session_state.findings.append({
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "module": module,
        "severity": severity,
        "title": title,
        "details": details
    })

def sha256(data):
    return hashlib.sha256(data).hexdigest()


def check_url(value):
    from urllib.parse import urlsplit
    import ipaddress
    import re

    value = value.strip()
    issues = []

    if not value:
        return "Invalid input", ["Enter a URL to analyze."]

    # Reject spaces and control characters that can make parsing ambiguous.
    if any(ch.isspace() or ord(ch) < 32 for ch in value):
        return "Invalid input", [
            "The URL contains whitespace or control characters. "
            "Enter a properly formatted URL."
        ]

    # Require an explicit HTTP or HTTPS scheme.
    try:
        parsed = urlsplit(value)
        if parsed.scheme.lower() not in ("http", "https"):
            return "Invalid input", [
                "URL must start with http:// or https://."
            ]

        if not parsed.hostname:
            return "Invalid input", [
                "A valid hostname is missing."
            ]

        host = parsed.hostname.lower().rstrip(".")
        port = parsed.port  # Also validates malformed port numbers.

    except ValueError:
        return "Invalid input", [
            "The URL has an invalid hostname, port, or bracket format."
        ]

    # Check whether the hostname is an IP address.
    is_ip = False
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        pass

    if parsed.username is not None or parsed.password is not None:
        issues.append(
            "The URL contains user information before the hostname, "
            "which can be used to disguise the destination."
        )

    if parsed.scheme.lower() != "https":
        issues.append(
            "The URL uses HTTP rather than HTTPS. The connection may "
            "lack transport encryption."
        )

    if is_ip:
        issues.append(
            "The destination is an IP address rather than a domain name. "
            "This alone does not prove malicious activity."
        )

    if host.startswith("xn--") or ".xn--" in host:
        issues.append(
            "The hostname contains an internationalized domain label. "
            "Check carefully for lookalike characters."
        )

    if len(value) > 200:
        issues.append("The URL is unusually long.")

    if len(host.split(".")) >= 5 and not is_ip:
        issues.append(
            "The hostname has many subdomain levels. "
            "Check which organization controls the registered domain."
        )

    if re.search(r"(login|verify|account|password|wallet|payment)", 
                 parsed.path + "?" + parsed.query, re.IGNORECASE):
        issues.append(
            "The URL path or query contains account-related wording. "
            "This is only a weak warning signal."
        )

    if not issues:
        return "No obvious warning detected", [
            "No configured warning rules matched. This is not a safety "
            "certification; the website could still be malicious."
        ]

    return "Review recommended", issues


def scan_prompt(text):
    import re

    rules = [
        {
            "category": "Instruction override",
            "severity": "High",
            "pattern": (
                r"\b(ignore|disregard|override|forget)\b.{0,60}"
                r"\b(previous|prior|above|all)\b.{0,40}"
                r"\b(instructions?|rules?|prompts?)\b"
            ),
            "explanation": "Text may be attempting to override earlier instructions.",
            "recommendation": "Keep system instructions separate and do not follow untrusted overrides."
        },
        {
            "category": "Hidden prompt extraction",
            "severity": "High",
            "pattern": (
                r"\b(reveal|print|show|disclose|repeat|leak)\b.{0,60}"
                r"\b(system prompt|hidden instructions|developer message|secret prompt)\b"
            ),
            "explanation": "Text appears to request hidden instructions or internal prompts.",
            "recommendation": "Do not disclose confidential system or developer instructions."
        },
        {
            "category": "Safety bypass attempt",
            "severity": "High",
            "pattern": (
                r"\b(bypass|disable|evade|ignore)\b.{0,50}"
                r"\b(safety|guardrails?|security restrictions?|filters?)\b"
            ),
            "explanation": "Text may be asking to bypass safety controls.",
            "recommendation": "Preserve safety checks and evaluate the request under your policy."
        },
        {
            "category": "Role or authority manipulation",
            "severity": "Medium",
            "pattern": (
                r"\b(act as|pretend to be|you are now)\b.{0,60}"
                r"\b(unrestricted|no rules|administrator|system|developer)\b"
            ),
            "explanation": "Text may be trying to change the model's role or authority.",
            "recommendation": "Do not treat user text as higher-priority system instructions."
        },
        {
            "category": "Email address",
            "severity": "Low",
            "pattern": r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
            "explanation": "An email-address-shaped string was found.",
            "recommendation": "Check whether this personal information needs to be included."
        },
        {
            "category": "Possible credential",
            "severity": "High",
            "pattern": (
                r"\b(api[_ -]?key|access[_ -]?token|client[_ -]?secret|"
                r"password|passwd|secret[_ -]?key)\b\s*[:=]\s*\S+"
            ),
            "explanation": "A possible credential assignment was detected.",
            "recommendation": "Remove secrets from the text and rotate exposed credentials if genuine."
        },
        {
            "category": "Possible payment-card number",
            "severity": "Medium",
            "pattern": r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)",
            "explanation": "A long digit sequence may represent sensitive payment information.",
            "recommendation": "Verify locally and redact payment information where unnecessary."
        }
    ]

    findings = []
    for rule in rules:
        if re.search(rule["pattern"], text, re.IGNORECASE):
            findings.append({
                "category": rule["category"],
                "severity": rule["severity"],
                "explanation": rule["explanation"],
                "recommendation": rule["recommendation"]
            })

    return findings

def make_sample_logs():
    return pd.DataFrame([
        {"timestamp": "2026-10-15 09:01", "source_ip": "192.0.2.10",
         "username": "student1", "event": "login", "status": "success",
         "bytes_out": 1200},
        {"timestamp": "2026-10-15 09:02", "source_ip": "198.51.100.8",
         "username": "admin", "event": "login", "status": "failed",
         "bytes_out": 100},
        {"timestamp": "2026-10-15 09:03", "source_ip": "198.51.100.8",
         "username": "admin", "event": "login", "status": "failed",
         "bytes_out": 100},
        {"timestamp": "2026-10-15 09:04", "source_ip": "198.51.100.8",
         "username": "admin", "event": "login", "status": "failed",
         "bytes_out": 100},
        {"timestamp": "2026-10-15 09:05", "source_ip": "192.0.2.22",
         "username": "student2", "event": "upload", "status": "success",
         "bytes_out": 15000000}
    ])


def analyze_logs(df):
    import ipaddress

    alerts = []
    required = {"source_ip", "status"}
    missing = required - set(df.columns)

    if missing:
        return [{
            "severity": "High",
            "rule": "Schema validation",
            "source_ip": "",
            "evidence": "Missing required columns: " +
                        ", ".join(sorted(missing)),
            "recommendation": "Add the required columns and upload again."
        }]

    data = df.copy()
    data.columns = [str(c).strip().lower() for c in data.columns]

    # Validate source IP addresses where possible.
    invalid_ips = []
    for idx, raw_ip in data["source_ip"].items():
        try:
            ipaddress.ip_address(str(raw_ip).strip())
        except ValueError:
            invalid_ips.append((idx, str(raw_ip)))

    for idx, raw_ip in invalid_ips:
        alerts.append({
            "severity": "Low",
            "rule": "Invalid source IP",
            "source_ip": raw_ip,
            "evidence": f"Row {idx + 1} has an invalid IP value.",
            "recommendation": "Check the source_ip field in the original log."
        })

    # Repeated failed logins from one source IP.
    statuses = data["status"].fillna("").astype(str).str.strip().str.lower()
    failed = data[statuses.isin(["failed", "failure", "denied"])]

    failed_counts = failed["source_ip"].fillna("UNKNOWN").astype(str).value_counts()

    for ip, count in failed_counts.items():
        if count >= 3:
            alerts.append({
                "severity": "High" if count >= 5 else "Medium",
                "rule": "Repeated failed logins",
                "source_ip": ip,
                "evidence": f"{count} failed events were found for this source.",
                "recommendation": (
                    "Review authentication logs and verify whether the "
                    "activity belongs to an authorized user."
                )
            })

    # Large outbound transfers; threshold is configurable in the UI.
    if "bytes_out" in data.columns:
        sizes = pd.to_numeric(data["bytes_out"], errors="coerce")

        invalid_sizes = sizes.isna() & data["bytes_out"].notna()
        if invalid_sizes.any():
            alerts.append({
                "severity": "Low",
                "rule": "Invalid transfer-size values",
                "source_ip": "",
                "evidence": f"{int(invalid_sizes.sum())} rows have non-numeric bytes_out values.",
                "recommendation": "Correct the bytes_out column before relying on transfer alerts."
            })

        threshold = 10_000_000
        for idx in data.index[sizes >= threshold]:
            alerts.append({
                "severity": "Medium",
                "rule": "Large outbound transfer",
                "source_ip": str(data.loc[idx, "source_ip"]),
                "evidence": f"Row {idx + 1}: {sizes.loc[idx]:,.0f} bytes sent.",
                "recommendation": (
                    "Compare the transfer with normal activity and approved "
                    "data-transfer policies."
                )
            })

    # Several distinct usernames failing from the same IP.
    if "username" in data.columns:
        failed_with_users = failed.copy()
        failed_with_users["username"] = (
            failed_with_users["username"].fillna("").astype(str).str.strip()
        )
        for ip, group in failed_with_users.groupby("source_ip"):
            users = sorted({
                u for u in group["username"].tolist() if u
            })
            if len(users) >= 3:
                alerts.append({
                    "severity": "High",
                    "rule": "Multiple-account login failures",
                    "source_ip": str(ip),
                    "evidence": f"Failed attempts involved {len(users)} usernames.",
                    "recommendation": (
                        "Review for password spraying and confirm whether "
                        "the source is an approved scanner or administrator."
                    )
                })

    if not alerts:
        alerts.append({
            "severity": "Info",
            "rule": "No configured rule matched",
            "source_ip": "",
            "evidence": "The analyzer did not detect activity covered by its rules.",
            "recommendation": (
                "This does not prove the logs are benign. Add relevant "
                "detection rules for your environment."
            )
        })

    return alerts


st.title("🛡️ CyberShield AI")
st.caption("Unified cybersecurity analysis — Hackathon MVP")
st.info(
    "Prototype only: checks are rule-based, not a trained AI or a substitute "
    "for professional security tools. Use sample or authorized data."
)

with st.sidebar:
    st.header("Navigation")
    page = st.radio(
        "Choose a module",
        ["Dashboard", "VisionGuard", "PhishProof",
         "PromptFence AI", "NetSage", "SOC Copilot"]
    )
    st.divider()
    st.caption("CyberShield 2K26 • MVP")


if page == "Dashboard":
    st.title("🛡️ CyberShield AI")
    st.caption("UNIFIED SECURITY OPERATIONS CENTER  •  HACKATHON MVP")

    findings = st.session_state.findings

    high = sum(x["severity"] == "High" for x in findings)
    medium = sum(x["severity"] == "Medium" for x in findings)
    low = sum(x["severity"] == "Low" for x in findings)

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Findings", len(findings))
    c2.metric("High Severity", high)
    c3.metric("Medium Severity", medium)
    c4.metric("Low Severity", low)

    st.divider()
    st.subheader("Security Modules")

    modules = [
        ("🔎 VisionGuard", "File integrity and SHA-256 verification"),
        ("🔗 PhishProof", "Suspicious URL pattern analysis"),
        ("🧠 PromptFence AI", "Prompt injection and data-pattern scanning"),
        ("📊 NetSage", "Rule-based security log analysis"),
        ("📝 SOC Copilot", "Combined findings and incident reports")
    ]

    for left, right in zip(st.columns(2), [modules[:3], modules[3:]]):
        for name, description in right:
            with left:
                st.markdown(f"**{name}**")
                st.caption(description)

    st.divider()
    st.subheader("Latest Security Findings")

    if findings:
        recent = pd.DataFrame(findings).tail(10).iloc[::-1]
        st.dataframe(recent, use_container_width=True, hide_index=True)

        st.download_button(
            "⬇️ Export all findings",
            pd.DataFrame(findings).to_csv(index=False),
            "cybershield_all_findings.csv",
            "text/csv"
        )
    else:
        st.info(
            "No findings recorded yet. Open a module and run a test "
            "to populate this dashboard."
        )

    st.caption(
        "Prototype notice: detections are rule-based and require human "
        "verification. No live monitoring is implied."
    )

elif page == "VisionGuard":
    st.subheader("🔎 VisionGuard — File Integrity Monitor")
    st.write(
        "Create a trusted file baseline, download it, and later compare "
        "files against it to detect content changes."
    )

    files = st.file_uploader(
        "Choose files to inspect",
        accept_multiple_files=True,
        key="vision_files"
    )

    if st.button("Scan selected files", key="scan_files"):
        if not files:
            st.warning("Choose at least one file.")
        else:
            rows = []
            for file in files:
                data = file.getvalue()
                rows.append({
                    "filename": file.name,
                    "size_bytes": len(data),
                    "sha256": sha256(data)
                })

            hashes = Counter(row["sha256"] for row in rows)
            for row in rows:
                row["duplicate_in_upload"] = hashes[row["sha256"]] > 1

                if row["duplicate_in_upload"]:
                    add_finding(
                        "VisionGuard", "Medium", "Duplicate file content",
                        f"{row['filename']} matches another uploaded file."
                    )

            st.session_state["vision_results"] = rows

    results = st.session_state.get("vision_results", [])

    if results:
        results_df = pd.DataFrame(results)
        st.dataframe(results_df, use_container_width=True)

        st.download_button(
            "Download trusted baseline (CSV)",
            results_df[["filename", "size_bytes", "sha256"]].to_csv(index=False),
            "visionguard_baseline.csv",
            "text/csv"
        )

        st.download_button(
            "Download scan results (CSV)",
            results_df.to_csv(index=False),
            "visionguard_scan_results.csv",
            "text/csv"
        )

    st.divider()
    st.markdown("### Verify against a trusted baseline")
    st.caption(
        "Upload a baseline CSV that you previously created and protected. "
        "A baseline created from an already compromised file cannot establish trust."
    )

    baseline_file = st.file_uploader(
        "Upload baseline CSV",
        type=["csv"],
        key="vision_baseline"
    )
    verify_files = st.file_uploader(
        "Select files to verify",
        accept_multiple_files=True,
        key="vision_verify_files"
    )

    if st.button("Verify integrity", key="verify_integrity"):
        if not baseline_file or not verify_files:
            st.warning("Upload both a baseline CSV and files to verify.")
        else:
            try:
                baseline_df = pd.read_csv(baseline_file)

                required = {"filename", "sha256"}
                if not required.issubset(baseline_df.columns):
                    st.error(
                        "Baseline must contain filename and sha256 columns."
                    )
                elif baseline_df["filename"].duplicated().any():
                    st.error(
                        "Baseline contains duplicate filenames. "
                        "Create a baseline with unique filenames."
                    )
                else:
                    baseline = dict(zip(
                        baseline_df["filename"].astype(str),
                        baseline_df["sha256"].astype(str)
                    ))

                    verification_rows = []

                    for file in verify_files:
                        current_hash = sha256(file.getvalue())
                        name = file.name

                        if name not in baseline:
                            status = "NOT IN BASELINE"
                            severity = "Medium"
                            add_finding(
                                "VisionGuard", severity,
                                "File absent from baseline",
                                f"{name} was not listed in the trusted baseline."
                            )
                        elif current_hash != baseline[name]:
                            status = "HASH MISMATCH"
                            severity = "High"
                            add_finding(
                                "VisionGuard", severity,
                                "File integrity mismatch",
                                f"{name} does not match its baseline SHA-256."
                            )
                        else:
                            status = "MATCH"
                        
                        verification_rows.append({
                            "filename": name,
                            "current_sha256": current_hash,
                            "integrity_status": status
                        })

                    verification_df = pd.DataFrame(verification_rows)
                    st.dataframe(
                        verification_df, use_container_width=True
                    )

                    st.download_button(
                        "Download verification report",
                        verification_df.to_csv(index=False),
                        "visionguard_verification.csv",
                        "text/csv"
                    )

            except Exception as exc:
                st.error(f"Could not verify files: {exc}")


elif page == "PhishProof":
    st.subheader("🔗 PhishProof — URL Risk Check")
    url = st.text_input(
        "Paste a URL to inspect",
        placeholder="https://example.com"
    )
    if st.button("Analyze URL"):
        verdict, reasons = check_url(url)
        st.markdown(f"### Result: {verdict}")
        for reason in reasons:
            st.write("• " + reason)
        if "Suspicious" in verdict:
            add_finding(
                "PhishProof", "High", "Suspicious URL pattern",
                f"URL checked: {url}. Reasons: {'; '.join(reasons)}"
            )
        else:
            add_finding(
                "PhishProof", "Info", "URL heuristic check completed",
                f"URL checked: {url}. Result: {verdict}"
            )
        st.warning(
            "Do not open suspicious links. This prototype does not query "
            "live reputation databases and may miss dangerous URLs."
        )


elif page == "PromptFence AI":
    st.subheader("🧠 PromptFence AI — Prompt Security Scanner")
    st.warning(
        "Use synthetic test data. This prototype scans text using rules; "
        "it does not call an AI model or guarantee that secrets are protected."
    )

    prompt = st.text_area(
        "Text to inspect",
        placeholder="Paste a test prompt here. Do not paste real passwords, tokens, or confidential data.",
        height=180
    )

    if st.button("Scan text", key="promptfence_scan"):
        if not prompt.strip():
            st.warning("Enter some text to scan.")
        else:
            findings = scan_prompt(prompt)

            if findings:
                high_count = sum(f["severity"] == "High" for f in findings)
                medium_count = sum(f["severity"] == "Medium" for f in findings)

                a, b, c = st.columns(3)
                a.metric("Patterns detected", len(findings))
                b.metric("High severity", high_count)
                c.metric("Medium severity", medium_count)

                st.markdown("### Detection evidence")

                for finding in findings:
                    with st.expander(
                        f"{finding['severity']} — {finding['category']}",
                        expanded=True
                    ):
                        st.write(finding["explanation"])
                        st.write("**Recommended action:** " + finding["recommendation"])

                    add_finding(
                        "PromptFence AI",
                        finding["severity"],
                        finding["category"],
                        finding["explanation"] + " Recommendation: " +
                        finding["recommendation"]
                    )

                st.session_state["promptfence_results"] = findings
            else:
                st.success("No configured patterns were detected.")
                st.caption(
                    "This does not prove the text is safe. Unrecognized attacks "
                    "and sensitive-data formats may not be detected."
                )
                st.session_state["promptfence_results"] = []

    results = st.session_state.get("promptfence_results", [])
    if results:
        report = pd.DataFrame(results)
        st.download_button(
            "Download PromptFence report",
            report.to_csv(index=False),
            "promptfence_report.csv",
            "text/csv"
        )


elif page == "NetSage":
    st.subheader("📊 NetSage — Security Log Analyzer")
    st.caption("Rule-based detection prototype; validate alerts before acting.")

    threshold_mb = st.slider(
        "Large outbound transfer threshold (MB)",
        min_value=1,
        max_value=100,
        value=10
    )
    st.session_state["netsage_threshold_bytes"] = threshold_mb * 1_000_000

    uploaded = st.file_uploader(
        "Upload a security log CSV",
        type=["csv"],
        key="netsage_upload"
    )

    col1, col2 = st.columns(2)

    with col1:
        if st.button("Load sample logs", key="netsage_sample"):
            st.session_state["net_logs"] = make_sample_logs()
            st.session_state.pop("net_alerts", None)

    with col2:
        if st.button("Clear NetSage results", key="netsage_clear"):
            st.session_state.pop("net_logs", None)
            st.session_state.pop("net_alerts", None)
            st.rerun()

    if uploaded is not None:
        try:
            st.session_state["net_logs"] = pd.read_csv(uploaded)
            st.session_state.pop("net_alerts", None)
        except Exception as exc:
            st.error(f"Could not read CSV: {exc}")

    df = st.session_state.get("net_logs")

    if df is not None:
        st.markdown("### Uploaded log preview")
        st.write(f"Rows: {len(df)} | Columns: {len(df.columns)}")
        st.dataframe(df.head(200), use_container_width=True)

        if st.button("Analyze security logs", key="netsage_analyze"):
            original_analyzer = analyze_logs
            alerts = original_analyzer(df)

            # Apply the threshold chosen in the UI.
            threshold = st.session_state.get(
                "netsage_threshold_bytes", 10_000_000
            )
            if "bytes_out" in df.columns:
                sizes = pd.to_numeric(df["bytes_out"], errors="coerce")
                large_rows = df.index[sizes >= threshold]
                alerts = [
                    a for a in alerts
                    if a["rule"] != "Large outbound transfer"
                ]
                for idx in large_rows:
                    alerts.append({
                        "severity": "Medium",
                        "rule": "Large outbound transfer",
                        "source_ip": str(df.loc[idx, "source_ip"]),
                        "evidence": (
                            f"Row {idx + 1}: {sizes.loc[idx]:,.0f} bytes; "
                            f"threshold is {threshold:,} bytes."
                        ),
                        "recommendation": (
                            "Validate this transfer against normal usage "
                            "and approved data-transfer policies."
                        )
                    })

            st.session_state["net_alerts"] = alerts

            # Share alerts with the common SOC Copilot dashboard.
            for alert in alerts:
                if alert["severity"] != "Info":
                    add_finding(
                        "NetSage",
                        alert["severity"],
                        alert["rule"],
                        f"{alert['evidence']} Recommendation: "
                        f"{alert['recommendation']}"
                    )

        alerts = st.session_state.get("net_alerts", [])

        if alerts:
            st.markdown("### Detection results")
            alert_df = pd.DataFrame(alerts)

            a, b, c = st.columns(3)
            a.metric("Total alerts", len(alerts))
            b.metric(
                "High",
                sum(x["severity"] == "High" for x in alerts)
            )
            c.metric(
                "Medium",
                sum(x["severity"] == "Medium" for x in alerts)
            )

            st.dataframe(alert_df, use_container_width=True)

            st.download_button(
                "Download NetSage alerts CSV",
                alert_df.to_csv(index=False),
                "netsage_alerts.csv",
                "text/csv"
            )

elif page == "SOC Copilot":
    st.subheader("📝 SOC Copilot — Incident Summary")
    findings = st.session_state.findings
    if not findings:
        st.info("Run one or more modules first. Findings will appear here.")
    else:
        df = pd.DataFrame(findings)
        st.dataframe(df, use_container_width=True)

        high = sum(item["severity"] == "High" for item in findings)
        medium = sum(item["severity"] == "Medium" for item in findings)
        st.markdown("### Summary")
        st.write(f"- Total recorded findings: **{len(findings)}**")
        st.write(f"- High severity: **{high}**")
        st.write(f"- Medium severity: **{medium}**")
        st.write(
            "- Review high-severity findings first, validate them manually, "
            "and document the response."
        )

        report = {
            "product": "CyberShield AI MVP",
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "notice": "Rule-based prototype; validate findings before acting.",
            "summary": {
                "total_findings": len(findings),
                "high": high,
                "medium": medium
            },
            "findings": findings
        }
        st.download_button(
            "Download incident report JSON",
            json.dumps(report, indent=2),
            "cybershield_incident_report.json",
            "application/json"
        )
        st.download_button(
            "Download findings CSV",
            df.to_csv(index=False),
            "cybershield_findings.csv",
            "text/csv"
        )

    if st.button("Clear all findings"):
        st.session_state.findings = []
        st.rerun()
