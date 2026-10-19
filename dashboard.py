"""EgressEye control room: policy, egress signals and delivery assurance."""

from __future__ import annotations

import json
import os

import pandas as pd
import requests
import streamlit as st

import delivery_gate
import detector
import policy
import simulator

st.set_page_config(
    page_title="EgressEye | Container Network Watchdog",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

APP_URL = os.environ.get("APP_URL", "http://127.0.0.1:5000").rstrip("/")

st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=Manrope:wght@400;500;600;700;800&display=swap');
    :root {
      --ink:#edf3fb; --muted:#91a1b8; --muted-2:#71829a;
      --panel:#101a2a; --panel-2:#142136; --line:#26374e;
      --teal:#61dfc5; --amber:#f4c46e; --red:#ff788b; --blue:#8ebcff;
    }
    html, body, [class*="css"] { font-family:'Manrope',sans-serif; }
    .stApp { background:radial-gradient(ellipse at 76% -8%,#183243 0,#0c1726 38%,#09111c 78%); color:var(--ink); }
    [data-testid="stHeader"] { background:rgba(8,15,25,.62); }
    [data-testid="stSidebar"] { background:linear-gradient(180deg,#0d1828 0%,#0a1320 100%); border-right:1px solid #223149; }
    [data-testid="stSidebar"] * { color:var(--ink); }
    [data-testid="stSidebar"] [data-testid="stMarkdownContainer"] h2 { letter-spacing:-.04em; }
    [data-testid="stSidebar"] [data-testid="stCaptionContainer"] { color:#8091a9; }
    .brand-lockup { display:flex; align-items:center; gap:.68rem; margin:.1rem 0 1.15rem; }
    .brand-mark { display:grid; place-items:center; width:2.18rem; height:2.18rem; border-radius:9px; color:#08211f; background:linear-gradient(145deg,#8af0d9,#37b9a1); font:700 .75rem 'DM Mono',monospace; box-shadow:0 5px 18px rgba(57,190,165,.18); }
    .brand-name { color:#f0f6fd; font-size:1rem; font-weight:800; letter-spacing:-.035em; line-height:1.1; }
    .brand-sub { color:#8091a9; font:500 .58rem 'DM Mono',monospace; letter-spacing:.13em; margin-top:.22rem; }
    .block-container { padding:1.65rem 2.35rem 3rem; max-width:1540px; }
    h1,h2,h3 { letter-spacing:-.04em; color:#f1f6fd; }
    h1 { font-size:2.45rem !important; line-height:1.1 !important; font-weight:800 !important; }
    h2 { font-size:1.38rem !important; font-weight:750 !important; }
    h3 { font-size:1.02rem !important; font-weight:700 !important; }
    p, label, [data-testid="stCaptionContainer"] { color:var(--muted); }
    .eyebrow { color:var(--teal); font:500 .69rem 'DM Mono',monospace; letter-spacing:.17em; text-transform:uppercase; margin-bottom:.48rem; }
    .hero { position:relative; display:flex; align-items:flex-end; justify-content:space-between; gap:2rem; padding:1.1rem 1.25rem 1.4rem; margin:.1rem 0 1.05rem; border:1px solid rgba(113,151,181,.17); border-radius:16px; background:linear-gradient(115deg,rgba(19,37,55,.92),rgba(14,27,43,.8) 63%,rgba(19,49,57,.67)); box-shadow:0 18px 50px rgba(0,0,0,.14); overflow:hidden; }
    .hero:after { content:''; position:absolute; width:260px; height:260px; right:12%; top:-205px; border:1px solid rgba(97,223,197,.17); border-radius:50%; box-shadow:0 0 0 28px rgba(97,223,197,.025),0 0 0 58px rgba(97,223,197,.02); pointer-events:none; }
    .hero-copy,.hero-state { position:relative; z-index:1; }
    .hero-copy p { max-width:760px; margin:.48rem 0 0; color:#aab8ca; line-height:1.55; font-size:.94rem; }
    .hero-state { border:1px solid rgba(97,223,197,.32); color:#a5f2e3; background:rgba(16,52,52,.72); padding:.62rem .88rem; border-radius:9px; font:500 .69rem 'DM Mono',monospace; letter-spacing:.05em; white-space:nowrap; box-shadow:inset 0 1px rgba(255,255,255,.04); }
    .section-kicker { color:#8496ad; font:500 .68rem 'DM Mono',monospace; text-transform:uppercase; letter-spacing:.14em; margin:0 0 .42rem; }
    [data-testid="stMetric"] { position:relative; background:linear-gradient(145deg,rgba(21,37,57,.97),rgba(14,25,40,.97)); border:1px solid #2a3a50; padding:1.05rem 1.1rem .98rem; border-radius:12px; box-shadow:0 9px 24px rgba(0,0,0,.12); min-height:112px; overflow:hidden; }
    [data-testid="stMetric"]:before { content:''; position:absolute; top:0; left:0; right:0; height:2px; background:linear-gradient(90deg,rgba(97,223,197,.85),rgba(97,223,197,0)); opacity:.8; }
    [data-testid="stHorizontalBlock"] [data-testid="stMetric"] { transition:transform .18s ease,border-color .18s ease; }
    [data-testid="stMetricLabel"] { color:#a5b3c6 !important; font-size:.72rem !important; font-weight:600 !important; letter-spacing:.015em; }
    [data-testid="stMetricValue"] { color:#f1f7ff !important; font-size:1.78rem !important; font-weight:750 !important; letter-spacing:-.055em; }
    [data-testid="stMetricDelta"] { font-size:.72rem !important; }
    .stButton>button, [data-testid="stDownloadButton"] button { border-radius:8px; border:1px solid #344a63; background:linear-gradient(180deg,#17283d,#132237); color:#e7eef8; font-weight:650; min-height:2.48rem; transition:border-color .16s ease,background .16s ease,transform .16s ease; }
    .stButton>button:hover, [data-testid="stDownloadButton"] button:hover { border-color:var(--teal); color:var(--teal); background:#172c40; transform:translateY(-1px); }
    .stButton>button[kind="primary"] { background:linear-gradient(180deg,#218275,#17665f); border-color:#35a991; color:#f4fffc; }
    .stButton>button[kind="primary"]:hover { background:#258e7d; color:white; }
    .stTextInput input, .stNumberInput input, [data-baseweb="select"] > div { background:#101b2a; border-color:#304057; color:#e8eef7; border-radius:8px; }
    [data-testid="stTextInput"] input:focus, [data-testid="stNumberInput"] input:focus { border-color:var(--teal); box-shadow:0 0 0 1px rgba(97,223,197,.2); }
    [data-testid="stDataFrame"] { border:1px solid #2a3a50; border-radius:10px; overflow:hidden; background:rgba(13,23,37,.7); }
    [data-baseweb="tab-list"] { gap:.3rem; border-bottom:1px solid #2a3a50; padding:0 .25rem; }
    [data-baseweb="tab"] { background:transparent; border-radius:7px 7px 0 0; color:#8fa0b7; padding:.68rem .95rem; font-size:.85rem; font-weight:650; }
    [data-baseweb="tab"]:hover { color:#dce8f5; background:rgba(255,255,255,.035); }
    [aria-selected="true"][data-baseweb="tab"] { color:var(--teal) !important; }
    [data-testid="stAlert"] { border-radius:10px; border:1px solid rgba(255,255,255,.08); }
    [data-testid="stExpander"] { border:1px solid #26374e; border-radius:10px; background:rgba(16,27,43,.48); }
    [data-testid="stExpander"] summary { color:#dce6f2; font-weight:650; }
    .mono { font-family:'DM Mono',monospace; }
    .small-note { color:var(--muted); font-size:.84rem; }
    hr { border-color:#26374e; }
    @media (max-width: 800px) {
      .block-container { padding:.9rem 1rem 2rem; }
      .hero { align-items:flex-start; flex-direction:column; gap:1rem; padding:1rem; }
      h1 { font-size:2rem !important; }
      [data-testid="stMetric"] { min-height:98px; padding:.85rem; }
      [data-testid="stMetricValue"] { font-size:1.45rem !important; }
    }
    </style>
    """,
    unsafe_allow_html=True,
)


def trigger_live_probe(route: str, label: str) -> None:
    try:
        response = requests.get(f"{APP_URL}{route}", timeout=18)
        try:
            detail = response.json()
        except ValueError:
            detail = {"result": response.text[:400]}
        st.session_state["last_probe"] = {"label": label, "http": response.status_code, "detail": detail}
    except requests.RequestException as exc:
        st.session_state["last_probe"] = {"label": label, "error": str(exc)}


def save_current_policy(mode: str, byte_limit: int) -> None:
    current = policy.load_policy()
    current["mode"] = mode
    current["max_bytes_out"] = byte_limit
    policy.save_policy(current)
    detector.reanalyze_all()


def show_table(frame: pd.DataFrame, columns: list[str] | None = None) -> None:
    if frame.empty:
        st.info("No matching connection events yet.")
        return
    selected = columns or [
        "timestamp", "container", "dest_host", "dest_port", "protocol",
        "bytes_attempted", "status", "severity", "action", "outcome", "source", "reason",
    ]
    selected = [column for column in selected if column in frame.columns]
    labels = {
        "timestamp": "Time", "container": "Workload", "dest_host": "Destination",
        "dest_port": "Port", "protocol": "Protocol", "bytes_attempted": "Bytes",
        "bytes_out": "Bytes out", "status": "Signal", "severity": "Severity",
        "action": "Decision", "outcome": "Outcome", "source": "Source", "reason": "Reason",
    }
    number_columns = {"dest_port", "bytes_attempted", "bytes_out"}
    column_config = {
        column: (
            st.column_config.NumberColumn(labels.get(column, column), format="%.0f")
            if column in number_columns
            else st.column_config.TextColumn(labels.get(column, column))
        )
        for column in selected
    }
    st.dataframe(frame[selected], use_container_width=True, hide_index=True, height=390, column_config=column_config)


def delivery_report() -> dict | None:
    path = delivery_gate.REPORT_FILE
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


with st.sidebar:
    st.markdown("<div class='eyebrow'>CONTROL PLANE</div>", unsafe_allow_html=True)
    st.markdown(
        "<div class='brand-lockup'><span class='brand-mark'>EE</span><div><div class='brand-name'>EgressEye</div><div class='brand-sub'>NETWORK CONTROL</div></div></div>",
        unsafe_allow_html=True,
    )
    active_policy = policy.load_policy()
    mode = active_policy["mode"].upper()
    status_color = "#55dbc2" if mode == "BLOCK" else "#f5c36a"
    status_copy = "ENFORCING" if mode == "BLOCK" else "MONITORING"
    st.markdown(
        f"<div style='border:1px solid {status_color};background:#101d29;padding:.7rem .8rem;border-radius:9px;margin:.6rem 0 1.1rem;color:{status_color};font:500 .76rem DM Mono,monospace'>● {status_copy} · HTTPS / HTTP proxy</div>",
        unsafe_allow_html=True,
    )
    st.markdown("<div class='section-kicker'>Live workload probes</div>", unsafe_allow_html=True)
    if st.button("↗  Try approved destination", use_container_width=True):
        trigger_live_probe("/demo/allowed", "Approved live egress")
    if st.button("⛔  Attempt unapproved destination", type="primary", use_container_width=True):
        trigger_live_probe("/demo/blocked", "Unapproved live egress")
    if st.session_state.get("last_probe"):
        probe = st.session_state["last_probe"]
        with st.expander(f"Latest probe · {probe['label']}", expanded=True):
            st.json(probe.get("detail", {"error": probe.get("error")}))
    st.divider()
    st.markdown("<div class='section-kicker'>Repeatable event demo</div>", unsafe_allow_html=True)
    if st.button("Generate normal activity", use_container_width=True):
        simulator.generate_normal(5)
        st.rerun()
    if st.button("Generate suspicious activity", use_container_width=True):
        simulator.generate_suspicious()
        st.rerun()
    st.caption("Synthetic events are labeled in the event stream. Live probes traverse the Docker egress proxy.")
    st.divider()
    if st.button("Refresh event stream", use_container_width=True):
        st.rerun()
    if st.button("Clear event history", use_container_width=True):
        detector.clear_history()
        st.rerun()
    st.caption("Policy changes take effect on the next proxy request.")

try:
    ingest = detector.process_events()
    events = detector.get_events()
    active_policy = policy.load_policy()
except (OSError, RuntimeError, ValueError) as exc:
    st.error(f"EgressEye could not load its local policy or event store: {exc}")
    st.stop()

frame = pd.DataFrame(events)
if frame.empty:
    frame = pd.DataFrame(columns=[
        "timestamp", "container", "dest_host", "dest_port", "protocol", "bytes_out",
        "bytes_attempted", "status", "severity", "reason", "action", "outcome", "source",
    ])
else:
    frame["bytes_out"] = pd.to_numeric(frame["bytes_out"], errors="coerce").fillna(0)
    frame["bytes_attempted"] = pd.to_numeric(frame["bytes_attempted"], errors="coerce").fillna(frame["bytes_out"])

alert_frame = frame[frame["status"] == "ALERT"]
blocked_frame = frame[frame["action"] == "BLOCK"]
allowed_frame = frame[frame["action"] == "ALLOW"]
serious_frame = alert_frame[alert_frame["severity"].isin(["HIGH", "CRITICAL"])]

st.markdown(
    f"""
    <div class="hero">
      <div class="hero-copy">
        <div class="eyebrow">CONTAINER NETWORK WATCHDOG</div>
        <h1>Know every way out.</h1>
        <p>Policy-driven egress visibility for container workloads. Detect unexpected destinations, inspect the evidence, and block unapproved HTTP/S connections at the gateway.</p>
      </div>
      <div class="hero-state" style="border-color:{status_color};color:{status_color}">● {mode} MODE &nbsp;·&nbsp; POLICY ACTIVE</div>
    </div>
    """,
    unsafe_allow_html=True,
)

if ingest["malformed"]:
    st.warning(f"{ingest['malformed']} malformed event line(s) were ignored.")
if not frame.empty and len(alert_frame):
    st.error(f"{len(alert_frame)} connection alert(s) · {len(blocked_frame)} blocked · {len(serious_frame)} high or critical")
elif not frame.empty:
    st.success("No policy violations in the observed event history.")

metric_cols = st.columns(4)
metric_cols[0].metric("Connections observed", f"{len(frame):,}")
metric_cols[1].metric("Policy allowed", f"{len(allowed_frame):,}")
metric_cols[2].metric("Blocked at gateway", f"{len(blocked_frame):,}")
metric_cols[3].metric("High / critical alerts", f"{len(serious_frame):,}")

tabs = st.tabs(["Overview", "Event stream", "Egress policy", "Container delivery"])

with tabs[0]:
    left, right = st.columns([1.5, 1], gap="large")
    with left:
        st.markdown("<div class='section-kicker'>SIGNAL OVERVIEW</div>", unsafe_allow_html=True)
        st.subheader("Outbound destinations")
        if not frame.empty:
            counts = frame.groupby("dest_host", dropna=False).size().sort_values(ascending=False).head(8)
            st.bar_chart(counts, color="#55dbc2", height=260)
        else:
            st.info("Generate demo activity or run a live probe to populate this view.")
        st.markdown("<div class='section-kicker' style='margin-top:1.2rem'>RECENT ACTIVITY</div>", unsafe_allow_html=True)
        recent = frame.head(7)
        show_table(recent, ["timestamp", "container", "dest_host", "dest_port", "bytes_attempted", "severity", "action", "source"])
    with right:
        st.markdown("<div class='section-kicker'>NEEDS REVIEW</div>", unsafe_allow_html=True)
        st.subheader("Alert queue")
        if alert_frame.empty:
            st.success("Queue clear")
            st.caption("An unapproved connection is treated as a signal for investigation. Legitimate services may need to be added to policy.")
        else:
            for _, row in alert_frame.head(6).iterrows():
                label = f"{row['severity']}  ·  {row['dest_host']}:{row['dest_port']}"
                with st.container(border=True):
                    st.markdown(f"**{label}**")
                    st.caption(f"{row['action']} · {row['container']} · {int(row['bytes_attempted']):,} bytes attempted")
                    st.write(row["reason"] or "Destination requires review")
        st.markdown("<div class='section-kicker' style='margin-top:1.35rem'>POLICY SNAPSHOT</div>", unsafe_allow_html=True)
        st.subheader(f"{len(active_policy['destinations'])} trusted destinations")
        st.caption(f"Outbound byte alert limit: {active_policy['max_bytes_out']:,} bytes per connection")
        st.caption("Untrusted destinations are blocked in BLOCK mode. HTTPS tunnel payloads stay encrypted; the gateway records destination, port, outcome, and byte counts.")

with tabs[1]:
    st.markdown("<div class='section-kicker'>INVESTIGATION</div>", unsafe_allow_html=True)
    st.subheader("Connection event stream")
    f1, f2, f3, f4 = st.columns([.9, .9, 1.4, .65])
    status_filter = f1.selectbox("Classification", ["All", "Alerts", "Clear"])
    source_filter = f2.selectbox("Source", ["All", "proxy", "simulator"])
    query = f3.text_input("Search destination or workload", placeholder="example.com")
    filtered = frame.copy()
    if status_filter == "Alerts":
        filtered = filtered[filtered["status"] == "ALERT"]
    elif status_filter == "Clear":
        filtered = filtered[filtered["status"] == "OK"]
    if source_filter != "All":
        filtered = filtered[filtered["source"] == source_filter]
    if query.strip():
        needle = query.strip().lower()
        filtered = filtered[
            filtered["dest_host"].astype(str).str.lower().str.contains(needle)
            | filtered["container"].astype(str).str.lower().str.contains(needle)
        ]
    f4.download_button(
        "Export CSV",
        data=filtered.to_csv(index=False).encode("utf-8"),
        file_name="egresseye-events.csv",
        mime="text/csv",
        use_container_width=True,
        disabled=filtered.empty,
    )
    st.caption(f"Showing {len(filtered):,} of {len(frame):,} events. Event history is stored locally in SQLite.")
    show_table(filtered)
    if not filtered.empty:
        with st.expander("Inspect an event"):
            event_labels = {
                f"{r['timestamp']} · {r['dest_host']}:{r['dest_port']} · {r['action']} · {r['id'][:8]}": r
                for _, r in filtered.iterrows()
            }
            selected = st.selectbox("Select event", list(event_labels))
            st.json(event_labels[selected].to_dict())

with tabs[2]:
    st.markdown("<div class='section-kicker'>ZERO-TRUST EGRESS</div>", unsafe_allow_html=True)
    st.subheader("Approved destinations")
    st.caption("Use exact hostnames or a `*.domain.example` wildcard for subdomains. Ports are explicit. The gateway reloads this file for every new connection.")
    current = policy.load_policy()
    with st.form("policy_settings"):
        p1, p2, p3 = st.columns([1, 1, 1.5])
        selected_mode = p1.selectbox("Enforcement", ["block", "monitor"], index=0 if current["mode"] == "block" else 1, format_func=lambda x: x.upper())
        selected_limit = p2.number_input("Alert / block threshold (bytes)", min_value=0, max_value=1_000_000_000, value=min(current["max_bytes_out"], 1_000_000_000), step=50_000)
        p3.markdown("**BLOCK** rejects any unapproved destination and stops transfers above the byte threshold. **MONITOR** allows connections and raises alerts.")
        if st.form_submit_button("Save enforcement settings", type="primary"):
            save_current_policy(selected_mode, int(selected_limit))
            st.success("Enforcement settings saved. The proxy uses them on the next connection.")
            st.rerun()

    destinations = current["destinations"]
    if destinations:
        display = pd.DataFrame(destinations)
        display["ports"] = display["ports"].apply(lambda ports: ", ".join(str(port) for port in ports))
        st.dataframe(display, use_container_width=True, hide_index=True)
    else:
        st.warning("No destinations are currently approved. All new destinations will alert; BLOCK mode will reject them.")

    add_col, remove_col = st.columns(2, gap="large")
    with add_col:
        st.markdown("#### Add a destination")
        with st.form("add_destination", clear_on_submit=True):
            new_host = st.text_input("Hostname or wildcard", placeholder="*.vendor.example")
            new_ports = st.text_input("Allowed ports", value="443", help="Comma-separated numeric ports")
            new_note = st.text_input("Purpose", placeholder="Document why this destination is trusted")
            submitted = st.form_submit_button("Add to allowlist")
        if submitted:
            try:
                entry = {"host": policy.normalize_host(new_host), "ports": [int(p.strip()) for p in new_ports.split(",") if p.strip()], "note": new_note}
                updated = dict(current)
                updated["destinations"] = [*current["destinations"], entry]
                policy.save_policy(updated)
                detector.reanalyze_all()
                st.success(f"Added {entry['host']}")
                st.rerun()
            except (ValueError, RuntimeError) as exc:
                st.error(str(exc))
    with remove_col:
        st.markdown("#### Remove a destination")
        if destinations:
            remove_host = st.selectbox("Select destination", [item["host"] for item in destinations])
            if st.button("Remove selected destination"):
                updated = dict(current)
                updated["destinations"] = [item for item in destinations if item["host"] != remove_host]
                policy.save_policy(updated)
                detector.reanalyze_all()
                st.success(f"Removed {remove_host}")
                st.rerun()
        else:
            st.caption("The allowlist is empty.")

with tabs[3]:
    st.markdown("<div class='section-kicker'>SECURE CONTAINER DELIVERY</div>", unsafe_allow_html=True)
    st.subheader("Image admission gate")
    st.caption("ContainerTrust’s useful digest and signature checks are preserved here with a Trivy vulnerability and secret scan. The gate runs from the host and reports into this dashboard.")
    report = delivery_report()
    if report is None:
        st.info("No delivery gate report yet. Run the host-side commands below; the result will appear here.")
    else:
        if report.get("decision") == "APPROVED":
            st.success(f"APPROVED · {report.get('image')} · deployment may proceed")
        else:
            st.error(f"BLOCKED · {report.get('image')} · do not deploy")
            for reason in report.get("reasons", []):
                st.write(f"- {reason}")
        st.caption(f"Checked {report.get('time', 'unknown time')}")
        scan = report.get("scan", {})
        digest = report.get("digest", {})
        signature = report.get("signature", {})
        cols = st.columns(5)
        counts = scan.get("counts", {})
        cols[0].metric("Critical", counts.get("CRITICAL", "—"))
        cols[1].metric("High", counts.get("HIGH", "—"))
        cols[2].metric("Secrets", len(scan.get("secrets", [])) if scan.get("ok") else "—")
        cols[3].metric("Signature", "Valid" if signature.get("valid") else "Invalid")
        cols[4].metric("Digest", "Match" if digest.get("match") else "Mismatch")
        if scan.get("top_vulns"):
            st.markdown("#### High and critical findings")
            st.dataframe(pd.DataFrame(scan["top_vulns"]), use_container_width=True, hide_index=True)
        if scan.get("secrets"):
            st.markdown("#### Secret findings")
            st.dataframe(pd.DataFrame(scan["secrets"]), use_container_width=True, hide_index=True)
    with st.expander("Host-side secure delivery workflow"):
        st.code(
            "# Push the image to a registry reachable by Docker, Trivy and Cosign\n"
            "docker build -t REGISTRY/attendance-api:1.0 ./app\n"
            "docker push REGISTRY/attendance-api:1.0\n\n"
            "# Generate a demo key pair once; keep cosign.key private\n"
            "cosign generate-key-pair --output-key-prefix config/cosign\n"
            "cosign sign --key config/cosign.key --tlog-upload=false REGISTRY/attendance-api:1.0\n"
            "python delivery_gate.py baseline REGISTRY/attendance-api:1.0\n"
            "python delivery_gate.py check REGISTRY/attendance-api:1.0",
            language="powershell",
        )
        st.caption("The delivery gate fails closed if Docker, Trivy, the Cosign public key, signature verification, or the trusted digest is missing. Never commit config/cosign.key.")

st.divider()
st.caption("EgressEye demo scope: the workload is isolated on an internal Docker network and reaches external hosts through the HTTP/S proxy. This covers proxy-aware TCP HTTP/HTTPS traffic; TLS content is not decrypted. Production Kubernetes deployments should enforce equivalent routing with a CNI egress policy or gateway and collect its flow telemetry.")
