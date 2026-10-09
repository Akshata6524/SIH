"""ULPF dashboard: The Universal Log Translator (offline, no external assets)."""
import os
import hashlib
import json
import random
import datetime as dt

import httpx
import pandas as pd
import streamlit as st

st.set_page_config(page_title="ULPF", page_icon="🔷", layout="wide")

DEFAULT_API = os.environ.get("ULPF_API_URL", "http://127.0.0.1:8000")
TEAL, AMBER, GREEN, RED, MUTED = "#2DD4BF", "#F59E0B", "#22C55E", "#EF4444", "#94A3B8"

NAV = ["🏠 Home", "📊 Live Overview", "🔍 Trace: Prove It",
       "✅ Quality", "🧩 Onboard New Source", "🚨 Anomaly Detection"]


# ---------------------------------------------------------------- styling
def inject_css():
    st.markdown(f"""
<style>
#MainMenu, footer, header {{visibility:hidden;}}
html, body, [class*="css"], .stApp {{font-family:'Segoe UI',system-ui,sans-serif;}}
.stApp {{background:#0B1220; color:#E2E8F0;}}
section[data-testid="stSidebar"] {{background:#0A0F1C; border-right:1px solid #1F2B45;}}
.block-container {{padding-top:1.5rem; max-width:1250px;}}
h1,h2,h3 {{color:#F1F5F9;}}
.card {{background:#111A2E; border:1px solid #1F2B45; border-radius:14px; padding:18px 20px;
        margin-bottom:14px; transition:all .2s;}}
.card:hover {{border-color:{TEAL}; box-shadow:0 0 18px rgba(45,212,191,.18);}}
.raw {{border-left:4px solid {AMBER};}}
.norm {{border-left:4px solid {TEAL};}}
.mono {{font-family:Consolas,monospace; font-size:12.5px; word-break:break-all; color:#E2E8F0;}}
.muted {{color:{MUTED}; font-size:14px;}}
.hero {{background:radial-gradient(circle at 20% 0%, rgba(45,212,191,.22), transparent 55%), #111A2E;
        border:1px solid #1F2B45; border-radius:18px; padding:34px 36px; margin-bottom:18px;}}
.hero h1 {{font-size:38px; line-height:1.15; margin:0 0 10px 0;}}
.hl {{color:{TEAL};}}
.chip {{display:inline-block; background:#0B1220; border:1px solid {TEAL}; border-radius:999px;
        padding:8px 18px; margin:10px 10px 0 0; font-weight:600;}}
.chip b {{color:{TEAL}; font-size:20px;}}
.sec {{border-bottom:2px solid {TEAL}; display:inline-block; padding-bottom:4px; margin-bottom:6px;}}
.pill {{display:inline-block; border-radius:999px; padding:2px 12px; font-size:12px; font-weight:700;}}
.p-success,.p-allow {{background:rgba(34,197,94,.15); color:{GREEN};}}
.p-partial {{background:rgba(245,158,11,.15); color:{AMBER};}}
.p-failed,.p-block {{background:rgba(239,68,68,.15); color:{RED};}}
.metric {{text-align:center;}}
.metric .v {{font-size:34px; font-weight:800; color:{TEAL};}}
.metric .l {{color:{MUTED}; font-size:13px; text-transform:uppercase; letter-spacing:.06em;}}
.banner {{border-radius:14px; padding:18px 22px; font-size:20px; font-weight:700; margin:10px 0;}}
.b-ok {{background:rgba(34,197,94,.14); border:1px solid {GREEN}; color:{GREEN};}}
.b-bad {{background:rgba(239,68,68,.14); border:1px solid {RED}; color:{RED};}}
.flow {{display:flex; flex-wrap:wrap; gap:8px; align-items:center; margin:8px 0 14px 0;}}
.step {{background:#111A2E; border:1px solid {TEAL}; border-radius:10px; padding:10px 14px;
        font-weight:600; font-size:14px; text-align:center;}}
.step.vault {{border-color:{AMBER}; color:{AMBER};}}
.step small {{display:block; color:{MUTED}; font-weight:400; font-size:11px;}}
.arrow {{color:{TEAL}; font-size:20px; animation:pulse 1.6s infinite;}}
@keyframes pulse {{0%,100%{{opacity:.3}} 50%{{opacity:1}}}}
.bar {{background:#0B1220; border-radius:8px; height:14px; overflow:hidden; margin:4px 0 12px 0;}}
.bar > div {{height:100%; border-radius:8px;}}
.tick {{display:inline-block; background:rgba(45,212,191,.12); color:{TEAL}; border-radius:6px;
        padding:3px 9px; margin:3px; font-size:13px; font-weight:600;}}
.empty {{text-align:center; padding:40px; color:{MUTED};}}
div.stButton > button {{background:#111A2E; color:{TEAL}; border:1px solid {TEAL}; border-radius:10px;
        font-weight:600;}}
div.stButton > button:hover {{background:{TEAL}; color:#0B1220;}}
</style>""", unsafe_allow_html=True)


def logo_svg():
    return f"""<svg width="46" height="46" viewBox="0 0 48 48"><polygon points="24,3 43,14 43,34 24,45 5,34 5,14"
    fill="none" stroke="{TEAL}" stroke-width="2.5"/><path d="M12 17 L24 24 M12 31 L24 24 M24 24 L38 24"
    stroke="{AMBER}" stroke-width="2.5" stroke-linecap="round"/><circle cx="38" cy="24" r="3" fill="{TEAL}"/></svg>"""


def section_header(title, what, why):
    st.markdown(f"<h2 class='sec'>{title}</h2>", unsafe_allow_html=True)
    st.markdown(f"<p class='muted'><b>What am I looking at?</b> {what}</p>", unsafe_allow_html=True)
    with st.expander("Why this matters"):
        st.markdown(why)


def metric_card(icon, value, label):
    st.markdown(f"<div class='card metric'><div style='font-size:26px'>{icon}</div>"
                f"<div class='v'>{value}</div><div class='l'>{label}</div></div>", unsafe_allow_html=True)


def pill(text):
    t = str(text).lower()
    return f"<span class='pill p-{t}'>{text}</span>"


def empty_state(icon, msg):
    st.markdown(f"<div class='card empty'><div style='font-size:42px'>{icon}</div>{msg}</div>",
                unsafe_allow_html=True)


def pipeline_diagram():
    steps = [("Sources", "firewall, IDS, proxy", ""), ("Raw Vault", "SHA-256 · lossless", "vault"),
             ("Detect", "format + device", ""), ("Parse", "YAML · zero-code", ""),
             ("Normalize", "one schema", ""), ("Score", "quality", ""),
             ("Export", "CEF · OCSF · Parquet", "")]
    html = "<div class='flow'>"
    for i, (n, s, c) in enumerate(steps):
        html += f"<div class='step {c}'>{n}<small>{s}</small></div>"
        if i < len(steps) - 1:
            html += "<span class='arrow'>➜</span>"
    st.markdown(html + "</div>", unsafe_allow_html=True)


# ---------------------------------------------------------------- API
def api_url():
    return st.session_state.get("api", DEFAULT_API)


def _listify(data):
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for k in ("events", "items", "results", "data"):
            if isinstance(data.get(k), list):
                return data[k]
    return []


@st.cache_data(ttl=5)
def fetch_events(base, limit=2000):
    r = httpx.get(f"{base}/events", params={"limit": limit}, timeout=15)
    r.raise_for_status()
    return _listify(r.json())


@st.cache_data(ttl=5)
def fetch_json(base, path):
    r = httpx.get(f"{base}{path}", timeout=15)
    r.raise_for_status()
    return r.json()


def post(path, payload):
    r = httpx.post(f"{api_url()}{path}", json=payload, timeout=60)
    r.raise_for_status()
    return r.json()


def events_df():
    ev = fetch_events(api_url())
    if not ev:
        return pd.DataFrame()
    df = pd.json_normalize(ev)
    for c in ("source.product", "src.ip", "dst.ip", "action", "category", "parse_status", "timestamp"):
        if c not in df.columns:
            df[c] = None
    if "parse_score" not in df.columns:
        df["parse_score"] = 0.0
    df["source.product"] = df["source.product"].fillna("unknown")
    return df


# ---------------------------------------------------------------- pages
def page_home(df):
    total = len(df)
    n_src = df["source.product"].nunique() if total else 0
    score = f"{df['parse_score'].astype(float).mean() * 100:.0f}%" if total else "–"
    st.markdown(f"""<div class='hero'><h1>Every device speaks a different language.<br>
<span class='hl'>ULPF translates them all.</span></h1>
<p class='muted' style='font-size:17px'>One universal translator between your security devices and your SIEM:
lossless, traceable and ready for AI.</p>
<span class='chip'><b>{total}</b> events processed</span>
<span class='chip'><b>{n_src}</b> sources connected</span>
<span class='chip'><b>{score}</b> understanding score</span></div>""", unsafe_allow_html=True)

    st.markdown("<h3 class='sec'>See the translation</h3>", unsafe_allow_html=True)
    c1, c2, c3 = st.columns([5, 1.3, 4])
    with c1:
        for name, line in [
            ("FortiGate", "srcip=10.1.1.5 dstip=8.8.8.8 dstport=53 proto=17 action=deny"),
            ("Cisco ASA", "%ASA-4-106023: Deny udp src inside:10.1.1.5 dst outside:8.8.8.8/53"),
            ("Cloud JSON", '{"src_endpoint":{"ip":"10.1.1.5"},"dst_endpoint":{"ip":"8.8.8.8"},"disposition":"blocked"}')]:
            st.markdown(f"<div class='card raw'><span class='muted'>{name} (original)</span>"
                        f"<div class='mono'>{line}</div></div>", unsafe_allow_html=True)
    with c2:
        st.markdown(f"<div style='text-align:center;padding-top:60px'><div class='arrow' style='font-size:44px'>➜</div>"
                    f"<b class='hl'>ULPF</b></div>", unsafe_allow_html=True)
    with c3:
        st.markdown(f"""<div class='card norm' style='margin-top:20px'><span class='muted'>One unified event</span>
<div class='mono'>src.ip &nbsp;= 10.1.1.5<br>dst.ip &nbsp;= 8.8.8.8<br>dst.port = 53<br>protocol = udp<br>
action &nbsp;&nbsp;= <span style='color:{RED}'>block</span><br>raw_sha256 = ✔ linked</div></div>""",
                    unsafe_allow_html=True)

    st.markdown("<h3 class='sec'>How it works</h3>", unsafe_allow_html=True)
    pipeline_diagram()

    st.markdown("<h3 class='sec'>What makes it different</h3>", unsafe_allow_html=True)
    feats = [("🔒", "Lossless", "The original log is stored untouched, always."),
             ("🔗", "Traceable", "Every clean event links back to its original."),
             ("🧩", "Plug-and-play", "New device = one config file, or auto-generated."),
             ("🌐", "Unified view", "All vendors in one schema and one dashboard."),
             ("🤖", "AI-ready", "Consistent typed fields for analytics and ML."),
             ("📴", "Air-gapped", "No internet, no telemetry. Runs in Docker.")]
    cols = st.columns(3)
    for i, (ic, t, d) in enumerate(feats):
        with cols[i % 3]:
            st.markdown(f"<div class='card'><div style='font-size:28px'>{ic}</div><b>{t}</b>"
                        f"<div class='muted'>{d}</div></div>", unsafe_allow_html=True)
    st.markdown("".join(f"<span class='tick'>✔ {c}</span>" for c in "abcdefghijk"), unsafe_allow_html=True)


def page_overview(df):
    section_header("Live Overview", "Events from all devices in one place, all using the same fields.",
                   "Before ULPF, each vendor looked completely different. Here a security team gets one view of the "
                   "whole network.")
    if df.empty:
        return empty_state("📭", "No events yet. Run <code>python scripts/load_samples.py</code>, then click Refresh.")
    blocked = (df["action"] == "block").mean() * 100
    c = st.columns(4)
    with c[0]: metric_card("📥", len(df), "Total events")
    with c[1]: metric_card("🔌", df["source.product"].nunique(), "Sources")
    with c[2]: metric_card("🎯", f"{df['parse_score'].astype(float).mean():.2f}", "Avg understanding")
    with c[3]: metric_card("⛔", f"{blocked:.0f}%", "Blocked")
    a, b, d = st.columns(3)
    with a:
        st.caption("Events by source")
        st.bar_chart(df["source.product"].value_counts(), color=TEAL)
    with b:
        st.caption("Events by category")
        st.bar_chart(df["category"].fillna("other").value_counts(), color=TEAL)
    with d:
        st.caption("Events by action")
        st.bar_chart(df["action"].fillna("unknown").value_counts(), color=AMBER)
    left, right = st.columns(2)
    with left:
        st.markdown("<h3 class='sec'>Top blocked source IPs</h3>", unsafe_allow_html=True)
        top = df[df["action"] == "block"]["src.ip"].value_counts().head(10)
        html = "<div class='card'>" + "".join(
            f"<div style='display:flex;justify-content:space-between;margin:5px 0'><span class='mono'>{ip}</span>"
            f"<span class='pill p-block'>{n} blocked</span></div>" for ip, n in top.items()) + "</div>"
        st.markdown(html if len(top) else "<div class='card muted'>No blocked events.</div>", unsafe_allow_html=True)
    with right:
        st.markdown("<h3 class='sec'>Most recent events</h3>", unsafe_allow_html=True)
        cols = ["timestamp", "source.product", "src.ip", "dst.ip", "action", "parse_status"]
        st.dataframe(df.sort_values("timestamp", ascending=False)[cols].head(20), width="stretch", hide_index=True)


def page_trace(df):
    section_header("Trace: Prove It", "Pick a clean event and see the exact original log it came from.",
                   "Forensics and compliance need the original evidence. The SHA-256 (a digital fingerprint of the text) "
                   "is computed when the log arrives. If it still matches, the log was never changed.")
    if df.empty:
        return empty_state("📭", "No events to trace yet. Load the sample logs first.")
    recent = df.sort_values("timestamp", ascending=False).head(200).reset_index(drop=True)
    labels = [f"{r['timestamp']} | {r['src.ip']} | {r['action']}" for _, r in recent.iterrows()]
    idx = st.selectbox("Choose an event", range(len(labels)), format_func=lambda i: labels[i])
    ev = fetch_events(api_url())
    ev_map = {e.get("event_id"): e for e in ev}
    event = ev_map.get(recent.loc[idx, "event_id"], {})
    raw_id = event.get("raw_event_id")
    try:
        raw = fetch_json(api_url(), f"/raw/{raw_id}")
    except Exception:
        return st.error("Could not fetch the raw log for this event.")
    raw_text = next((raw[k] for k in ("raw_text", "raw", "text", "raw_log") if k in raw), "")
    stored = event.get("raw_sha256") or raw.get("sha256") or raw.get("raw_sha256") or ""
    recomputed = hashlib.sha256(str(raw_text).encode("utf-8")).hexdigest()
    ok = bool(raw.get("verified")) or (stored != "" and stored == recomputed)

    l, r = st.columns(2)
    with l:
        st.markdown(f"<div class='card raw'><b style='color:{AMBER}'>Original raw log (untouched)</b>"
                    f"<div class='mono' style='margin-top:10px'>{raw_text}</div></div>", unsafe_allow_html=True)
    with r:
        st.markdown(f"<div class='card norm'><b style='color:{TEAL}'>Normalized ULPF event</b></div>",
                    unsafe_allow_html=True)
        st.json(event)
    if ok:
        st.markdown("<div class='banner b-ok'>✔ VERIFIED: the original log is unchanged</div>", unsafe_allow_html=True)
    else:
        st.markdown("<div class='banner b-bad'>✖ MISMATCH: the original log may have changed</div>",
                    unsafe_allow_html=True)
    st.markdown(f"<div class='card'><span class='muted'>Stored SHA-256</span><div class='mono'>{stored}</div>"
                f"<span class='muted'>Recomputed SHA-256</span><div class='mono'>{recomputed}</div></div>",
                unsafe_allow_html=True)
    d1, d2 = st.columns(2)
    for col, fmt in ((d1, "cef"), (d2, "ocsf")):
        with col:
            try:
                r_ = httpx.get(f"{api_url()}/export/{event.get('event_id')}", params={"format": fmt}, timeout=15)
                st.download_button(f"Download as {fmt.upper()}", r_.text, file_name=f"event.{fmt}",
                                   key=f"dl_{fmt}", width="stretch")
            except Exception:
                st.caption(f"{fmt.upper()} export unavailable.")


def page_quality(df):
    section_header("Quality", "How well ULPF understood the logs from each device.",
                   "No parser is perfect, so we measure it. The parse score (0 to 1) is the share of fields mapped "
                   "to the standard. Low scores show exactly which source needs a better config.")
    if df.empty:
        return empty_state("📭", "No data yet.")
    df = df.copy()
    df["parse_score"] = df["parse_score"].astype(float)
    g = df.groupby("source.product")["parse_score"].mean().sort_values(ascending=False)
    for name, s in g.items():
        color, label = (GREEN, "Fully understood") if s >= .8 else (AMBER, "Partly understood") if s >= .4 \
            else (RED, "Not understood")
        st.markdown(f"<div class='card'><b>{name}</b> <span class='muted'>· {label} · {s * 100:.0f}%</span>"
                    f"<div class='bar'><div style='width:{s * 100}%;background:{color}'></div></div></div>",
                    unsafe_allow_html=True)
    st.markdown("<h3 class='sec'>Success / partial / failed per source</h3>", unsafe_allow_html=True)
    st.dataframe(pd.crosstab(df["source.product"], df["parse_status"].fillna("unknown")), width="stretch")
    st.markdown("<h3 class='sec'>Fields not yet mapped (kept in vendor_extras)</h3>", unsafe_allow_html=True)
    extras = [c for c in df.columns if c.startswith("vendor_extras.")]
    if extras:
        rows = {s: df[df["source.product"] == s][extras].notna().sum().sort_values(ascending=False).head(5)
                for s in df["source.product"].unique()}
        for s, ser in rows.items():
            tags = "".join(f"<span class='tick'>{k.replace('vendor_extras.', '')} ({v})</span>"
                           for k, v in ser.items() if v > 0)
            st.markdown(f"<div class='card'><b>{s}</b><br>{tags or '<span class=muted>none</span>'}</div>",
                        unsafe_allow_html=True)


def page_onboard():
    section_header("Onboard New Source", "Teach ULPF a brand-new device from a few sample logs, with no code.",
                   "Normally an engineer spends days writing a parser for each device. ULPF detects the format, guesses "
                   "which field is the source IP, action and so on, and writes the config itself.")
    st.markdown("<div class='card'><b class='hl'>1 · Paste sample logs</b></div>", unsafe_allow_html=True)
    samples = st.text_area("One log per line (5 or more is best)", height=150, key="samples")
    c = st.columns(3)
    name = c[0].text_input("Name", "mydevice")
    vendor = c[1].text_input("Vendor", "Acme")
    product = c[2].text_input("Product", "AcmeFW")
    lines = [x for x in samples.splitlines() if x.strip()]
    payload = {"samples": lines, "name": name, "vendor": vendor, "product": product}
    st.markdown("<div class='card'><b class='hl'>2 · Generate parser</b></div>", unsafe_allow_html=True)
    b1, b2 = st.columns(2)
    try:
        if b1.button("Generate parser config", width="stretch") and lines:
            st.session_state["gen"] = post("/autogen", {**payload, "save": False})
        if b2.button("Save and activate", width="stretch") and lines:
            st.session_state["gen"] = post("/autogen", {**payload, "save": True})
            st.success("Saved. The new source is active now.")
    except Exception as e:
        st.error(f"Autogen failed: {e}")
    gen = st.session_state.get("gen")
    if gen:
        yml = gen.get("yaml") or gen.get("config_yaml") or gen.get("config")
        st.markdown("<div class='card norm'><b style='color:#2DD4BF'>Generated parser config</b></div>",
                    unsafe_allow_html=True)
        st.code(yml if isinstance(yml, str) else json.dumps(yml, indent=2), language="yaml")
        rep = gen.get("confidence") or gen.get("report") or gen.get("confidence_report")
        if rep:
            st.markdown("**Confidence report**")
            st.json(rep)
    st.markdown("<div class='card'><b class='hl'>3 · Test a new log</b></div>", unsafe_allow_html=True)
    test = st.text_input("Paste one NEW log from the same device")
    if st.button("Test parse", width="stretch") and test.strip():
        try:
            post("/ingest", [test])
            ev = httpx.get(f"{api_url()}/events", params={"limit": 1}, timeout=15)
            e = (_listify(ev.json()) or [{}])[0]
            st.json(e)
            if e.get("parse_status") in ("success", "partial"):
                st.markdown("<div class='banner b-ok'>✔ New device understood in seconds. No code written.</div>",
                            unsafe_allow_html=True)
        except Exception as ex:
            st.error(f"Test failed: {ex}")


def demo_lines():
    now, out = dt.datetime.utcnow(), []
    for i in range(200):
        t = now - dt.timedelta(seconds=random.randint(0, 3000))
        burst = i < 80
        ip = "203.0.113.66" if burst else f"10.1.1.{random.randint(2, 40)}"
        act = "deny" if burst or random.random() < .08 else "accept"
        out.append(f"date={t:%Y-%m-%d} time={t:%H:%M:%S} devname=FW1 srcip={ip} srcport={random.randint(1024, 65000)} "
                   f"dstip=8.8.8.{random.randint(1, 9)} dstport={random.choice([53, 80, 443, 22])} proto=6 "
                   f"action={act} policyid={random.randint(1, 20)}")
    return out


def page_anomaly(df):
    section_header("Anomaly Detection", "IPs with an unusual number of blocked connections.",
                   "An anomaly is behavior far from normal, like one IP blocked 80 times in minutes, which looks like "
                   "a scan or attack. Consistent ULPF data lets a model (Isolation Forest) find it automatically. "
                   "This is a demo model.")
    if len(df) < 20:
        empty_state("🧪", "Not enough events yet. Generate some demo traffic.")
        if st.button("Generate demo traffic"):
            try:
                post("/ingest", demo_lines())
                st.cache_data.clear()
                st.success("200 demo events sent. Click Refresh.")
            except Exception as e:
                st.error(f"Failed: {e}")
        return
    from sklearn.ensemble import IsolationForest
    b = df[df["action"] == "block"].copy()
    b["ts"] = pd.to_datetime(b["timestamp"], errors="coerce", utc=True)
    b = b.dropna(subset=["ts"])
    if len(b) < 5:
        return empty_state("🧪", "Not enough blocked events.")
    b["window"] = b["ts"].dt.floor("5min")
    c = b.groupby(["src.ip", "window"]).size().reset_index(name="blocked")
    c["flag"] = IsolationForest(contamination=0.05, random_state=42).fit_predict(c[["blocked"]]) == -1
    n = int(c["flag"].sum())
    st.markdown(f"<div class='banner {'b-bad' if n else 'b-ok'}'>{n} suspicious IP window(s) flagged</div>",
                unsafe_allow_html=True)
    top = c.groupby("src.ip")["blocked"].max().sort_values(ascending=False).head(15)
    st.caption("Peak blocked connections per IP (5-minute window)")
    st.bar_chart(top, color=RED)
    st.markdown("<h3 class='sec'>Flagged IPs</h3>", unsafe_allow_html=True)
    st.dataframe(c[c["flag"]].sort_values("blocked", ascending=False), width="stretch", hide_index=True)


# ---------------------------------------------------------------- main
def main():
    inject_css()
    with st.sidebar:
        st.markdown(f"<div style='display:flex;gap:10px;align-items:center'>{logo_svg()}"
                    f"<div><b style='font-size:22px;color:{TEAL}'>ULPF</b><br>"
                    f"<span class='muted' style='font-size:11px'>Universal Log Translator</span></div></div>",
                    unsafe_allow_html=True)
        st.caption("Any log in. One language out. Nothing lost.")
        page = st.radio("Navigate", NAV, label_visibility="collapsed")
        st.text_input("API URL", DEFAULT_API, key="api")
        if st.button("🔄 Refresh", width="stretch"):
            st.cache_data.clear()
    try:
        df = events_df()
    except Exception:
        st.error("Cannot reach the ULPF API. Start it with: uvicorn ulpf.ingest:app --reload")
        return
    if page == NAV[0]: page_home(df)
    elif page == NAV[1]: page_overview(df)
    elif page == NAV[2]: page_trace(df)
    elif page == NAV[3]: page_quality(df)
    elif page == NAV[4]: page_onboard()
    else: page_anomaly(df)
    st.markdown(f"<p class='muted' style='text-align:center;margin-top:30px'>"
                f"ULPF v1.0 | Offline-first | No telemetry</p>", unsafe_allow_html=True)


main()
