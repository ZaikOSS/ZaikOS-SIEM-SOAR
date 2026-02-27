import { useEffect, useState, useRef, Component } from "react";
import { io } from "socket.io-client";

const socket = io("http://localhost:3000");

// ── Error Boundary (catches any render crash and shows a message instead of white screen) ──
class ErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = { error: null };
  }
  static getDerivedStateFromError(e) {
    return { error: e };
  }
  render() {
    if (this.state.error) {
      return (
        <div
          style={{
            background: "#020c14",
            color: "#ff4d4d",
            padding: "2rem",
            fontFamily: "monospace",
            minHeight: "100vh",
          }}
        >
          <h2 style={{ color: "#ff4d4d" }}>[RENDER ERROR]</h2>
          <pre
            style={{
              color: "#b8d4e8",
              marginTop: "1rem",
              whiteSpace: "pre-wrap",
            }}
          >
            {this.state.error.message}
            {"\n\n"}
            {this.state.error.stack}
          </pre>
          <button
            onClick={() => this.setState({ error: null })}
            style={{
              marginTop: "1rem",
              background: "#0a1628",
              color: "#00b4ff",
              border: "1px solid #00b4ff",
              padding: "0.5rem 1rem",
              cursor: "pointer",
              fontFamily: "monospace",
            }}
          >
            RETRY
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}

// ── helpers ──────────────────────────────────────────────────────────────────
const fmt = (n) => String(n).padStart(3, "0");

function parseVerdict(verdict) {
  const v = verdict || "";
  if (!v) return { level: "processing", label: "ANALYZING", color: "#f0c040" };

  // Blocked = firewall rule was successfully added
  if (
    v.includes("[ACTION]:    SUCCESS") ||
    v.includes("already_blocked") ||
    v.includes("permanently blocked")
  )
    return { level: "blocked", label: "BLOCKED", color: "#00ff9d" };

  // Clean = no threat found
  if (v.includes("CLEAN (No known"))
    return { level: "clean", label: "CLEAN", color: "#58a6ff" };

  // Critical = threat detected (may or may not have been blocked)
  if (v.includes("CRITICAL RISK") || v.includes("HIGH RISK"))
    return { level: "critical", label: "CRITICAL", color: "#ff4d4d" };

  // Medium risk
  if (v.includes("MEDIUM RISK"))
    return { level: "warning", label: "SUSPICIOUS", color: "#f0c040" };

  // Still running
  return { level: "processing", label: "ANALYZING", color: "#f0c040" };
}

function extractVT(verdict) {
  const v = verdict || "";
  const m = v.match(/(\d+) malicious vendors/);
  return m ? parseInt(m[1]) : null;
}

// ── sub-components ────────────────────────────────────────────────────────────
function Scanline() {
  return <div className="scanline" />;
}

function StatBox({ value, label, color, icon }) {
  return (
    <div className="stat-box" style={{ "--accent": color }}>
      <div className="stat-icon">{icon}</div>
      <div className="stat-value" style={{ color }}>
        {value}
      </div>
      <div className="stat-label">{label}</div>
    </div>
  );
}

function AlertCard({ alert, index }) {
  const [expanded, setExpanded] = useState(true);
  const { level, label, color } = parseVerdict(alert.verdict);
  const vtCount = extractVT(alert.verdict);
  const lines = (alert.verdict || "").split("\n").filter(Boolean);

  return (
    <div
      className={`alert-card alert-${level}`}
      style={{ "--card-accent": color, animationDelay: `${index * 0.05}s` }}
    >
      <div className="alert-header" onClick={() => setExpanded(!expanded)}>
        <div className="alert-meta">
          <span className="alert-index">#{fmt(index + 1)}</span>
          <span className="alert-ip">{alert.ip}</span>
          <span className="badge" style={{ "--badge-color": color }}>
            {label}
          </span>
          {vtCount !== null && (
            <span className="vt-badge">
              <svg
                width="12"
                height="12"
                viewBox="0 0 24 24"
                fill="currentColor"
              >
                <path
                  d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"
                  stroke="currentColor"
                  strokeWidth="2"
                  fill="none"
                />
              </svg>
              VT: {vtCount} vendors
            </span>
          )}
        </div>
        <div className="alert-right">
          <span className="alert-time">{alert.timestamp}</span>
          <span className="expand-icon">{expanded ? "▲" : "▼"}</span>
        </div>
      </div>

      <div className="alert-rule">
        <span className="rule-label">TRIGGER</span>
        <span className="rule-text">{alert.rule}</span>
      </div>

      {expanded && (
        <div className="terminal-block">
          <div className="terminal-header">
            <span className="terminal-dot" style={{ background: "#ff5f57" }} />
            <span className="terminal-dot" style={{ background: "#febc2e" }} />
            <span className="terminal-dot" style={{ background: "#28c840" }} />
            <span className="terminal-title">analyzer.py — output</span>
          </div>
          <div className="terminal-body">
            {lines.map((line, i) => {
              let cls = "t-line";
              if (
                line.includes("[ACTION]:    SUCCESS") ||
                line.includes("permanently blocked") ||
                line.includes("CLEAN (No known")
              )
                cls += " t-success";
              else if (
                line.includes("[VERDICT]") ||
                line.includes("CRITICAL RISK") ||
                line.includes("HIGH RISK")
              )
                cls += " t-critical";
              else if (
                line.includes("[*]") ||
                line.includes("[+]") ||
                line.includes("[VT]") ||
                line.includes("[AB]")
              )
                cls += " t-info";
              else if (
                line.includes("[!]") ||
                line.includes("[FAILED]") ||
                line.includes("ACTION]:    FAILED") ||
                line.includes("timed out")
              )
                cls += " t-warn";
              else if (
                line.includes("[ACTION]") ||
                line.includes("[SYSTEM DEFENSE]") ||
                line.includes("[TARGET IP]") ||
                line.includes("[QUERY IP]")
              )
                cls += " t-action";
              else if (line.startsWith("-")) cls += " t-line";
              return (
                <div key={i} className={cls}>
                  {line}
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}

function ThreatGraph({ alerts }) {
  const data = alerts.slice().reverse().slice(-20);
  const max = Math.max(...data.map((_, i) => i + 1), 1);
  return (
    <div className="threat-graph">
      <div className="graph-title">THREAT TIMELINE (LAST 20)</div>
      <div className="graph-bars">
        {data.map((a, i) => {
          const { color } = parseVerdict(a.verdict);
          return (
            <div key={i} className="graph-bar-wrap">
              <div
                className="graph-bar"
                style={{
                  height: `${((i + 1) / max) * 60}px`,
                  background: color,
                }}
                title={`${a.ip} — ${a.timestamp}`}
              />
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── main app ──────────────────────────────────────────────────────────────────
function App() {
  const [alerts, setAlerts] = useState([]);
  const [connected, setConnected] = useState(false);
  const [filter, setFilter] = useState("ALL");
  const [tick, setTick] = useState(0);
  const feedRef = useRef(null);

  useEffect(() => {
    socket.on("connect", () => setConnected(true));
    socket.on("disconnect", () => setConnected(false));

    // New alert arrives (initially verdict may be null = "ANALYZING")
    socket.on("threat_alert", (data) => {
      if (!data || !data.ip) return;
      setAlerts((prev) => [data, ...prev]);
    });

    // Verdict update — patch existing alert by id
    socket.on("threat_verdict", ({ id, verdict }) => {
      if (!id || !verdict) return;
      setAlerts((prev) =>
        prev.map((a) => (a.id === id ? { ...a, verdict } : a)),
      );
    });

    // History replay on reconnect
    socket.on("history", (items) => {
      if (!Array.isArray(items)) return;
      setAlerts(items.filter((a) => a && a.ip));
    });

    const interval = setInterval(() => setTick((t) => t + 1), 1000);

    return () => {
      socket.off("connect");
      socket.off("disconnect");
      socket.off("threat_alert");
      socket.off("threat_verdict");
      socket.off("history");
      clearInterval(interval);
    };
  }, []);

  const stats = {
    total: alerts.length,
    critical: alerts.filter((a) => parseVerdict(a.verdict).level === "critical")
      .length,
    blocked: alerts.filter((a) => parseVerdict(a.verdict).level === "blocked")
      .length,
    clean: alerts.filter((a) => parseVerdict(a.verdict).level === "clean")
      .length,
  };

  const filtered =
    filter === "ALL"
      ? alerts
      : alerts.filter(
          (a) => parseVerdict(a.verdict).level === filter.toLowerCase(),
        );

  const now = new Date();
  const timeStr = now.toLocaleTimeString("en-US", { hour12: false });
  const dateStr = now.toLocaleDateString("en-US", {
    year: "numeric",
    month: "short",
    day: "2-digit",
  });

  return (
    <>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@400;700;900&family=Exo+2:wght@300;400;600&display=swap');

        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

        html, body, #root {
          width: 100%;
          min-height: 100vh;
        }

        :root {
          --bg: #020c14;
          --bg2: #060f1a;
          --bg3: #0a1628;
          --border: #0d2a40;
          --border2: #1a3a55;
          --text: #b8d4e8;
          --text-dim: #4a7090;
          --green: #00ff9d;
          --red: #ff4d4d;
          --blue: #00b4ff;
          --yellow: #f0c040;
          --font-mono: 'Share Tech Mono', monospace;
          --font-display: 'Orbitron', monospace;
          --font-body: 'Exo 2', sans-serif;
        }

        body {
          background: var(--bg);
          color: var(--text);
          font-family: var(--font-body);
          min-height: 100vh;
          width: 100%;
          overflow-x: hidden;
          display: flex;
          flex-direction: column;
          align-items: stretch;
        }

        /* CRT grid background */
        body::before {
          content: '';
          position: fixed; inset: 0;
          background-image:
            linear-gradient(rgba(0,180,255,0.03) 1px, transparent 1px),
            linear-gradient(90deg, rgba(0,180,255,0.03) 1px, transparent 1px);
          background-size: 40px 40px;
          pointer-events: none;
          z-index: 0;
        }

        body::after {
          content: '';
          position: fixed; inset: 0;
          background: radial-gradient(ellipse at 50% 0%, rgba(0,80,160,0.15) 0%, transparent 70%);
          pointer-events: none;
          z-index: 0;
        }

        .scanline {
          position: fixed; inset: 0;
          background: repeating-linear-gradient(
            0deg,
            transparent,
            transparent 2px,
            rgba(0,0,0,0.08) 2px,
            rgba(0,0,0,0.08) 4px
          );
          pointer-events: none;
          z-index: 9999;
          animation: scanmove 8s linear infinite;
        }

        @keyframes scanmove {
          0% { background-position: 0 0; }
          100% { background-position: 0 100%; }
        }

        .app {
          position: relative;
          z-index: 1;
          min-height: 100vh;
          display: grid;
          grid-template-rows: auto auto auto 1fr;
          width: 100%;
          max-width: 1600px;
          margin-left: auto;
          margin-right: auto;
          padding: 0 2rem 3rem;
        }

        /* ── TOPBAR ── */
        .topbar {
          display: flex;
          align-items: center;
          gap: 2rem;
          padding: 0.6rem 0;
          border-bottom: 1px solid var(--border);
          font-family: var(--font-mono);
          font-size: 0.7rem;
          color: var(--text-dim);
          letter-spacing: 2px;
          text-transform: uppercase;
        }
        .topbar-id { color: var(--blue); }
        .topbar-sep { flex: 1; border-top: 1px dashed var(--border2); }
        .conn-dot {
          width: 8px; height: 8px; border-radius: 50%;
          display: inline-block; margin-right: 6px;
        }
        .conn-dot.on { background: var(--green); box-shadow: 0 0 8px var(--green); animation: pulse-dot 2s infinite; }
        .conn-dot.off { background: var(--red); }
        @keyframes pulse-dot {
          0%, 100% { opacity: 1; } 50% { opacity: 0.4; }
        }

        /* ── HEADER ── */
        .header {
          padding: 1.5rem 0 1.2rem;
          display: grid;
          grid-template-columns: 1fr auto;
          gap: 2rem;
          align-items: start;
          border-bottom: 1px solid var(--border);
        }
        .logo-area {}
        .logo-eyebrow {
          font-family: var(--font-mono);
          font-size: 0.65rem;
          letter-spacing: 4px;
          color: var(--blue);
          text-transform: uppercase;
          margin-bottom: 0.4rem;
        }
        .logo-title {
          font-family: var(--font-display);
          font-size: clamp(1.6rem, 4vw, 2.8rem);
          font-weight: 900;
          color: #fff;
          letter-spacing: 4px;
          text-transform: uppercase;
          line-height: 1;
          text-shadow: 0 0 40px rgba(0,180,255,0.4);
        }
        .logo-title span { color: var(--blue); }
        .logo-sub {
          font-family: var(--font-mono);
          font-size: 0.75rem;
          color: var(--text-dim);
          letter-spacing: 2px;
          margin-top: 0.5rem;
        }

        .stats-row {
          display: flex;
          gap: 1rem;
        }

        .stat-box {
          background: var(--bg3);
          border: 1px solid var(--border2);
          border-top: 2px solid var(--accent, var(--blue));
          padding: 0.9rem 1.2rem;
          min-width: 110px;
          text-align: center;
          position: relative;
          transition: border-color 0.3s;
        }
        .stat-box::before {
          content: '';
          position: absolute;
          top: 0; left: 0; right: 0;
          height: 1px;
          background: linear-gradient(90deg, transparent, var(--accent, var(--blue)), transparent);
        }
        .stat-icon { font-size: 1rem; margin-bottom: 0.3rem; }
        .stat-value {
          font-family: var(--font-display);
          font-size: 1.8rem;
          font-weight: 700;
          line-height: 1;
          margin-bottom: 0.3rem;
          transition: all 0.3s;
        }
        .stat-label {
          font-family: var(--font-mono);
          font-size: 0.6rem;
          letter-spacing: 2px;
          color: var(--text-dim);
          text-transform: uppercase;
        }

        /* ── TOOLBAR ── */
        .toolbar {
          display: flex;
          align-items: center;
          gap: 1rem;
          padding: 1rem 0;
          border-bottom: 1px solid var(--border);
          flex-wrap: wrap;
        }
        .toolbar-label {
          font-family: var(--font-mono);
          font-size: 0.65rem;
          letter-spacing: 3px;
          color: var(--text-dim);
          text-transform: uppercase;
        }
        .filter-group { display: flex; gap: 0.5rem; }
        .filter-btn {
          background: transparent;
          border: 1px solid var(--border2);
          color: var(--text-dim);
          font-family: var(--font-mono);
          font-size: 0.7rem;
          letter-spacing: 2px;
          padding: 0.35rem 0.8rem;
          cursor: pointer;
          text-transform: uppercase;
          transition: all 0.2s;
        }
        .filter-btn:hover { border-color: var(--blue); color: var(--blue); }
        .filter-btn.active { background: rgba(0,180,255,0.1); border-color: var(--blue); color: var(--blue); }
        .filter-btn.f-critical.active { background: rgba(255,77,77,0.1); border-color: var(--red); color: var(--red); }
        .filter-btn.f-blocked.active { background: rgba(0,255,157,0.1); border-color: var(--green); color: var(--green); }
        .filter-btn.f-clean.active { background: rgba(0,180,255,0.1); border-color: var(--blue); color: var(--blue); }

        .count-badge {
          margin-left: auto;
          font-family: var(--font-mono);
          font-size: 0.7rem;
          color: var(--text-dim);
        }
        .count-badge span { color: var(--blue); }

        /* ── MAIN CONTENT ── */
        .main-content {
          display: grid;
          grid-template-columns: 1fr 280px;
          gap: 1.5rem;
          padding-top: 1.5rem;
          align-items: start;
        }

        /* ── FEED ── */
        .feed { display: flex; flex-direction: column; gap: 1rem; }

        .empty-state {
          border: 1px dashed var(--border2);
          padding: 4rem 2rem;
          text-align: center;
          font-family: var(--font-mono);
        }
        .empty-title {
          font-family: var(--font-display);
          font-size: 1rem;
          color: var(--text-dim);
          letter-spacing: 4px;
          margin-bottom: 1rem;
        }
        .empty-blink {
          color: var(--green);
          animation: blink 1.2s step-end infinite;
        }
        @keyframes blink { 0%, 100% { opacity: 1; } 50% { opacity: 0; } }

        /* ── ALERT CARD ── */
        .alert-card {
          border: 1px solid var(--border2);
          border-left: 3px solid var(--card-accent, var(--blue));
          background: var(--bg2);
          overflow: hidden;
          animation: slideIn 0.3s ease both;
          transition: border-color 0.3s;
        }
        .alert-card:hover { border-color: var(--card-accent, var(--blue)); }
        .alert-card.alert-critical { --glow: rgba(255,77,77,0.05); background: linear-gradient(135deg, var(--glow) 0%, var(--bg2) 40%); }
        .alert-card.alert-blocked { --glow: rgba(0,255,157,0.04); background: linear-gradient(135deg, var(--glow) 0%, var(--bg2) 40%); }

        @keyframes slideIn {
          from { opacity: 0; transform: translateX(-12px); }
          to { opacity: 1; transform: translateX(0); }
        }

        .alert-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          padding: 0.85rem 1.1rem;
          cursor: pointer;
          user-select: none;
          transition: background 0.2s;
          gap: 1rem;
        }
        .alert-header:hover { background: rgba(255,255,255,0.02); }

        .alert-meta { display: flex; align-items: center; gap: 0.7rem; flex-wrap: wrap; }
        .alert-index { font-family: var(--font-mono); font-size: 0.7rem; color: var(--text-dim); }
        .alert-ip { font-family: var(--font-mono); font-size: 1.05rem; color: #fff; font-weight: bold; letter-spacing: 1px; }

        .badge {
          font-family: var(--font-mono);
          font-size: 0.65rem;
          letter-spacing: 2px;
          padding: 2px 8px;
          border: 1px solid var(--badge-color, var(--blue));
          color: var(--badge-color, var(--blue));
          background: color-mix(in srgb, var(--badge-color, var(--blue)) 10%, transparent);
          text-transform: uppercase;
        }

        .vt-badge {
          font-family: var(--font-mono);
          font-size: 0.65rem;
          color: var(--yellow);
          display: flex;
          align-items: center;
          gap: 4px;
          padding: 2px 6px;
          border: 1px solid rgba(240,192,64,0.3);
          background: rgba(240,192,64,0.05);
        }

        .alert-right { display: flex; align-items: center; gap: 1rem; }
        .alert-time { font-family: var(--font-mono); font-size: 0.7rem; color: var(--text-dim); white-space: nowrap; }
        .expand-icon { color: var(--text-dim); font-size: 0.6rem; }

        .alert-rule {
          padding: 0.5rem 1.1rem;
          border-top: 1px solid var(--border);
          display: flex;
          align-items: baseline;
          gap: 0.7rem;
          background: rgba(0,0,0,0.2);
        }
        .rule-label {
          font-family: var(--font-mono);
          font-size: 0.6rem;
          letter-spacing: 2px;
          color: var(--text-dim);
          white-space: nowrap;
        }
        .rule-text { font-size: 0.82rem; color: var(--text); }

        /* ── TERMINAL ── */
        .terminal-block { border-top: 1px solid var(--border); }
        .terminal-header {
          display: flex;
          align-items: center;
          gap: 6px;
          padding: 0.5rem 0.8rem;
          background: #010a12;
          border-bottom: 1px solid var(--border);
        }
        .terminal-dot { width: 10px; height: 10px; border-radius: 50%; }
        .terminal-title { font-family: var(--font-mono); font-size: 0.65rem; color: var(--text-dim); margin-left: 6px; }
        .terminal-body {
          background: #010d18;
          padding: 0.9rem 1.1rem;
          font-family: var(--font-mono);
          font-size: 0.8rem;
          line-height: 1.7;
          overflow-x: auto;
        }
        .t-line { color: #6a8fa8; }
        .t-info { color: #a0bfd4; }
        .t-critical { color: #ff6b6b; font-weight: bold; }
        .t-success { color: #00ff9d; font-weight: bold; }
        .t-warn { color: #f0c040; }
        .t-action { color: #00b4ff; }

        /* ── SIDEBAR ── */
        .sidebar { display: flex; flex-direction: column; gap: 1rem; position: sticky; top: 1rem; }

        .sidebar-panel {
          background: var(--bg2);
          border: 1px solid var(--border2);
          overflow: hidden;
        }
        .sidebar-panel-title {
          font-family: var(--font-mono);
          font-size: 0.6rem;
          letter-spacing: 3px;
          color: var(--blue);
          text-transform: uppercase;
          padding: 0.6rem 0.9rem;
          border-bottom: 1px solid var(--border);
          background: rgba(0,180,255,0.04);
        }

        /* ── THREAT GRAPH ── */
        .threat-graph { padding: 0.8rem 0.9rem; }
        .graph-title { font-family: var(--font-mono); font-size: 0.6rem; color: var(--text-dim); letter-spacing: 2px; margin-bottom: 0.6rem; }
        .graph-bars { display: flex; align-items: flex-end; gap: 3px; height: 70px; }
        .graph-bar-wrap { flex: 1; display: flex; align-items: flex-end; }
        .graph-bar { width: 100%; min-height: 4px; transition: height 0.3s; opacity: 0.8; }

        /* ── RECENT IPs ── */
        .recent-ips { padding: 0; }
        .ip-row {
          display: flex;
          justify-content: space-between;
          align-items: center;
          padding: 0.55rem 0.9rem;
          border-bottom: 1px solid var(--border);
          font-family: var(--font-mono);
          font-size: 0.75rem;
          transition: background 0.15s;
        }
        .ip-row:last-child { border-bottom: none; }
        .ip-row:hover { background: rgba(255,255,255,0.02); }
        .ip-addr { color: #fff; }
        .ip-status { font-size: 0.6rem; letter-spacing: 1px; }

        /* ── SYSTEM STATUS ── */
        .sys-status { padding: 0.7rem 0.9rem; display: flex; flex-direction: column; gap: 0.5rem; }
        .sys-row { display: flex; justify-content: space-between; align-items: center; font-family: var(--font-mono); font-size: 0.7rem; }
        .sys-key { color: var(--text-dim); }
        .sys-val { color: var(--green); }
        .sys-val.off { color: var(--red); }
        .sys-val.warn { color: var(--yellow); }

        /* ── ACTIVITY LOG ── */
        .activity-log { padding: 0.6rem 0.9rem; max-height: 220px; overflow-y: auto; }
        .log-entry { display: flex; gap: 0.6rem; font-family: var(--font-mono); font-size: 0.65rem; padding: 0.25rem 0; border-bottom: 1px solid rgba(13,42,64,0.5); }
        .log-time { color: var(--text-dim); white-space: nowrap; }
        .log-msg { color: var(--text); }
        .log-msg.c { color: var(--red); }
        .log-msg.b { color: var(--green); }
        .log-msg.i { color: var(--blue); }

        /* ── SCROLLBAR ── */
        ::-webkit-scrollbar { width: 4px; height: 4px; }
        ::-webkit-scrollbar-track { background: var(--bg); }
        ::-webkit-scrollbar-thumb { background: var(--border2); }

        @media (max-width: 900px) {
          .main-content { grid-template-columns: 1fr; }
          .sidebar { position: static; }
          .stats-row { flex-wrap: wrap; }
          .header { grid-template-columns: 1fr; }
        }
      `}</style>

      <Scanline />

      <div className="app">
        {/* TOPBAR */}
        <div className="topbar">
          <span className="topbar-id">ZAIKOS // SIEM+SOAR // v2.0</span>
          <div className="topbar-sep" />
          <span>
            <span className={`conn-dot ${connected ? "on" : "off"}`} />
            {connected ? "SOCKET CONNECTED" : "DISCONNECTED"}
          </span>
          <div className="topbar-sep" />
          <span>
            {dateStr} // {timeStr}
          </span>
        </div>

        {/* HEADER */}
        <div className="header">
          <div className="logo-area">
            <div className="logo-eyebrow">
              // Security Information & Event Management
            </div>
            <div className="logo-title">
              Zaik<span>OS</span>
            </div>
            <div className="logo-sub">
              THREAT INTELLIGENCE &nbsp;|&nbsp; AUTOMATED RESPONSE &nbsp;|&nbsp;
              WAZUH INTEGRATED
            </div>
          </div>
          <div className="stats-row">
            <StatBox
              value={fmt(stats.total)}
              label="Events"
              color="var(--blue)"
              icon="⬡"
            />
            <StatBox
              value={fmt(stats.critical)}
              label="Critical"
              color="var(--red)"
              icon="⚠"
            />
            <StatBox
              value={fmt(stats.blocked)}
              label="Blocked"
              color="var(--green)"
              icon="⛔"
            />
            <StatBox
              value={fmt(stats.clean)}
              label="Clean"
              color="#58a6ff"
              icon="✓"
            />
          </div>
        </div>

        {/* TOOLBAR */}
        <div className="toolbar">
          <span className="toolbar-label">Filter:</span>
          <div className="filter-group">
            {["ALL", "CRITICAL", "BLOCKED", "CLEAN"].map((f) => (
              <button
                key={f}
                className={`filter-btn f-${f.toLowerCase()} ${filter === f ? "active" : ""}`}
                onClick={() => setFilter(f)}
              >
                {f}
              </button>
            ))}
          </div>
          <div className="count-badge">
            SHOWING <span>{filtered.length}</span> / {alerts.length} EVENTS
          </div>
        </div>

        {/* MAIN */}
        <div className="main-content">
          {/* FEED */}
          <div className="feed" ref={feedRef}>
            {filtered.length === 0 ? (
              <div className="empty-state">
                <div className="empty-title">NO ACTIVE THREATS</div>
                <div
                  style={{
                    color: "var(--text-dim)",
                    fontSize: "0.8rem",
                    fontFamily: "var(--font-mono)",
                  }}
                >
                  Monitoring network traffic on all configured endpoints
                  <span className="empty-blink">_</span>
                </div>
              </div>
            ) : (
              filtered.map((alert, i) => (
                <AlertCard key={i} alert={alert} index={i} />
              ))
            )}
          </div>

          {/* SIDEBAR */}
          <div className="sidebar">
            {/* Threat Graph */}
            {alerts.length > 0 && (
              <div className="sidebar-panel">
                <div className="sidebar-panel-title">// Threat Timeline</div>
                <ThreatGraph alerts={alerts} />
              </div>
            )}

            {/* System Status */}
            <div className="sidebar-panel">
              <div className="sidebar-panel-title">// System Status</div>
              <div className="sys-status">
                <div className="sys-row">
                  <span className="sys-key">WAZUH INTEGRATION</span>
                  <span className="sys-val">ACTIVE</span>
                </div>
                <div className="sys-row">
                  <span className="sys-key">SOCKET.IO</span>
                  <span className={`sys-val ${connected ? "" : "off"}`}>
                    {connected ? "LIVE" : "DOWN"}
                  </span>
                </div>
                <div className="sys-row">
                  <span className="sys-key">VIRUSTOTAL API</span>
                  <span className="sys-val">ENABLED</span>
                </div>
                <div className="sys-row">
                  <span className="sys-key">AUTO-BLOCK</span>
                  <span className="sys-val">ARMED</span>
                </div>
                <div className="sys-row">
                  <span className="sys-key">UPTIME</span>
                  <span className="sys-val">
                    {Math.floor(tick / 3600)
                      .toString()
                      .padStart(2, "0")}
                    :
                    {Math.floor((tick % 3600) / 60)
                      .toString()
                      .padStart(2, "0")}
                    :{(tick % 60).toString().padStart(2, "0")}
                  </span>
                </div>
              </div>
            </div>

            {/* Recent IPs */}
            {alerts.length > 0 && (
              <div className="sidebar-panel">
                <div className="sidebar-panel-title">// Recent Attackers</div>
                <div className="recent-ips">
                  {[...new Map(alerts.map((a) => [a.ip, a])).values()]
                    .slice(0, 8)
                    .map((a, i) => {
                      const { label, color } = parseVerdict(a.verdict);
                      return (
                        <div key={i} className="ip-row">
                          <span className="ip-addr">{a.ip}</span>
                          <span className="ip-status" style={{ color }}>
                            {label}
                          </span>
                        </div>
                      );
                    })}
                </div>
              </div>
            )}

            {/* Activity Log */}
            <div className="sidebar-panel">
              <div className="sidebar-panel-title">// Activity Log</div>
              <div className="activity-log">
                {alerts.slice(0, 30).map((a, i) => {
                  const { level, label } = parseVerdict(a.verdict);
                  return (
                    <div key={i} className="log-entry">
                      <span className="log-time">{a.timestamp}</span>
                      <span
                        className={`log-msg ${level === "critical" ? "c" : level === "blocked" ? "b" : "i"}`}
                      >
                        {a.ip} &rarr; {label}
                      </span>
                    </div>
                  );
                })}
                {alerts.length === 0 && (
                  <div className="log-entry">
                    <span className="log-msg i">Awaiting events...</span>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>
    </>
  );
}

export default function AppWithBoundary() {
  return (
    <ErrorBoundary>
      <App />
    </ErrorBoundary>
  );
}
