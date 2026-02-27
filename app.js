const express = require("express");
const { exec } = require("child_process");
const cors = require("cors");
const http = require("http");
const { Server } = require("socket.io");
const path = require("path");

const app = express();
app.use(express.json({ limit: "10mb" }));
app.use(cors());

const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: "*" },
  pingTimeout: 60000,
});

// ── In-memory alert store (last 500) ──────────────────────────────────────────
const alertHistory = [];
const MAX_HISTORY = 500;

function storeAlert(alertObj) {
  alertHistory.unshift(alertObj);
  if (alertHistory.length > MAX_HISTORY) alertHistory.pop();
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function extractSrcIp(alert) {
  return alert?.data?.srcip || alert?.data?.src_ip || alert?.agent?.ip || null;
}

function extractRule(alert) {
  return alert?.rule?.description || alert?.rule?.id || "Unknown Rule";
}

function sanitizeIp(ip) {
  // Basic validation – only allow valid IPv4/IPv6
  const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/;
  const ipv6 = /^[a-fA-F0-9:]+$/;
  if (ipv4.test(ip) || ipv6.test(ip)) return ip;
  return null;
}

// ── Socket connection ─────────────────────────────────────────────────────────
io.on("connection", (socket) => {
  console.log(`💻 Dashboard connected: ${socket.id}`);

  // Send last 50 alerts to newly connected client so the dashboard isn't empty
  socket.emit("history", alertHistory.slice(0, 50));

  socket.on("disconnect", () => {
    console.log(`🔌 Dashboard disconnected: ${socket.id}`);
  });
});

// ── Wazuh webhook ─────────────────────────────────────────────────────────────
app.post("/wazuh-alert", (req, res) => {
  const alert = req.body;

  if (!alert || typeof alert !== "object") {
    return res.status(400).json({ error: "Invalid payload" });
  }

  const ruleDesc = extractRule(alert);
  const rawIp = extractSrcIp(alert);
  const srcIp = rawIp ? sanitizeIp(rawIp) : null;
  const ruleLevel = alert?.rule?.level ?? 0;
  const ruleId = alert?.rule?.id ?? "N/A";

  console.log(`\n🚨 ALERT  [level=${ruleLevel}] [rule=${ruleId}] ${ruleDesc}`);
  console.log(`   Source IP: ${srcIp || "Unknown"}`);

  // Build the initial "processing" alert so the dashboard reacts immediately
  const alertObj = {
    id: `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
    timestamp: new Date().toLocaleTimeString("en-US", { hour12: false }),
    ip: srcIp || "UNKNOWN",
    rule: ruleDesc,
    ruleId,
    ruleLevel,
    verdict: null, // will be filled by python output
  };

  // Acknowledge Wazuh immediately (it has a short timeout)
  res.status(200).json({ received: true, id: alertObj.id });

  if (!srcIp) {
    alertObj.verdict = "[!] No source IP in alert. Skipping threat analysis.";
    storeAlert(alertObj);
    io.emit("threat_alert", alertObj);
    return;
  }

  // Emit "processing" state right away
  storeAlert(alertObj);
  io.emit("threat_alert", alertObj);

  // Run the python analyzer
  const analyzerPath = path.join(__dirname, "analyzer.py");
  const pythonCmd = process.platform === "win32" ? "python" : "python3";
  const cmd = `${pythonCmd} "${analyzerPath}" "${srcIp}"`;

  exec(
    cmd,
    { timeout: 60000, env: { ...process.env, PYTHONIOENCODING: "utf-8" } },
    (error, stdout, stderr) => {
      let verdict = stdout.trim();

      if (error) {
        console.error(`⚠️  Analyzer error: ${error.message}`);
        verdict = `[FAILED]: Analyzer exited with error.\n${stderr || error.message}`;
      }

      // Update the stored alert
      alertObj.verdict = verdict || "[!] No output from analyzer.";
      // Replace in history (it was already stored)
      const idx = alertHistory.findIndex((a) => a.id === alertObj.id);
      if (idx !== -1) alertHistory[idx] = alertObj;

      console.log(`✅ Verdict for ${srcIp}:\n${verdict}`);

      // Push updated alert to all connected dashboards
      io.emit("threat_verdict", { id: alertObj.id, verdict: alertObj.verdict });
    },
  );
});

// ── Health / API ──────────────────────────────────────────────────────────────
app.get("/health", (_req, res) => {
  res.json({
    status: "ok",
    uptime: process.uptime(),
    alerts_stored: alertHistory.length,
    connected_clients: io.engine.clientsCount,
  });
});

app.get("/api/alerts", (_req, res) => {
  res.json(alertHistory.slice(0, 100));
});

// ── Start ─────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
server.listen(PORT, "0.0.0.0", () => {
  console.log(`\n🛡️  ZaikOS SOAR Backend running on port ${PORT}`);
  console.log(`   POST /wazuh-alert   ← Wazuh webhook`);
  console.log(`   GET  /health        ← Status check`);
  console.log(`   GET  /api/alerts    ← Alert history`);
  console.log(`   WS   socket.io      ← Dashboard feed\n`);
});
