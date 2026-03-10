const statusDot = document.getElementById("statusDot");
const statusText = document.getElementById("statusText");
const packetCount = document.getElementById("packetCount");

const analyzeBtn = document.getElementById("analyzeBtn");
const riskScore = document.getElementById("riskScore");
const riskLevel = document.getElementById("riskLevel");
const riskBarFill = document.getElementById("riskBarFill");
const analysisMeta = document.getElementById("analysisMeta");

const paramRows = document.getElementById("paramRows");
const ruleRows = document.getElementById("ruleRows");
const statRows = document.getElementById("statRows");
const mlRows = document.getElementById("mlRows");
const mlStatusRows = document.getElementById("mlStatusRows");
const insightRows = document.getElementById("insightRows");
const featureRows = document.getElementById("featureRows");
const ruleCount = document.getElementById("ruleCount");
const statCount = document.getElementById("statCount");
const mlCount = document.getElementById("mlCount");

async function fetchStatus() {
  const res = await fetch("/api/status");
  return res.json();
}

function updateStatus(status) {
  if (status.running) {
    statusDot.classList.add("on");
    statusText.textContent = "Capturing";
  } else {
    statusDot.classList.remove("on");
    statusText.textContent = "Stopped";
  }
  packetCount.textContent = `${status.packet_count} packets`;
}

function renderParams(params) {
  if (!params || params.length === 0) {
    paramRows.innerHTML = `<tr><td>-</td><td>No parameters</td><td>-</td></tr>`;
    return;
  }
  paramRows.innerHTML = params
    .map((p) => {
      return `<tr><td>${p.id}</td><td>${p.name}</td><td>${p.value}</td></tr>`;
    })
    .join("");
}

function renderAlerts(rows, alerts) {
  if (!alerts || alerts.length === 0) {
    rows.innerHTML = `<tr><td colspan="6">No alerts</td></tr>`;
    return;
  }
  rows.innerHTML = alerts
    .map((a) => {
      return `
        <tr>
          <td>${a.type}</td>
          <td>${a.src_ip}</td>
          <td>${a.dst_ip}</td>
          <td>${a.severity}</td>
          <td>${a.reason}</td>
          <td>${a.time_window}</td>
        </tr>
      `;
    })
    .join("");
}

function renderMlStatus(status, featureWindows, datasetSize) {
  const safe = status || {};
  const train = safe.training || {};
  const metadata = safe.model_metadata || {};
  const trainedAt = metadata.trained_at_epoch
    ? new Date(metadata.trained_at_epoch * 1000).toLocaleString()
    : "N/A";
  const trainState = safe.last_training_state || (train.trained ? "Trained" : (train.reason || "N/A"));
  const rows = [
    ["ML Supported", safe.supported ? "Yes" : "No"],
    ["Model Trained", safe.model_trained ? "Yes" : "No"],
    ["Feature Windows (current analysis)", featureWindows ?? 0],
    ["Stored Feature Samples", datasetSize ?? 0],
    ["Last Trained At", trainedAt],
    ["Last Training State", trainState],
  ];
  mlStatusRows.innerHTML = rows
    .map((r) => `<tr><td>${r[0]}</td><td>${r[1]}</td></tr>`)
    .join("");
}

function renderInsights(insights) {
  if (!insights || insights.length === 0) {
    insightRows.innerHTML = `<tr><td colspan="6">No active threat explanations in current window.</td></tr>`;
    return;
  }
  insightRows.innerHTML = insights
    .map((i) => {
      return `
        <tr>
          <td>${i.type}</td>
          <td>${i.count}</td>
          <td>${i.where}</td>
          <td>${i.what}</td>
          <td>${i.possible_causes}</td>
          <td>${i.impact}</td>
        </tr>
      `;
    })
    .join("");
}

function renderTopFeatures(features) {
  if (!features || features.length === 0) {
    featureRows.innerHTML = `<tr><td colspan="3">No strong ML deviations detected.</td></tr>`;
    return;
  }
  featureRows.innerHTML = features
    .map((f) => `<tr><td>${f.feature}</td><td>${f.z_score}</td><td>${f.value}</td></tr>`)
    .join("");
}

function renderBreakdown(breakdown) {
  const safe = breakdown || {};
  ruleCount.textContent = safe.rule_alerts ?? 0;
  statCount.textContent = safe.statistical_alerts ?? 0;
  mlCount.textContent = safe.ml_alerts ?? 0;
}

async function runAnalysis() {
  const res = await fetch("/api/analyze", { method: "POST" });
  if (res.status === 409) {
    analysisMeta.textContent = "Stop capture before running analysis.";
    return;
  }
  const data = await res.json();
  riskScore.textContent = data.risk_score ?? 0;
  riskLevel.textContent = data.risk_level ?? "Low";
  riskBarFill.style.width = `${Math.max(0, Math.min(100, data.risk_score ?? 0))}%`;
  analysisMeta.textContent = `Active alerts in recent window: ${data.alert_count} | New alerts stored: ${data.new_alert_count ?? 0}`;
  renderParams(data.parameters);
  renderAlerts(ruleRows, data.rule_alerts);
  renderAlerts(statRows, data.stat_alerts);
  renderAlerts(mlRows, data.ml_alerts);
  renderMlStatus(data.ml_status, data.feature_windows, data.feature_dataset_size);
  renderInsights(data.threat_insights);
  renderTopFeatures(data.top_abnormal_features);
  renderBreakdown(data.detector_breakdown);
}

analyzeBtn.addEventListener("click", runAnalysis);

fetchStatus().then(updateStatus);
