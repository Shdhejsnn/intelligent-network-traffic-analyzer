const statusDot = document.getElementById("statusDot");
const statusText = document.getElementById("statusText");
const packetCount = document.getElementById("packetCount");

const analyzeBtn = document.getElementById("analyzeBtn");
const riskScore = document.getElementById("riskScore");
const analysisMeta = document.getElementById("analysisMeta");

const paramRows = document.getElementById("paramRows");
const ruleRows = document.getElementById("ruleRows");
const statRows = document.getElementById("statRows");

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

async function runAnalysis() {
  const res = await fetch("/api/analyze", { method: "POST" });
  if (res.status === 409) {
    analysisMeta.textContent = "Stop capture before running analysis.";
    return;
  }
  const data = await res.json();
  riskScore.textContent = data.risk_score ?? 0;
  analysisMeta.textContent = `Alerts: ${data.alert_count}`;
  renderParams(data.parameters);
  renderAlerts(ruleRows, data.rule_alerts);
  renderAlerts(statRows, data.stat_alerts);
}

analyzeBtn.addEventListener("click", runAnalysis);

fetchStatus().then(updateStatus);
