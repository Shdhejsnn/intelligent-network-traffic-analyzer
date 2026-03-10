const statusDot = document.getElementById("statusDot");
const statusText = document.getElementById("statusText");
const packetCount = document.getElementById("packetCount");
const packetRows = document.getElementById("packetRows");

const startBtn = document.getElementById("startBtn");
const stopBtn = document.getElementById("stopBtn");
const restartBtn = document.getElementById("restartBtn");

async function fetchStatus() {
  const res = await fetch("/api/status");
  return res.json();
}

async function fetchPackets() {
  const res = await fetch("/api/packets?limit=200");
  return res.json();
}

function formatTime(ts) {
  if (!ts) return "-";
  const date = new Date(ts * 1000);
  return date.toLocaleTimeString();
}

function renderPackets(packets) {
  const rows = packets.map((p) => {
    return `
      <tr>
        <td>${formatTime(p.timestamp)}</td>
        <td>${p.domain || "-"}</td>
        <td>${p.src_ip || "-"}</td>
        <td>${p.dst_ip || "-"}</td>
        <td>${p.protocol || "-"}</td>
        <td>${p.src_port ?? "-"}</td>
        <td>${p.dst_port ?? "-"}</td>
        <td>${p.size ?? "-"}</td>
      </tr>
    `;
  });
  packetRows.innerHTML = rows.join("");
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

async function refresh() {
  try {
    const [status, packets] = await Promise.all([
      fetchStatus(),
      fetchPackets(),
    ]);
    updateStatus(status);
    renderPackets(packets);
  } catch (err) {
    statusText.textContent = "Disconnected";
  }
}

startBtn.addEventListener("click", async () => {
  await fetch("/api/start", { method: "POST" });
  refresh();
});

stopBtn.addEventListener("click", async () => {
  await fetch("/api/stop", { method: "POST" });
  refresh();
});

restartBtn.addEventListener("click", async () => {
  await fetch("/api/restart", { method: "POST" });
  refresh();
});

refresh();
setInterval(refresh, 1000);
