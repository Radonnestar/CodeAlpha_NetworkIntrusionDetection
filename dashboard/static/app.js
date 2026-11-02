const POLL_MS = 1000;
const LIVE_COLOR = "#7cf0c9";

const byId = (id) => document.getElementById(id);

function element(tag, text, className) {
  const node = document.createElement(tag);

  node.textContent = text;

  if (className) {
    node.className = className;
  }

  return node;
}

function renderRanked(listId, items, label) {
  const list = byId(listId);
  const max = Math.max(1, ...items.map(({ count }) => count));

  const rows = items.map(({ name, count }) => {
    const row = document.createElement("li");

    row.style.setProperty("--share", `${(count / max) * 100}%`);
    row.append(element("span", label ? label(name) : name), element("strong", String(count)));

    return row;
  });

  list.replaceChildren(...(rows.length ? rows : [element("li", "Nothing yet", "empty")]));
}

function renderBans(bans) {
  const rows = bans.map(({ ip, reason, seconds_left: left }) => {
    const row = document.createElement("li");

    row.className = "ban";
    row.append(element("span", `${ip} · ${reason}`), element("strong", `${left}s`));

    return row;
  });

  byId("bans").replaceChildren(...(rows.length ? rows : [element("li", "No active bans", "empty")]));
}

let lastFeedKey = "";

function renderFeed(feed) {
  const key = feed.map(({ time }) => time).join();

  if (key === lastFeedKey) {
    return;
  }

  lastFeedKey = key;

  const rows = feed.map(({ time, ip, signature, technique, severity }) => {
    const row = document.createElement("li");

    row.className = `sev${severity}`;
    row.append(
      element("time", time.slice(11, 19)),
      element("code", technique),
      element("span", signature),
      element("span", ip)
    );

    return row;
  });

  byId("feed").replaceChildren(...(rows.length ? rows : [element("li", "Waiting for alerts", "empty")]));
}

function drawChart(values) {
  const canvas = byId("chart");
  const ratio = window.devicePixelRatio || 1;
  const width = canvas.clientWidth;
  const height = canvas.clientHeight;

  canvas.width = width * ratio;
  canvas.height = height * ratio;

  const context = canvas.getContext("2d");
  const max = Math.max(1, ...values);
  const step = width / values.length;

  context.scale(ratio, ratio);
  context.clearRect(0, 0, width, height);

  const gradient = context.createLinearGradient(0, 0, 0, height);

  gradient.addColorStop(0, "rgba(124, 240, 201, 0.7)");
  gradient.addColorStop(1, "rgba(124, 240, 201, 0.05)");

  context.beginPath();
  context.moveTo(0, height);

  values.forEach((value, index) => {
    context.lineTo(index * step + step / 2, height - (value / max) * (height - 10) - 2);
  });

  context.lineTo(width, height);
  context.closePath();
  context.fillStyle = gradient;
  context.fill();

  context.beginPath();

  values.forEach((value, index) => {
    const y = height - (value / max) * (height - 10) - 2;

    if (index === 0) {
      context.moveTo(step / 2, y);
    } else {
      context.lineTo(index * step + step / 2, y);
    }
  });

  context.strokeStyle = LIVE_COLOR;
  context.lineWidth = 2;
  context.stroke();
}

function setStatus(isLive) {
  const status = byId("status");

  status.textContent = isLive ? "Live" : "Disconnected";
  status.className = `status ${isLive ? "status--live" : "status--down"}`;
}

function render(data) {
  byId("kpi-total").textContent = String(data.total);
  byId("kpi-attackers").textContent = String(data.attackers.length);
  byId("kpi-blocked").textContent = String(data.bans.length);
  byId("kpi-techniques").textContent = String(data.techniques.length);

  renderRanked("attackers", data.attackers);
  renderRanked("rules", data.rules, (name) => name.replace(/^LAB /, ""));
  renderRanked("techniques", data.techniques);
  renderBans(data.bans);
  renderFeed(data.feed);
  drawChart(data.timeline);
}

async function poll() {
  try {
    const response = await fetch("/api/stats", { cache: "no-store" });

    render(await response.json());
    setStatus(true);
  } catch {
    setStatus(false);
  }
}

poll();
setInterval(poll, POLL_MS);