"use strict";

const API = "http://127.0.0.1:8000/api/v1/dashboard";

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = String(text ?? "UNKNOWN");
  return node;
}

function replaceChildren(selector, children) {
  document.querySelector(selector).replaceChildren(...children);
}

function statusBadge(value) {
  const safeValue = String(value ?? "UNKNOWN");
  return element("span", `status status-${safeValue}`, safeValue);
}

function formatPercent(value) {
  return typeof value === "number" ? `${value}%` : "UNKNOWN";
}

function progressRow(label, value) {
  const row = element("div", "progress-row");
  row.append(element("label", "", label), element("b", "", formatPercent(value)));
  const bar = element("div", "bar");
  const fill = element("i");
  const bounded = typeof value === "number" ? Math.min(100, Math.max(0, value)) : 0;
  fill.style.width = `${bounded}%`;
  bar.append(fill);
  row.append(bar);
  return row;
}

function detailLine(label, value) {
  const line = element("div", "detail-line");
  line.append(element("small", "", label), element("b", "", value));
  return line;
}

function projectCard(project, runtimes) {
  const card = element("article", "project");
  const header = element("div", "project-header");
  const identity = element("div");
  identity.append(element("h3", "", project.name), element("small", "", project.id));
  const runtime = runtimes.find((item) => item.project_id === project.id);
  header.append(identity, statusBadge(runtime?.observed_status));
  card.append(header, element("p", "description", project.description));
  card.append(
    progressRow("PLAN PROGRESS", project.plan_progress),
    progressRow("CERTIFICATION READINESS", project.certification_readiness),
    progressRow("OPERATIONAL READINESS", project.operational_readiness),
  );

  const gates = element("div", "gates");
  gates.append(element("h4", "", "GATES"));
  for (const gate of [...project.certification_gates, ...project.operational_gates]) {
    const row = element("div", "gate-row");
    row.append(element("span", "", `${gate.label} · weight ${gate.weight}`));
    row.append(statusBadge(gate.effective_status));
    gates.append(row);
  }
  card.append(gates);

  if (Object.keys(project.domain).length) {
    const domain = element("div", "domain");
    for (const [key, value] of Object.entries(project.domain)) {
      domain.append(detailLine(key.replaceAll("_", " ").toUpperCase(), value));
    }
    card.append(domain);
  }

  const next = element("div", "next");
  next.append(element("b", "", "NEXT ACTION"), element("span", "", project.next_action));
  card.append(next);
  return card;
}

function render(data) {
  const mode = document.querySelector("#mode");
  mode.textContent = `DATA MODE: ${data.data_mode}`;
  mode.className = "mode fixture";

  const connection = document.querySelector("#connection");
  connection.className = "connection online";
  connection.textContent = `API ONLINE · ${data.schema_version} · GENERATED ${data.generated_at}`;

  const summaryItems = [
    ["GLOBAL HEALTH", data.summary.global_health],
    ["AUTONOMY READINESS", data.summary.autonomy_readiness],
    ["CRITICAL ALERTS", data.summary.critical_alerts],
    ["HUMAN APPROVAL REQUIRED", data.summary.human_approval_required ? "REQUIRED" : "NONE"],
    ["ACTIVE AGENTS", data.summary.active_agents],
    ["ACTIVE TASKS", data.summary.active_tasks],
    ["BLOCKERS", data.summary.blockers],
  ].map(([label, value]) => {
    const metric = element("article", "metric");
    metric.append(element("label", "", label), element("strong", "", value));
    return metric;
  });
  replaceChildren("#summary", summaryItems);
  replaceChildren("#projects", data.projects.map((project) => projectCard(project, data.runtimes)));

  replaceChildren("#agents", data.agents.map((agent) => {
    const row = element("div", "agent");
    row.append(element("b", "", agent.name), statusBadge(agent.availability));
    row.append(element("small", "", `Task ${agent.current_task ?? "UNKNOWN"} · Stage ${agent.task_stage ?? "UNKNOWN"} · Progress ${formatPercent(agent.progress)} · Heartbeat ${agent.heartbeat ?? "UNKNOWN"} · Provider ${agent.provider_status ?? "UNKNOWN"} · Quota ${agent.quota_status ?? "UNKNOWN"} · Blocker ${agent.blocker ?? "NONE"}`));
    return row;
  }));

  replaceChildren("#tasks", data.tasks.map((task) => {
    const row = element("div", "task");
    row.append(element("b", "", task.label), statusBadge(task.stage));
    row.append(element("small", "", `Project ${task.project_id} · Progress ${formatPercent(task.progress)} · Blocker ${task.blocker ?? "NONE"}`));
    return row;
  }));

  replaceChildren("#alerts", data.alerts.map((alert) => {
    const row = element("div", "alert");
    row.append(element("b", "", alert.title), statusBadge(alert.level));
    row.append(element("small", "", alert.detail));
    return row;
  }));

  replaceChildren("#approvals", data.approvals.map((approval) => {
    const row = element("div", "approval");
    row.append(element("b", "", approval.label), statusBadge(approval.status));
    row.append(element("small", "", `Reason ${approval.reason} · Requested ${approval.requested_at ?? "UNKNOWN"} · Required ${approval.required} · Execution enabled ${approval.execution_enabled}`));
    return row;
  }));

  replaceChildren("#timeline", data.evidence.map((evidence) => {
    const event = element("div", "event");
    event.append(element("b", "", evidence.label), statusBadge(evidence.status));
    event.append(element("small", "", `${evidence.source ?? "UNKNOWN"} · ${evidence.verified_at ?? "UNKNOWN"}`));
    return event;
  }));
}

fetch(API, {method: "GET", credentials: "omit"})
  .then((response) => {
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return response.json();
  })
  .then(render)
  .catch((error) => {
    const connection = document.querySelector("#connection");
    connection.className = "connection error";
    connection.textContent = `API OFFLINE · Start backend on 127.0.0.1:8000 · ${error.message}`;
  });

document.querySelector("#theme").addEventListener("click", () => {
  const root = document.documentElement;
  root.dataset.theme = root.dataset.theme === "light" ? "dark" : "light";
});
setInterval(() => {
  document.querySelector("#clock").textContent = new Date().toLocaleTimeString();
}, 1000);
