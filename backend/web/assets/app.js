const statsGrid = document.querySelector("#stats-grid");
const chartNode = document.querySelector("#chart");
const accountsList = document.querySelector("#accounts-list");
const errorsList = document.querySelector("#errors-list");
const summaryReport = document.querySelector("#summary-report");
const historyBody = document.querySelector("#history-body");
const form = document.querySelector("#account-form");
const formStatus = document.querySelector("#form-status");
const formTitle = document.querySelector("#account-form-title");
const accountSubmit = document.querySelector("#account-submit");
const accountCancel = document.querySelector("#account-cancel");
const manualCheckForm = document.querySelector("#manual-check-form");
const manualCheckStatus = document.querySelector("#manual-check-status");
const manualCheckResult = document.querySelector("#manual-check-result");
const healthDot = document.querySelector("#health-dot");
const healthLabel = document.querySelector("#health-label");
const periodSelect = document.querySelector("#period-select");
const historyVerdictFilter = document.querySelector("#history-verdict-filter");
const historySearch = document.querySelector("#history-search");
const refreshButton = document.querySelector("#refresh-all");
const exportReportButton = document.querySelector("#export-report");
const exportSummaryButton = document.querySelector("#export-summary");
const pollButton = document.querySelector("#poll-once");
const toolbarStatus = document.querySelector("#toolbar-status");
const statTemplate = document.querySelector("#stat-card-template");

let historyItemsState = [];
let editingAccountId = null;

const statLabels = {
  total_accounts: "Аккаунты",
  total_emails: "Письма",
  total_urls: "Ссылки",
  total_scans: "Сканирования",
  safe_count: "Безопасные",
  suspicious_count: "Подозрительные",
  phishing_count: "Фишинг",
};

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });

  if (!response.ok) {
    let message = `HTTP ${response.status}`;
    try {
      const payload = await response.json();
      message = payload.error || payload.message || message;
    } catch (_) {
      // ignore
    }
    throw new Error(message);
  }

  if (response.status === 204) {
    return null;
  }

  return response.json();
}

function formatNumber(value) {
  return new Intl.NumberFormat("ru-RU").format(value || 0);
}

function formatDate(value) {
  if (!value) return "—";
  return new Date(value).toLocaleString("ru-RU");
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function setHealth(ok, text) {
  healthDot.className = "status-dot";
  healthDot.classList.add(ok ? "is-ok" : "is-bad");
  healthLabel.textContent = text;
}

function setToolbarStatus(message, tone = "muted") {
  toolbarStatus.textContent = message;
  toolbarStatus.className = `toolbar-status ${tone}`;
}

function renderStats(stats) {
  statsGrid.innerHTML = "";
  Object.entries(statLabels).forEach(([key, label]) => {
    const fragment = statTemplate.content.cloneNode(true);
    fragment.querySelector(".stat-label").textContent = label;
    fragment.querySelector(".stat-value").textContent = formatNumber(stats[key]);
    statsGrid.appendChild(fragment);
  });
}

function resetAccountForm() {
  editingAccountId = null;
  form.reset();
  form.elements.account_id.value = "";
  form.elements.imap_port.value = "993";
  form.elements.source_mailbox.value = "INBOX";
  form.elements.poll_interval_seconds.value = "900";
  form.elements.target_mailbox.value = "Phishing";
  form.elements.action_on_high.value = "MOVE";
  form.elements.imap_tls.checked = true;
  form.elements.reset_last_uid.checked = false;
  formTitle.textContent = "Подключение почтового аккаунта";
  accountSubmit.textContent = "Сохранить аккаунт";
  accountCancel.classList.add("hidden");
}

function beginEditAccount(item) {
  editingAccountId = item.id;
  form.elements.account_id.value = item.id;
  form.elements.email_address.value = item.email_address || "";
  form.elements.imap_host.value = item.imap_host || "";
  form.elements.imap_port.value = item.imap_port ?? 993;
  form.elements.username.value = item.username || "";
  form.elements.password.value = "";
  form.elements.source_mailbox.value = item.source_mailbox || "INBOX";
  form.elements.poll_interval_seconds.value = item.poll_interval_seconds ?? 900;
  form.elements.action_on_high.value = item.action_on_high || "MOVE";
  form.elements.target_mailbox.value = item.target_mailbox || "Phishing";
  form.elements.imap_tls.checked = Boolean(item.imap_tls);
  form.elements.reset_last_uid.checked = false;
  formTitle.textContent = `Редактирование: ${item.email_address}`;
  accountSubmit.textContent = "Обновить аккаунт";
  accountCancel.classList.remove("hidden");
  form.scrollIntoView({ behavior: "smooth", block: "start" });
}

async function toggleAccountEnabled(id, enabled) {
  await api(`/api/v1/accounts/${id}`, {
    method: "PATCH",
    body: JSON.stringify({ enabled }),
  });
  await refreshAll();
}

async function deleteAccount(id, email) {
  const confirmed = window.confirm(`Удалить аккаунт ${email}? Все связанные письма и результаты тоже будут удалены.`);
  if (!confirmed) return;
  await api(`/api/v1/accounts/${id}`, { method: "DELETE" });
  if (editingAccountId === id) {
    resetAccountForm();
  }
  await refreshAll();
}

function renderAccounts(items) {
  accountsList.innerHTML = "";
  if (!items.length) {
    accountsList.innerHTML = '<p class="muted">Пока нет подключенных аккаунтов.</p>';
    return;
  }

  items.forEach((item) => {
    const card = document.createElement("article");
    card.className = "account-card";
    card.innerHTML = `
      <div class="account-header">
        <strong>${escapeHtml(item.email_address)}</strong>
        <span class="badge ${item.enabled ? "badge-safe" : "badge-suspicious"}">${item.enabled ? "active" : "paused"}</span>
      </div>
      <p class="muted">${escapeHtml(item.imap_host)}:${item.imap_port} · user ${escapeHtml(item.username)}</p>
      <div class="account-meta">
        <span class="pill">${escapeHtml(item.source_mailbox)}</span>
        <span class="pill">UID ${item.last_uid}</span>
        <span class="pill">${escapeHtml(item.action_on_high)} → ${escapeHtml(item.target_mailbox)}</span>
        <span class="pill">${item.poll_interval_seconds}s</span>
        <span class="pill">${item.imap_tls ? "TLS" : "No TLS"}</span>
      </div>
      <div class="account-actions">
        <button class="button button-secondary account-edit">Edit</button>
        <button class="button button-secondary account-toggle">${item.enabled ? "Pause" : "Resume"}</button>
        <button class="button button-danger account-delete">Delete</button>
      </div>
    `;

    card.querySelector(".account-edit").addEventListener("click", () => beginEditAccount(item));
    card.querySelector(".account-toggle").addEventListener("click", async (event) => {
      const button = event.currentTarget;
      button.disabled = true;
      try {
        await toggleAccountEnabled(item.id, !item.enabled);
      } catch (error) {
        alert(`Не удалось обновить аккаунт: ${error.message}`);
      } finally {
        button.disabled = false;
      }
    });
    card.querySelector(".account-delete").addEventListener("click", async (event) => {
      const button = event.currentTarget;
      button.disabled = true;
      try {
        await deleteAccount(item.id, item.email_address);
      } catch (error) {
        alert(`Не удалось удалить аккаунт: ${error.message}`);
      } finally {
        button.disabled = false;
      }
    });

    accountsList.appendChild(card);
  });
}

function renderErrors(items) {
  errorsList.innerHTML = "";
  if (!items.length) {
    errorsList.innerHTML = '<p class="muted">Ошибок пока нет.</p>';
    return;
  }

  items.forEach((item) => {
    const card = document.createElement("article");
    card.className = "error-card";
    const details = Object.entries(item.details || {})
      .map(([key, value]) => `<span class="pill pill-error">${escapeHtml(key)}: ${escapeHtml(value)}</span>`)
      .join("");

    card.innerHTML = `
      <div class="error-top">
        <strong>${escapeHtml(item.email_address || "system")}</strong>
        <span class="error-time">${formatDate(item.created_at)}</span>
      </div>
      <div class="error-stage">${escapeHtml(item.stage)}</div>
      <p class="error-message">${escapeHtml(item.error_message)}</p>
      <div class="account-meta">${details}</div>
    `;
    errorsList.appendChild(card);
  });
}

function renderSummary(report) {
  if (!report) {
    summaryReport.innerHTML = '<p class="muted">Нет данных для сводного отчета.</p>';
    return;
  }

  const topDomains = (report.top_domains || [])
    .map((item) => `<li><span>${escapeHtml(item.domain)}</span><strong>${item.count}</strong></li>`)
    .join("");
  const topAccounts = (report.top_accounts || [])
    .map((item) => `<li><span>${escapeHtml(item.email_address)}</span><strong>${item.count}</strong></li>`)
    .join("");

  summaryReport.innerHTML = `
    <div class="summary-grid">
      <div class="result-metric"><span>Emails</span><strong>${formatNumber(report.total_emails)}</strong></div>
      <div class="result-metric"><span>URLs</span><strong>${formatNumber(report.total_urls)}</strong></div>
      <div class="result-metric"><span>Scans</span><strong>${formatNumber(report.total_scans)}</strong></div>
      <div class="result-metric"><span>Safe</span><strong>${formatNumber(report.safe_count)}</strong></div>
      <div class="result-metric"><span>Suspicious</span><strong>${formatNumber(report.suspicious_count)}</strong></div>
      <div class="result-metric"><span>Phishing</span><strong>${formatNumber(report.phishing_count)}</strong></div>
    </div>
    <div class="summary-lists">
      <div class="summary-card">
        <h3>Top domains</h3>
        <ul class="summary-list">${topDomains || '<li><span class="muted">Нет данных</span><strong>0</strong></li>'}</ul>
      </div>
      <div class="summary-card">
        <h3>Top accounts</h3>
        <ul class="summary-list">${topAccounts || '<li><span class="muted">Нет данных</span><strong>0</strong></li>'}</ul>
      </div>
    </div>
  `;
}

function verdictBadge(verdict) {
  const kind = verdict || "safe";
  return `<span class="badge badge-${kind}">${escapeHtml(kind)}</span>`;
}

function detailRowMarkup(items) {
  if (!items.length) {
    return '<div class="detail-empty">Для письма пока нет деталей по URL.</div>';
  }

  const rows = items.map((item) => `
    <tr>
      <td><a href="${escapeHtml(item.normalized_url)}" target="_blank" rel="noreferrer">${escapeHtml(item.domain || item.normalized_url)}</a></td>
      <td>${Number(item.score || 0).toFixed(3)}</td>
      <td>${item.risk ?? 0}</td>
      <td>${verdictBadge(item.verdict)}</td>
      <td>${escapeHtml(item.model_version || "")}</td>
    </tr>
  `).join("");

  return `
    <div class="detail-card">
      <table class="detail-table">
        <thead>
          <tr>
            <th>URL / домен</th>
            <th>Score</th>
            <th>Risk</th>
            <th>Verdict</th>
            <th>Model</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
  `;
}

async function toggleHistoryDetails(row, item) {
  const next = row.nextElementSibling;
  if (next?.classList.contains("history-detail-row")) {
    next.remove();
    row.classList.remove("is-expanded");
    return;
  }

  const detailRow = document.createElement("tr");
  detailRow.className = "history-detail-row";
  detailRow.innerHTML = '<td colspan="9"><div class="detail-loading">Загружаем детали по URL...</div></td>';
  row.after(detailRow);
  row.classList.add("is-expanded");

  try {
    const data = await api(`/api/v1/history/${item.email_id}`);
    detailRow.firstElementChild.innerHTML = detailRowMarkup(data.items || []);
  } catch (error) {
    detailRow.firstElementChild.innerHTML = `<div class="detail-empty">Ошибка загрузки: ${escapeHtml(error.message)}</div>`;
  }
}

function renderHistory(items) {
  historyBody.innerHTML = "";
  if (!items.length) {
    historyBody.innerHTML = '<tr><td colspan="9" class="muted">История пока пуста.</td></tr>';
    return;
  }

  items.forEach((item) => {
    const row = document.createElement("tr");
    row.className = "history-row";
    row.innerHTML = `
      <td>${formatDate(item.checked_at)}</td>
      <td>${escapeHtml(item.email_address)}</td>
      <td>${escapeHtml(item.sender || "—")}</td>
      <td>${escapeHtml(item.subject || "—")}</td>
      <td>${item.url_count ?? 0}</td>
      <td>${escapeHtml(item.top_domain || "—")}</td>
      <td>${Number(item.max_score || 0).toFixed(3)}</td>
      <td>${item.max_risk ?? 0}</td>
      <td>${verdictBadge(item.verdict)}</td>
    `;
    row.addEventListener("click", () => toggleHistoryDetails(row, item));
    historyBody.appendChild(row);
  });
}

function applyHistoryFilters() {
  const verdict = historyVerdictFilter.value;
  const query = historySearch.value.trim().toLowerCase();

  const filtered = historyItemsState.filter((item) => {
    const matchesVerdict = verdict === "all" || item.verdict === verdict;
    const haystack = [item.email_address, item.sender, item.subject, item.top_domain]
      .filter(Boolean)
      .join(" ")
      .toLowerCase();
    const matchesQuery = query === "" || haystack.includes(query);
    return matchesVerdict && matchesQuery;
  });

  renderHistory(filtered);
}

function renderChart(items) {
  chartNode.innerHTML = "";
  if (!items.length) {
    chartNode.innerHTML = '<p class="chart-empty">Нет данных за выбранный период.</p>';
    return;
  }

  const maxValue = Math.max(...items.map((item) => item.total_count || 0), 1);
  items.forEach((item) => {
    const group = document.createElement("div");
    group.className = "bar-group";

    const safeHeight = ((item.safe_count || 0) / maxValue) * 220;
    const suspiciousHeight = ((item.suspicious_count || 0) / maxValue) * 220;
    const phishingHeight = ((item.phishing_count || 0) / maxValue) * 220;
    const label = new Date(item.bucket).toLocaleDateString("ru-RU", {
      day: "2-digit",
      month: "2-digit",
    });

    group.innerHTML = `
      <div class="bar-stack">
        <div class="bar bar-safe" style="height:${safeHeight}px" title="safe: ${item.safe_count || 0}"></div>
        <div class="bar bar-suspicious" style="height:${suspiciousHeight}px" title="suspicious: ${item.suspicious_count || 0}"></div>
        <div class="bar bar-phishing" style="height:${phishingHeight}px" title="phishing: ${item.phishing_count || 0}"></div>
      </div>
      <div class="bar-label">${label}</div>
    `;
    chartNode.appendChild(group);
  });
}

function renderManualCheckResult(result) {
  const verdict = result.verdict || "safe";
  const components = result.features?.components || {};
  const urlFeatures = result.features?.url_features || {};

  manualCheckResult.className = `result-card ${verdict}`;
  manualCheckResult.innerHTML = `
    <div class="result-top">
      <strong>${escapeHtml(result.url)}</strong>
      ${verdictBadge(verdict)}
    </div>
    <div class="result-grid">
      <div class="result-metric">
        <span>Score</span>
        <strong>${Number(result.score || 0).toFixed(4)}</strong>
      </div>
      <div class="result-metric">
        <span>Risk</span>
        <strong>${result.risk ?? 0}</strong>
      </div>
      <div class="result-metric">
        <span>Model</span>
        <strong>${escapeHtml(result.model_version || "")}</strong>
      </div>
    </div>
    <ul class="result-features">
      <li><span>URL score</span><strong>${components.url_score ?? "n/a"}</strong></li>
      <li><span>Text score</span><strong>${components.text_score ?? "n/a"}</strong></li>
      <li><span>Trusted domain</span><strong>${urlFeatures.trusted_domain ? "yes" : "no"}</strong></li>
      <li><span>Host</span><strong>${escapeHtml(urlFeatures.host || "n/a")}</strong></li>
      <li><span>Brand similarity</span><strong>${urlFeatures.brand_similarity ?? "n/a"}</strong></li>
      <li><span>Suspicious keywords</span><strong>${urlFeatures.suspicious_keyword_count ?? "n/a"}</strong></li>
    </ul>
  `;
}

async function loadHealth() {
  try {
    const data = await api("/healthz");
    setHealth(Boolean(data.ok), data.ok ? "Backend доступен" : "Ошибка");
  } catch (error) {
    setHealth(false, error.message);
  }
}

async function loadStats() {
  const stats = await api("/api/v1/stats");
  renderStats(stats);
}

async function loadAccounts() {
  const data = await api("/api/v1/accounts");
  renderAccounts(data.items || []);
}

async function loadErrors() {
  const data = await api("/api/v1/accounts/errors?limit=10");
  renderErrors(data.items || []);
}

async function loadSummary() {
  const period = periodSelect.value;
  const data = await api(`/api/v1/reports/summary?period=${encodeURIComponent(period)}`);
  renderSummary(data);
}

async function loadHistory() {
  const data = await api("/api/v1/history");
  historyItemsState = data.items || [];
  applyHistoryFilters();
}

async function loadChart() {
  const period = periodSelect.value;
  const data = await api(`/api/v1/stats/timeseries?period=${encodeURIComponent(period)}`);
  renderChart(data.items || []);
}

async function refreshAll() {
  refreshButton.disabled = true;
  setToolbarStatus("Обновляем данные...", "is-pending");
  try {
    const tasks = [
      ["health", loadHealth],
      ["stats", loadStats],
      ["accounts", loadAccounts],
      ["errors", loadErrors],
      ["summary", loadSummary],
      ["history", loadHistory],
      ["chart", loadChart],
    ];
    const results = await Promise.allSettled(tasks.map(([, fn]) => fn()));
    const failed = results
      .map((result, index) => ({ result, name: tasks[index][0] }))
      .filter((item) => item.result.status === "rejected");

    if (failed.length > 0) {
      const labels = failed.map((item) => item.name).join(", ");
      setToolbarStatus(`Часть данных не обновлена: ${labels}. Проверь журналы и статус сервиса.`, "is-error");
    } else {
      setToolbarStatus("Данные успешно обновлены.", "is-ok");
    }
  } finally {
    refreshButton.disabled = false;
  }
}

function buildCreatePayload() {
  const formData = new FormData(form);
  return {
    email_address: formData.get("email_address"),
    imap_host: formData.get("imap_host"),
    imap_port: Number(formData.get("imap_port") || 993),
    imap_tls: Boolean(formData.get("imap_tls")),
    username: formData.get("username"),
    password: formData.get("password"),
    source_mailbox: formData.get("source_mailbox"),
    poll_interval_seconds: Number(formData.get("poll_interval_seconds") || 900),
    action_on_high: formData.get("action_on_high"),
    target_mailbox: formData.get("target_mailbox"),
  };
}

function buildUpdatePayload() {
  const formData = new FormData(form);
  const payload = {
    email_address: formData.get("email_address"),
    imap_host: formData.get("imap_host"),
    imap_port: Number(formData.get("imap_port") || 993),
    imap_tls: Boolean(formData.get("imap_tls")),
    username: formData.get("username"),
    source_mailbox: formData.get("source_mailbox"),
    poll_interval_seconds: Number(formData.get("poll_interval_seconds") || 900),
    action_on_high: formData.get("action_on_high"),
    target_mailbox: formData.get("target_mailbox"),
    reset_last_uid: Boolean(formData.get("reset_last_uid")),
  };
  const password = String(formData.get("password") || "").trim();
  if (password !== "") {
    payload.password = password;
  }
  return payload;
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  formStatus.textContent = editingAccountId ? "Обновляем аккаунт..." : "Сохраняем аккаунт...";

  try {
    if (editingAccountId) {
      const result = await api(`/api/v1/accounts/${editingAccountId}`, {
        method: "PATCH",
        body: JSON.stringify(buildUpdatePayload()),
      });
      formStatus.textContent = result.message || "Аккаунт обновлен.";
      resetAccountForm();
    } else {
      const result = await api("/api/v1/accounts", {
        method: "POST",
        body: JSON.stringify(buildCreatePayload()),
      });
      formStatus.textContent = result.message || "Аккаунт добавлен.";
      resetAccountForm();
    }

    await refreshAll();
  } catch (error) {
    formStatus.textContent = `Ошибка: ${error.message}`;
  }
});

accountCancel.addEventListener("click", () => {
  resetAccountForm();
  formStatus.textContent = "Редактирование отменено.";
});

manualCheckForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  manualCheckStatus.textContent = "Проверяем ссылку...";
  manualCheckResult.className = "result-card is-empty";
  manualCheckResult.innerHTML = '<p class="muted">Запрос отправлен в ML service.</p>';

  try {
    const formData = new FormData(manualCheckForm);
    const payload = {
      url: formData.get("url"),
      subject: formData.get("subject") || "",
      snippet: formData.get("snippet") || "",
    };

    const result = await api("/api/v1/check/url", {
      method: "POST",
      body: JSON.stringify(payload),
    });

    renderManualCheckResult(result);
    manualCheckStatus.textContent = "Проверка завершена.";
  } catch (error) {
    manualCheckResult.className = "result-card is-empty";
    manualCheckResult.innerHTML = '<p class="muted">Ошибка ручной проверки.</p>';
    manualCheckStatus.textContent = `Ошибка: ${error.message}`;
  }
});

pollButton.addEventListener("click", async () => {
  pollButton.disabled = true;
  setToolbarStatus("Запускаем сканирование сейчас...", "is-pending");
  try {
    await api("/api/v1/poll/once", { method: "POST", body: "{}" });
    await refreshAll();
    setToolbarStatus("Сканирование завершено, данные обновлены.", "is-ok");
  } catch (error) {
    setToolbarStatus(`Сканирование не удалось: ${error.message}`, "is-error");
    alert(`Не удалось запустить сканирование: ${error.message}`);
  } finally {
    pollButton.disabled = false;
  }
});

exportReportButton.addEventListener("click", () => {
  const period = periodSelect.value || "week";
  window.open(`/api/v1/reports/detections.csv?period=${encodeURIComponent(period)}`, "_blank");
});

exportSummaryButton.addEventListener("click", () => {
  const period = periodSelect.value || "week";
  window.open(`/api/v1/reports/summary.csv?period=${encodeURIComponent(period)}`, "_blank");
});

periodSelect.addEventListener("change", async () => {
  await Promise.all([loadChart(), loadSummary()]);
});
historyVerdictFilter.addEventListener("change", applyHistoryFilters);
historySearch.addEventListener("input", applyHistoryFilters);
refreshButton.addEventListener("click", refreshAll);

resetAccountForm();
refreshAll();
