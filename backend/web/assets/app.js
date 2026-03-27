const statsGrid = document.querySelector("#stats-grid");
const chartNode = document.querySelector("#chart");
const accountsList = document.querySelector("#accounts-list");
const historyBody = document.querySelector("#history-body");
const form = document.querySelector("#account-form");
const formStatus = document.querySelector("#form-status");
const manualCheckForm = document.querySelector("#manual-check-form");
const manualCheckStatus = document.querySelector("#manual-check-status");
const manualCheckResult = document.querySelector("#manual-check-result");
const healthDot = document.querySelector("#health-dot");
const healthLabel = document.querySelector("#health-label");
const periodSelect = document.querySelector("#period-select");
const historyVerdictFilter = document.querySelector("#history-verdict-filter");
const historySearch = document.querySelector("#history-search");
const refreshButton = document.querySelector("#refresh-all");
const pollButton = document.querySelector("#poll-once");
const statTemplate = document.querySelector("#stat-card-template");

let historyItemsState = [];

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
      // ignore non-json errors
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
  if (!value) {
    return "—";
  }
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

function renderStats(stats) {
  statsGrid.innerHTML = "";
  Object.entries(statLabels).forEach(([key, label]) => {
    const fragment = statTemplate.content.cloneNode(true);
    fragment.querySelector(".stat-label").textContent = label;
    fragment.querySelector(".stat-value").textContent = formatNumber(stats[key]);
    statsGrid.appendChild(fragment);
  });
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
      <strong>${escapeHtml(item.email_address)}</strong>
      <p class="muted">${escapeHtml(item.imap_host)}:${item.imap_port} · user ${escapeHtml(item.username)}</p>
      <div class="account-meta">
        <span class="pill">${escapeHtml(item.source_mailbox)}</span>
        <span class="pill">UID ${item.last_uid}</span>
        <span class="pill">${escapeHtml(item.action_on_high)} → ${escapeHtml(item.target_mailbox)}</span>
        <span class="pill">${item.poll_interval_seconds}s</span>
        <span class="pill">${item.imap_tls ? "TLS" : "No TLS"}</span>
      </div>
    `;
    accountsList.appendChild(card);
  });
}

function verdictBadge(verdict) {
  const kind = verdict || "safe";
  return `<span class="badge badge-${kind}">${escapeHtml(kind)}</span>`;
}

function detailRowMarkup(items) {
  if (!items.length) {
    return '<div class="detail-empty">Для письма пока нет деталей по URL.</div>';
  }

  const rows = items
    .map(
      (item) => `
        <tr>
          <td><a href="${escapeHtml(item.normalized_url)}" target="_blank" rel="noreferrer">${escapeHtml(item.domain || item.normalized_url)}</a></td>
          <td>${Number(item.score || 0).toFixed(3)}</td>
          <td>${item.risk ?? 0}</td>
          <td>${verdictBadge(item.verdict)}</td>
          <td>${escapeHtml(item.model_version || "")}</td>
        </tr>
      `
    )
    .join("");

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
  try {
    await Promise.all([loadHealth(), loadStats(), loadAccounts(), loadHistory(), loadChart()]);
  } finally {
    refreshButton.disabled = false;
  }
}

function getFormPayload() {
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

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  formStatus.textContent = "Сохраняем аккаунт...";

  try {
    const payload = getFormPayload();
    const result = await api("/api/v1/accounts", {
      method: "POST",
      body: JSON.stringify(payload),
    });

    form.reset();
    form.querySelector('input[name="imap_port"]').value = "993";
    form.querySelector('input[name="source_mailbox"]').value = "INBOX";
    form.querySelector('input[name="poll_interval_seconds"]').value = "900";
    form.querySelector('input[name="target_mailbox"]').value = "Phishing";
    form.querySelector('select[name="action_on_high"]').value = "MOVE";
    form.querySelector('input[name="imap_tls"]').checked = true;

    formStatus.textContent = result.message || "Аккаунт добавлен.";
    await refreshAll();
  } catch (error) {
    formStatus.textContent = `Ошибка: ${error.message}`;
  }
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
  try {
    await api("/api/v1/poll/once", { method: "POST", body: "{}" });
    await refreshAll();
  } catch (error) {
    alert(`Не удалось запустить сканирование: ${error.message}`);
  } finally {
    pollButton.disabled = false;
  }
});

periodSelect.addEventListener("change", loadChart);
historyVerdictFilter.addEventListener("change", applyHistoryFilters);
historySearch.addEventListener("input", applyHistoryFilters);
refreshButton.addEventListener("click", refreshAll);

refreshAll();
