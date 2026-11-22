/**
 * Azure FinSecOps Platform - Core Client Application
 * Native Vanilla JavaScript (ES6+), pure HTML5 & CSS3.
 * Full integration with Flask REST API & background evaluation engine.
 */

// ============================================================
// GLOBAL APPLICATION STATE
// ============================================================
const state = {
  connectionId: null,
  workspaceName: "",
  accessibleSubscriptionsCount: 0,
  currency: null,
  targetTags: "",
  configuredTags: [],
  catalog: [],             // Assessment definitions
  results: {},             // Module results mapped by assessment_id
  summary: {},             // Aggregated summary metrics
  latestJobId: null,       // Currently active or last completed job
  lastRunScope: null,      // 'security', 'cost', or 'all'
  activeTab: "tab-overview",
  pollInterval: null,      // Active polling timer handle
  isJobRunning: false,     // Job active status
  activeAssessmentId: null,// Currently inspected assessment in modal
  statusDismissTimeout: null
};

const SESSION_STORAGE_KEY = "azure_finsecops_session";

// ============================================================
// FORMATTERS & UTILITIES
// ============================================================
const CURRENCY_SYMBOLS = {
  USD: "$",
  EUR: "€",
  GBP: "£",
  INR: "₹",
  JPY: "¥",
  AUD: "A$",
  CAD: "C$",
  CHF: "CHF",
  CNY: "¥",
  SGD: "S$",
  NZD: "NZ$",
  BRL: "R$",
  AED: "AED",
  SAR: "SAR",
  SEK: "kr",
  NOK: "kr",
  DKK: "kr",
  PLN: "zł",
  MXN: "Mex$",
  ZAR: "R"
};

function getCurrencySymbol(currencyCode) {
  const code = (currencyCode || state.currency || "USD").toUpperCase();
  return CURRENCY_SYMBOLS[code] || "$";
}

function formatCurrency(val, currencyCode) {
  const curr = (currencyCode || state.currency || "USD").toUpperCase();
  if (val === null || val === undefined || isNaN(val)) {
    const sym = getCurrencySymbol(curr);
    return `${sym}0.00`;
  }
  const locale = curr === "INR" ? "en-IN" : "en-US";
  try {
    return new Intl.NumberFormat(locale, {
      style: "currency",
      currency: curr,
      minimumFractionDigits: 2,
      maximumFractionDigits: 2
    }).format(val);
  } catch (e) {
    const sym = getCurrencySymbol(curr);
    return `${sym}${Number(val).toLocaleString(locale, { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
  }
}

function formatSavingsWithMonthly(annualVal, monthlyVal, currencyCode) {
  let val = Number(annualVal);
  if (!val || isNaN(val) || val <= 0) {
    if (monthlyVal !== undefined && monthlyVal !== null && Number(monthlyVal) > 0) {
      val = Number(monthlyVal) * 12;
    } else {
      val = 0;
    }
  }
  return formatCurrency(val, currencyCode);
}

function formatNumber(val) {
  if (val === null || val === undefined || isNaN(val)) return "0";
  return new Intl.NumberFormat("en-US").format(val);
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function getSeverityBadge(severity) {
  const sev = (severity || "Medium").toLowerCase();
  if (sev === "critical") return `<span class="badge badge-critical">Critical</span>`;
  if (sev === "high") return `<span class="badge badge-high">High</span>`;
  if (sev === "medium") return `<span class="badge badge-medium">Medium</span>`;
  if (sev === "low") return `<span class="badge badge-low">Low</span>`;
  return `<span class="badge badge-info">${escapeHtml(severity)}</span>`;
}

function getStatusBadge(status) {
  const st = (status || "Pending").toLowerCase();
  if (st.includes("completed")) {
    return `<span class="badge badge-success"><i class="fa-solid fa-check"></i> Completed</span>`;
  }
  if (st.includes("running")) {
    return `<span class="badge badge-warning"><i class="fa-solid fa-circle-notch fa-spin"></i> Running</span>`;
  }
  if (st.includes("failed")) {
    return `<span class="badge badge-danger"><i class="fa-solid fa-xmark"></i> Failed</span>`;
  }
  if (st.includes("warning")) {
    return `<span class="badge badge-warning">${escapeHtml(status)}</span>`;
  }
  return `<span class="badge badge-info">${escapeHtml(status)}</span>`;
}

// Toast Notifications with 7s timer & close button
function showToast(message, type = "info", duration = 7000) {
  const container = document.getElementById("toastContainer");
  if (!container) return;

  const toast = document.createElement("div");
  toast.className = `toast toast-${type}`;

  let icon = "fa-circle-info";
  if (type === "success") icon = "fa-circle-check";
  if (type === "error") icon = "fa-circle-exclamation";
  if (type === "warning") icon = "fa-triangle-exclamation";

  toast.innerHTML = `
    <i class="fa-solid ${icon} toast-icon"></i>
    <span class="toast-message">${escapeHtml(message)}</span>
    <button type="button" class="toast-close-btn" title="Dismiss">&times;</button>
  `;

  const closeBtn = toast.querySelector(".toast-close-btn");
  let timer = null;

  const dismiss = () => {
    if (timer) clearTimeout(timer);
    toast.style.opacity = "0";
    toast.style.transform = "translateX(20px)";
    setTimeout(() => {
      try { toast.remove(); } catch (e) {}
    }, 250);
  };

  if (closeBtn) {
    closeBtn.addEventListener("click", dismiss);
  }

  container.appendChild(toast);
  timer = setTimeout(dismiss, duration);
}
window.showToast = showToast;

// ============================================================
// STATE PERSISTENCE (sessionStorage)
// ============================================================
function saveSessionState() {
  if (!state.connectionId) {
    sessionStorage.removeItem(SESSION_STORAGE_KEY);
    return;
  }
  const payload = {
    connectionId: state.connectionId,
    workspaceName: state.workspaceName,
    accessibleSubscriptionsCount: state.accessibleSubscriptionsCount,
    currency: state.currency,
    targetTags: state.targetTags,
    configuredTags: state.configuredTags,
    results: state.results,
    summary: state.summary,
    latestJobId: state.latestJobId,
    lastRunScope: state.lastRunScope,
    activeTab: state.activeTab
  };
  try {
    sessionStorage.setItem(SESSION_STORAGE_KEY, JSON.stringify(payload));
    if (state.configuredTags) {
      sessionStorage.setItem("azure_finsecops_tags", JSON.stringify(state.configuredTags));
    }
  } catch (err) {
    console.warn("Failed to persist session to sessionStorage:", err);
  }
}

async function restoreSessionState() {
  try {
    const raw = sessionStorage.getItem(SESSION_STORAGE_KEY);
    if (!raw) return false;

    const data = JSON.parse(raw);
    if (!data || !data.connectionId) return false;

    state.connectionId = data.connectionId;
    state.workspaceName = data.workspaceName || "";
    state.accessibleSubscriptionsCount = data.accessibleSubscriptionsCount || 1;
    state.currency = data.currency || null;
    state.targetTags = data.targetTags || "";
    if (data.configuredTags && Array.isArray(data.configuredTags)) {
      state.configuredTags = data.configuredTags;
    } else if (state.targetTags) {
      state.configuredTags = state.targetTags.split(",").map(t => t.trim().toLowerCase()).filter(Boolean);
    } else {
      state.configuredTags = [];
    }
    renderTagPills();
    state.results = data.results || {};
    state.summary = data.summary || {};
    state.latestJobId = data.latestJobId || null;
    state.lastRunScope = data.lastRunScope || null;
    state.activeTab = data.activeTab || "tab-overview";

    updateSessionUI();
    showView("dashboard");
    await loadCatalog();

    updateKPIs();
    updateReportButtons();

    // Check URL hash first, else saved tab
    const hash = (window.location.hash || "").replace("#", "");
    const targetTab = hash ? `tab-${hash}` : state.activeTab;
    if (document.getElementById(targetTab)) {
      switchTab(targetTab);
    } else {
      switchTab("tab-overview");
    }

    return true;
  } catch (err) {
    console.warn("Failed to restore session:", err);
    return false;
  }
}

function clearSessionState() {
  try {
    sessionStorage.removeItem(SESSION_STORAGE_KEY);
  } catch (e) {}
}

// ============================================================
// NAVIGATION & TABS
// ============================================================
function switchTab(tabId) {
  state.activeTab = tabId;
  const shortName = tabId.replace("tab-", "");
  try {
    history.replaceState(null, null, `#${shortName}`);
  } catch (e) {}

  const tabs = document.querySelectorAll(".nav-tab-btn");
  tabs.forEach(btn => {
    if (btn.getAttribute("data-tab") === tabId) {
      btn.classList.add("active");
    } else {
      btn.classList.remove("active");
    }
  });

  const panes = document.querySelectorAll(".tab-pane");
  panes.forEach(pane => {
    if (pane.id === tabId) {
      pane.classList.add("active");
      const bar = document.getElementById("inlineStatusBar");
      if (bar && state.isJobRunning && bar.parentElement !== pane) {
        pane.insertBefore(bar, pane.firstChild);
      }
    } else {
      pane.classList.remove("active");
    }
  });

  saveSessionState();
  if (tabId === "tab-scheduler") {
    fetchEmailConfig();
    fetchSchedules();
  }
  window.scrollTo({ top: 0, behavior: "smooth" });
}
window.switchTab = switchTab;

function setupTabs() {
  document.querySelectorAll(".nav-tab-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      const tabId = btn.getAttribute("data-tab");
      switchTab(tabId);
    });
  });
}

function showView(viewName) {
  const connView = document.getElementById("connectionView");
  const dashView = document.getElementById("dashboardView");
  if (viewName === "dashboard") {
    connView.classList.add("d-none");
    dashView.classList.remove("d-none");
  } else {
    connView.classList.remove("d-none");
    dashView.classList.add("d-none");
  }
}

// ============================================================
// TARGET SUBSCRIPTION IDS TABLE & LIVE VALIDATION
// ============================================================
let targetSubsEnabled = false;

function toggleSubscriptionTable(enable) {
  targetSubsEnabled = typeof enable === "boolean" ? enable : !targetSubsEnabled;
  const card = document.getElementById("subsCardContainer");
  const toggleBtn = document.getElementById("btnToggleSubsTable");
  const addBtn = document.getElementById("btnAddSubscriptionRow");
  const defaultNotice = document.getElementById("subsDefaultNotice");
  const subsTable = document.getElementById("subsTable");
  const badge = document.getElementById("subsVerifiedBadge");

  if (targetSubsEnabled) {
    if (card) card.classList.add("subs-card-colored");
    if (toggleBtn) {
      toggleBtn.classList.add("btn-active-colored");
      toggleBtn.innerHTML = `<i class="fa-solid fa-list-check"></i> Scoped Mode Active`;
    }
    if (addBtn) addBtn.classList.remove("d-none");
    if (defaultNotice) defaultNotice.classList.add("d-none");
    if (subsTable) subsTable.classList.remove("d-none");
    if (badge) badge.classList.add("pill-colored");

    const tableBody = document.getElementById("subsTableBody");
    if (tableBody && tableBody.children.length === 0) {
      addSubscriptionRow("", "- Pending Verification -");
    }
  } else {
    if (card) card.classList.remove("subs-card-colored");
    if (toggleBtn) {
      toggleBtn.classList.remove("btn-active-colored");
      toggleBtn.innerHTML = `<i class="fa-solid fa-list-check"></i> Enter Subscription IDs`;
    }
    if (addBtn) addBtn.classList.add("d-none");
    if (defaultNotice) defaultNotice.classList.remove("d-none");
    if (subsTable) subsTable.classList.add("d-none");
    if (badge) badge.classList.remove("pill-colored");
  }
  updateSubscriptionCountBadge();
}

function initSubscriptionTable() {
  const toggleBtn = document.getElementById("btnToggleSubsTable");
  const addBtn = document.getElementById("btnAddSubscriptionRow");
  const tableBody = document.getElementById("subsTableBody");

  if (toggleBtn) {
    toggleBtn.addEventListener("click", () => toggleSubscriptionTable());
  }

  if (addBtn) {
    addBtn.addEventListener("click", () => {
      addSubscriptionRow("", "- Pending Verification -");
    });
  }

  if (tableBody) {
    tableBody.innerHTML = "";
  }

  updateSubscriptionCountBadge();
}

function addSubscriptionRow(subId = "", name = "- Pending Verification -", status = "Pending") {
  const tableBody = document.getElementById("subsTableBody");
  if (!tableBody) return;

  const rowCount = tableBody.querySelectorAll("tr").length + 1;
  const tr = document.createElement("tr");
  tr.className = "sub-row";

  let statusBadge = `<span class="badge badge-warning"><i class="fa-regular fa-clock"></i> Pending</span>`;
  if (status === "Verified") {
    statusBadge = `<span class="badge badge-success"><i class="fa-solid fa-circle-check"></i> Verified</span>`;
    tr.classList.add("row-verified");
  } else if (status === "Failed") {
    statusBadge = `<span class="badge badge-danger"><i class="fa-solid fa-circle-xmark"></i> Inaccessible</span>`;
    tr.classList.add("row-failed");
  }

  tr.innerHTML = `
    <td class="sub-index-cell col-center text-muted" style="text-align: center; font-weight: 700;">${rowCount}</td>
    <td>
      <input type="text" class="subs-input-field font-mono" placeholder="00000000-0000-0000-0000-000000000000" value="${escapeHtml(subId)}">
    </td>
    <td class="sub-name-cell">
      <span class="sub-name-text ${name.startsWith('-') ? 'text-muted' : ''}">
        ${name.startsWith('-') ? '' : '<i class="fa-solid fa-cloud text-purple"></i> '}
        ${escapeHtml(name)}
      </span>
    </td>
    <td class="sub-status-cell">
      ${statusBadge}
    </td>
    <td class="col-center" style="text-align: center;">
      <button type="button" class="btn-del-sub" title="Remove subscription row">
        <i class="fa-solid fa-trash-can"></i>
      </button>
    </td>
  `;

  // Delete row handler
  const delBtn = tr.querySelector(".btn-del-sub");
  if (delBtn) {
    delBtn.addEventListener("click", () => {
      tr.remove();
      renumberSubscriptionRows();
      checkForDuplicateSubscriptions();
      updateSubscriptionCountBadge();
    });
  }

  // Input change handler with live duplicate detection
  const inputField = tr.querySelector(".subs-input-field");
  if (inputField) {
    inputField.addEventListener("input", () => {
      tr.classList.remove("row-verified", "row-failed");
      const statusCell = tr.querySelector(".sub-status-cell");
      const nameCell = tr.querySelector(".sub-name-cell");
      if (statusCell) {
        statusCell.innerHTML = `<span class="badge badge-warning"><i class="fa-regular fa-clock"></i> Pending</span>`;
      }
      if (nameCell && !inputField.value.trim()) {
        nameCell.innerHTML = `<span class="sub-name-text text-muted">- Pending Verification -</span>`;
      }
      checkForDuplicateSubscriptions();
      updateSubscriptionCountBadge();
    });
  }

  tableBody.appendChild(tr);
  renumberSubscriptionRows();
  checkForDuplicateSubscriptions();
  updateSubscriptionCountBadge();
}

function renumberSubscriptionRows() {
  const tableBody = document.getElementById("subsTableBody");
  if (!tableBody) return;
  const rows = tableBody.querySelectorAll("tr");
  rows.forEach((row, idx) => {
    const idxCell = row.querySelector(".sub-index-cell");
    if (idxCell) idxCell.textContent = idx + 1;
  });
}

function checkForDuplicateSubscriptions() {
  const tableBody = document.getElementById("subsTableBody");
  if (!tableBody) return false;

  const rows = Array.from(tableBody.querySelectorAll("tr"));
  const seen = new Map(); // subIdLower -> { rowNumber: number, rowEl: HTMLElement }
  let hasDuplicates = false;

  rows.forEach((row, idx) => {
    const rowNum = idx + 1;
    const input = row.querySelector(".subs-input-field");
    const statusCell = row.querySelector(".sub-status-cell");
    const nameCell = row.querySelector(".sub-name-cell");
    if (!input) return;

    const val = input.value.trim().toLowerCase();
    if (!val) {
      row.classList.remove("row-duplicate");
      input.classList.remove("input-duplicate");
      return;
    }

    if (seen.has(val)) {
      hasDuplicates = true;
      const firstEntry = seen.get(val);
      row.classList.add("row-duplicate");
      row.classList.remove("row-verified");
      input.classList.add("input-duplicate");
      if (statusCell) {
        statusCell.innerHTML = `<span class="badge badge-warning badge-duplicate"><i class="fa-solid fa-triangle-exclamation"></i> Duplicate Sub ID</span>`;
      }
      if (nameCell) {
        nameCell.innerHTML = `<span class="text-danger small font-semibold"><i class="fa-solid fa-triangle-exclamation"></i> Already entered in Row #${firstEntry.rowNumber}</span>`;
      }
    } else {
      seen.set(val, { rowNumber: rowNum, rowEl: row });
      if (row.classList.contains("row-duplicate")) {
        row.classList.remove("row-duplicate");
        input.classList.remove("input-duplicate");
        if (statusCell) {
          statusCell.innerHTML = `<span class="badge badge-info"><i class="fa-regular fa-clock"></i> Pending</span>`;
        }
        if (nameCell) {
          nameCell.innerHTML = `<span class="sub-name-text text-muted">- Pending Verification -</span>`;
        }
      }
    }
  });

  return hasDuplicates;
}

function updateSubscriptionCountBadge() {
  const tableBody = document.getElementById("subsTableBody");
  const countText = document.getElementById("subsCountText");
  const badge = document.getElementById("subsVerifiedBadge");
  if (!countText) return;

  const rows = tableBody ? tableBody.querySelectorAll("tr") : [];
  let filledCount = 0;
  let verifiedCount = 0;

  rows.forEach(r => {
    const input = r.querySelector(".subs-input-field");
    if (input && input.value.trim()) filledCount++;
    if (r.classList.contains("row-verified")) verifiedCount++;
  });

  if (verifiedCount > 0) {
    if (badge) badge.classList.remove("d-none");
    countText.innerHTML = `${verifiedCount} Verified / ${filledCount} Target`;
  } else if (filledCount > 0) {
    if (badge) badge.classList.remove("d-none");
    countText.innerHTML = `${filledCount} Target Subscriptions`;
  } else {
    if (badge) badge.classList.add("d-none");
    countText.innerHTML = "";
  }
}

// ============================================================
// ENVIRONMENT EVALUATION TAGS PILLS MANAGER
// ============================================================
window.addExampleTag = function(tagName) {
  if (!tagName) return;
  const tag = tagName.trim();
  if (!state.configuredTags.includes(tag)) {
    state.configuredTags.push(tag);
    renderTagPills();
  }
};

window.removeTag = function(tagToRemove) {
  state.configuredTags = state.configuredTags.filter(t => t !== tagToRemove);
  renderTagPills();
};

window.handleAddTagInput = function() {
  const tagInput = document.getElementById("tagInput");
  if (!tagInput) return;
  const raw = tagInput.value.trim();
  if (!raw) {
    showToast("Please type a tag keyword (e.g. prod, test, dev, staging) before clicking Add.", "warning");
    tagInput.focus();
    return;
  }

  // Support comma-separated or single word - preserve exact casing and format as typed by user
  const parts = raw.split(",").map(p => p.trim().replace(/^#+/, "")).filter(Boolean);
  let addedAny = false;
  let alreadyAdded = [];

  parts.forEach(tag => {
    // Exact format check for duplicates
    if (!state.configuredTags.includes(tag)) {
      state.configuredTags.push(tag);
      addedAny = true;
    } else {
      alreadyAdded.push(tag);
    }
  });

  tagInput.value = "";
  renderTagPills();

  if (addedAny) {
    tagInput.focus();
  } else if (alreadyAdded.length > 0) {
    showToast(`Tag "${alreadyAdded.join(', ')}" is already added.`, "info");
    tagInput.focus();
  }
};

function initTagsManager() {
  let savedTags = null;
  try {
    const raw = sessionStorage.getItem("azure_finsecops_tags");
    if (raw) savedTags = JSON.parse(raw);
  } catch (e) {}

  state.configuredTags = Array.isArray(savedTags) ? savedTags : [];

  const tagInput = document.getElementById("tagInput");
  const addBtn = document.getElementById("btnAddTag");

  if (addBtn) {
    addBtn.onclick = function(e) {
      if (e) {
        e.preventDefault();
        e.stopPropagation();
      }
      window.handleAddTagInput();
    };
  }

  if (tagInput) {
    tagInput.onkeydown = function(e) {
      if (e.key === "Enter") {
        e.preventDefault();
        e.stopPropagation();
        window.handleAddTagInput();
      }
    };
  }

  renderTagPills();
}

function renderTagPills() {
  const container = document.getElementById("tagsPillsContainer");
  const badge = document.getElementById("tagsCountBadge");
  const hiddenInput = document.getElementById("targetTags");
  const hintText = document.getElementById("tagsHintText");

  if (hiddenInput) {
    hiddenInput.value = state.configuredTags.join(", ");
  }
  state.targetTags = state.configuredTags.join(", ");

  try {
    sessionStorage.setItem("azure_finsecops_tags", JSON.stringify(state.configuredTags));
  } catch (e) {}

  if (hintText) {
    if (state.configuredTags.length > 0) {
      hintText.classList.add("d-none");
    } else {
      hintText.classList.remove("d-none");
    }
  }

  if (badge) {
    const count = state.configuredTags.length;
    if (count === 0) {
      badge.textContent = "0 configured";
      badge.className = "tags-count-badge";
    } else {
      badge.textContent = `${count} configured`;
      badge.className = "tags-count-badge";
    }
  }

  if (!container) return;
  container.innerHTML = "";

  if (state.configuredTags.length === 0) {
    return;
  }

  state.configuredTags.forEach(tag => {
    const pill = document.createElement("span");
    pill.className = "tag-pill";
    pill.innerHTML = `
      <i class="fa-solid fa-tag tag-pill-icon"></i>
      <span class="tag-pill-text">${escapeHtml(tag)}</span>
      <button type="button" class="tag-pill-remove" title="Remove ${escapeHtml(tag)}" onclick="removeTag('${escapeHtml(tag)}')">&times;</button>
    `;

    const rmBtn = pill.querySelector(".tag-pill-remove");
    if (rmBtn) {
      rmBtn.addEventListener("click", () => {
        window.removeTag(tag);
      });
    }

    container.appendChild(pill);
  });
}

// ============================================================
// AUTHENTICATION & CONNECTION WITH LIVE VALIDATION
// ============================================================
function setConnectionControlsState(isConnecting) {
  const ids = [
    "connectSubmitBtn",
    "btnToggleSubsTable",
    "btnAddSubscriptionRow",
    "btnAddTag",
    "tagInput",
    "workspaceName",
    "tenantId",
    "clientId",
    "clientSecret",
    "toggleSecretBtn"
  ];
  ids.forEach(id => {
    const el = document.getElementById(id);
    if (el) el.disabled = isConnecting;
  });

  document.querySelectorAll(".subs-input-field").forEach(el => { el.disabled = isConnecting; });
  document.querySelectorAll(".btn-del-sub").forEach(el => { el.disabled = isConnecting; });
  document.querySelectorAll(".tag-pill-remove").forEach(el => { el.disabled = isConnecting; });
}

async function handleConnect(event) {
  event.preventDefault();
  const alertBox = document.getElementById("connectionAlert");
  const alertText = document.getElementById("connectionAlertText");
  const submitBtn = document.getElementById("connectSubmitBtn");
  const liveStatusPill = document.getElementById("subsLiveValidationStatus");

  // Per requirements, never show error alert banner inside the credentials card; use toasts exclusively
  if (alertBox) alertBox.classList.add("d-none");
  setConnectionControlsState(true);
  submitBtn.innerHTML = `<i class="fa-solid fa-circle-notch fa-spin"></i> Authenticating...`;

  const workspaceName = document.getElementById("workspaceName").value.trim();
  const tenantId = document.getElementById("tenantId").value.trim();
  const clientId = document.getElementById("clientId").value.trim();
  const clientSecret = document.getElementById("clientSecret").value.trim();
  const targetTags = state.configuredTags && state.configuredTags.length > 0 
    ? state.configuredTags.join(", ") 
    : (document.getElementById("targetTags")?.value || "").trim();

  const validationErrors = [];
  const guidRegex = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

  if (!workspaceName || !tenantId || !clientId || !clientSecret) {
    validationErrors.push({
      msg: "Please provide Customer / Workspace Name, Azure Tenant ID, Client ID, and Client Secret.",
      type: "error"
    });
  } else {
    if (!guidRegex.test(tenantId)) {
      validationErrors.push({
        msg: "Azure Tenant ID must be a valid GUID (e.g. 00000000-0000-0000-0000-000000000000).",
        type: "error"
      });
    }
    if (!guidRegex.test(clientId)) {
      validationErrors.push({
        msg: "Service Principal Client ID must be a valid GUID (e.g. 00000000-0000-0000-0000-000000000000).",
        type: "error"
      });
    }
  }

  // Collect target subscriptions from table if any entered
  const tableBody = document.getElementById("subsTableBody");
  const rows = tableBody ? Array.from(tableBody.querySelectorAll("tr")) : [];
  const enteredSubs = [];

  rows.forEach(r => {
    const inp = r.querySelector(".subs-input-field");
    if (inp && inp.value.trim()) {
      enteredSubs.push({
        row: r,
        id: inp.value.trim(),
        nameCell: r.querySelector(".sub-name-cell"),
        statusCell: r.querySelector(".sub-status-cell")
      });
    }
  });

  // Check for duplicate subscription IDs before connecting
  const hasDuplicates = checkForDuplicateSubscriptions();
  if (hasDuplicates) {
    validationErrors.push({
      msg: "Duplicate Subscription IDs detected in the table. Please resolve or remove duplicate entries before connecting.",
      type: "warning"
    });
  }

  // If user enabled Scoped Mode ("Enter Subscription IDs"), require at least one subscription ID to be entered
  if (targetSubsEnabled && enteredSubs.length === 0) {
    validationErrors.push({
      msg: "You enabled Scoped Mode. Please enter at least one Subscription ID (GUID) in the Target Subscriptions table, or click 'Enter Subscription IDs' again to revert to Full Tenant Scope.",
      type: "warning"
    });
  } else if (enteredSubs.length > 0) {
    const invalidSub = enteredSubs.find(s => !guidRegex.test(s.id));
    if (invalidSub) {
      validationErrors.push({
        msg: `Invalid Subscription ID format: "${invalidSub.id}". Subscription IDs must be valid GUIDs (e.g. 00000000-0000-0000-0000-000000000000).`,
        type: "error"
      });
    }
  }

  if (validationErrors.length > 0) {
    if (alertBox) alertBox.classList.add("d-none");
    validationErrors.forEach(err => showToast(err.msg, err.type, 7000));
    setConnectionControlsState(false);
    submitBtn.innerHTML = `<i class="fa-solid fa-plug"></i> Connect to Azure`;
    return;
  }

  const verifiedSubIds = [];

  try {
    // If subscriptions were specified, validate them one by one in live action
    if (enteredSubs.length > 0) {
      submitBtn.innerHTML = `<i class="fa-solid fa-circle-notch fa-spin"></i> Verifying Subscriptions...`;

      for (let i = 0; i < enteredSubs.length; i++) {
        const item = enteredSubs[i];
        item.row.classList.remove("row-verified", "row-failed");
        if (item.statusCell) {
          item.statusCell.innerHTML = `<span class="badge badge-warning"><i class="fa-solid fa-circle-notch fa-spin"></i> Checking...</span>`;
        }

        try {
          const valRes = await fetch("/api/subscriptions/validate", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              tenant_id: tenantId,
              client_id: clientId,
              client_secret: clientSecret,
              subscription_id: item.id
            })
          });

          const valData = await valRes.json();

          if (valData.valid) {
            item.row.classList.add("row-verified");
            if (item.statusCell) {
              item.statusCell.innerHTML = `<span class="badge badge-success"><i class="fa-solid fa-circle-check"></i> Verified</span>`;
            }
            if (item.nameCell) {
              item.nameCell.innerHTML = `<span class="sub-name-text"><i class="fa-solid fa-cloud text-purple"></i> ${escapeHtml(valData.display_name || item.id)}</span>`;
            }
            verifiedSubIds.push(valData.subscription_id);
          } else {
            item.row.classList.add("row-failed");
            if (item.statusCell) {
              item.statusCell.innerHTML = `<span class="badge badge-danger" title="${escapeHtml(valData.error || 'Access Denied')}"><i class="fa-solid fa-circle-xmark"></i> Inaccessible</span>`;
            }
            if (item.nameCell) {
              item.nameCell.innerHTML = `<span class="sub-name-text text-danger small" title="${escapeHtml(valData.error)}"><i class="fa-solid fa-triangle-exclamation"></i> ${escapeHtml(valData.error || 'Access Denied')}</span>`;
            }
          }
        } catch (err) {
          item.row.classList.add("row-failed");
          if (item.statusCell) {
            item.statusCell.innerHTML = `<span class="badge badge-danger"><i class="fa-solid fa-circle-xmark"></i> Error</span>`;
          }
          if (item.nameCell) {
            item.nameCell.innerHTML = `<span class="sub-name-text text-danger small"><i class="fa-solid fa-triangle-exclamation"></i> ${escapeHtml(err.message)}</span>`;
          }
        }

        updateSubscriptionCountBadge();
        await new Promise(r => setTimeout(r, 200));
      }

      if (verifiedSubIds.length === 0) {
        throw new Error("Live Validation Failed: None of the entered subscriptions could be verified with this Service Principal. Please verify Reader role assignments.");
      }
    }

    // Now establish the connection session
    submitBtn.innerHTML = `<i class="fa-solid fa-circle-notch fa-spin"></i> Establishing Session...`;

    const res = await fetch("/api/connection/connect", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        workspace_name: workspaceName,
        tenant_id: tenantId,
        client_id: clientId,
        client_secret: clientSecret,
        target_tags: targetTags,
        target_subscription_ids: verifiedSubIds.length > 0 ? verifiedSubIds : undefined
      })
    });

    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.detail || "Failed to authenticate with Azure.");
    }

    state.connectionId = data.connection_id;
    state.workspaceName = data.workspace_name;
    state.accessibleSubscriptionsCount = data.accessible_subscriptions_count || 1;
    state.currency = data.currency || state.currency || null;
    state.targetTags = data.target_tags || targetTags;
    state.results = {};
    state.summary = {};
    state.latestJobId = null;
    state.lastRunScope = null;
    state.activeTab = "tab-overview";

    updateSessionUI();
    showView("dashboard");
    await loadCatalog();
    updateKPIs();
    updateReportButtons();
    saveSessionState();
    switchTab("tab-overview");
    showToast(`Connected to Azure successfully (${state.accessibleSubscriptionsCount} subscriptions loaded).`, "success");
  } catch (err) {
    if (alertBox) alertBox.classList.add("d-none");
    showToast(err.message, "error", 7000);
    if (liveStatusPill) liveStatusPill.classList.add("d-none");
  } finally {
    setConnectionControlsState(false);
    submitBtn.disabled = false;
    submitBtn.innerHTML = `<i class="fa-solid fa-plug"></i> Connect to Azure`;
  }
}

async function handleDisconnect() {
  if (state.pollInterval) {
    clearInterval(state.pollInterval);
    state.pollInterval = null;
  }
  if (state.statusDismissTimeout) {
    clearTimeout(state.statusDismissTimeout);
    state.statusDismissTimeout = null;
  }

  if (state.connectionId) {
    try {
      await fetch(`/api/connection/${state.connectionId}`, { method: "DELETE" });
    } catch (e) {
      console.warn("Disconnect error:", e);
    }
  }

  clearSessionState();
  state.connectionId = null;
  state.latestJobId = null;
  state.lastRunScope = null;
  state.results = {};
  state.summary = {};
  state.workspaceName = "";
  state.accessibleSubscriptionsCount = 0;

  // Clear all credentials and form inputs in the connection view
  const wsInput = document.getElementById("workspaceName");
  const tenantInput = document.getElementById("tenantId");
  const clientInput = document.getElementById("clientId");
  const secretInput = document.getElementById("clientSecret");
  const tagInput = document.getElementById("tagInput");
  const hiddenTags = document.getElementById("targetTags");

  if (wsInput) wsInput.value = "";
  if (tenantInput) tenantInput.value = "";
  if (clientInput) clientInput.value = "";
  if (secretInput) secretInput.value = "";
  if (tagInput) tagInput.value = "";
  if (hiddenTags) hiddenTags.value = "";

  // Reset tag pills to empty
  state.configuredTags = [];
  renderTagPills();

  // Reset subscription table to initial auto-discovery state and clear rows
  const tableBody = document.getElementById("subsTableBody");
  if (tableBody) tableBody.innerHTML = "";
  toggleSubscriptionTable(false);

  // Clear all storages
  try {
    sessionStorage.clear();
    localStorage.removeItem("azure_finsecops_tags");
  } catch (e) {}

  // Hide any lingering alerts
  const alertBox = document.getElementById("connectionAlert");
  if (alertBox) alertBox.classList.add("d-none");
  const liveStatusPill = document.getElementById("subsLiveValidationStatus");
  if (liveStatusPill) liveStatusPill.classList.add("d-none");

  // Reset UI
  hideInlineStatusBar();
  updateReportButtons();
  showView("connection");
  showToast("Disconnected successfully. Session, credentials, and tags cleared.", "info");
}

function updateSessionUI() {
  const wsPill = document.getElementById("sessionWorkspace");
  const greeting = document.getElementById("viewGreeting");
  const elSubs = document.getElementById("kpiSubs");
  const secTitle = document.getElementById("secWorkspaceTitle");
  const costTitle = document.getElementById("costWorkspaceTitle");

  if (wsPill) wsPill.textContent = state.workspaceName;
  if (elSubs) elSubs.textContent = formatNumber(state.accessibleSubscriptionsCount || 0);
  if (greeting) {
    greeting.textContent = state.workspaceName ? `${state.workspaceName} - Assessment Dashboard` : "Assessment Dashboard";
  }
  if (secTitle) {
    secTitle.textContent = state.workspaceName ? `${state.workspaceName} - Security Assessment` : "Security Assessment";
  }
  if (costTitle) {
    costTitle.textContent = state.workspaceName ? `${state.workspaceName} - Cost Assessment` : "Cost Assessment";
  }
}

function setupPasswordToggle() {
  const toggleBtn = document.getElementById("toggleSecretBtn");
  const secretInput = document.getElementById("clientSecret");
  if (toggleBtn && secretInput) {
    toggleBtn.addEventListener("click", () => {
      if (secretInput.type === "password") {
        secretInput.type = "text";
        toggleBtn.innerHTML = `<i class="fa-solid fa-eye-slash"></i>`;
      } else {
        secretInput.type = "password";
        toggleBtn.innerHTML = `<i class="fa-solid fa-eye"></i>`;
      }
    });
  }
}

// ============================================================
// ASSESSMENT CATALOGUE & CARDS RENDERING
// ============================================================
async function loadCatalog() {
  try {
    const res = await fetch("/api/assessments");
    if (!res.ok) throw new Error("Could not load assessments catalogue.");
    state.catalog = await res.json();

    renderSecurityCards();
    renderCostCards();
  } catch (err) {
    console.error("Catalog load error:", err);
  }
}

function renderSecurityCards(filterText = "") {
  const grid = document.getElementById("securityCardsGrid");
  const countLabel = document.getElementById("secCountLabel");
  if (!grid) return;

  const secDefs = state.catalog.filter(d => d.category === "security");
  const term = filterText.toLowerCase().trim();
  const filtered = secDefs.filter(d =>
    !term ||
    d.code.toLowerCase().includes(term) ||
    d.name.toLowerCase().includes(term) ||
    d.description.toLowerCase().includes(term)
  );

  if (countLabel) {
    countLabel.textContent = "Security Modules";
  }

  if (filtered.length === 0) {
    grid.innerHTML = `<div class="empty-state">No matching security modules found for "${escapeHtml(filterText)}".</div>`;
    return;
  }

  grid.innerHTML = filtered.map(def => {
    const res = state.results[def.assessment_id];
    const status = res ? res.status : "Pending";
    const findingsCount = res ? (res.findings_count || 0) : 0;
    const hasRun = Boolean(res && res.status && res.status !== "Pending");
    const scoreImpactVal = (res && res.security_score_improvement)
      ? res.security_score_improvement
      : (res && res.findings && res.findings.length > 0
          ? res.findings.reduce((acc, f) => acc + (Number(f.security_score_impact) || 0), 0)
          : 0);
    const scoreImpact = scoreImpactVal > 0
      ? `+${scoreImpactVal.toFixed(1)}%`
      : "--";

    return `
      <div class="ass-card" id="card-${def.assessment_id}">
        <div>
          <div class="ass-card-header">
            <span class="ass-code code-purple">${escapeHtml(def.code)}</span>
            ${getStatusBadge(status)}
          </div>
          <h4 class="ass-title">${escapeHtml(def.name)}</h4>
          <p class="ass-desc">${escapeHtml(def.description)}</p>
        </div>
        <div>
          <div class="ass-meta-row">
            <span>Findings: <b>${findingsCount}</b></span>
            <span>Score Potential: <b class="text-purple">${scoreImpact}</b></span>
          </div>
          <div class="ass-card-prog-slot" id="card-prog-${def.assessment_id}"></div>
          <div class="ass-actions">
            <div class="card-actions-left">
              <button class="btn btn-outline btn-sm" onclick="openFindingsModal('${def.assessment_id}')">
                <i class="fa-solid fa-list-check"></i> Inspect Findings
              </button>
              <div class="card-report-btn-group">
                <button class="btn btn-outline btn-sm btn-card-dl btn-card-dl-pdf ${hasRun ? '' : 'btn-disabled'}" id="card-pdf-${def.assessment_id}" title="Download Module PDF" onclick="triggerSingleCardReportDownload('${def.assessment_id}', 'pdf', this)">
                  <i class="fa-solid fa-file-pdf"></i> PDF
                </button>
                <button class="btn btn-outline btn-sm btn-card-dl btn-card-dl-excel ${hasRun ? '' : 'btn-disabled'}" id="card-excel-${def.assessment_id}" title="Download Module Excel" onclick="triggerSingleCardReportDownload('${def.assessment_id}', 'excel', this)">
                  <i class="fa-solid fa-file-excel"></i> Excel
                </button>
              </div>
            </div>
            <button class="btn btn-primary-purple btn-sm" onclick="startSingleJob('${def.assessment_id}')">
              <i class="fa-solid fa-play"></i> Run
            </button>
          </div>
        </div>
      </div>
    `;
  }).join("");
}

function renderCostCards(filterText = "") {
  const grid = document.getElementById("costCardsGrid");
  const countLabel = document.getElementById("costCountLabel");
  if (!grid) return;

  const costDefs = state.catalog.filter(d => d.category === "cost");
  const term = filterText.toLowerCase().trim();
  const filtered = costDefs.filter(d =>
    !term ||
    d.code.toLowerCase().includes(term) ||
    d.name.toLowerCase().includes(term) ||
    d.description.toLowerCase().includes(term)
  );

  if (countLabel) {
    countLabel.textContent = "Cost Modules";
  }

  if (filtered.length === 0) {
    grid.innerHTML = `<div class="empty-state">No matching cost modules found for "${escapeHtml(filterText)}".</div>`;
    return;
  }

  grid.innerHTML = filtered.map(def => {
    const res = state.results[def.assessment_id];
    const status = res ? res.status : "Pending";
    const findingsCount = res ? (res.findings_count || 0) : 0;
    const hasRun = Boolean(res && res.status && res.status !== "Pending");
    const annualVal = (res && (res.total_annual_savings || (res.total_monthly_savings || 0) * 12)) || 0;
    const annualStr = annualVal > 0 ? formatCurrency(annualVal) : "$0.00";

    return `
      <div class="ass-card" id="card-${def.assessment_id}">
        <div>
          <div class="ass-card-header">
            <span class="ass-code code-red">${escapeHtml(def.code)}</span>
            ${getStatusBadge(status)}
          </div>
          <h4 class="ass-title">${escapeHtml(def.name)}${annualVal > 0 ? ` <span class="ass-title-amount text-green">(${annualStr})</span>` : ''}</h4>
          <p class="ass-desc">${escapeHtml(def.description)}</p>
        </div>
        <div>
          <div class="ass-meta-row">
            <span class="ass-meta-findings">Findings: <b>${findingsCount}</b></span>
            <span class="ass-meta-savings">Est. Annual Savings: <b class="text-green">${annualStr}</b></span>
          </div>
          <div class="ass-card-prog-slot" id="card-prog-${def.assessment_id}"></div>
          <div class="ass-actions">
            <div class="card-actions-left">
              <button class="btn btn-outline btn-sm" onclick="openFindingsModal('${def.assessment_id}')">
                <i class="fa-solid fa-list-check"></i> Inspect Findings
              </button>
              <div class="card-report-btn-group">
                <button class="btn btn-outline btn-sm btn-card-dl btn-card-dl-pdf ${hasRun ? '' : 'btn-disabled'}" id="card-pdf-${def.assessment_id}" title="Download Module PDF" onclick="triggerSingleCardReportDownload('${def.assessment_id}', 'pdf', this)">
                  <i class="fa-solid fa-file-pdf"></i> PDF
                </button>
                <button class="btn btn-outline btn-sm btn-card-dl btn-card-dl-excel ${hasRun ? '' : 'btn-disabled'}" id="card-excel-${def.assessment_id}" title="Download Module Excel" onclick="triggerSingleCardReportDownload('${def.assessment_id}', 'excel', this)">
                  <i class="fa-solid fa-file-excel"></i> Excel
                </button>
              </div>
            </div>
            <button class="btn btn-primary-red btn-sm" onclick="startSingleJob('${def.assessment_id}')">
              <i class="fa-solid fa-play"></i> Run
            </button>
          </div>
        </div>
      </div>
    `;
  }).join("");
}

function updateAssessmentCardInPlace(assessmentId) {
  const card = document.getElementById(`card-${assessmentId}`);
  if (!card) return false;

  const def = state.catalog.find(d => d.assessment_id === assessmentId);
  if (!def) return false;

  const res = state.results[assessmentId];
  const status = res ? res.status : "Pending";
  const findingsCount = res ? (res.findings_count || 0) : 0;

  // 1. Update badge in place
  const existingBadge = card.querySelector(".ass-card-header .badge");
  if (existingBadge) {
    existingBadge.outerHTML = getStatusBadge(status);
  } else {
    const header = card.querySelector(".ass-card-header");
    if (header) {
      header.insertAdjacentHTML("beforeend", getStatusBadge(status));
    }
  }

  // 2. Update title in place with amount if cost
  const titleEl = card.querySelector(".ass-title");
  if (titleEl) {
    if (def.category === "cost") {
      const annualVal = (res && (res.total_annual_savings || (res.total_monthly_savings || 0) * 12)) || 0;
      const annualStr = annualVal > 0 ? formatCurrency(annualVal) : "$0.00";
      titleEl.innerHTML = `${escapeHtml(def.name)}${annualVal > 0 ? ` <span class="ass-title-amount text-green">(${annualStr})</span>` : ''}`;
    } else {
      titleEl.textContent = def.name;
    }
  }

  // 3. Update meta row in place without touching the rest of the card
  const metaRow = card.querySelector(".ass-meta-row");
  if (metaRow) {
    if (def.category === "security") {
      const scoreImpactVal = (res && res.security_score_improvement)
        ? res.security_score_improvement
        : (res && res.findings && res.findings.length > 0
            ? res.findings.reduce((acc, f) => acc + (Number(f.security_score_impact) || 0), 0)
            : 0);
      const scoreImpact = scoreImpactVal > 0 ? `+${scoreImpactVal.toFixed(1)}%` : "--";
      metaRow.innerHTML = `
        <span class="ass-meta-findings">Findings: <b>${findingsCount}</b></span>
        <span class="ass-meta-score">Score Potential: <b class="text-purple">${scoreImpact}</b></span>
      `;
    } else {
      const annualVal = (res && (res.total_annual_savings || (res.total_monthly_savings || 0) * 12)) || 0;
      const annualStr = annualVal > 0 ? formatCurrency(annualVal) : "$0.00";
      metaRow.innerHTML = `
        <span class="ass-meta-findings">Findings: <b>${findingsCount}</b></span>
        <span class="ass-meta-savings">Est. Annual Savings: <b class="text-green">${annualStr}</b></span>
      `;
    }
  }

  // 4. Update card-level PDF/Excel download buttons
  const hasRun = Boolean(res && res.status && res.status !== "Pending");
  const cardPdf = card.querySelector(`#card-pdf-${assessmentId}`);
  const cardExcel = card.querySelector(`#card-excel-${assessmentId}`);
  if (cardPdf) {
    if (hasRun) cardPdf.classList.remove("btn-disabled");
    else cardPdf.classList.add("btn-disabled");
  }
  if (cardExcel) {
    if (hasRun) cardExcel.classList.remove("btn-disabled");
    else cardExcel.classList.add("btn-disabled");
  }

  return true;
}

function setupSearchFilters() {
  const secInput = document.getElementById("secSearchInput");
  if (secInput) {
    secInput.addEventListener("input", (e) => renderSecurityCards(e.target.value));
  }

  const costInput = document.getElementById("costSearchInput");
  if (costInput) {
    costInput.addEventListener("input", (e) => renderCostCards(e.target.value));
  }
}

// ============================================================
// INLINE STATUS BAR & REAL-TIME JOB POLLING
// ============================================================
let liveTimerInterval = null;
let liveTimerStartTime = null;

function formatElapsedMinsSecs(seconds) {
  const total = Math.max(0, Math.floor(seconds || 0));
  const m = Math.floor(total / 60);
  const s = total % 60;
  if (m > 0) {
    return `${m}m ${s < 10 ? '0' : ''}${s}s`;
  }
  return `${s}s`;
}

function startLiveDurationTimer() {
  if (liveTimerInterval) clearInterval(liveTimerInterval);
  liveTimerStartTime = Date.now();
  liveTimerInterval = setInterval(() => {
    const dur = document.getElementById("statusDuration");
    if (dur && liveTimerStartTime) {
      const elapsed = (Date.now() - liveTimerStartTime) / 1000;
      dur.textContent = formatElapsedMinsSecs(elapsed);
    }
  }, 250);
}

function stopLiveDurationTimer() {
  if (liveTimerInterval) {
    clearInterval(liveTimerInterval);
    liveTimerInterval = null;
  }
}

function showInlineStatusBar(initialMessage) {
  const bar = document.getElementById("inlineStatusBar");
  const icon = document.getElementById("statusIcon");
  const msg = document.getElementById("statusMessage");
  const pct = document.getElementById("statusPercentage");
  const dur = document.getElementById("statusDuration");
  const progFill = document.getElementById("statusProgressBar");
  const dismissBtn = document.getElementById("dismissStatusBtn");

  // Mount the status bar:
  // On tab-overview, keep it directly below the execution-bar (Run Assessment buttons)
  const activeTabId = state.activeTab || "tab-overview";
  const activeTabEl = document.getElementById(activeTabId);
  if (activeTabId === "tab-overview") {
    const execBar = document.querySelector("#tab-overview .execution-bar");
    if (execBar && bar && bar.previousElementSibling !== execBar) {
      execBar.insertAdjacentElement("afterend", bar);
    }
  } else if (activeTabEl && bar && bar.parentElement !== activeTabEl) {
    activeTabEl.insertBefore(bar, activeTabEl.firstChild);
  }

  if (state.statusDismissTimeout) {
    clearTimeout(state.statusDismissTimeout);
    state.statusDismissTimeout = null;
  }

  if (bar) bar.classList.remove("d-none");
  if (icon) icon.className = "fa-solid fa-circle-notch fa-spin text-purple";
  if (msg) msg.textContent = initialMessage || "Evaluating Azure resources in real-time...";
  if (pct) pct.textContent = "0%";
  if (dur) dur.textContent = "0s";
  if (progFill) {
    progFill.style.width = "0%";
    progFill.classList.remove("status-progress-success", "status-progress-error");
  }
  if (dismissBtn) dismissBtn.classList.add("d-none");

  startLiveDurationTimer();
}

function updateInlineStatusProgress(prog) {
  const bar = document.getElementById("inlineStatusBar");
  const msg = document.getElementById("statusMessage");
  const pct = document.getElementById("statusPercentage");
  const dur = document.getElementById("statusDuration");
  const progFill = document.getElementById("statusProgressBar");

  if (!bar) return;
  const percentage = Math.min(100, Math.max(0, prog.progress_percentage || 0));

  if (progFill) progFill.style.width = `${percentage}%`;
  if (pct) pct.textContent = `${percentage.toFixed(0)}%`;

  // Sync live timer with backend duration while continuing smooth live ticking
  if (prog.duration_seconds && prog.duration_seconds > 0 && liveTimerStartTime) {
    liveTimerStartTime = Date.now() - (prog.duration_seconds * 1000);
  }

  if (msg) {
    if (prog.current_assessment) {
      msg.textContent = `Evaluating [${prog.current_assessment}] across subscriptions...`;
    } else {
      msg.textContent = "Evaluating Azure resources in real-time...";
    }
  }
}

// ============================================================
// INDIVIDUAL CARD-LEVEL PROGRESS TRACKING
// ============================================================
let activeSingleAssessmentId = null;
let cardProgStartTime = null;
let cardProgTimerInterval = null;

function showCardProgressBar(assessmentId, isCost = false) {
  const slot = document.getElementById(`card-prog-${assessmentId}`);
  if (!slot) return;
  activeSingleAssessmentId = assessmentId;
  cardProgStartTime = Date.now();
  slot.innerHTML = `
    <div class="card-inline-prog-wrap">
      <div class="card-inline-prog-track">
        <div class="card-inline-prog-fill ${isCost ? 'fill-cost' : ''}" id="card-prog-fill-${assessmentId}" style="width: 0%"></div>
      </div>
      <div class="card-inline-prog-meta">
        <span class="card-prog-pct" id="card-prog-pct-${assessmentId}">0%</span>
        <span class="card-prog-dur" id="card-prog-dur-${assessmentId}">0s</span>
      </div>
    </div>
  `;
  if (cardProgTimerInterval) clearInterval(cardProgTimerInterval);
  cardProgTimerInterval = setInterval(() => {
    const durEl = document.getElementById(`card-prog-dur-${assessmentId}`);
    if (durEl && cardProgStartTime) {
      const elapsed = (Date.now() - cardProgStartTime) / 1000;
      durEl.textContent = formatElapsedMinsSecs(elapsed);
    }
  }, 250);
}

function updateCardProgress(assessmentId, pct, durationSec) {
  const fill = document.getElementById(`card-prog-fill-${assessmentId}`);
  const pctEl = document.getElementById(`card-prog-pct-${assessmentId}`);
  if (fill) fill.style.width = `${Math.min(100, Math.max(0, pct))}%`;
  if (pctEl) pctEl.textContent = `${Math.round(pct)}%`;
  if (durationSec && durationSec > 0 && cardProgStartTime) {
    cardProgStartTime = Date.now() - (durationSec * 1000);
  }
}

function hideCardProgressBar(assessmentId) {
  if (cardProgTimerInterval) {
    clearInterval(cardProgTimerInterval);
    cardProgTimerInterval = null;
  }
  if (!assessmentId) return;
  const fill = document.getElementById(`card-prog-fill-${assessmentId}`);
  const pctEl = document.getElementById(`card-prog-pct-${assessmentId}`);
  if (fill) fill.style.width = "100%";
  if (pctEl) pctEl.textContent = "100%";
  setTimeout(() => {
    const slot = document.getElementById(`card-prog-${assessmentId}`);
    if (slot) slot.innerHTML = "";
    if (activeSingleAssessmentId === assessmentId) {
      activeSingleAssessmentId = null;
      cardProgStartTime = null;
    }
  }, 1000);
}

function setInlineStatusComplete(success = true) {
  stopLiveDurationTimer();
  const icon = document.getElementById("statusIcon");
  const msg = document.getElementById("statusMessage");
  const pct = document.getElementById("statusPercentage");
  const progFill = document.getElementById("statusProgressBar");
  const dismissBtn = document.getElementById("dismissStatusBtn");

  if (progFill) {
    progFill.style.width = "100%";
    progFill.classList.add(success ? "status-progress-success" : "status-progress-error");
  }

  if (success) {
    if (icon) icon.className = "fa-solid fa-circle-check text-green";
    if (msg) msg.innerHTML = `<strong>Executed Successfully</strong> - All findings analyzed`;
    if (pct) pct.textContent = "100%";
  } else {
    if (icon) icon.className = "fa-solid fa-triangle-exclamation text-red";
    if (msg) msg.innerHTML = `<strong>Evaluation Ended</strong> with warnings or errors`;
  }

  if (dismissBtn) dismissBtn.classList.remove("d-none");

  // Automatically fade out status bar after 8 seconds of completion
  state.statusDismissTimeout = setTimeout(() => {
    hideInlineStatusBar();
  }, 8000);
}

function hideInlineStatusBar() {
  const bar = document.getElementById("inlineStatusBar");
  if (bar) bar.classList.add("d-none");
  if (state.statusDismissTimeout) {
    clearTimeout(state.statusDismissTimeout);
    state.statusDismissTimeout = null;
  }
}

function setupInlineStatusBar() {
  const dismissBtn = document.getElementById("dismissStatusBtn");
  if (dismissBtn) {
    dismissBtn.addEventListener("click", hideInlineStatusBar);
  }
}

// ============================================================
// JOB EXECUTION CONTROLLER
// ============================================================
async function startJob(scope = "all") {
  if (state.isJobRunning) {
    showToast("An assessment is currently running. Please wait for it to complete.", "warning");
    return;
  }
  if (!state.connectionId) {
    showToast("Please connect to Azure first.", "warning");
    return;
  }

  let endpoint = "/api/assessments/run-all";
  let promptMsg = "Running All Assessments across subscriptions...";
  if (scope === "security") {
    endpoint = "/api/assessments/run-security";
    promptMsg = "Running Security Assessment across resources...";
  } else if (scope === "cost") {
    endpoint = "/api/assessments/run-cost";
    promptMsg = "Running Cost Assessment across resources...";
  }

  setExecutionButtonsState(true);
  showInlineStatusBar(promptMsg);

  try {
    const res = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ connection_id: state.connectionId })
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Failed to trigger assessment job.");

    state.latestJobId = data.job_id;
    state.isJobRunning = true;

    // Track the scope for report downloads (strictly scoped, no automatic merging)
    state.lastRunScope = scope;

    // Start polling
    if (state.pollInterval) clearInterval(state.pollInterval);
    state.pollInterval = setInterval(() => pollJobProgress(data.job_id), 600);
  } catch (err) {
    showToast("Job launch failed: " + err.message, "error");
    setInlineStatusComplete(false);
    setExecutionButtonsState(false);
  }
}
window.startJob = startJob;

async function startSingleJob(assessmentId) {
  if (state.isJobRunning) {
    showToast("An assessment is currently running. Please wait for it to complete.", "warning");
    return;
  }
  if (!state.connectionId) {
    showToast("Please connect to Azure first.", "warning");
    return;
  }

  const def = state.catalog.find(d => d.assessment_id === assessmentId);
  const defName = def ? def.name : assessmentId;
  const isCost = def && def.category === "cost";

  setExecutionButtonsState(true);
  showCardProgressBar(assessmentId, isCost);

  try {
    const res = await fetch(`/api/assessments/${assessmentId}/run`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ connection_id: state.connectionId })
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Failed to trigger single assessment.");

    state.latestJobId = data.job_id;
    state.isJobRunning = true;

    // Note: Individual assessment runs do not set or alter state.lastRunScope
    // so they do not inadvertently enable Suite/Overview reports.

    if (state.pollInterval) clearInterval(state.pollInterval);
    state.pollInterval = setInterval(() => pollJobProgress(data.job_id), 600);
  } catch (err) {
    showToast("Single assessment run failed: " + err.message, "error");
    hideCardProgressBar(assessmentId);
    setExecutionButtonsState(false);
  }
}
window.startSingleJob = startSingleJob;

async function pollJobProgress(jobId) {
  try {
    const res = await fetch(`/api/jobs/${jobId}`);
    if (!res.ok) return;

    const prog = await res.json();
    if (activeSingleAssessmentId) {
      updateCardProgress(activeSingleAssessmentId, prog.progress_percentage || 0, prog.duration_seconds);
    } else {
      updateInlineStatusProgress(prog);
    }

    if (prog.status === "Completed" || prog.status === "Completed with Warnings" || prog.status === "Failed") {
      clearInterval(state.pollInterval);
      state.pollInterval = null;
      state.isJobRunning = false;
      setExecutionButtonsState(false);

      const isSuccess = prog.status !== "Failed";
      if (activeSingleAssessmentId) {
        hideCardProgressBar(activeSingleAssessmentId);
      } else {
        setInlineStatusComplete(isSuccess);
      }

      await handleJobCompletion(jobId);
    }
  } catch (err) {
    console.warn("Polling error:", err);
  }
}

async function handleJobCompletion(jobId) {
  try {
    const res = await fetch(`/api/jobs/${jobId}/results`);
    if (!res.ok) throw new Error("Could not fetch job results.");

    const data = await res.json();
    // Merge results with existing ones
    state.results = Object.assign({}, state.results, data.results || {});
    
    // Smart-merge summary so running cost doesn't wipe security metrics, and vice versa
    const oldSummary = state.summary || {};
    const newSummary = data.summary || {};
    const mergedSummary = Object.assign({}, oldSummary, newSummary);

    // If new job is cost-only (security score is null/undefined), preserve previous security scores and counts
    if (newSummary.current_security_score === null || newSummary.current_security_score === undefined) {
      if (oldSummary.current_security_score !== undefined && oldSummary.current_security_score !== null) {
        mergedSummary.current_security_score = oldSummary.current_security_score;
      }
      if (oldSummary.security_score !== undefined && oldSummary.security_score !== null) {
        mergedSummary.security_score = oldSummary.security_score;
      }
      if (oldSummary.achievable_security_score !== undefined && oldSummary.achievable_security_score !== null) {
        mergedSummary.achievable_security_score = oldSummary.achievable_security_score;
      }
      if (oldSummary.security_findings_count !== undefined && oldSummary.security_findings_count !== null) {
        mergedSummary.security_findings_count = oldSummary.security_findings_count;
      }
      if (oldSummary.security_severity_counts) {
        mergedSummary.security_severity_counts = oldSummary.security_severity_counts;
      }
      if (oldSummary.findings_by_severity) {
        mergedSummary.findings_by_severity = oldSummary.findings_by_severity;
      }
    }

    // If new job is security-only (no cost savings produced), preserve previous cost metrics
    if ((newSummary.total_monthly_savings === null || newSummary.total_monthly_savings === undefined || newSummary.total_monthly_savings === 0) &&
        (oldSummary.total_monthly_savings || oldSummary.current_cost_wastage)) {
      mergedSummary.total_monthly_savings = oldSummary.total_monthly_savings;
      mergedSummary.total_annual_savings = oldSummary.total_annual_savings;
      mergedSummary.current_cost_wastage = oldSummary.current_cost_wastage;
      mergedSummary.unique_monthly_savings = oldSummary.unique_monthly_savings;
      mergedSummary.unique_annual_savings = oldSummary.unique_annual_savings;
      mergedSummary.cost_findings_count = oldSummary.cost_findings_count;
      mergedSummary.cost_by_confidence = oldSummary.cost_by_confidence;
    }

    // Calculate total cost savings from all cost assessment results currently in state.results
    let calcMonthly = 0;
    let calcAnnual = 0;
    let hasCostResults = false;
    let costFindingsCount = 0;
    for (const [aid, res] of Object.entries(state.results || {})) {
      const def = state.catalog.find(d => d.assessment_id === aid);
      if (def && def.category === "cost" && res) {
        hasCostResults = true;
        costFindingsCount += (res.findings_count || 0);
        if (res.total_monthly_savings) calcMonthly += Number(res.total_monthly_savings);
        if (res.total_annual_savings) {
          calcAnnual += Number(res.total_annual_savings);
        } else if (res.total_monthly_savings) {
          calcAnnual += Number(res.total_monthly_savings) * 12;
        }
      }
    }

    if (hasCostResults) {
      mergedSummary.total_monthly_savings = Math.max(mergedSummary.total_monthly_savings || 0, calcMonthly);
      mergedSummary.total_annual_savings = Math.max(mergedSummary.total_annual_savings || 0, calcAnnual);
      mergedSummary.current_cost_wastage = Math.max(mergedSummary.current_cost_wastage || 0, calcMonthly);
      mergedSummary.unique_monthly_savings = Math.max(mergedSummary.unique_monthly_savings || 0, calcMonthly);
      mergedSummary.unique_annual_savings = Math.max(mergedSummary.unique_annual_savings || 0, calcAnnual);
      mergedSummary.cost_findings_count = Math.max(mergedSummary.cost_findings_count || 0, costFindingsCount);
    }

    // Recalculate combined total findings count across both pillars
    const secCount = mergedSummary.security_findings_count || 0;
    const costCount = mergedSummary.cost_findings_count || 0;
    mergedSummary.total_findings = secCount + costCount;

    state.summary = mergedSummary;

    // Update currency only if non-USD or if current state.currency is default USD
    if (data.summary && data.summary.currency && data.summary.currency !== "USD") {
      state.currency = data.summary.currency;
    } else if (!state.currency || state.currency === "USD") {
      if (data.summary && data.summary.currency) {
        state.currency = data.summary.currency;
      }
    }

    // Check findings for non-USD currency
    for (const r of Object.values(state.results)) {
      if (r && r.findings) {
        for (const f of r.findings) {
          if (f.currency && f.currency !== "USD") {
            state.currency = f.currency;
            break;
          }
          if (f.evidence && f.evidence.currency && f.evidence.currency !== "USD") {
            state.currency = f.evidence.currency;
            break;
          }
        }
      }
    }

    // Refresh UI elements
    updateKPIs();

    // Update only the cards evaluated in this job in-place, without resetting the whole DOM
    const updatedIds = Object.keys(data.results || {});
    let allUpdatedInPlace = true;
    for (const aid of updatedIds) {
      const ok = updateAssessmentCardInPlace(aid);
      if (!ok) allUpdatedInPlace = false;
    }

    // Only render full grids if elements do not exist in DOM yet (e.g. initial load)
    const secGrid = document.getElementById("securityCardsGrid");
    const costGrid = document.getElementById("costCardsGrid");
    if (!allUpdatedInPlace || (secGrid && secGrid.children.length === 0) || (costGrid && costGrid.children.length === 0)) {
      if (secGrid && secGrid.children.length === 0) {
        renderSecurityCards(document.getElementById("secSearchInput")?.value || "");
      }
      if (costGrid && costGrid.children.length === 0) {
        renderCostCards(document.getElementById("costSearchInput")?.value || "");
      }
    }

    updateReportButtons();

    // Persist full state to sessionStorage
    saveSessionState();
    showToast("Assessment Executed Successfully", "success");
  } catch (err) {
    console.error("Result fetch error:", err);
  }
}

function setExecutionButtonsState(disabled) {
  const b1 = document.getElementById("runAllBtn");
  const b2 = document.getElementById("runSecurityBtn");
  const b3 = document.getElementById("runCostBtn");
  [b1, b2, b3].forEach(b => {
    if (b) {
      b.disabled = disabled;
      if (disabled) {
        b.classList.add("btn-disabled");
      } else {
        b.classList.remove("btn-disabled");
      }
    }
  });

  // Also disable/enable all module card Run buttons across tabs
  const allRunButtons = document.querySelectorAll(".ass-actions button, button[onclick*='startSingleJob'], button[onclick*='startJob']");
  allRunButtons.forEach(btn => {
    if (btn.getAttribute("onclick")?.includes("start") || btn.textContent.includes("Run")) {
      btn.disabled = disabled;
      if (disabled) {
        btn.classList.add("btn-disabled");
      } else {
        btn.classList.remove("btn-disabled");
      }
    }
  });
}

// ============================================================
// DASHBOARD 6-CARD KPI METRICS
// ============================================================
function updateKPIs() {
  const s = state.summary || {};

  const elSubs = document.getElementById("kpiSubs");
  const elCurrentScore = document.getElementById("kpiCurrentScore");
  const elAchievableScore = document.getElementById("kpiAchievableScore");
  const elCostWastage = document.getElementById("kpiCostWastage");
  const elMonthly = document.getElementById("kpiMonthlySavings");
  const elAnnual = document.getElementById("kpiAnnualSavings");

  // 1. Total Subscriptions
  if (elSubs) {
    elSubs.textContent = formatNumber(state.accessibleSubscriptionsCount || 0);
  }

  // 2. Current Security Score (Integer Round Off)
  if (elCurrentScore) {
    let curScore = s.current_security_score ?? s.security_score;
    if (curScore === undefined || curScore === null) {
      const secRes = state.results?.subscription_security_score || state.results?.secure_score;
      if (secRes && secRes.findings) {
        const ascF = secRes.findings.find(f => (f.evidence && (f.evidence.security_control === "Microsoft Defender Overall Secure Score" || f.evidence.security_control === "ascScore Overall")) || String(f.finding_id || "").includes("ascScore"));
        if (ascF && ascF.evidence && ascF.evidence.current_score !== undefined && ascF.evidence.max_score) {
          curScore = (ascF.evidence.current_score / ascF.evidence.max_score) * 100.0;
        }
      }
    }
    if (curScore !== undefined && curScore !== null) {
      elCurrentScore.textContent = `${Math.round(curScore)}%`;
    } else {
      elCurrentScore.textContent = "--%";
    }
  }

  // 3. Achievable Security Score (Genuine potential based on contributing Defender recommendations)
  if (elAchievableScore) {
    let achScore = s.achievable_security_score;
    if (achScore === undefined || achScore === null) {
      let cur = s.current_security_score ?? s.security_score ?? 0;
      let recomImpact = 0;
      const seenControls = new Set();
      for (const [aid, res] of Object.entries(state.results || {})) {
        if (res && res.findings) {
          for (const f of res.findings) {
            const ctrl = (f.evidence && f.evidence.security_control) || f.resource_name || "";
            if (ctrl.includes("ascScore") || ctrl.includes("Overall Secure Score")) continue;
            if (seenControls.has(ctrl)) continue;
            if (ctrl) seenControls.add(ctrl);

            if (f.security_score_impact) {
              const imp = Number(f.security_score_impact);
              if (imp > 0) recomImpact += imp;
            }
          }
        }
      }
      if (cur > 0) {
        achScore = Math.min(100, Math.round(cur + recomImpact));
      }
    }
    if (achScore !== undefined && achScore !== null) {
      elAchievableScore.textContent = `${Math.round(achScore)}%`;
    } else {
      elAchievableScore.textContent = "--%";
    }
  }

  // Calculate cost savings across all cost assessment results currently in state.results
  let calcMonthly = 0;
  let calcAnnual = 0;
  let hasCostResults = false;
  for (const [aid, res] of Object.entries(state.results || {})) {
    const def = state.catalog.find(d => d.assessment_id === aid);
    if (def && def.category === "cost" && res) {
      hasCostResults = true;
      if (res.total_monthly_savings) calcMonthly += Number(res.total_monthly_savings);
      if (res.total_annual_savings) {
        calcAnnual += Number(res.total_annual_savings);
      } else if (res.total_monthly_savings) {
        calcAnnual += Number(res.total_monthly_savings) * 12;
      }
    }
  }

  // 4. Current Cost Wastage
  if (elCostWastage) {
    let wastage = s.current_cost_wastage;
    if ((wastage === undefined || wastage === null || wastage === 0) && hasCostResults) {
      wastage = calcMonthly;
    }
    elCostWastage.textContent = formatCurrency(wastage || 0);
  }

  // 5. Monthly Savings
  if (elMonthly) {
    let monthly = s.total_monthly_savings;
    if ((monthly === undefined || monthly === null || monthly === 0) && hasCostResults) {
      monthly = calcMonthly;
    }
    elMonthly.textContent = formatCurrency(monthly || 0);
  }

  // 6. Annual Savings
  if (elAnnual) {
    let annual = s.total_annual_savings;
    if ((annual === undefined || annual === null || annual === 0) && hasCostResults) {
      annual = calcAnnual;
    }
    elAnnual.textContent = formatCurrency(annual || 0);
  }
}

// ============================================================
// ASSESSMENT SPECIFIC COLUMNS SPECIFICATION (ALL 14 SECURITY MODULES)
// ============================================================
const SECURITY_COLUMNS_SPEC = {
  "subscription_security_score": {
    columns: ["Subscription Name", "Security Control", "Score Percentage", "Potential Score Increase", "Unhealthy Resources Count"],
    extractor: (f) => [
      f.subscription_name,
      f.evidence?.security_control || f.resource_name?.replace("ascScore-", "").replace("ascScore", "Defender Secure Score") || "Microsoft Defender Overall Secure Score",
      f.measured_value ? f.measured_value : (f.evidence?.percentage !== undefined ? `${f.evidence.percentage}%` : "--"),
      f.security_score_impact ? `+${f.security_score_impact.toFixed(1)}%` : (f.evidence?.potential_increase ? `+${f.evidence.potential_increase}%` : "--"),
      f.evidence?.unhealthy_resources_count !== undefined ? String(f.evidence.unhealthy_resources_count) : "--"
    ]
  },
  "secure_score": {
    columns: ["Subscription Name", "Security Control", "Score Percentage", "Potential Score Increase", "Unhealthy Resources Count"],
    extractor: (f) => [
      f.subscription_name,
      f.evidence?.security_control || f.resource_name?.replace("ascScore-", "").replace("ascScore", "Defender Secure Score") || "Microsoft Defender Overall Secure Score",
      f.measured_value ? f.measured_value : (f.evidence?.percentage !== undefined ? `${f.evidence.percentage}%` : "--"),
      f.security_score_impact ? `+${f.security_score_impact.toFixed(1)}%` : (f.evidence?.potential_increase ? `+${f.evidence.potential_increase}%` : "--"),
      f.evidence?.unhealthy_resources_count !== undefined ? String(f.evidence.unhealthy_resources_count) : "--"
    ]
  },
  "new_recommendations": {
    columns: ["Subscription Name", "Resource Group", "Resource Name", "Resource Type", "Recommendation Name", "Severity", "Status", "First Detected", "Description", "Azure Remediation Recommendation", "Related Control", "Score Potential"],
    extractor: (f) => [
      f.subscription_name,
      f.resource_group || "--",
      f.resource_name,
      f.resource_type?.split("/").pop() || f.resource_type,
      f.evidence?.recommendation_name || f.resource_name,
      getSeverityBadge(f.severity),
      f.status,
      f.evidence?.first_detected_date || f.collected_at?.slice(0, 10) || "--",
      f.evidence?.description || f.current_configuration || "--",
      f.recommendation,
      f.evidence?.security_control || "--",
      f.security_score_impact ? `+${f.security_score_impact.toFixed(1)}%` : (f.evidence?.potential_score_increase || "--")
    ]
  },
  "resources_without_logs": {
    columns: ["Subscription Name", "Resource Group", "Resource Name", "Resource Type", "Region", "Environment", "Diagnostic Status", "Log Categories", "Log Analytics Workspace", "Storage Destination"],
    extractor: (f) => [
      f.subscription_name,
      f.resource_group || "--",
      f.resource_name,
      f.resource_type?.split("/").pop() || f.resource_type,
      f.region || "global",
      f.evidence?.environment || "Production",
      f.status || "Missing",
      f.evidence?.enabled_log_categories || "None",
      f.evidence?.workspace_name || "None Configured",
      f.evidence?.storage_destination || "None"
    ]
  },
  "high_priority_recommendations": {
    columns: ["Subscription Name", "Resource Group", "Resource Name", "Resource Type", "Recommendation Name", "Severity", "Risk Level", "Description", "Azure Remediation Recommendation", "Related Control", "Score Potential"],
    extractor: (f) => [
      f.subscription_name,
      f.resource_group || "--",
      f.resource_name,
      f.resource_type?.split("/").pop() || f.resource_type,
      f.evidence?.recommendation_name || f.resource_name,
      getSeverityBadge(f.severity),
      f.evidence?.risk_level || f.severity,
      f.evidence?.description || f.current_configuration || "--",
      f.recommendation,
      f.evidence?.security_control || "--",
      f.security_score_impact ? `+${f.security_score_impact.toFixed(1)}%` : (f.evidence?.potential_score_increase || "--")
    ]
  },
  "service_retirement": {
    columns: ["Subscription Name", "Resource Group", "Resource Name", "Resource Type", "Region", "Service Name", "Installed / Configured Version", "Support Status", "End-of-Support Date", "Retirement Date"],
    extractor: (f) => [
      f.subscription_name,
      f.resource_group || "--",
      f.resource_name,
      f.resource_type?.split("/").pop() || f.resource_type,
      f.region || "global",
      f.evidence?.service_name || f.resource_type?.split("/").pop(),
      f.evidence?.current_runtime || f.current_configuration || "--",
      f.status || "Retired",
      f.evidence?.end_of_support_date || "--",
      f.evidence?.retirement_date || "--"
    ]
  },
  "security_alerts": {
    columns: ["Subscription Name", "Resource Group", "Resource Name", "Resource Type", "Alert Name", "Severity", "Alert Status", "Generated Time", "Description", "Affected Entity", "Attack Tactics"],
    extractor: (f) => [
      f.subscription_name,
      f.resource_group || "--",
      f.resource_name,
      f.resource_type?.split("/").pop() || f.resource_type,
      f.evidence?.alert_name || f.resource_name,
      getSeverityBadge(f.severity),
      f.status,
      f.evidence?.generated_time || f.collected_at?.slice(0, 16) || "--",
      f.evidence?.description || f.current_configuration || "--",
      f.evidence?.affected_entity || f.resource_name,
      f.evidence?.attack_tactics || f.evidence?.alert_type || "--"
    ]
  },
  "attack_paths": {
    columns: ["Subscription Name", "Attack Path Name", "Source Resource", "Target Resource", "Affected Resource", "Resource Group", "Resource Type", "Region", "Risk Level", "Attack Techniques", "Related Recommendations"],
    extractor: (f) => [
      f.subscription_name,
      f.resource_name,
      f.evidence?.source_resource || f.evidence?.entry_point || "Internet",
      f.evidence?.target_resource || f.evidence?.target || "--",
      f.evidence?.affected_resource || f.resource_name,
      f.resource_group || "--",
      f.resource_type?.split("/").pop() || f.resource_type,
      f.region || "global",
      f.evidence?.risk_level || f.severity,
      f.evidence?.attack_techniques || "MITRE ATT&CK T1078",
      f.recommendation
    ]
  },
  "vm_os_version": {
    columns: ["Subscription Name", "Resource Group", "Virtual Machine Name", "Region", "Operating System", "OS Version", "OS Build", "Publisher", "Image Version", "Support Status", "End-of-Support Date"],
    extractor: (f) => [
      f.subscription_name,
      f.resource_group || "--",
      f.resource_name,
      f.region || "global",
      f.evidence?.os_type || f.evidence?.offer || "Windows / Linux",
      f.evidence?.os_version || f.evidence?.sku || f.current_configuration || "--",
      f.evidence?.os_build || "--",
      f.evidence?.publisher || "--",
      f.evidence?.image_version || "--",
      f.status,
      f.evidence?.end_of_support_date || "--"
    ]
  },
  "vm_patching": {
    columns: ["Subscription Name", "Resource Group", "Virtual Machine Name", "Region", "Operating System", "OS Version", "Patch Status", "Last Assessment Date", "Missing Security Updates", "Missing Critical Updates", "Reboot Required", "Overall Status"],
    extractor: (f) => [
      f.subscription_name,
      f.resource_group || "--",
      f.resource_name,
      f.region || "global",
      f.evidence?.os_type || "Windows / Linux",
      f.evidence?.os_version || "--",
      f.status,
      f.evidence?.last_assessment_date || f.collected_at?.slice(0, 10) || "--",
      f.evidence?.security_updates !== undefined ? f.evidence.security_updates : "--",
      f.evidence?.critical_updates !== undefined ? f.evidence.critical_updates : "--",
      f.evidence?.reboot_required !== undefined ? (f.evidence.reboot_required ? "Yes" : "No") : "--",
      f.status
    ]
  },
  "software_upgrades": {
    columns: ["Subscription Name", "Resource Group", "Virtual Machine Name", "Region", "Software Name", "Publisher", "Installed Version", "Latest Verified Version", "Support Status", "End-of-Support Date", "Vulnerability Severity"],
    extractor: (f) => [
      f.subscription_name,
      f.resource_group || "--",
      f.resource_name,
      f.region || "global",
      f.evidence?.software || f.evidence?.software_name || "--",
      f.evidence?.publisher || "--",
      f.evidence?.installed_version || f.current_configuration || "--",
      f.evidence?.recommended_version || f.evidence?.latest_version || "--",
      f.status,
      f.evidence?.end_of_support_date || "--",
      getSeverityBadge(f.severity)
    ]
  },
  "disk_encryption": {
    columns: ["Subscription Name", "Resource Group", "VM Attached", "Disk Name", "Disk Type", "SKU", "Size", "Region", "Encryption Type", "Encryption at Host", "Disk Encryption Set", "CMK Configuration", "Status", "Security Control", "Score Potential", "Azure Remediation Recommendation"],
    extractor: (f) => [
      f.subscription_name,
      f.resource_group || "--",
      f.evidence?.attached_vm || "--",
      f.resource_name,
      f.evidence?.disk_type || "Managed Disk",
      f.evidence?.disk_sku || "Premium_LRS",
      f.evidence?.disk_size_gb || "512 GB",
      f.region || "global",
      f.evidence?.encryption_type || f.current_configuration || "PMK Only",
      f.evidence?.encryption_at_host ? "Enabled" : "Disabled",
      f.evidence?.disk_encryption_set || "None",
      f.evidence?.cmk_configured || "Not Configured",
      f.status,
      f.evidence?.security_control || "Apply disk encryption",
      f.security_score_impact ? `+${f.security_score_impact.toFixed(1)}%` : "--",
      f.recommendation
    ]
  },
  "tls_version": {
    columns: ["Subscription Name", "Resource Group", "Resource Name", "Resource Type", "Region", "Service Name", "Minimum TLS", "Configured TLS", "Required TLS", "Status", "Security Control", "Score Potential", "Azure Remediation Recommendation"],
    extractor: (f) => [
      f.subscription_name,
      f.resource_group || "--",
      f.resource_name,
      f.resource_type?.split("/").pop() || f.resource_type,
      f.region || "global",
      f.evidence?.service_name || f.resource_type?.split("/").pop(),
      f.evidence?.minimumTlsVersion || f.current_configuration || "TLS 1.0",
      f.evidence?.configured_tls_version || f.measured_value || "TLS 1.0",
      f.evidence?.required || "TLS 1.2",
      f.status,
      f.evidence?.security_control || "Enforce secure TLS version",
      f.security_score_impact ? `+${f.security_score_impact.toFixed(1)}%` : "--",
      f.recommendation
    ]
  },
  "keyvault_rbac": {
    columns: ["Subscription Name", "Resource Group", "Key Vault Name", "Region", "Authorization Model", "RBAC Status", "Access Policies", "Role Assignments", "Permissions", "Assigned Roles", "Security Control", "Score Potential", "Azure Remediation Recommendation"],
    extractor: (f) => [
      f.subscription_name,
      f.resource_group || "--",
      f.resource_name,
      f.region || "global",
      f.evidence?.enableRbacAuthorization ? "Azure RBAC" : "Vault Access Policies",
      f.evidence?.enableRbacAuthorization ? "Enabled" : "Disabled",
      f.evidence?.policy_count !== undefined ? f.evidence.policy_count : "--",
      f.evidence?.role_assignment_count !== undefined ? f.evidence.role_assignment_count : "--",
      f.evidence?.permissions || "Keys/Secrets full access",
      f.evidence?.assigned_roles || "None",
      f.evidence?.security_control || "Migrate Key Vault to Azure RBAC",
      f.security_score_impact ? `+${f.security_score_impact.toFixed(1)}%` : "--",
      f.recommendation
    ]
  },
  "contributor_rbac": {
    columns: ["Subscription Name", "Resource Group", "Resource Name", "Principal Name", "Principal Type", "Role Name", "Assignment Scope", "Assignment Type", "Security Control", "Score Potential", "Azure Remediation Recommendation"],
    extractor: (f) => [
      f.subscription_name,
      f.resource_group || "Subscription Scope",
      f.resource_name,
      f.evidence?.principal_name || f.resource_name,
      f.evidence?.principal_type || "User (Direct)",
      f.evidence?.role_name || "Contributor",
      f.evidence?.scope || f.measured_value || "Subscription Scope",
      f.evidence?.assignment_type || "Direct Assignment",
      f.evidence?.security_control || "Review Contributor permissions",
      f.security_score_impact ? `+${f.security_score_impact.toFixed(1)}%` : "--",
      f.recommendation
    ]
  }
};

const COST_COLUMNS_SPEC = {
  "underutilized_vms": {
    columns: ["VM Name", "Subscription", "Resource Group", "Environment", "VM Size", "CPU Utilization", "Memory Utilization", "Cost", "Est. Annual Savings"],
    extractor: (f) => [
      f.resource_name,
      f.subscription_name || f.subscription_id,
      f.resource_group || "--",
      f.evidence?.environment || "Production",
      f.evidence?.vm_size || f.evidence?.size || "--",
      f.measured_value || `${f.evidence?.avg_cpu ?? 0.4}%`,
      f.evidence?.avg_memory || (f.evidence?.memory_utilization ? `${f.evidence.memory_utilization}%` : "Telemetry Unavailable"),
      formatCurrency(f.evidence?.actual_cost_mtd ?? f.current_monthly_cost ?? 0),
      `<span class="text-darkgreen font-mono"><b>${formatSavingsWithMonthly(f.estimated_annual_savings || 0, f.estimated_monthly_savings)}</b></span>`
    ]
  },
  "orphan_resources": {
    columns: ["Resource Name", "Resource Type", "Subscription", "Resource Group", "Environment", "Resource Status", "Cost", "Est. Annual Savings"],
    extractor: (f) => [
      f.resource_name,
      f.resource_type?.toLowerCase().includes("serverfarms") ? "App Service Plan" : (f.resource_type?.split("/").pop() || f.resource_type),
      f.subscription_name || f.subscription_id,
      f.resource_group || "--",
      f.evidence?.environment || "Production",
      f.status || f.evidence?.orphan_reason || "Unattached",
      formatCurrency(f.evidence?.actual_cost_mtd ?? f.current_monthly_cost ?? 0),
      `<span class="text-darkgreen font-mono"><b>${formatSavingsWithMonthly(f.estimated_annual_savings || 0, f.estimated_monthly_savings)}</b></span>`
    ]
  },
  "underutilized_data_disks": {
    columns: ["Disk Name", "VM Name", "Subscription", "Resource Group", "Environment", "Disk Tier", "Disk Size", "IOPS Utilization", "Cost", "Est. Annual Savings"],
    extractor: (f) => [
      f.resource_name,
      f.evidence?.vm_name || f.evidence?.attached_vm || "Attached",
      f.subscription_name || f.subscription_id,
      f.resource_group || "--",
      f.evidence?.environment || "Production",
      f.evidence?.disk_tier || f.evidence?.tier || "Premium SSD P30",
      `${f.evidence?.disk_size_gb || 1024} GiB`,
      f.measured_value || f.evidence?.iops_utilization || `Avg ${f.evidence?.avg_iops || 12} IOPS`,
      formatCurrency(f.evidence?.actual_cost_mtd ?? f.current_monthly_cost ?? 0),
      `<span class="text-darkgreen font-mono"><b>${formatSavingsWithMonthly(f.estimated_annual_savings || 0, f.estimated_monthly_savings)}</b></span>`
    ]
  },
  "underutilized_os_disks": {
    columns: ["OS Disk Name", "VM Name", "Subscription", "Resource Group", "Environment", "Disk Tier", "Disk Size", "Cost", "Est. Annual Savings"],
    extractor: (f) => [
      f.resource_name,
      f.evidence?.vm_name || "Primary VM",
      f.subscription_name || f.subscription_id,
      f.resource_group || "--",
      f.evidence?.environment || "Production",
      f.evidence?.disk_tier || f.evidence?.tier || "Premium SSD P15",
      `${f.evidence?.disk_size_gb || 128} GiB`,
      formatCurrency(f.evidence?.actual_cost_mtd ?? f.current_monthly_cost ?? 0),
      `<span class="text-darkgreen font-mono"><b>${formatSavingsWithMonthly(f.estimated_annual_savings || 0, f.estimated_monthly_savings)}</b></span>`
    ]
  },
  "cost_comparison": {
    columns: ["Resource / Service", "Resource Type", "Subscription", "Resource Group", "Environment", "Previous Period Cost", "Current Period Cost", "Cost Difference", "Cost Change (%)"],
    extractor: (f) => {
      const prev = Number(f.evidence?.previous_period_cost ?? f.evidence?.prev_cost ?? 0);
      const curr = Number(f.evidence?.current_period_cost ?? f.current_monthly_cost ?? 0);
      const diff = Number(f.evidence?.cost_difference ?? (curr - prev));
      const pct = f.evidence?.cost_change_pct !== undefined ? Number(f.evidence.cost_change_pct) : (prev > 0 ? ((diff / prev) * 100) : (curr > 0 ? 100 : 0));
      const diffSign = diff > 0 ? "+" : "";
      const pctSign = pct > 0 ? "+" : "";
      const pctColor = diff > 0 ? "text-red" : (diff < 0 ? "text-darkgreen" : "text-dark");
      const resType = f.resource_type ? (f.resource_type.includes('/') ? f.resource_type.split('/').pop() : f.resource_type) : "Service";
      return [
        f.resource_name,
        resType,
        f.subscription_name || f.subscription_id,
        f.resource_group || "--",
        f.evidence?.environment || "Production",
        formatCurrency(prev),
        formatCurrency(curr),
        `${diffSign}${formatCurrency(diff)}`,
        `<span class="${pctColor} font-mono"><b>${pctSign}${pct.toFixed(1)}%</b></span>`
      ];
    }
  },
  "top_20_opportunities": {
    columns: ["Resource Name", "Assessment Type", "Subscription", "Resource Group", "Environment", "Current Configuration", "Cost", "Est. Annual Savings"],
    extractor: (f) => [
      f.resource_name,
      f.evidence?.assessment_type || "Compute Optimization",
      f.subscription_name || f.subscription_id,
      f.resource_group || "--",
      f.evidence?.environment || "Production",
      f.current_configuration || f.evidence?.configuration || "--",
      formatCurrency(f.evidence?.actual_cost_mtd ?? f.current_monthly_cost ?? 0),
      `<span class="text-darkgreen font-mono"><b>${formatSavingsWithMonthly(f.estimated_annual_savings || 0, f.estimated_monthly_savings)}</b></span>`
    ]
  },
  "vm_license_ahb": {
    columns: ["VM Name", "Subscription", "Resource Group", "Environment", "VM Size", "License Status", "Cost", "Est. Annual Savings"],
    extractor: (f) => [
      f.resource_name,
      f.subscription_name || f.subscription_id,
      f.resource_group || "--",
      f.evidence?.environment || "Production",
      f.evidence?.vm_size || "Standard_D4s_v5",
      f.evidence?.license_status || f.status || "Not Enabled (PAYG)",
      formatCurrency(f.evidence?.actual_cost_mtd ?? f.current_monthly_cost ?? 0),
      `<span class="text-darkgreen font-mono"><b>${formatSavingsWithMonthly(f.estimated_annual_savings || 0, f.estimated_monthly_savings)}</b></span>`
    ]
  },
  "auto_shutdown": {
    columns: ["VM Name", "Subscription", "Resource Group", "Environment", "VM Size", "Deallocated Status", "Auto Shutdown Enabled", "Scheduled Shutdown Time", "Cost", "Est. Annual Savings"],
    extractor: (f) => [
      f.resource_name,
      f.subscription_name || f.subscription_id,
      f.resource_group || "--",
      f.evidence?.environment || "NonProd",
      f.evidence?.vm_size || "Standard_D2s_v5",
      f.evidence?.power_state || f.evidence?.deallocated_status || "Running",
      (f.evidence?.auto_shutdown_enabled || f.evidence?.auto_shutdown_status === "Enabled") ? "Yes" : "No",
      f.evidence?.scheduled_shutdown_time || (f.evidence?.shutdown_time ? `${f.evidence.shutdown_time} (${f.evidence?.timezone || 'UTC'})` : "Unavailable"),
      formatCurrency(f.evidence?.actual_cost_mtd ?? f.current_monthly_cost ?? 0),
      `<span class="text-darkgreen font-mono"><b>${formatSavingsWithMonthly(f.estimated_annual_savings || 0, f.estimated_monthly_savings)}</b></span>`
    ]
  },
  "disk_space": {
    columns: ["VM Name", "Disk Name", "Subscription", "Resource Group", "Environment", "Total Capacity", "Used Space", "Free Space", "Utilization (%)", "Cost"],
    extractor: (f) => [
      f.evidence?.vm_name || "Host VM",
      f.resource_name,
      f.subscription_name || f.subscription_id,
      f.resource_group || "--",
      f.evidence?.environment || "Production",
      `${f.evidence?.total_capacity_gb || 512} GB`,
      `${f.evidence?.used_space_gb || 476} GB`,
      `${f.evidence?.free_space_gb || 36} GB`,
      `<span class="text-red font-mono"><b>${f.evidence?.utilization_pct || 93}%</b></span>`,
      formatCurrency(f.evidence?.actual_cost_mtd ?? f.current_monthly_cost ?? 0)
    ]
  },
  "database_usage": {
    columns: ["Database Name", "Subscription", "Resource Group", "Environment", "Database Tier", "CPU / DTU Utilization", "Storage Utilization", "Cost", "Est. Annual Savings"],
    extractor: (f) => [
      f.resource_name,
      f.subscription_name || f.subscription_id,
      f.resource_group || "--",
      f.evidence?.environment || "Production",
      f.evidence?.database_tier || "Standard S3",
      f.measured_value || `Avg ${f.evidence?.avg_dtu_cpu_pct || 1.8}%`,
      `${f.evidence?.storage_used_gb || 14} / ${f.evidence?.storage_allocated_gb || 250} GB`,
      formatCurrency(f.evidence?.actual_cost_mtd ?? f.current_monthly_cost ?? 0),
      `<span class="text-darkgreen font-mono"><b>${formatSavingsWithMonthly(f.estimated_annual_savings || 0, f.estimated_monthly_savings)}</b></span>`
    ]
  },
  "new_unused_resources": {
    columns: ["Resource Name", "Resource Type", "Subscription", "Resource Group", "Environment", "Creation Date", "Last Activity", "Days Inactive", "Unwanted Asset Status", "Cost", "Est. Annual Savings"],
    extractor: (f) => [
      f.resource_name,
      f.resource_type?.split("/").pop() || f.resource_type,
      f.subscription_name || f.subscription_id,
      f.resource_group || "--",
      f.evidence?.environment || "Test",
      f.evidence?.creation_date || (f.collected_at ? f.collected_at.slice(0, 10) : "--"),
      f.evidence?.last_activity || "None recorded",
      f.evidence?.days_inactive !== undefined ? `${f.evidence.days_inactive} Days` : (f.days_inactive !== undefined ? `${f.days_inactive} Days` : "--"),
      `<span class="badge badge-warning">${f.evidence?.unwanted_status || f.evidence?.unwanted_asset_status || f.unwanted_asset_status || "Unwanted (Cost Savable)"}</span>`,
      formatCurrency(f.evidence?.actual_cost_mtd ?? f.current_monthly_cost ?? 0),
      `<span class="text-darkgreen font-mono"><b>${formatSavingsWithMonthly(f.estimated_annual_savings || 0, f.estimated_monthly_savings)}</b></span>`
    ]
  },
  "storage_lifecycle": {
    columns: ["Storage Account", "Subscription", "Resource Group", "Environment", "Storage Tier", "Access Tier", "Redundancy", "Cost", "Est. Annual Savings"],
    extractor: (f) => [
      f.resource_name,
      f.subscription_name || f.subscription_id,
      f.resource_group || "--",
      f.evidence?.environment || "Production",
      f.evidence?.storage_tier || "Standard",
      f.evidence?.access_tier || "Hot",
      f.evidence?.redundancy || "GRS",
      formatCurrency(f.evidence?.actual_cost_mtd ?? f.current_monthly_cost ?? 0),
      `<span class="text-darkgreen font-mono"><b>${formatSavingsWithMonthly(f.estimated_annual_savings || 0, f.estimated_monthly_savings)}</b></span>`
    ]
  },
  "database_allocated_usage": {
    columns: ["Database Name", "Subscription", "Resource Group", "Environment", "Allocated Storage", "Used Storage", "Storage Utilization (%)", "Cost", "Est. Annual Savings"],
    extractor: (f) => [
      f.resource_name,
      f.subscription_name || f.subscription_id,
      f.resource_group || "--",
      f.evidence?.environment || "Production",
      f.evidence?.allocated_storage_gb !== undefined ? `${f.evidence.allocated_storage_gb} GB` : "--",
      f.evidence?.used_storage_gb !== undefined ? `${f.evidence.used_storage_gb} GB` : "--",
      f.evidence?.utilization_pct !== undefined ? `${f.evidence.utilization_pct}%` : "--",
      formatCurrency(f.evidence?.actual_cost_mtd ?? f.current_monthly_cost ?? 0),
      `<span class="text-darkgreen font-mono"><b>${formatSavingsWithMonthly(f.estimated_annual_savings || 0, f.estimated_monthly_savings)}</b></span>`
    ]
  },
  "database_sku": {
    columns: ["Database Name", "Subscription", "Resource Group", "Environment", "Current SKU", "CPU Utilization", "Storage Utilization", "Cost", "Est. Annual Savings"],
    extractor: (f) => [
      f.resource_name,
      f.subscription_name || f.subscription_id,
      f.resource_group || "--",
      f.evidence?.environment || "--",
      f.evidence?.current_sku || "--",
      f.evidence?.avg_cpu_pct !== undefined ? `Avg ${f.evidence.avg_cpu_pct}%` : "--",
      f.evidence?.storage_utilization_pct !== undefined ? `${f.evidence.storage_utilization_pct}%` : "--",
      formatCurrency(f.evidence?.actual_cost_mtd ?? f.current_monthly_cost ?? 0),
      `<span class="text-darkgreen font-mono"><b>${formatSavingsWithMonthly(f.estimated_annual_savings || 0, f.estimated_monthly_savings)}</b></span>`
    ]
  },
  "backup_status": {
    columns: ["Resource Name", "Subscription", "Resource Group", "Environment", "Backup Status", "Backup Policy", "Retention Period", "Backup Storage Used", "Cost", "Est. Annual Savings"],
    extractor: (f) => [
      f.resource_name,
      f.subscription_name || f.subscription_id,
      f.resource_group || "--",
      f.evidence?.environment || "--",
      f.evidence?.backup_status || f.status || "--",
      f.evidence?.backup_policy || "--",
      f.evidence?.retention_days !== undefined ? `${f.evidence.retention_days} days` : "--",
      f.evidence?.backup_storage_tb !== undefined ? `${f.evidence.backup_storage_tb} TB` : "--",
      formatCurrency(f.evidence?.actual_cost_mtd ?? f.current_monthly_cost ?? 0),
      `<span class="text-darkgreen font-mono"><b>${formatSavingsWithMonthly(f.estimated_annual_savings || 0, f.estimated_monthly_savings)}</b></span>`
    ]
  },
  "old_snapshots": {
    columns: ["Snapshot Name", "Source Disk", "Subscription", "Resource Group", "Environment", "Snapshot Age", "Snapshot Size", "Cost", "Est. Annual Savings"],
    extractor: (f) => [
      f.resource_name,
      f.evidence?.source_disk || "--",
      f.subscription_name || f.subscription_id,
      f.resource_group || "--",
      f.evidence?.environment || "--",
      f.evidence?.age_days !== undefined ? `${f.evidence.age_days} days` : "--",
      f.evidence?.disk_size_gb !== undefined ? `${f.evidence.disk_size_gb} GiB` : "--",
      formatCurrency(f.evidence?.actual_cost_mtd ?? f.current_monthly_cost ?? 0),
      `<span class="text-darkgreen font-mono"><b>${formatSavingsWithMonthly(f.estimated_annual_savings || 0, f.estimated_monthly_savings)}</b></span>`
    ]
  },
  "function_apps": {
    columns: ["Function App Name", "Subscription", "Resource Group", "Environment", "Hosting Plan", "Execution Count", "Average Execution Duration", "Cost", "Est. Annual Savings"],
    extractor: (f) => [
      f.resource_name,
      f.subscription_name || f.subscription_id,
      f.resource_group || "--",
      f.evidence?.environment || "--",
      f.evidence?.hosting_plan || "--",
      f.evidence?.execution_count !== undefined ? `${f.evidence.execution_count} runs/mo` : "--",
      f.evidence?.avg_duration_ms !== undefined ? `${f.evidence.avg_duration_ms} ms` : "--",
      formatCurrency(f.evidence?.actual_cost_mtd ?? f.current_monthly_cost ?? 0),
      `<span class="text-darkgreen font-mono"><b>${formatSavingsWithMonthly(f.estimated_annual_savings || 0, f.estimated_monthly_savings)}</b></span>`
    ]
  },
  "auto_start_vm": {
    columns: ["VM Name", "Subscription", "Resource Group", "Environment", "VM Size", "Auto Start Status", "Configured Start Time", "Cost", "Est. Annual Cost Impact"],
    extractor: (f) => {
      const annualImpact = f.evidence?.annual_cost_impact ?? f.estimated_annual_savings ?? 0;
      return [
        f.resource_name,
        f.subscription_name || f.subscription_id,
        f.resource_group || "--",
        f.evidence?.environment || "--",
        f.evidence?.vm_size || "--",
        f.evidence?.auto_start_status || f.status || "--",
        f.evidence?.configured_start_time || "--",
        formatCurrency(f.evidence?.actual_cost_mtd ?? f.current_monthly_cost ?? 0),
        `<span class="text-amber font-mono"><b>${formatSavingsWithMonthly(annualImpact, annualImpact / 12)}</b></span>`
      ];
    }
  },
  "non_lrs_storage_redundancy": {
    columns: ["Storage Account", "Subscription", "Resource Group", "Environment", "Current Redundancy", "Required Redundancy", "Cost", "Est. Annual Savings"],
    extractor: (f) => [
      f.resource_name,
      f.subscription_name || f.subscription_id,
      f.resource_group || "--",
      f.evidence?.environment || "--",
      f.evidence?.current_redundancy || "--",
      f.evidence?.recommended_redundancy || "LRS",
      formatCurrency(f.evidence?.actual_cost_mtd ?? f.current_monthly_cost ?? 0),
      `<span class="text-darkgreen font-mono"><b>${formatSavingsWithMonthly(f.estimated_annual_savings || 0, f.estimated_monthly_savings)}</b></span>`
    ]
  }
};

// ============================================================
// FINDINGS INSPECTOR MODAL
// ============================================================
function openFindingsModal(assessmentId) {
  state.activeAssessmentId = assessmentId;
  const def = state.catalog.find(d => d.assessment_id === assessmentId);
  const res = state.results[assessmentId];

  const modal = document.getElementById("findingsModal");
  const modalCode = document.getElementById("modalAssCode");
  const modalTitle = document.getElementById("modalAssTitle");
  const modalDesc = document.getElementById("modalAssDesc");
  const modalSource = document.getElementById("modalAssDataSource");
  const thead = document.getElementById("findingsTableHead");
  const tbody = document.getElementById("findingsTableBody");

  if (!modal || !def) return;

  const spec = SECURITY_COLUMNS_SPEC[assessmentId] || COST_COLUMNS_SPEC[assessmentId];

  if (modalCode) {
    modalCode.textContent = def.code;
    modalCode.className = `modal-code ${def.category === 'security' ? 'code-purple' : 'code-red'}`;
  }
  if (modalTitle) {
    if (def.category === "cost") {
      const annualVal = (res && (res.total_annual_savings || (res.total_monthly_savings || 0) * 12)) || 0;
      modalTitle.textContent = def.name + (annualVal > 0 ? ` — Est. Annual Savings: ${formatCurrency(annualVal)}` : "");
    } else {
      modalTitle.textContent = def.name;
    }
  }
  if (modalDesc) modalDesc.textContent = def.description;
  if (modalSource) modalSource.textContent = (def.required_data_sources || []).join(", ") || "Azure Resource Graph & Management APIs";

  let findings = (res && res.findings) ? [...res.findings] : [];
  if (assessmentId === "top_20_opportunities") {
    findings.sort((a, b) => {
      const costA = Number(a.current_monthly_cost ?? a.evidence?.actual_cost_mtd ?? 0);
      const costB = Number(b.current_monthly_cost ?? b.evidence?.actual_cost_mtd ?? 0);
      return costB - costA;
    });
  }

  if (spec) {
    // Assessment-Specific Columns
    if (thead) {
      thead.innerHTML = `<tr>${spec.columns.map(c => `<th>${escapeHtml(c)}</th>`).join("")}</tr>`;
    }

    if (findings.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="${spec.columns.length}" class="text-center" style="padding: 36px; color: var(--text-muted);">
            <b>${def.category === 'security' ? 'No security gaps identified.' : 'No financial wastage identified.'}</b><br>
            <span style="font-size: 0.8rem;">All evaluated resources satisfy architectural benchmarks for this module.</span>
          </td>
        </tr>
      `;
    } else {
      tbody.innerHTML = findings.map(f => {
        const rowVals = spec.extractor(f);
        return `<tr>${rowVals.map(val => `<td>${typeof val === 'string' && val.startsWith('<') ? val : escapeHtml(val)}</td>`).join("")}</tr>`;
      }).join("");
    }
  } else {
    // Default Fallback
    const fallbackHeaders = ["Resource & Type", "Subscription", "Resource Group", "Cost", "Est. Annual Savings", "Recommendation"];
    if (thead) {
      thead.innerHTML = `<tr>${fallbackHeaders.map(c => `<th>${escapeHtml(c)}</th>`).join("")}</tr>`;
    }

    if (findings.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="6" class="text-center" style="padding: 36px; color: var(--text-muted);">
            <b>No findings recorded.</b>
          </td>
        </tr>
      `;
    } else {
      tbody.innerHTML = findings.map(f => {
        const mCost = formatCurrency(f.current_monthly_cost || 0);
        const aSav = formatSavingsWithMonthly(f.estimated_annual_savings || ((f.estimated_monthly_savings || 0) * 12), f.estimated_monthly_savings);

        return `
          <tr>
            <td>
              <div style="font-weight: 600;">${escapeHtml(f.resource_name)}</div>
              <div style="font-size: 0.75rem; color: var(--text-muted); font-family: var(--font-mono);">${escapeHtml(f.resource_type || "Resource")}</div>
            </td>
            <td>${escapeHtml(f.subscription_name || f.subscription_id)}</td>
            <td>${escapeHtml(f.resource_group || "--")}</td>
            <td>${mCost}</td>
            <td><span class="text-darkgreen font-mono"><b>${aSav}</b></span></td>
            <td style="font-size: 0.8rem; max-width: 320px;">${escapeHtml(f.recommendation)}</td>
          </tr>
        `;
      }).join("");
    }
  }

  modal.classList.remove("d-none");
}
window.openFindingsModal = openFindingsModal;

function closeFindingsModal() {
  const modal = document.getElementById("findingsModal");
  if (modal) modal.classList.add("d-none");
}

function setupFindingsModal() {
  const closeBtn = document.getElementById("closeFindingsModalBtn");
  if (closeBtn) closeBtn.addEventListener("click", closeFindingsModal);

  const modal = document.getElementById("findingsModal");
  if (modal) {
    modal.addEventListener("click", (e) => {
      if (e.target === modal) closeFindingsModal();
    });
  }
}

// ============================================================
// ASSESSMENT REPORTS: CONDITIONAL ENABLING & DOWNLOAD
// ============================================================
function updateReportButtons() {
  const scope = state.lastRunScope;
  const secEnabled = (scope === "security" || scope === "all");
  const costEnabled = (scope === "cost" || scope === "all");
  const combEnabled = (scope === "all");

  const btnSecPdf = document.getElementById("btnDownloadSecPdf");
  const btnSecXlsx = document.getElementById("btnDownloadSecXlsx");
  const btnCostPdf = document.getElementById("btnDownloadCostPdf");
  const btnCostXlsx = document.getElementById("btnDownloadCostXlsx");
  const btnCombPdf = document.getElementById("btnDownloadCombinedPdf");
  const btnCombXlsx = document.getElementById("btnDownloadCombinedXlsx");

  setButtonState(btnSecPdf, secEnabled, "Security Assessment Report (PDF)");
  setButtonState(btnSecXlsx, secEnabled, "Security Assessment Report (Excel)");
  setButtonState(btnCostPdf, costEnabled, "Cost Assessment Report (PDF)");
  setButtonState(btnCostXlsx, costEnabled, "Cost Assessment Report (Excel)");
  setButtonState(btnCombPdf, combEnabled, "Security & Cost Assessment Report (PDF)");
  setButtonState(btnCombXlsx, combEnabled, "Security & Cost Assessment Report (Excel)");
}

function setButtonState(btn, enabled, activeTitle) {
  if (!btn) return;
  if (enabled) {
    btn.classList.remove("btn-disabled");
    btn.setAttribute("title", `Download ${activeTitle}`);
  } else {
    btn.classList.add("btn-disabled");
    btn.setAttribute("title", "First run the assessment");
  }
}

function setupReportDownloads() {
  const reportButtons = [
    { id: "btnDownloadSecPdf", type: "security", format: "pdf" },
    { id: "btnDownloadSecXlsx", type: "security", format: "excel" },
    { id: "btnDownloadCostPdf", type: "cost", format: "pdf" },
    { id: "btnDownloadCostXlsx", type: "cost", format: "excel" },
    { id: "btnDownloadCombinedPdf", type: "combined", format: "pdf" },
    { id: "btnDownloadCombinedXlsx", type: "combined", format: "excel" }
  ];

  reportButtons.forEach(({ id, type, format }) => {
    const btn = document.getElementById(id);
    if (!btn) return;

    btn.addEventListener("click", () => {
      if (btn.classList.contains("btn-disabled")) {
        showToast("First run the assessment", "warning");
        return;
      }
      triggerReportDownload(type, format, btn);
    });
  });
}

async function triggerReportDownload(type, format, buttonElement) {
  if (!state.latestJobId && !state.connectionId) {
    showToast("First run the assessment", "warning");
    return;
  }

  const originalHtml = buttonElement.innerHTML;
  buttonElement.disabled = true;
  buttonElement.innerHTML = `<i class="fa-solid fa-circle-notch fa-spin"></i> Preparing...`;

  try {
    const reportTargetId = state.latestJobId || state.connectionId;
    const endpoint = `/api/reports/${type}/${format}/${reportTargetId}`;
    const res = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        connection_id: state.connectionId,
        results: state.results,
        summary: state.summary,
        subscriptions: state.subscriptions || []
      })
    });
    const data = await res.json();

    if (!res.ok) throw new Error(data.detail || "Report compilation failed.");

    // Trigger download via anchor
    const downloadLink = document.createElement("a");
    downloadLink.href = data.download_url;
    downloadLink.download = data.filename;
    document.body.appendChild(downloadLink);
    downloadLink.click();
    document.body.removeChild(downloadLink);

    showToast(`Downloaded: ${data.filename}`, "success");
  } catch (err) {
    showToast(`Report download error: ${err.message}`, "error");
  } finally {
    buttonElement.disabled = false;
    buttonElement.innerHTML = originalHtml;
  }
}

async function triggerSingleCardReportDownload(assessmentId, format, buttonElement) {
  if (buttonElement && buttonElement.classList.contains("btn-disabled")) {
    showToast("First run this assessment", "warning");
    return;
  }

  const originalHtml = buttonElement ? buttonElement.innerHTML : "";
  if (buttonElement) {
    buttonElement.disabled = true;
    buttonElement.innerHTML = `<i class="fa-solid fa-circle-notch fa-spin"></i>`;
  }

  try {
    const endpoint = `/api/reports/single/${format}/${assessmentId}`;
    const res = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        connection_id: state.connectionId,
        results: state.results
      })
    });

    let data;
    try {
      data = await res.json();
    } catch (parseErr) {
      throw new Error(`Server returned status ${res.status}: ${res.statusText || 'Unable to parse server response'}`);
    }

    if (!res.ok) throw new Error(data.detail || "Single assessment report compilation failed.");

    const downloadLink = document.createElement("a");
    downloadLink.href = data.download_url;
    downloadLink.download = data.filename;
    document.body.appendChild(downloadLink);
    downloadLink.click();
    document.body.removeChild(downloadLink);

    showToast(`Downloaded: ${data.filename}`, "success");
  } catch (err) {
    showToast(`Download error: ${err.message}`, "error");
  } finally {
    if (buttonElement) {
      buttonElement.disabled = false;
      buttonElement.innerHTML = originalHtml;
    }
  }
}
window.triggerSingleCardReportDownload = triggerSingleCardReportDownload;

// ============================================================
// AI ADVISOR (ZERO-FOOTPRINT INTELLIGENT CLOUD CHATBOT)
// ============================================================
const aiChatState = {
  history: [],
  isLoading: false
};

function renderMarkdownToHtml(md) {
  if (!md) return "";

  // 1. Extract and preserve code blocks
  const codeBlocks = [];
  let text = md.replace(/```([a-zA-Z0-9_-]*)\n([\s\S]*?)```/g, (match, lang, code) => {
    const idx = codeBlocks.length;
    const escapedCode = code.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    codeBlocks.push(`<pre><code class="language-${lang || 'text'}">${escapedCode}</code></pre>`);
    return `__CODE_BLOCK_${idx}__`;
  });

  // 2. Extract and preserve inline code
  const inlineCodes = [];
  text = text.replace(/`([^`\n]+)`/g, (match, code) => {
    const idx = inlineCodes.length;
    const escaped = code.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    inlineCodes.push(`<code>${escaped}</code>`);
    return `__INLINE_CODE_${idx}__`;
  });

  // 3. Process tables
  const lines = text.split("\n");
  const processedLines = [];
  let inTable = false;
  let tableRows = [];

  function flushTable() {
    if (tableRows.length === 0) return;
    let html = "<table>";
    let isHeader = true;
    for (let r = 0; r < tableRows.length; r++) {
      const row = tableRows[r];
      // Check if separator row (| :--- | :--- |)
      if (/^\s*\|?\s*(:?-+:?)\s*(\|?\s*(:?-+:?)\s*)*\|?\s*$/.test(row)) {
        isHeader = false;
        continue;
      }
      const cells = row.split("|").slice(1, -1).map(c => c.trim());
      if (cells.length === 0) continue;

      if (isHeader) {
        html += "<thead><tr>" + cells.map(c => `<th>${c}</th>`).join("") + "</tr></thead><tbody>";
        isHeader = false;
      } else {
        html += "<tr>" + cells.map(c => `<td>${c}</td>`).join("") + "</tr>";
      }
    }
    if (!html.includes("<tbody>")) html += "<tbody>";
    html += "</tbody></table>";
    processedLines.push(html);
    tableRows = [];
    inTable = false;
  }

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const isTableRow = /^\s*\|.*\|\s*$/.test(line);
    if (isTableRow) {
      inTable = true;
      tableRows.push(line);
    } else {
      if (inTable) {
        flushTable();
      }
      processedLines.push(line);
    }
  }
  if (inTable) flushTable();
  text = processedLines.join("\n");

  // 4. Headers
  text = text.replace(/^#### (.*$)/gim, '<h4>$1</h4>');
  text = text.replace(/^### (.*$)/gim, '<h3>$1</h3>');
  text = text.replace(/^## (.*$)/gim, '<h2>$1</h2>');
  text = text.replace(/^# (.*$)/gim, '<h1>$1</h1>');

  // 5. Blockquotes
  text = text.replace(/^> (.*$)/gim, '<blockquote>$1</blockquote>');

  // 6. Bold and Italic
  text = text.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
  text = text.replace(/\*(.*?)\*/g, '<em>$1</em>');

  // 6b. Links & Report Download Cards
  text = text.replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" target="_blank" rel="noopener noreferrer" class="ai-msg-link">$1</a>');
  text = text.replace(/<a href="(\/api\/reports\/download\/[^"]+)"[^>]*>([^<]+)<\/a>/g, '<div class="ai-report-card"><div class="ai-report-card-info"><i class="fa-solid fa-file-arrow-down ai-report-card-icon"></i><div><div class="ai-report-card-title">$2</div><div class="ai-report-card-sub">FinSecOps Deliverable Ready</div></div></div><a href="$1" class="btn-ai-download-report" download><i class="fa-solid fa-download"></i> Download</a></div>');

  // 7. Lists
  text = text.replace(/^\s*[-*]\s+(.*$)/gim, '<li>$1</li>');
  text = text.replace(/(<li>.*<\/li>(?:\s*<li>.*<\/li>)*)/gim, '<ul>$1</ul>');

  // 8. Paragraphs
  const paragraphs = text.split(/\n{2,}/);
  text = paragraphs.map(p => {
    p = p.trim();
    if (!p) return "";
    if (p.startsWith("<h") || p.startsWith("<table") || p.startsWith("<ul") || p.startsWith("<ol") || p.startsWith("<blockquote") || p.startsWith("<pre")) {
      return p;
    }
    return `<p>${p.replace(/\n/g, "<br>")}</p>`;
  }).join("\n");

  // 9. Restore inline code and code blocks
  text = text.replace(/__INLINE_CODE_(\d+)__/g, (match, idx) => inlineCodes[idx] || "");
  text = text.replace(/__CODE_BLOCK_(\d+)__/g, (match, idx) => codeBlocks[idx] || "");

  return text;
}

function appendUserMessage(text) {
  const container = document.getElementById("aiChatMessages");
  if (!container) return;

  const welcomeBox = document.getElementById("aiWelcomeBox");
  if (welcomeBox) welcomeBox.remove();

  const now = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  const div = document.createElement("div");
  div.className = "ai-message ai-message-user";
  div.innerHTML = `
    <div class="ai-msg-avatar-wrapper">
      <div class="ai-user-avatar"><i class="fa-solid fa-user"></i></div>
    </div>
    <div class="ai-msg-content">
      <div class="ai-msg-header">
        <span class="ai-msg-sender">You</span>
        <span class="ai-msg-time">${now}</span>
      </div>
      <div class="ai-msg-text">
        <p>${escapeHtml(text).replace(/\n/g, "<br>")}</p>
      </div>
    </div>
  `;
  container.appendChild(div);
  scrollAiChatToBottom();
}

function showAiLoadingIndicator() {
  const container = document.getElementById("aiChatMessages");
  if (!container) return;

  const loadingDiv = document.createElement("div");
  loadingDiv.id = "aiLoadingIndicator";
  loadingDiv.className = "ai-message ai-message-assistant";
  loadingDiv.innerHTML = `
    <div class="ai-msg-avatar-wrapper">
      <img src="/static/images/aichatboticon.png" alt="AI Advisor" class="ai-msg-avatar">
    </div>
    <div class="ai-msg-content">
      <div class="ai-loading-bubble">
        <span class="ai-loading-spinner"></span>
        <span class="ai-loading-text">Analysing...</span>
      </div>
    </div>
  `;
  container.appendChild(loadingDiv);
  scrollAiChatToBottom();
}

function removeAiLoadingIndicator() {
  const loading = document.getElementById("aiLoadingIndicator");
  if (loading) loading.remove();
}

function appendAssistantMessage(htmlContent, meta = {}) {
  const container = document.getElementById("aiChatMessages");
  if (!container) return;

  const now = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  const div = document.createElement("div");
  div.className = "ai-message ai-message-assistant";

  // Build tool execution steps transparency card if tools were executed
  let stepsHtml = "";
  if (meta.steps && Array.isArray(meta.steps) && meta.steps.length > 0) {
    const stepItems = meta.steps.map(s => {
      const isSuccess = s.status === "Success";
      const badgeCls = isSuccess ? "success" : "failed";
      const icon = isSuccess ? "fa-circle-check" : "fa-circle-xmark";
      const dur = s.duration_ms ? `${s.duration_ms}ms` : "";
      return `
        <div class="ai-step-item">
          <div class="ai-step-info">
            <i class="fa-solid ${icon} ${isSuccess ? 'text-green' : 'text-danger'}"></i>
            <span><strong>${escapeHtml(s.tool_name)}</strong> &bull; ${escapeHtml(s.summary || s.source || '')}</span>
          </div>
          <div>
            <span class="ai-step-badge ${badgeCls}">${escapeHtml(s.status)}</span>
            ${dur ? `<span class="ai-step-duration">${dur}</span>` : ''}
          </div>
        </div>
      `;
    }).join("");

    stepsHtml = `
      <details class="ai-execution-details">
        <summary class="ai-execution-summary">
          <i class="fa-solid fa-bolt text-purple"></i>
          <span>Executed ${meta.steps.length} Live Agent Tool${meta.steps.length > 1 ? 's' : ''}</span>
          <i class="fa-solid fa-chevron-down" style="margin-left: auto; font-size: 0.75rem;"></i>
        </summary>
        <div class="ai-step-list">
          ${stepItems}
        </div>
      </details>
    `;
  }

  // Provenance badges
  let sourceBadgesHtml = "";
  if (meta.is_live_data) {
    sourceBadgesHtml += `<span class="ai-source-badge live"><i class="fa-solid fa-satellite-dish"></i> Live Azure Data</span>`;
  }
  if (meta.sources && Array.isArray(meta.sources)) {
    meta.sources.forEach(src => {
      if (src && !src.includes("Live Azure")) {
        sourceBadgesHtml += `<span class="ai-source-badge"><i class="fa-solid fa-database"></i> ${escapeHtml(src)}</span>`;
      }
    });
  }

  // Suggested follow-ups
  let followupsHtml = "";
  if (meta.suggested_followups && Array.isArray(meta.suggested_followups) && meta.suggested_followups.length > 0) {
    const chips = meta.suggested_followups.map(q => {
      const escapedQ = escapeHtml(q).replace(/'/g, "\\'");
      return `<button type="button" class="ai-followup-chip" onclick="sendAiMessage('${escapedQ}')"><i class="fa-regular fa-comment-dots"></i> ${escapeHtml(q)}</button>`;
    }).join("");
    followupsHtml = `<div class="ai-followups-container">${chips}</div>`;
  }

  const rawTextAttr = escapeHtml(meta.rawReply || "");

  div.innerHTML = `
    <div class="ai-msg-avatar-wrapper">
      <img src="/static/images/aichatboticon.png" alt="AI Advisor" class="ai-msg-avatar">
    </div>
    <div class="ai-msg-content">
      <div class="ai-msg-header">
        <span class="ai-msg-sender">AI Advisor</span>
        <span class="ai-msg-time">${now}</span>
      </div>
      <div class="ai-msg-text" data-raw="${rawTextAttr}">
        ${stepsHtml}
        ${htmlContent}
        <div class="ai-msg-footer">
          <div class="ai-source-tags">
            ${sourceBadgesHtml}
          </div>
          <button type="button" class="ai-copy-btn" onclick="copyAiResponse(this)" title="Copy response to clipboard">
            <i class="fa-regular fa-copy"></i> Copy
          </button>
        </div>
      </div>
      ${followupsHtml}
    </div>
  `;
  container.appendChild(div);
  scrollAiChatToBottom();
}

function copyAiResponse(btn) {
  if (!btn) return;
  const msgTextEl = btn.closest(".ai-msg-text");
  if (!msgTextEl) return;

  const rawText = msgTextEl.getAttribute("data-raw") || msgTextEl.innerText;
  navigator.clipboard.writeText(rawText).then(() => {
    const originalHtml = btn.innerHTML;
    btn.innerHTML = `<i class="fa-solid fa-check"></i> Copied!`;
    btn.classList.add("copied");
    setTimeout(() => {
      btn.innerHTML = originalHtml;
      btn.classList.remove("copied");
    }, 2000);
  }).catch(err => {
    console.warn("Failed to copy AI response:", err);
  });
}
window.copyAiResponse = copyAiResponse;

function scrollAiChatToBottom() {
  const body = document.getElementById("aiChatBody");
  if (body) {
    body.scrollTop = body.scrollHeight;
  }
}

async function sendAiMessage(customText = null) {
  const inputEl = document.getElementById("aiChatInput");
  const sendBtn = document.getElementById("btnSendAiChat");
  const query = (customText || (inputEl ? inputEl.value : "")).trim();

  if (!query || aiChatState.isLoading) return;

  // Clear input
  if (inputEl) {
    inputEl.value = "";
    inputEl.style.height = "auto";
  }

  aiChatState.isLoading = true;
  if (sendBtn) sendBtn.disabled = true;

  appendUserMessage(query);
  showAiLoadingIndicator();

  aiChatState.history.push({ role: "user", content: query });

  try {
    const res = await fetch("/api/ai/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        connection_id: state.connectionId,
        message: query,
        history: aiChatState.history
      })
    });

    const data = await res.json();
    removeAiLoadingIndicator();

    if (!res.ok) {
      throw new Error(data.detail || "Failed to get advice from AI Advisor.");
    }

    const replyRaw = data.reply || "No response received.";
    aiChatState.history.push({ role: "assistant", content: replyRaw });

    const formattedHtml = renderMarkdownToHtml(replyRaw);
    appendAssistantMessage(formattedHtml, {
      steps: data.steps || [],
      sources: data.sources || [],
      is_live_data: data.is_live_data,
      suggested_followups: data.suggested_followups || [],
      rawReply: replyRaw
    });
  } catch (err) {
    removeAiLoadingIndicator();
    appendAssistantMessage(`
      <p style="color: #DC2626;"><strong><i class="fa-solid fa-triangle-exclamation"></i> Error communicating with AI Advisor:</strong> ${escapeHtml(err.message)}</p>
    `);
  } finally {
    aiChatState.isLoading = false;
    if (sendBtn) sendBtn.disabled = false;
    if (inputEl) inputEl.focus();
  }
}

function resetAiChat() {
  const container = document.getElementById("aiChatMessages");
  if (!container) return;

  aiChatState.history = [];
  container.innerHTML = `
    <div class="ai-welcome-box" id="aiWelcomeBox">
      <div class="ai-welcome-avatar-wrapper">
        <img src="/static/images/aichatboticon.png" alt="AI Advisor" class="ai-welcome-avatar">
      </div>
      <h3 class="ai-welcome-title">AI Advisor</h3>
      <p class="ai-welcome-desc">
        Your autonomous Azure intelligence agent connected to your tenant with zero footprint.<br>
        Ask any cloud or software architecture question, query live resources, inspect security scores, or request custom reports and remediations.
      </p>
    </div>
  `;
  scrollAiChatToBottom();
  showToast("AI Advisor conversation reset.", "info");
}

function setupAiAdvisor() {
  const sendBtn = document.getElementById("btnSendAiChat");
  const inputEl = document.getElementById("aiChatInput");
  const resetBtn = document.getElementById("btnAiResetChat");

  if (sendBtn) {
    sendBtn.addEventListener("click", () => sendAiMessage());
  }

  if (inputEl) {
    inputEl.addEventListener("keydown", (e) => {
      if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault();
        sendAiMessage();
      }
    });

    // Auto resize
    inputEl.addEventListener("input", () => {
      inputEl.style.height = "auto";
      inputEl.style.height = Math.min(120, inputEl.scrollHeight) + "px";
    });
  }

  if (resetBtn) {
    resetBtn.addEventListener("click", resetAiChat);
  }
}

// ============================================================
// SCHEDULER & EMAIL DISPATCH MODULE
// ============================================================
function setupScheduler() {
  const openModalBtn = document.getElementById("openScheduleModalBtn");
  const closeModalBtn = document.getElementById("closeScheduleModalBtn");
  const cancelModalBtn = document.getElementById("cancelScheduleModalBtn");
  const modal = document.getElementById("scheduleModal");

  if (openModalBtn && modal) {
    openModalBtn.addEventListener("click", () => {
      const form = document.getElementById("newScheduleForm");
      if (form) form.reset();
      updateFrequencyVisibility();
      modal.classList.remove("d-none");
    });
  }

  const closeModal = () => {
    if (modal) modal.classList.add("d-none");
  };

  if (closeModalBtn) closeModalBtn.addEventListener("click", closeModal);
  if (cancelModalBtn) cancelModalBtn.addEventListener("click", closeModal);
  if (modal) {
    modal.addEventListener("click", (e) => {
      if (e.target === modal) closeModal();
    });
  }

  const freqSelect = document.getElementById("newSchedFreq");
  if (freqSelect) {
    freqSelect.addEventListener("change", updateFrequencyVisibility);
  }

  const submitBtn = document.getElementById("submitCreateScheduleBtn");
  if (submitBtn) {
    submitBtn.addEventListener("click", handleCreateSchedule);
  }

  const togglePwdBtn = document.getElementById("toggleSchedPwdBtn");
  const pwdInput = document.getElementById("schedSenderPassword");
  if (togglePwdBtn && pwdInput) {
    togglePwdBtn.addEventListener("click", () => {
      const isPwd = pwdInput.type === "password";
      pwdInput.type = isPwd ? "text" : "password";
      togglePwdBtn.innerHTML = isPwd ? '<i class="fa-regular fa-eye-slash"></i>' : '<i class="fa-regular fa-eye"></i>';
    });
  }

  const saveCfgBtn = document.getElementById("saveEmailConfigBtn");
  if (saveCfgBtn) {
    saveCfgBtn.addEventListener("click", handleSaveEmailConfig);
  }

  const testEmailBtn = document.getElementById("testEmailConfigBtn");
  if (testEmailBtn) {
    testEmailBtn.addEventListener("click", handleTestEmailConfig);
  }
}

function updateFrequencyVisibility() {
  const freq = document.getElementById("newSchedFreq")?.value || "daily";
  const dayOfWeekGroup = document.getElementById("schedDayOfWeekGroup");
  const dayOfMonthGroup = document.getElementById("schedDayOfMonthGroup");

  if (dayOfWeekGroup) {
    dayOfWeekGroup.style.display = freq === "weekly" ? "block" : "none";
  }
  if (dayOfMonthGroup) {
    dayOfMonthGroup.style.display = freq === "monthly" ? "block" : "none";
  }
}

async function fetchEmailConfig() {
  try {
    const res = await fetch("/api/scheduler/config");
    if (!res.ok) return;
    const cfg = await res.json();

    const senderEl = document.getElementById("schedSenderEmail");
    const pwdEl = document.getElementById("schedSenderPassword");
    const hostEl = document.getElementById("schedSmtpHost");
    const portEl = document.getElementById("schedSmtpPort");
    const tlsEl = document.getElementById("schedUseTls");
    const receiverEl = document.getElementById("schedReceiverEmail");
    const ccEl = document.getElementById("schedCcEmail");

    if (senderEl) senderEl.value = cfg.sender_email || "";
    if (hostEl) hostEl.value = cfg.smtp_host || "smtp.gmail.com";
    if (portEl) portEl.value = cfg.smtp_port || 587;
    if (tlsEl) tlsEl.checked = cfg.use_tls !== false;
    if (receiverEl) receiverEl.value = cfg.default_receiver || "";
    if (ccEl) ccEl.value = cfg.default_cc || "";

    if (pwdEl) {
      if (cfg.has_password) {
        pwdEl.placeholder = "•••••••••••• (Password Saved)";
        pwdEl.value = "";
      } else {
        pwdEl.placeholder = "16-character App Password";
        pwdEl.value = "";
      }
    }
  } catch (err) {
    console.error("Failed to load email config:", err);
  }
}

async function handleSaveEmailConfig() {
  const sender = document.getElementById("schedSenderEmail")?.value?.trim();
  const pwd = document.getElementById("schedSenderPassword")?.value;
  const host = document.getElementById("schedSmtpHost")?.value?.trim() || "smtp.gmail.com";
  const port = parseInt(document.getElementById("schedSmtpPort")?.value || "587", 10);
  const useTls = document.getElementById("schedUseTls")?.checked ?? true;
  const receiver = document.getElementById("schedReceiverEmail")?.value?.trim();
  const cc = document.getElementById("schedCcEmail")?.value?.trim();

  if (!sender) {
    showToast("Sender email address is required.", "error");
    return;
  }

  const saveBtn = document.getElementById("saveEmailConfigBtn");
  const origText = saveBtn.innerHTML;
  saveBtn.disabled = true;
  saveBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Saving...';

  try {
    const res = await fetch("/api/scheduler/config", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        sender_email: sender,
        sender_password: pwd,
        smtp_host: host,
        smtp_port: port,
        use_tls: useTls,
        default_receiver: receiver,
        default_cc: cc
      })
    });
    const result = await res.json();
    if (res.ok) {
      showToast("Email configuration saved successfully!", "success");
      fetchEmailConfig();
    } else {
      showToast(result.detail || "Failed to save configuration.", "error");
    }
  } catch (err) {
    showToast("Network error saving configuration.", "error");
  } finally {
    saveBtn.disabled = false;
    saveBtn.innerHTML = origText;
  }
}

async function handleTestEmailConfig() {
  const sender = document.getElementById("schedSenderEmail")?.value?.trim();
  const pwd = document.getElementById("schedSenderPassword")?.value;
  const host = document.getElementById("schedSmtpHost")?.value?.trim() || "smtp.gmail.com";
  const port = parseInt(document.getElementById("schedSmtpPort")?.value || "587", 10);
  const useTls = document.getElementById("schedUseTls")?.checked ?? true;
  const receiver = document.getElementById("schedReceiverEmail")?.value?.trim() || sender;
  const cc = document.getElementById("schedCcEmail")?.value?.trim();

  const feedbackEl = document.getElementById("emailTestFeedback");
  if (!sender) {
    showToast("Please enter a sender email address first.", "error");
    return;
  }

  const testBtn = document.getElementById("testEmailConfigBtn");
  const origText = testBtn.innerHTML;
  testBtn.disabled = true;
  testBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Sending Test Email...';

  if (feedbackEl) {
    feedbackEl.className = "email-test-banner d-none";
    feedbackEl.innerHTML = "";
  }

  try {
    const res = await fetch("/api/scheduler/test-email", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        sender_email: sender,
        sender_password: pwd,
        smtp_host: host,
        smtp_port: port,
        use_tls: useTls,
        receiver_email: receiver,
        cc_email: cc
      })
    });
    const result = await res.json();

    if (res.ok && result.success) {
      showToast("Verification email sent successfully!", "success");
      if (feedbackEl) {
        feedbackEl.className = "email-test-banner success";
        feedbackEl.innerHTML = `<i class="fa-solid fa-circle-check" style="color:#16a34a; font-size:1.1rem;"></i> <div><strong>Success!</strong> ${result.detail}</div>`;
      }
    } else {
      showToast("SMTP verification failed.", "error");
      if (feedbackEl) {
        feedbackEl.className = "email-test-banner error";
        feedbackEl.innerHTML = `<i class="fa-solid fa-circle-exclamation" style="color:#dc2626; font-size:1.1rem;"></i> <div><strong>Error:</strong> ${result.detail || "Authentication or network failure."}</div>`;
      }
    }
  } catch (err) {
    showToast("Network error contacting test endpoint.", "error");
    if (feedbackEl) {
      feedbackEl.className = "email-test-banner error";
      feedbackEl.innerHTML = `<i class="fa-solid fa-circle-exclamation" style="color:#dc2626;"></i> <div><strong>Error:</strong> ${err.message}</div>`;
    }
  } finally {
    testBtn.disabled = false;
    testBtn.innerHTML = origText;
  }
}

async function fetchSchedules() {
  try {
    const res = await fetch("/api/scheduler/schedules");
    if (!res.ok) return;
    const data = await res.json();
    renderSchedulesTable(data.schedules || []);
  } catch (err) {
    console.error("Failed to fetch schedules:", err);
  }
}

function renderSchedulesTable(schedules) {
  const countBadge = document.getElementById("schedulesCountBadge");
  const emptyState = document.getElementById("schedulesEmptyState");
  const tableContainer = document.getElementById("schedulesTableContainer");
  const tbody = document.getElementById("schedulesTableBody");

  const activeCount = schedules.filter(s => s.status === "Active").length;
  if (countBadge) countBadge.textContent = `${activeCount} Active`;

  if (!schedules || schedules.length === 0) {
    if (emptyState) emptyState.classList.remove("d-none");
    if (tableContainer) tableContainer.classList.add("d-none");
    if (tbody) tbody.innerHTML = "";
    return;
  }

  if (emptyState) emptyState.classList.add("d-none");
  if (tableContainer) tableContainer.classList.remove("d-none");
  if (!tbody) return;

  tbody.innerHTML = schedules.map(s => {
    let scopeBadge = '<span class="badge-scope badge-scope-all">Comprehensive</span>';
    if (s.scope === "security") scopeBadge = '<span class="badge-scope badge-scope-security">Security</span>';
    if (s.scope === "cost") scopeBadge = '<span class="badge-scope badge-scope-cost">FinOps Cost</span>';

    const statusBadge = s.status === "Active" 
      ? '<span class="badge-status active"><i class="fa-solid fa-circle-play"></i> Active</span>'
      : '<span class="badge-status paused"><i class="fa-solid fa-circle-pause"></i> Paused</span>';

    let freqDesc = s.frequency.charAt(0).toUpperCase() + s.frequency.slice(1);
    if (s.frequency === "daily") freqDesc = `Daily at ${s.time_of_day}`;
    else if (s.frequency === "weekly") freqDesc = `Weekly (${s.day_of_week}) at ${s.time_of_day}`;
    else if (s.frequency === "monthly") freqDesc = `Monthly (Day ${s.day_of_month}) at ${s.time_of_day}`;
    else if (s.frequency === "every_6_hours") freqDesc = "Every 6 Hours";
    else if (s.frequency === "hourly") freqDesc = "Hourly";

    let nextRunDesc = "--";
    if (s.next_run_at) {
      try {
        const d = new Date(s.next_run_at);
        nextRunDesc = d.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
      } catch (e) {
        nextRunDesc = s.next_run_at;
      }
    }

    const recips = s.recipients || "Default Receiver";
    const ccPart = s.cc ? ` <br><span class="text-muted" style="font-size:0.75rem;">CC: ${escapeHtml(s.cc)}</span>` : "";

    const pauseIcon = s.status === "Active" ? "fa-pause" : "fa-play";
    const pauseTitle = s.status === "Active" ? "Pause Schedule" : "Resume Schedule";

    return `
      <tr>
        <td>
          <strong style="color:#0f172a; font-size:0.9rem;">${escapeHtml(s.name)}</strong>
          ${s.last_run_status ? `<br><span class="text-muted" style="font-size:0.75rem;">Last: ${escapeHtml(s.last_run_status)}</span>` : ''}
        </td>
        <td>${scopeBadge}</td>
        <td><i class="fa-regular fa-clock" style="color:#64748b; margin-right:4px;"></i> ${freqDesc}</td>
        <td><strong>${nextRunDesc}</strong></td>
        <td><span style="font-size:0.8rem;">${escapeHtml(recips)}</span>${ccPart}</td>
        <td>${statusBadge}</td>
        <td>
          <div class="table-actions-cell">
            <button class="btn-action-icon btn-run-now" onclick="triggerRunScheduleNow('${s.id}', this)" title="Run Assessment & Email Now">
              <i class="fa-solid fa-paper-plane"></i>
            </button>
            <button class="btn-action-icon" onclick="toggleScheduleStatus('${s.id}')" title="${pauseTitle}">
              <i class="fa-solid ${pauseIcon}"></i>
            </button>
            <button class="btn-action-icon btn-delete-sched" onclick="deleteScheduleItem('${s.id}')" title="Delete Schedule">
              <i class="fa-solid fa-trash"></i>
            </button>
          </div>
        </td>
      </tr>
    `;
  }).join("");
}

async function handleCreateSchedule() {
  const name = document.getElementById("newSchedName")?.value?.trim();
  const scope = document.getElementById("newSchedScope")?.value || "all";
  const freq = document.getElementById("newSchedFreq")?.value || "daily";
  const timeOfDay = document.getElementById("newSchedTime")?.value || "09:00";
  const dayOfWeek = document.getElementById("newSchedDayOfWeek")?.value || "Monday";
  const dayOfMonth = parseInt(document.getElementById("newSchedDayOfMonth")?.value || "1", 10);
  const recipients = document.getElementById("newSchedRecipients")?.value?.trim();
  const cc = document.getElementById("newSchedCc")?.value?.trim();
  const includeReport = document.getElementById("newSchedIncludeReport")?.checked ?? true;

  if (!name) {
    showToast("Please enter a schedule name.", "error");
    return;
  }

  const submitBtn = document.getElementById("submitCreateScheduleBtn");
  submitBtn.disabled = true;

  try {
    const res = await fetch("/api/scheduler/schedules", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        name,
        scope,
        frequency: freq,
        time_of_day: timeOfDay,
        day_of_week: dayOfWeek,
        day_of_month: dayOfMonth,
        recipients,
        cc,
        include_body_report: includeReport
      })
    });

    if (res.ok) {
      showToast(`Schedule '${name}' created successfully!`, "success");
      document.getElementById("scheduleModal")?.classList.add("d-none");
      fetchSchedules();
    } else {
      const errData = await res.json();
      showToast(errData.detail || "Failed to create schedule.", "error");
    }
  } catch (err) {
    showToast("Network error creating schedule.", "error");
  } finally {
    submitBtn.disabled = false;
  }
}

async function triggerRunScheduleNow(scheduleId, btnEl) {
  if (btnEl) {
    btnEl.disabled = true;
    btnEl.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i>';
  }

  showToast("Executing scheduled assessment and dispatching email report...", "info");

  try {
    const res = await fetch(`/api/scheduler/schedules/${scheduleId}/run-now`, {
      method: "POST"
    });
    const data = await res.json();

    if (res.ok) {
      if (data.email_status && data.email_status.success) {
        showToast(`Assessment complete! Report emailed to ${data.email_status.recipients.join(", ")}.`, "success");
      } else {
        showToast(`Assessment finished, but email failed: ${data.email_status?.detail || 'SMTP error'}`, "warning");
      }
      fetchSchedules();
    } else {
      showToast(data.detail || "Error executing scheduled run.", "error");
    }
  } catch (err) {
    showToast(`Network error executing schedule: ${err.message}`, "error");
  } finally {
    if (btnEl) {
      btnEl.disabled = false;
      btnEl.innerHTML = '<i class="fa-solid fa-paper-plane"></i>';
    }
  }
}
window.triggerRunScheduleNow = triggerRunScheduleNow;

async function toggleScheduleStatus(scheduleId) {
  try {
    const res = await fetch(`/api/scheduler/schedules/${scheduleId}/toggle`, {
      method: "POST"
    });
    if (res.ok) {
      fetchSchedules();
      showToast("Schedule status updated.", "info");
    }
  } catch (err) {
    showToast("Failed to toggle schedule.", "error");
  }
}
window.toggleScheduleStatus = toggleScheduleStatus;

async function deleteScheduleItem(scheduleId) {
  if (!confirm("Are you sure you want to delete this scheduled routine?")) return;

  try {
    const res = await fetch(`/api/scheduler/schedules/${scheduleId}`, {
      method: "DELETE"
    });
    if (res.ok) {
      showToast("Schedule deleted.", "success");
      fetchSchedules();
    }
  } catch (err) {
    showToast("Failed to delete schedule.", "error");
  }
}
window.deleteScheduleItem = deleteScheduleItem;

// ============================================================
// APPLICATION INITIALIZATION
// ============================================================
document.addEventListener("DOMContentLoaded", async () => {
  setupTabs();
  setupPasswordToggle();
  setupInlineStatusBar();
  setupFindingsModal();
  setupSearchFilters();
  setupReportDownloads();
  initSubscriptionTable();
  initTagsManager();
  setupAiAdvisor();
  setupScheduler();

  // Auth Form Submit
  const connectForm = document.getElementById("connectForm");
  if (connectForm) connectForm.addEventListener("submit", handleConnect);

  // Disconnect Session
  const disBtn = document.getElementById("disconnectBtn");
  if (disBtn) disBtn.addEventListener("click", handleDisconnect);

  // Execution Bar Buttons
  const runAllBtn = document.getElementById("runAllBtn");
  if (runAllBtn) runAllBtn.addEventListener("click", () => startJob("all"));

  const runSecBtn = document.getElementById("runSecurityBtn");
  if (runSecBtn) runSecBtn.addEventListener("click", () => startJob("security"));

  const runCostBtn = document.getElementById("runCostBtn");
  if (runCostBtn) runCostBtn.addEventListener("click", () => startJob("cost"));

  // Check and restore persisted session
  const restored = await restoreSessionState();
  if (!restored) {
    showView("connection");
  }
});
