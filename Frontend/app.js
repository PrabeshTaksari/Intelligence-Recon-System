// ===== CONFIG =====
// API Base URL: use same-origin first so API works when app is served from the same server
let defaultApiBase = window.location.origin || `http://${window.location.hostname}:8080`;

const API_ROUTES = {
  config: () => "/api/config",  // Fetch API config from backend
  createScan: () => "/api/scans",
  listScans: () => "/api/scans",
  scanDetail: (id) => `/api/scans/${id}`,
  scanStatus: (id) => `/api/scans/${id}/status`,
  scanIntelligence: (id) => `/api/scans/${id}/intelligence-summary`,
  health: () => "/api/health",
  reportHtml: (id) => `/api/scans/${id}/report`,
  reportPdf: (id) => `/api/scans/${id}/report/pdf`,
  markScanSaved: (id) => `/api/scans/${id}/mark-saved`,
  severityStatsCompleted: () => `/api/scans/stats/severity-completed`,
  purgeScans: () => `/api/scans/purge`,
  toolCommand: (toolName, target) => `/api/tools/${encodeURIComponent(toolName)}/command${target ? `?target=${encodeURIComponent(target)}` : ""}`,
};

// Initialize API config from backend on page load; also update apiBase so requests use correct URL
async function initializeApiConfig() {
  try {
    // Use relative fetch so it always stays same-origin (works in internal/external browsers).
    const response = await fetch("/api/config");
    if (response.ok) {
      const config = await response.json();
      // Only update apiBase if backend returns something compatible with the current origin.
      // Otherwise, keep the safe same-origin default (prevents 127.0.0.1/localhost from breaking external browsers).
      try {
        const curOrigin = (window.location.origin || "").replace(/\/$/, "");
        const cfgOrigin = (config.api_base_url || "").replace(/\/$/, "");
        if (curOrigin && cfgOrigin && curOrigin === cfgOrigin) {
          defaultApiBase = config.api_base_url;
          apiBase = config.api_base_url;
          console.log("✓ API Config loaded from backend:", apiBase);
        } else {
          apiBase = defaultApiBase;
        }
      } catch (_) {
        apiBase = defaultApiBase;
      }
    }
  } catch (error) {
    console.warn("⚠ Could not fetch API config from backend, using same-origin:", defaultApiBase);
    apiBase = defaultApiBase;
  }
}

// Config is loaded in initApp() before any API calls

// Track whether the user is currently manually scrolling in summary panel
let isUserScrolling = false;

// Tools & OWASP
const TOOL_LIST = [
  "Nuclei",
  "Naabu",
  "Httpx",
  "Subfinder",
  "Amass",
  "Assetfinder",
  "Sublist3r",
  "GAU",
  "Katana",
  "GoSpider",
  "FFuf",
  "Wfuzz",
  "CeWL",
  "DNSx",
  "ShuffleDNS",
];

// All 15 tools mapped to OWASP Top 10 2021 categories (each tool appears in at least one category)
const OWASP_MAP = [
  { id: "A01:2021", name: "Broken Access Control", tools: ["Nuclei", "FFuf", "Wfuzz", "Katana", "GoSpider", "GAU", "Subfinder", "Sublist3r"] },
  { id: "A02:2021", name: "Cryptographic Failures", tools: ["Nuclei", "Httpx"] },
  { id: "A03:2021", name: "Injection", tools: ["Nuclei", "FFuf", "Wfuzz", "Katana", "GoSpider", "GAU"] },
  { id: "A04:2021", name: "Insecure Design", tools: ["Nuclei", "Wfuzz", "Katana", "FFuf"] },
  { id: "A05:2021", name: "Security Misconfiguration", tools: ["Naabu", "Httpx", "Nuclei", "Subfinder", "DNSx", "Sublist3r"] },
  { id: "A06:2021", name: "Vulnerable and Outdated Components", tools: ["Nuclei", "Subfinder", "Amass", "Assetfinder", "Sublist3r", "DNSx", "ShuffleDNS"] },
  { id: "A07:2021", name: "Identification & Authentication Failures", tools: ["Nuclei", "FFuf", "Wfuzz", "CeWL"] },
  { id: "A08:2021", name: "Software & Data Integrity Failures", tools: ["Nuclei", "Httpx"] },
  { id: "A09:2021", name: "Security Logging & Monitoring Failures", tools: ["Nuclei", "Httpx"] },
  { id: "A10:2021", name: "Server-Side Request Forgery", tools: ["Httpx", "Nuclei", "GAU", "Subfinder", "Amass", "DNSx"] },
];

function getOwaspCategoryName(categoryId) {
  const category = OWASP_MAP.find(cat => cat.id === categoryId);
  return category ? category.name : `Unknown (${categoryId})`;
}

let apiBase = defaultApiBase;
let trendChart;
let severityChart;
/* ===== LIVE STATUS TRACKER – State (per Implementation Overview) =====
 * Data flow: Scan Launch → addLiveStatusItem() → startStatusPolling()
 *            → Polling (every 5s)
 *            → renderLiveStatus() → Updates #liveStatusList in the DOM
 * Polling: primary source (GET /api/scans/{id}/status every 5s)
 * SSE: disabled because the backend does not expose an SSE route
 */
let liveStatus = [];              // Rolling snapshot list (max 6 updates)
let statusPollingIntervals = {}; // Per-scan polling intervals
let commandTracking = {};        // Per-tool command/output tracking
let fallbackNotificationsShown = {}; // Track fallback alerts by scanId
const LIVE_STATUS_UPDATE_INTERVAL_MS = 5000; // Throttle: only show updates every 5 seconds
const lastLiveStatusUpdateByScan = {};       // scanId -> timestamp
const lastLiveStatusDisplayTimeByScan = {};  // scanId -> displayed timestamp

// Initialize liveStatus with OWASP category field
liveStatus.forEach(item => {
  if (item.owaspCategory === undefined) {
    item.owaspCategory = null;
  }
});

// EventSource placeholder retained for compatibility with older code paths.
let eventSource = null;
let currentScanId = null;

// Real-time command tracking data
let toolStatus = {};
const ALLOWED_THEMES = ["dark-soc", "light-minimal"];
let activeTheme = (() => {
  const stored = localStorage.getItem("irs_theme") || "dark-soc";
  return ALLOWED_THEMES.includes(stored) ? stored : "dark-soc";
})();
let lastScanId = null;
let scanSummaryInterval = null;

function createOrUpdateProgressWidget(scanId, progressPercent, statusText) {
  let widget = document.getElementById('scanProgressWidget');
  if (!widget) {
    widget = document.createElement('div');
    widget.id = 'scanProgressWidget';
    widget.innerHTML = `
      <div class="scan-progress-ring" data-percent="${progressPercent}">
        <svg viewBox="0 0 36 36" class="circular-chart" aria-hidden="true">
          <path class="circle-bg" d="M18 2.0845
              a 15.9155 15.9155 0 0 1 0 31.831
              a 15.9155 15.9155 0 0 1 0 -31.831" />
          <path class="circle" stroke-dasharray="${progressPercent},100" d="M18 2.0845
              a 15.9155 15.9155 0 0 1 0 31.831
              a 15.9155 15.9155 0 0 1 0 -31.831" />
        </svg>
        <span class="scan-progress-label">${progressPercent}%</span>
      </div>
      <div class="scan-progress-text">${statusText || 'Running'}</div>
    `;
    document.body.appendChild(widget);
    initProgressWidgetDrag(widget);
  }
  const ring = widget.querySelector('.scan-progress-ring');
  if (ring) {
    ring.dataset.percent = progressPercent;
    const path = ring.querySelector('.circle');
    if (path) {
      path.setAttribute('stroke-dasharray', `${progressPercent},100`);
    }
  }
  const label = widget.querySelector('.scan-progress-label');
  if (label) label.textContent = `${progressPercent}%`;
  const text = widget.querySelector('.scan-progress-text');
  if (text) text.textContent = statusText || 'Running';
}

function removeProgressWidget() {
  const widget = document.getElementById('scanProgressWidget');
  if (widget) {
    widget.remove();
  }
}

function initProgressWidgetDrag(widget) {
  let isDragging = false;
  let offsetX = 0;
  let offsetY = 0;

  widget.addEventListener('mousedown', (e) => {
    isDragging = true;
    widget.style.cursor = 'grabbing';
    offsetX = e.clientX - widget.getBoundingClientRect().left;
    offsetY = e.clientY - widget.getBoundingClientRect().top;
    document.body.style.userSelect = 'none';
  });

  window.addEventListener('mousemove', (e) => {
    if (!isDragging) return;
    const x = Math.max(10, Math.min(window.innerWidth - widget.offsetWidth - 10, e.clientX - offsetX));
    const y = Math.max(10, Math.min(window.innerHeight - widget.offsetHeight - 10, e.clientY - offsetY));
    widget.style.left = `${x}px`;
    widget.style.top = `${y}px`;
  });

  window.addEventListener('mouseup', () => {
    if (!isDragging) return;
    isDragging = false;
    widget.style.cursor = 'grab';
    document.body.style.userSelect = '';
  });
}

const SEVERITY_KEYS = ["critical", "high", "medium", "low", "info"];

/* ===== HELPERS ===== */
function getApiUrl(path) {
  // Always use same-origin relative API URLs to prevent host mismatch
  // (e.g., internal works on localhost/127.0.0.1 but external uses 0.0.0.0).
  if (!path) return path;
  if (String(path).startsWith("http://") || String(path).startsWith("https://")) return path;
  if (String(path).startsWith("/")) return path;
  return (apiBase || window.location.origin) + "/" + path;
}

async function apiRequest(path, options = {}) {
  const url = getApiUrl(path);
  const resp = await fetch(url, options);
  if (!resp.ok) {
    const text = await resp.text();
    // Try to parse JSON error response to extract detail field
    try {
      const errorData = JSON.parse(text);
      // Extract only the detail/message value, nothing else
      const detail = errorData.detail || errorData.message;
      if (detail) {
        throw new Error(detail);
      } else {
        throw new Error(text);
      }
    } catch (e) {
      // If not JSON or no detail field, use the raw text
      if (e instanceof Error && e.message !== text) {
        throw e;
      }
      throw new Error(text);
    }
  }
  const contentType = resp.headers.get("content-type") || "";
  if (contentType.includes("application/json")) {
    return await resp.json();
  }
  return await resp.text();
}

/* ===== LIVE STATUS TRACKER – SSE (optional real-time) =====
 * EventSource /api/sse/scan/{id} - messages dispatched to handleWebSocketMessage
 */
function connectSSE(scanId) {
  if (eventSource) {
    eventSource.close();
    eventSource = null;
  }
  currentScanId = scanId;
  console.debug(`SSE is disabled; using polling for scan ${scanId}`);
}

function disconnectSSE() {
  if (eventSource) {
    eventSource.close();
    eventSource = null;
    currentScanId = null;
  }
}

/* handleWebSocketMessage: Dispatches SSE/WebSocket events to Live Status Tracker.
 * Types: command_update, tool_status, tool_start, tool_output, tool_complete, initial_status, scan_phase, log */
function handleWebSocketMessage(message) {
  console.log("Handling WebSocket message of type:", message.type);
  
  if (message.type === "ping") {
    // Ignore ping messages - they're just keep-alive
    return;
  } else if (message.type === "command_update") {
    console.log("Handling command_update message");
    handleCommandUpdate(message.data);
  } else if (message.type === "tool_status") {
    console.log("Handling tool_status message");
    handleToolStatusUpdate(message.data);
  } else if (message.type === "tool_start") {
    console.log("Handling tool_start message");
    handleToolStart(message);
  } else if (message.type === "tool_output") {
    console.log("Handling tool_output message");
    handleToolOutput(message);
  } else if (message.type === "tool_complete") {
    console.log("Handling tool_complete message");
    handleToolComplete(message);
  } else if (message.type === "initial_status") {
    console.log("Handling initial_status message");
    handleInitialStatus(message);
  } else if (message.type === "scan_phase") {
    console.log("Handling scan_phase message");
    handleScanPhaseUpdate(message);
  } else if (message.type === "log") {
    console.log("Handling log message");
    handleLogMessage(message);
  } else {
    console.log("Unknown message type:", message.type);
  }
}

function handleCommandUpdate(data) {
  const { tool_name, command, status, output, is_error, timestamp } = data;
  
  // Initialize tracking for this tool if needed
  if (!commandTracking[tool_name]) {
    commandTracking[tool_name] = {
      command: "",
      status: "idle",
      output: [],
      lastUpdate: timestamp
    };
  }
  
  const toolTrack = commandTracking[tool_name];
  
  if (status === "started" && command) {
    toolTrack.command = command;
    toolTrack.status = "running";
    toolTrack.output = [];
  } else if (output !== undefined) {
    // Add output line
    toolTrack.output.push({
      text: output,
      is_error: is_error,
      timestamp: timestamp
    });
    
    // Keep only last 100 lines to prevent memory issues
    if (toolTrack.output.length > 100) {
      toolTrack.output = toolTrack.output.slice(-100);
    }
  } else if (status === "completed") {
    toolTrack.status = "completed";
  }
  
  toolTrack.lastUpdate = timestamp;
  
  // Update UI
  renderLiveStatus();
}

function handleToolStatusUpdate(data) {
  const { tool_name, status, details, timestamp } = data;
  
  toolStatus[tool_name] = {
    status: status,
    details: details || {},
    timestamp: timestamp
  };
  
  // Update UI
  renderLiveStatus();
}

function handleToolStart(message) {
  const { scan_id, tool } = message;
  const key = `scan_${scan_id}_${tool}`;
  if (!commandTracking[key]) {
    commandTracking[key] = {
      command: `Running ${tool}`,
      status: "running",
      output: [],
      lastUpdate: new Date().toISOString()
    };
  }

  // Update the live status item
  addLiveStatusItem({
    scanId: scan_id,
    // Get other properties from existing item if it exists
    status: "running",
    tools: (() => {
      const existingItem = liveStatus.find(item => item.scanId === scan_id);
      const existingTools = existingItem ? existingItem.tools : [];
      
      // Check if tool already exists
      const existingToolIndex = existingTools.findIndex(t => t.tool_name === tool);
      if (existingToolIndex >= 0) {
        // Update existing tool
        existingTools[existingToolIndex].status = "running";
        existingTools[existingToolIndex].started_at = new Date().toISOString();
        return existingTools;
      } else {
        // Add new tool
        return [...existingTools, {
          tool_name: tool,
          status: "running",
          started_at: new Date().toISOString()
        }];
      }
    })()
  });

  // Show live output section when this scan is selected
  const scanFilter = document.getElementById("scanSummaryFilter");
  if (scanFilter && scanFilter.value === String(scan_id)) {
    renderLiveOutputInSummary(scan_id);
  }
  renderLiveStatus();
}

function handleToolOutput(message) {
  const { scan_id, tool, output } = message;
  const key = `scan_${scan_id}_${tool}`;

  // Store output in command tracking for display (scoped by scan)
  if (!commandTracking[key]) {
    commandTracking[key] = {
      command: `Running ${tool}`,
      status: "running",
      output: [],
      lastUpdate: new Date().toISOString()
    };
  }

  commandTracking[key].output.push({
    text: output,
    is_error: false,
    timestamp: new Date().toISOString()
  });

  if (commandTracking[key].output.length > 100) {
    commandTracking[key].output = commandTracking[key].output.slice(-100);
  }

  // Update live output in Scanned Target Summary if this scan is selected
  const scanFilter = document.getElementById("scanSummaryFilter");
  if (scanFilter && scanFilter.value === String(scan_id)) {
    renderLiveOutputInSummary(scan_id);
  }

  // Update the live status item
  addLiveStatusItem({
    scanId: scan_id,
    tools: (() => {
      const existingItem = liveStatus.find(item => item.scanId === scan_id);
      const existingTools = existingItem ? existingItem.tools : [];
      
      // Make sure the tool is in the list
      const existingToolIndex = existingTools.findIndex(t => t.tool_name === tool);
      if (existingToolIndex >= 0) {
        // Tool already exists
        return existingTools;
      } else {
        // Add tool to list if not already there
        return [...existingTools, {
          tool_name: tool,
          status: "running"  // Default status if newly added
        }];
      }
    })()
  });
}

function handleToolComplete(message) {
  const { scan_id, tool, status } = message;
  const key = `scan_${scan_id}_${tool}`;
  if (commandTracking[key]) {
    commandTracking[key].status = status === true ? "completed" : "failed";
  }

  // Update live output in Scanned Target Summary if this scan is selected
  const scanFilter = document.getElementById("scanSummaryFilter");
  if (scanFilter && scanFilter.value === String(scan_id)) {
    renderLiveOutputInSummary(scan_id);
  }

  // Find the scan in liveStatus
  const scanItem = liveStatus.find(item => item.scanId === scan_id);
  
  if (scanItem) {
    // Update the tool status
    const toolIndex = scanItem.tools.findIndex(t => t.tool_name === tool);
    if (toolIndex >= 0) {
      scanItem.tools[toolIndex].status = status === true ? "completed" : "failed";
      scanItem.tools[toolIndex].finished_at = new Date().toISOString();
    } else {
      // If tool doesn't exist in the list, add it
      scanItem.tools.push({
        tool_name: tool,
        status: status === true ? "completed" : "failed",
        finished_at: new Date().toISOString()
      });
    }
    
    // Check if all tools are completed
    const allToolsCompleted = scanItem.tools.every(t => 
      t.status === "completed" || t.status === "failed" || t.status === "timeout"
    );
    
    // If all tools are completed, we can consider the scan complete
    if (allToolsCompleted) {
      // Update the scan status to completed
      scanItem.status = "completed";
      scanItem.phase = "All tools finished. Scan completed.";
      removeProgressWidget();
      
      // Keep WebSocket connection open to show final status
      // WebSocket will be disconnected when user navigates away or manually closes
    }
  }
  
  // Update UI
  renderLiveStatus();
}

function handleInitialStatus(message) {
  const { scan_id, status, target, owasp_category, tools } = message;
  
  // Update the live status item
  addLiveStatusItem({
    scanId: scan_id,
    target: target,
    status: status,
    tools: tools.map(t => ({
      tool_name: t.tool_name,
      status: t.status,
      started_at: t.started_at,
      finished_at: t.finished_at
    })),
    owaspCategory: owasp_category,
    phase: deriveScanPhase(status, tools)
  });
}

function handleScanPhaseUpdate(message) {
  const { scan_id, phase, details, timestamp } = message;
  
  console.log(`[Scan ${scan_id}] Phase update: ${phase}`, details);
  
  // Update the live status item with phase information
  addLiveStatusItem({
    scanId: scan_id,
    phaseInfo: {
      currentPhase: phase,
      ...details
    },
    serverTimestamp: timestamp ? new Date(timestamp * 1000) : new Date()
  });
}


function handleLogMessage(message) {
  const { scan_id, level, message: log_message } = message;
  
  // For now, just log to console
  console.log(`[${level.toUpperCase()}][Scan ${scan_id}] ${log_message}`);
  
  // Update UI if needed - just trigger a refresh for this scan
  addLiveStatusItem({
    scanId: scan_id
  });
}

// Validate that a scan target is a bare domain, IP (v4/v6), or full HTTP(S) URL
function isValidTarget(raw) {
  if (!raw || typeof raw !== "string") return false;
  const value = raw.trim();

  // Try HTTP(S) URL
  try {
    const url = new URL(value);
    if (!/^https?:$/.test(url.protocol)) return false;
    return !!url.hostname;
  } catch {
    // Not a URL; fall through to IP/domain checks
  }

  // IPv4
  const ipv4 =
    /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
  if (ipv4.test(value)) return true;

  // IPv6 (common forms, including ::1)
  const ipv6 =
    /^(([0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}|::1)$/;
  if (ipv6.test(value)) return true;

  // Bare domain (must contain at least one dot, reasonable length)
  const domain =
    /^(?=.{3,255}$)([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$/;
  if (domain.test(value)) return true;

  // Hostname or local host with optional port (localhost, localhost:3000, 127.0.0.1:8080, [::1]:8080)
  const hostWithPort =
    /^(?:\[(?:[0-9a-fA-F:]+)\]|[a-zA-Z0-9.-]+)(?::\d{1,5})?$/;
  if (hostWithPort.test(value)) return true;

  return false;
}

function getAxisColor() {
  return "#94a3b8";
}

function coerceSeverityCounts(input = {}) {
  const out = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  SEVERITY_KEYS.forEach((k) => {
    out[k] = Number(input?.[k]) || 0;
  });
  return out;
}

function resetSeverityUi({ subtitle } = {}) {
  const subtitleEl = document.getElementById("severitySubtitle");
  if (subtitleEl) subtitleEl.textContent = "";
  const set = (id, v) => {
    const el = document.getElementById(id);
    if (el) el.textContent = String(v);
  };
  set("sevCriticalCount", 0);
  set("sevHighCount", 0);
  set("sevMediumCount", 0);
  set("sevLowCount", 0);
  set("sevInfoCount", 0);
  set("totalFindingsCount", 0);
}

function resetSeverityChart({ subtitle } = {}) {
  resetSeverityUi({});
  if (!severityChart) return;
  severityChart.data.datasets[0].data = [0, 0, 0, 0, 0];
  severityChart.update();
}

/* === stats helpers for real charts (backend endpoints optional) === */
async function fetchSeverityStats() {
  console.log("=== FETCHING SEVERITY STATS FROM API ===");
  try {
    const result = await apiRequest("/api/scans/stats/severity", { method: "GET" });
    console.log("API Response:", result);
    return result;
  } catch (error) {
    console.error("Error fetching severity stats:", error);
    throw error;
  }
}

/**
 * @param {string} [rangeOrDate] - "7d"|"30d"|"90d" or "YYYY-MM-DD"
 * @param {string} [endDate] - when provided with rangeOrDate as startDate, use start_date & end_date
 */
async function fetchTrendStats(rangeOrDate, endDate) {
  if (rangeOrDate && endDate && /^\d{4}-\d{2}-\d{2}$/.test(rangeOrDate) && /^\d{4}-\d{2}-\d{2}$/.test(endDate)) {
    const q = `start_date=${encodeURIComponent(rangeOrDate)}&end_date=${encodeURIComponent(endDate)}`;
    return await apiRequest(`/api/scans/stats/trend?${q}`, { method: "GET" });
  }
  const isDate = /^\d{4}-\d{2}-\d{2}$/.test(rangeOrDate);
  const q = isDate ? `date=${encodeURIComponent(rangeOrDate)}` : `range=${encodeURIComponent(rangeOrDate || "7d")}`;
  return await apiRequest(`/api/scans/stats/trend?${q}`, { method: "GET" });
}

/* ===== NAVIGATION ===== */
function initNavigation() {
  const navItems = document.querySelectorAll(".nav-item");
  const sections = document.querySelectorAll(".content-section");

  function showSection(sectionId) {
    navItems.forEach((b) => b.classList.remove("active"));
    const navBtn = document.querySelector(`.nav-item[data-section="${sectionId}"]`);
    if (navBtn) navBtn.classList.add("active");
    sections.forEach((s) => {
      s.classList.toggle("visible", s.id === sectionId);
    });
  }

  navItems.forEach((btn) => {
    btn.addEventListener("click", () => {
      showSection(btn.dataset.section);
    });
  });

  const scheduledScansCard = document.getElementById("statCardScheduledScans");
  if (scheduledScansCard) {
    scheduledScansCard.addEventListener("click", () => showSection("scheduled-scans"));
    scheduledScansCard.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        showSection("scheduled-scans");
      }
    });
  }

  function openTargetsPopup(cardId, title, getItems) {
    const card = document.getElementById(cardId);
    if (!card) return;
    card.addEventListener("click", () => {
      const items = getItems();
      showTargetsListModal(title, items);
    });
    card.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        showTargetsListModal(title, getItems());
      }
    });
  }
  openTargetsPopup("statCardUniqueTargets", "Unique Targets (Last 30 days)", () => lastDashboardSummary.uniqueTargetList || []);
  openTargetsPopup("statCardCriticalTargets", "Targets with Criticals", () => lastDashboardSummary.criticalTargetList || []);
  openTargetsPopup("statCardCleanAssets", "Clean Assets", () => lastDashboardSummary.cleanAssetsList || []);
}

const QUICK_SEARCH_DEBOUNCE_MS = 150;
const QUICK_SEARCH_MAX_ITEMS = 12;

async function getQuickSearchTargets() {
  const list = lastDashboardSummary.uniqueTargetList || [];
  if (list.length > 0) return list;
  try {
    const data = await listScans({});
    const scans = data.scans || [];
    const targets = [...new Set(scans.map((s) => s.target).filter(Boolean))].sort();
    return targets;
  } catch (e) {
    return [];
  }
}

function initQuickSearch() {
  const input = document.getElementById("quickSearchInput");
  const dropdown = document.getElementById("quickSearchDropdown");
  if (!input || !dropdown) return;

  let debounceTimer = null;

  function hideDropdown() {
    dropdown.classList.add("hidden");
    dropdown.innerHTML = "";
    input.setAttribute("aria-expanded", "false");
  }

  function showDropdown(items) {
    dropdown.innerHTML = "";
    dropdown.classList.remove("hidden");
    input.setAttribute("aria-expanded", "true");
    if (items.length === 0) {
      const empty = document.createElement("div");
      empty.className = "quick-search-dropdown-empty";
      empty.textContent = "No targets found";
      dropdown.appendChild(empty);
      return;
    }
    const limited = items.slice(0, QUICK_SEARCH_MAX_ITEMS);
    limited.forEach((target) => {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "quick-search-dropdown-item";
      btn.setAttribute("role", "option");
      btn.innerHTML = `<code>${escapeHtml(target)}</code>`;
      btn.addEventListener("click", () => {
        openTargetDetailModal(target);
        input.value = "";
        hideDropdown();
      });
      dropdown.appendChild(btn);
    });
  }

  function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
  }

  function runSearch() {
    const q = (input.value || "").trim().toLowerCase();
    if (q.length === 0) {
      hideDropdown();
      return;
    }
    getQuickSearchTargets().then((targets) => {
      const matches = targets.filter((t) => t.toLowerCase().includes(q));
      showDropdown(matches);
    });
  }

  input.addEventListener("input", () => {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(runSearch, QUICK_SEARCH_DEBOUNCE_MS);
  });

  input.addEventListener("focus", () => {
    const q = (input.value || "").trim();
    if (q.length > 0) runSearch();
  });

  input.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      hideDropdown();
      input.blur();
      return;
    }
    if (e.key === "Enter") {
      const first = dropdown.querySelector(".quick-search-dropdown-item");
      if (first) {
        e.preventDefault();
        first.click();
      }
    }
  });

  document.addEventListener("click", (e) => {
    const wrap = document.getElementById("quickSearchWrap");
    if (wrap && !wrap.contains(e.target)) hideDropdown();
  });

  dropdown.addEventListener("mousedown", (e) => e.preventDefault());
}

/* ===== THEME (DARK ONLY, BUT KEEPS MODAL) ===== */
function applyTheme(themeKey) {
  const body = document.body;
  body.className = "";
  body.classList.add(`theme-${themeKey}`);

  activeTheme = themeKey;
  localStorage.setItem("irs_theme", themeKey);

  const label = document.getElementById("currentThemeLabel");
  if (label) {
    const friendly = { "dark-soc": "Dark", "light-minimal": "Light" }[themeKey] || themeKey;
    label.textContent = friendly;
  }

  const cards = document.querySelectorAll(".theme-card");
  cards.forEach((card) => {
    card.classList.toggle("active", card.dataset.theme === themeKey);
  });

  if (trendChart) {
    const axisColor = getAxisColor();
  // Line Shadow Plugin - Create glow/shadow effect for chart lines
  const lineShadowPlugin = {
    id: 'lineShadow',
    afterDatasetsDraw(chart) {
      const ctx = chart.ctx;
      const datasets = chart.data.datasets;
      
      datasets.forEach((dataset, dsIndex) => {
        if (!dataset.data || dataset.data.length === 0) return;
        
        const meta = chart.getDatasetMeta(dsIndex);
        if (!meta.data || meta.data.length === 0) return;
        
        const lineColor = dataset.borderColor || '#38bdf8';
        const isBlue = lineColor.includes('38bdf8');
        
        ctx.save();
        
        // Thick outer shadow
        ctx.lineWidth = dataset.borderWidth + 10;
        ctx.strokeStyle = isBlue ? 'rgba(56, 189, 248, 0.08)' : 'rgba(251, 113, 133, 0.08)';
        ctx.lineJoin = 'round';
        ctx.lineCap = 'round';
        
        ctx.beginPath();
        meta.data.forEach((point, index) => {
          if (index === 0) ctx.moveTo(point.x, point.y);
          else ctx.lineTo(point.x, point.y);
        });
        ctx.stroke();
        
        // Medium shadow
        ctx.lineWidth = dataset.borderWidth + 6;
        ctx.strokeStyle = isBlue ? 'rgba(56, 189, 248, 0.15)' : 'rgba(251, 113, 133, 0.15)';
        ctx.beginPath();
        meta.data.forEach((point, index) => {
          if (index === 0) ctx.moveTo(point.x, point.y);
          else ctx.lineTo(point.x, point.y);
        });
        ctx.stroke();
        
        // Inner shadow
        ctx.lineWidth = dataset.borderWidth + 2;
        ctx.strokeStyle = isBlue ? 'rgba(56, 189, 248, 0.25)' : 'rgba(251, 113, 133, 0.25)';
        ctx.beginPath();
        meta.data.forEach((point, index) => {
          if (index === 0) ctx.moveTo(point.x, point.y);
          else ctx.lineTo(point.x, point.y);
        });
        ctx.stroke();
        
        ctx.restore();
      });
    }
  };

    trendChart.options.scales.x.ticks.color = axisColor;
    trendChart.options.scales.y.ticks.color = axisColor;
    trendChart.update();
  }
  if (severityChart) severityChart.update();
}

function initThemeModal() {
  const grid = document.getElementById("themeCardGrid");
  if (!grid) return;

  const themes = [
    { key: "dark-soc", name: "Dark" },
    { key: "light-minimal", name: "Light" },
  ];

  grid.innerHTML = "";
  themes.forEach((t) => {
    const card = document.createElement("div");
    card.className = "theme-card";
    card.dataset.theme = t.key;
    if (t.key === activeTheme) card.classList.add("active");

    const preview = document.createElement("div");
    preview.className = "theme-card-preview";
    card.appendChild(preview);

    const name = document.createElement("div");
    name.className = "theme-card-name";
    name.textContent = t.name;
    card.appendChild(name);

    const tag = document.createElement("div");
    tag.className = "theme-card-tag";
    tag.textContent = "Active";
    card.appendChild(tag);

    card.addEventListener("click", () => {
      applyTheme(t.key);
    });

    grid.appendChild(card);
  });

  if (!ALLOWED_THEMES.includes(activeTheme)) {
    activeTheme = "dark-soc";
    localStorage.setItem("irs_theme", activeTheme);
  }
  applyTheme(activeTheme);
}

/* ===== LAUNCH SCAN FORM ===== */
function renderToolCheckboxes() {
  const container = document.getElementById("toolCheckboxGrid");
  container.innerHTML = "";
  TOOL_LIST.forEach((tool) => {
    const wrapper = document.createElement("label");
    wrapper.className = "tool-chip";

    const input = document.createElement("input");
    input.type = "checkbox";
    input.value = tool;

    const span = document.createElement("span");
    span.textContent = tool;

    wrapper.appendChild(input);
    wrapper.appendChild(span);
    input.addEventListener("change", () => {
      wrapper.classList.toggle("active", input.checked);
    });

    container.appendChild(wrapper);
  });
}

function getSelectedTools() {
  const checkboxes = document.querySelectorAll("#toolCheckboxGrid input[type=checkbox]");
  const selected = [];
  checkboxes.forEach((cb) => {
    if (cb.checked) selected.push(cb.value);
  });
  return selected;
}

async function handleLaunchScan(evt) {
  console.log("handleLaunchScan called");
  evt.preventDefault();
  const targetEl = document.getElementById("targetInput");
  const owasp = document.getElementById("owaspSelect").value;
  const tools = getSelectedTools();
  const runBtn = document.getElementById("runScanBtn");
  const help = document.getElementById("launchHelpText");

  const target = (targetEl?.value || "").trim();

  // Strict target validation: only accept domain, IP, or full HTTP(S) URL
  if (!isValidTarget(target)) {
    help.textContent = "Please enter a valid target (domain, IP, or URL).";
    return;
  }

  if (!target || !owasp || tools.length === 0) {
    help.textContent = "Please enter target, choose OWASP category, and select at least one tool.";
    return;
  }

  // Block if another scan is already running (stale runs >30min are ignored by backend)
  try {
    const runningCheck = await apiRequest("/api/scans/any-running", { method: "GET" });
    if (runningCheck && runningCheck.running === true) {
      const scanId = runningCheck.running_scan_id;
      if (scanId) {
        showRunningScanBlockedPopup(scanId);
      } else {
        showStyledPopup("Another scan is still running. Please wait for it to complete before starting a new one.");
      }
      return;
    }
  } catch (e) {
    // If check fails, still allow launch; backend will reject if one is running
  }

  runBtn.disabled = true;
  help.textContent = "Launching scan and validating toolchain via AI…";

  try {
    const body = {
      target: target,
      owasp_category: owasp,
      selected_tools: tools,
    };
    console.log("Making API request to create scan");
    const data = await apiRequest(API_ROUTES.createScan(), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    console.log("API response received:", data);

    const scanId = data.scan_id ?? data.id;
    console.log("Extracted scanId:", scanId);
    help.textContent = `Scan #${scanId} created. AI will optimize tools and execution has started.`;

    // Live Status Tracker trigger (per Implementation Overview):
    // addLiveStatusItem (initial) → connectSSE → startStatusPolling (5s) → startScanSummaryPolling
    addLiveStatusItem({
      scanId,
      target,
      status: data.status || "running",
      tools: [],
      phase: "Creating scan and starting initial clue gathering…",
      owaspCategory: data.owasp_category_name || data.owasp_category || owasp,
      serverTimestamp: data.created_at || data.updated_at
    });
    if (scanId) {
      console.log("Starting SSE connection and polling for scan:", scanId);
      await refreshScansViews(); // Populate dropdown with new scan before selecting
      connectSSE(scanId);
      startStatusPolling(scanId);
      startScanSummaryPolling(scanId);
      // Refresh Severity Distribution and Security Trend immediately so they show current state
      refreshDashboardCharts().catch((e) => console.warn("Initial chart refresh:", e));
    } else {
      console.error("No scan ID returned from API");
    }
    refreshScansViews();
  } catch (err) {
    console.error(err);
    const msg = (err && (err.message || err.detail)) ? String(err.message || err.detail) : "";
    if (msg && (msg.includes("another scan") || msg.toLowerCase().includes("still running"))) {
      try {
        const runningCheck = await apiRequest("/api/scans/any-running", { method: "GET" });
        if (runningCheck && runningCheck.running_scan_id) {
          showRunningScanBlockedPopup(runningCheck.running_scan_id);
        } else {
          showStyledPopup("Another scan is still running. Please wait for it to complete before starting a new one.");
        }
      } catch (_) {
        showStyledPopup("Another scan is still running. Please wait for it to complete before starting a new one.");
      }
    } else if (msg) {
      // Show backend error message (e.g., "Wrong Domain")
      help.textContent = msg;
    } else {
      help.textContent = "Failed to launch scan. Check backend or API base URL.";
    }
  } finally {
    runBtn.disabled = false;
  }
}

function clearLaunchForm() {
  document.getElementById("launchForm").reset();
  const chips = document.querySelectorAll(".tool-chip");
  chips.forEach((c) => c.classList.remove("active"));
}

/* ===== LIVE STATUS TRACKER – Phase Derivation =====
 * Maps status and tools to human-readable phase (Creating, Clues Gathering, Tool Run: X, Completed)
 */
function deriveScanPhase(status, tools, phaseInfo = null) {
  const normalizedStatus = (status || "").toLowerCase();
  const toolList = Array.isArray(tools) ? tools : [];

  // If phaseInfo is provided, use detailed phase information
  if (phaseInfo && phaseInfo.currentPhase) {
    switch(phaseInfo.currentPhase) {
      case "creating":
        return "Creating";
      case "clues_gathering":
        return "Clues Gathering";
      case "sending":
        return "Clues sent to AI";
      case "ai_decision":
        return "AI Decision";
      case "tool_execution":
        const currentTool = phaseInfo.currentTool;
        return `Tool Run: ${currentTool || 'N/A'}`;
      case "completed":
        return "Completed";
      case "failed":
        return "Failed";
      default:
        break;
    }
  }

  // Fallback to original logic if no phase info
  if (normalizedStatus === "creating") {
    return "Creating";
  }

  if (normalizedStatus === "preparing") {
    if (toolList.length === 0) {
      return "Clues Gathering";
    }
    return "Preparing for tool execution";
  }

  if (normalizedStatus === "running") {
    // Show current running tool if available
    const runningTools = toolList.filter(t => (t.status || "").toLowerCase() === "running");
    if (runningTools.length > 0) {
      return `Tool Run: ${runningTools[0].tool_name}`;
    }
    return "Running tools";
  }

  if (normalizedStatus === "completed" || normalizedStatus === "completed_with_errors") {
    return "Completed";
  }

  if (normalizedStatus === "failed") {
    return "Failed";
  }

  return "Updating status…";
}

/* addLiveStatusItem: Adds snapshot to liveStatus (keeps last 6). Called from:
 * - Polling: startStatusPolling (every 5s) via GET /api/scans/{id}/status
 * - SSE/WebSocket: handleToolStart, handleToolOutput, handleToolComplete, handleInitialStatus, handleScanPhaseUpdate, handleLogMessage
 */
function addLiveStatusItem({ scanId, target, status, tools = [], phase, owaspCategory, serverTimestamp, phaseInfo = null, fallbackActive = false, fromPolling = false }) {
  const statusLower = (status || "").toLowerCase();
  const isCompleted = statusLower === "completed" || statusLower === "completed_with_errors";

  // Once a scan is completed, show only one row: do not add any more completed updates for this scan
  if (isCompleted) {
    const alreadyHasCompleted = liveStatus.some(
      (item) => item.scanId === scanId && ((item.status || "").toLowerCase() === "completed" || (item.status || "").toLowerCase() === "completed_with_errors")
    );
    if (alreadyHasCompleted) return;
  }

  const now = Date.now();
  const lastUpdate = lastLiveStatusUpdateByScan[scanId];
  const isFinal = isCompleted || statusLower === "failed";
  const intervalOk = !lastUpdate || (now - lastUpdate) >= LIVE_STATUS_UPDATE_INTERVAL_MS;
  if (!fromPolling && !isFinal && !intervalOk) return;
  lastLiveStatusUpdateByScan[scanId] = now;

  const sourceTime = serverTimestamp ? (parseDateAsUTC(serverTimestamp) || new Date()) : new Date();
  const displayTime = lastLiveStatusDisplayTimeByScan[scanId]
    ? new Date(lastLiveStatusDisplayTimeByScan[scanId].getTime() + LIVE_STATUS_UPDATE_INTERVAL_MS)
    : sourceTime;
  lastLiveStatusDisplayTimeByScan[scanId] = displayTime;

  console.log("addLiveStatusItem called with:", { scanId, target, status, tools, phase, owaspCategory, serverTimestamp, phaseInfo });
  console.log("Current liveStatus before update:", liveStatus);

  const cleanTools = tools.map(tool => ({
    ...tool,
    tool_name: tool.tool_name || tool.name,
    status: tool.status || "queued",
    started_at: tool.started_at || null,
    finished_at: tool.finished_at || null,
  }));

  const baseEntry = {
    scanId,
    target: target || "",
    status: status || "running",
    tools: cleanTools,
    owaspCategory,
    phase: phase || deriveScanPhase(status, cleanTools, phaseInfo),
    phaseInfo: phaseInfo,
    fallbackActive: fallbackActive || false,
    phaseHistory: phaseInfo ? [{ phase: phaseInfo.currentPhase, timestamp: new Date(), ...phaseInfo }] : [],
    createdAt: displayTime,
    updatedAt: displayTime,
  };

  liveStatus.unshift(baseEntry);
  liveStatus = liveStatus.slice(0, 6);

  console.log("Current liveStatus after update:", liveStatus);

  // Use requestAnimationFrame to prevent UI blocking
  requestAnimationFrame(() => {
    renderLiveStatus();
  });
}

/* renderLiveStatus: Updates #liveStatusList in the DOM with target, phase, OWASP, tool status (✓/▶/⏳/✗), timestamp.
 * Shows rolling snapshots: each 5s poll/update adds a row (max 6), so you see history from creation. */
function renderLiveStatus() {
  console.log("renderLiveStatus called with liveStatus:", liveStatus);
  
  const list = document.getElementById("liveStatusList");
  if (!list) {
    console.error("liveStatusList element not found!");
    return;
  }
  
  list.innerHTML = "";
  // Show all snapshots (newest first) – each 5s update is a row, up to 6
  const itemsToShow = liveStatus.slice(0, 6);

  itemsToShow.forEach((item, index) => {
    const tools = Array.isArray(item.tools) ? item.tools : [];
    const phaseText = item.phase || deriveScanPhase(item.status, tools, item.phaseInfo);
    const phaseLower = (phaseText || "").toLowerCase();
    const currentPhase = (item.phaseInfo && item.phaseInfo.currentPhase) || "";
    const scanStatus = (item.status || "").toLowerCase();

    // Phase-based badge label: creating | preparing | sending | running | completed | failed
    let badgeLabel = "running";
    if (scanStatus === "completed" || scanStatus === "completed_with_errors") {
      badgeLabel = "completed";
    } else if (scanStatus === "failed") {
      badgeLabel = "failed";
    } else if (currentPhase === "creating" || phaseLower === "creating" || phaseLower.startsWith("creating")) {
      badgeLabel = "creating";
    } else if (currentPhase === "clues_gathering" || phaseLower.includes("clues gathering")) {
      badgeLabel = "preparing";
    } else if (currentPhase === "sending" || phaseLower === "sending" || phaseLower.includes("clues sent to ai")) {
      badgeLabel = "sending";
    } else if (currentPhase === "ai_decision" || phaseLower.includes("ai decision")) {
      badgeLabel = "running";
    } else {
      badgeLabel = "running";
    }

    const badgeClass = badgeLabel === "completed" ? "badge-completed" : badgeLabel === "failed" ? "badge-failed" : "badge-running";
    const owaspName = item.owaspCategory ? getOwaspCategoryName(item.owaspCategory) : "";
    // Per snapshot: show when this row was captured (poll/SSE), not scan created_at — otherwise every 5s row looks identical
    const timeStr = item.updatedAt
      ? formatCurrentTime(item.updatedAt)
      : item.createdAt
        ? formatCurrentTime(item.createdAt)
        : "just now";

    let statusDesc = "";
    if (scanStatus === "completed" || scanStatus === "completed_with_errors") {
      statusDesc = "All tools finished. Scan completed.";
    } else if (scanStatus === "failed") {
      statusDesc = "Scan failed.";
    } else if (currentPhase === "creating" || phaseLower === "creating" || phaseLower.startsWith("creating")) {
      statusDesc = "Creating";
    } else if (currentPhase === "clues_gathering" || phaseLower.includes("clues gathering")) {
      statusDesc = "Clues Gathering";
    } else if (currentPhase === "sending" || phaseLower === "sending" || phaseLower.includes("clues sent to ai")) {
      statusDesc = "Sending Clues data to AI for Analysis";
    } else if (currentPhase === "ai_decision" || phaseLower.includes("ai decision")) {
      statusDesc = "AI Decision";
    } else if (tools.length > 0 || phaseLower.includes("tool run") || phaseLower === "running tools") {
      const completed = tools.filter(t => t.status === "completed").length;
      const running = tools.filter(t => t.status === "running").length;
      const queued = tools.filter(t => t.status === "queued").length;
      const failed = tools.filter(t => t.status === "failed").length;
      statusDesc = `Running tools → completed: ${completed}, running: ${running}, queued: ${queued}, failed: ${failed}, timeout: 0`;
    } else {
      statusDesc = phaseText;
    }

    let toolsDisplay = "";
    if (tools.length > 0 && (badgeLabel === "running" || badgeLabel === "completed")) {
      const scanComplete = scanStatus === "completed" || scanStatus === "completed_with_errors";
      const toolNames = tools.map(t => {
        const s = (t.status || "").toLowerCase();
        if (s === "completed") return `${t.tool_name} ✓`;
        if (s === "running") return `${t.tool_name} ▶`;
        if (s === "queued") return `${t.tool_name} ⏳`;
        if (s === "failed") return scanComplete ? `${t.tool_name} ✗` : `${t.tool_name} ✓`;
        return t.tool_name;
      }).join(" ");
      toolsDisplay = `Tools: ${toolNames}`;
    }

    const titleText = item.scanId
      ? `Scan #${item.scanId}${item.target ? ` · ${escapeHtml(item.target)}` : ""}`
      : escapeHtml(item.target || "");

    const li = document.createElement("li");
    li.className = "status-item";
    li.innerHTML = `
      <div class="status-item-body">
        <div class="status-header">
          <div>
            ${titleText ? `<div class="status-title">${titleText}</div>` : ""}
            ${owaspName ? `<div class="status-subtitle">OWASP: ${escapeHtml(owaspName)}</div>` : ""}
          </div>
          <span class="status-item-badge ${badgeClass}">${badgeLabel}</span>
        </div>
        ${statusDesc ? `<div style="font-size: 12px; color: #cbd5e1; margin-top: 6px;">${statusDesc}</div>` : ""}
        ${toolsDisplay ? `<div style="font-size: 12px; color: #cbd5e1; margin-top: 6px;">${toolsDisplay}</div>` : ""}
        <div style="font-size: 11px; color: #64748b; margin-top: 8px;">Updated ${timeStr}</div>
      </div>
    `;

    list.appendChild(li);
  });
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

/** Exclude Sublist3r banner/log rows from All Findings (so only real subdomains show). */
function isSublist3rNoiseRow(r) {
  if (!r || (r.tool || "").toLowerCase() !== "sublist3r") return false;
  const loc = (r.location || "").replace(/\x1b\[[0-9;]*[a-zA-Z]?/g, "").replace(/\[\d*(?:;\d*)*[a-zA-Z]?/g, "").trim();
  const desc = (r.description || "").replace(/\x1b\[[0-9;]*[a-zA-Z]?/g, "").replace(/\[\d*(?:;\d*)*[a-zA-Z]?/g, "").trim();
  if (!loc) return true;
  const text = (loc + " " + desc).toLowerCase();
  const noise = ["searching now", "enumerating subdomains", "coded by", "error:", "probably now is blocking", "finished now the", "___", "|____/", "/ ___|", "\\___ \\", "___) |", "aboul3la"];
  if (noise.some(p => text.includes(p))) return true;
  if (loc.startsWith("[") || loc.startsWith("#")) return true;
  if (/[_ ]/.test(loc) && /_/.test(loc)) return true;
  if (/[^\w.\-]/.test(loc) || /\s/.test(loc)) return true;
  return false;
}

function formatDateTimeWithSeconds(date) {
  const d = date ? parseDateAsUTC(date) : new Date();
  const hours = d.getHours().toString().padStart(2, '0');
  const minutes = d.getMinutes().toString().padStart(2, '0');
  const seconds = d.getSeconds().toString().padStart(2, '0');
  return `Updated ${hours}:${minutes}:${seconds}`;
}

function formatCurrentTime(date) {
  const d = date ? parseDateAsUTC(date) : new Date();
  let hours = d.getHours();
  const minutes = d.getMinutes().toString().padStart(2, '0');
  const seconds = d.getSeconds().toString().padStart(2, '0');
  const ampm = hours >= 12 ? 'PM' : 'AM';
  hours = hours % 12;
  hours = hours ? hours : 12; // the hour '0' should be '12'
  return `${hours}:${minutes}:${seconds} ${ampm}`;
}

/* startStatusPolling: Primary source. GET /api/scans/{id}/status every 5s → addLiveStatusItem → renderLiveStatus.
 * Stops when status is completed/failed or after 3 retries. */
function startStatusPolling(scanId) {
  // Clear any existing interval for this scanId
  if (statusPollingIntervals[scanId]) {
    clearTimeout(statusPollingIntervals[scanId]);
  }
  
  // Track retry attempts
  let retryCount = 0;
  const maxRetries = 3;

  const pollIntervalMs = 5000;
  let nextPollAt = Date.now();

  const poll = async () => {
    nextPollAt += pollIntervalMs;
    try {
      const pollTimestamp = new Date(nextPollAt - pollIntervalMs);
      const data = await apiRequest(API_ROUTES.scanStatus(scanId), {
        method: "GET",
        cache: "no-store"
      });
      
      // Reset retry count on successful request
      retryCount = 0;
      
      const status = data.status || "running";
      const target = data.target || "";
      const tools = data.tools || [];
      const phaseInfo = data.phase ? { currentPhase: data.phase } : null;
      const phase = deriveScanPhase(status, tools, phaseInfo);
      const fallbackActive = Boolean(data.ai_fallback_active);

      addLiveStatusItem({
        scanId,
        target,
        status,
        tools,
        phase,
        phaseInfo,
        fallbackActive,
        owaspCategory: data.owasp_category_name || data.owasp_category,
        serverTimestamp: pollTimestamp,
        fromPolling: true
      });

      if (fallbackActive && !fallbackNotificationsShown[scanId]) {
        fallbackNotificationsShown[scanId] = true;
        showNotification(
          "AI fallback mode active: using safe default tool set for this scan.",
          "warning"
        );
      }

      if (status === "completed" || status === "completed_with_errors" || status === "failed") {
        clearTimeout(statusPollingIntervals[scanId]);
        delete statusPollingIntervals[scanId]; // Clean up the interval tracker
        
        // Auto-refresh scans table and update charts with latest findings
        await refreshScansViews();
        
        // Refresh dashboard charts immediately (short delay so DB has committed)
        try {
          await new Promise(resolve => setTimeout(resolve, 800));
          await refreshDashboardCharts();
        } catch (e) {
          console.warn("Failed to refresh charts after scan completion", e);
        }
      }
    } catch (e) {
      console.warn(`Status polling error (attempt ${retryCount + 1}/${maxRetries}):`, e);
      retryCount++;
      
      // If we've exceeded max retries, stop polling
      if (retryCount >= maxRetries) {
        console.warn(`Max retries exceeded for scan ${scanId}, stopping polling`);
        clearTimeout(statusPollingIntervals[scanId]);
        delete statusPollingIntervals[scanId];
        return;
      }
      
      // Exponential backoff - wait longer between retries
      const backoffDelay = Math.min(1000 * Math.pow(2, retryCount), 10000); // Max 10 seconds
      console.log(`Retrying in ${backoffDelay}ms...`);
      
      // Don't clear interval on error - just retry silently
      // The interval will continue and retry automatically
    }
    if (statusPollingIntervals[scanId]) {
      const delay = Math.max(0, nextPollAt - Date.now());
      statusPollingIntervals[scanId] = setTimeout(poll, delay);
    }
  };
  
  // Store the interval ID for this scan
  statusPollingIntervals[scanId] = setTimeout(poll, pollIntervalMs);
}

function startScanSummaryPolling(scanId) {
  console.log("Starting scan summary polling for scan:", scanId);
  
  // Clear any existing interval
  if (scanSummaryInterval) {
    clearInterval(scanSummaryInterval);
  }
  
  currentScanId = scanId;
  
  // Reset Scanned Target Summary so it shows the new scan (refresh previous content)
  const container = document.getElementById("scanSummaryContainer");
  if (container) {
    container.innerHTML = `
      <div class="scan-summary-placeholder">
        <div class="summary-placeholder-icon">⏳</div>
        <div class="summary-placeholder-text">Loading scan #${scanId}…</div>
        <div class="summary-placeholder-subtext">Summary will update as the scan runs.</div>
      </div>`;
    container.dataset.scanId = String(scanId);
    delete container.dataset.reportTimestamp;
  }
  
  // Show live status indicator
  const statusBadge = document.getElementById("scanSummaryStatus");
  if (statusBadge) {
    statusBadge.classList.remove("hidden");
    statusBadge.classList.add("live");
    console.log("Live status badge activated");
  } else {
    console.warn("Status badge not found");
  }

  // Create or update progress widget (initially 0%)
  createOrUpdateProgressWidget(scanId, 0, 'Starting');
  
  // Update dropdown to show this scan if available
  const scanFilter = document.getElementById('scanSummaryFilter');
  if (scanFilter) {
    // Try to find and select this scan in dropdown
    const optionExists = scanFilter.querySelector(`option[value="${scanId}"]`);
    if (optionExists) {
      scanFilter.value = scanId;
    }
  }
  
  // Test immediate fetch with error handling
  console.log("Testing immediate fetch");
  apiRequest(API_ROUTES.scanIntelligence(scanId), { method: "GET" })
    .then(data => {
      console.log("Immediate fetch successful:", data);
      if (data && (data.sections || data.message)) {
        renderScanSummary(data);
      } else {
        // Data not ready yet, show loading state
        console.log("Intelligence summary not ready yet, waiting for polling");
      }
    })
    .catch(error => {
      console.error("Immediate fetch failed:", error);
      // Try alternative approach
      console.log("Trying direct fetch approach");
      fetch(`/api/scans/${scanId}/intelligence-summary`)
        .then(response => response.json())
        .then(data => {
          console.log("Direct fetch successful:", data);
          if (data && (data.sections || data.message)) {
            renderScanSummary(data);
          }
        })
        .catch(err => console.error("Direct fetch also failed:", err));
    });
  
  // Start polling for intelligence summary
  console.log("Setting up polling interval");
  scanSummaryInterval = setInterval(async () => {
    console.log("Polling for scan summary, scanId:", scanId);
    try {
      const summary = await apiRequest(API_ROUTES.scanIntelligence(scanId), { method: "GET" });
      console.log("Received summary:", summary);
      
      // Only render if we have valid data
      if (summary && (summary.sections || summary.message)) {
        renderScanSummary(summary);
        
        // Update floating progress widget based on executive summary content (tools completed / total)
        let progressPercent = 0;
        let progressStatus = summary.status || 'Running';
        let toolsCompleted = 0;
        let toolsTotal = 0;

        if (Array.isArray(summary.sections)) {
          const execSection = summary.sections.find((s) => s.type === 'executive_summary');
          if (execSection && execSection.content) {
            toolsCompleted = Number(execSection.content.tools_completed || 0);
            toolsTotal = Number(execSection.content.tools_total || 0);
            if (execSection.content.status) {
              progressStatus = execSection.content.status;
            }
          }
        }

        if (toolsTotal > 0) {
          progressPercent = Math.round((toolsCompleted / toolsTotal) * 100);
        }

        // Fallback if not available
        if (toolsTotal === 0 && summary.findings_total && summary.findings_total > 0) {
          const done = (summary.findings_found || 0);
          progressPercent = Math.min(100, Math.round((done / summary.findings_total) * 100));
        }

        createOrUpdateProgressWidget(scanId, progressPercent, progressStatus);

        // Update severity distribution chart while scan is running
        if (typeof updateSeverityScope === 'function') {
          updateSeverityScope('all').catch((e) => console.warn('Failed to update severity distribution during scan:', e));
        }

        // Update trend analytics less frequently during scan (every 30s)
        try {
          const now = Date.now();
          if (now - lastTrendUpdateAt >= 30000) {
            lastTrendUpdateAt = now;
            if (typeof updateTrendFromApi === 'function') {
              const rangeInput = document.getElementById('trendRange') || null;
              const startDate = rangeInput && rangeInput.value ? rangeInput.value : new Date(Date.now() - 6 * 24 * 60 * 60 * 1000).toISOString().split('T')[0];
              const endDate = new Date().toISOString().split('T')[0];
              updateTrendFromApi(startDate, endDate).catch((e) => console.warn('Failed to update trend analytics during scan:', e));
            }
          }
        } catch (e) {
          console.warn('Trend polling helper exception:', e);
        }

      }
      
      // Stop polling when scan is complete; refresh dashboard charts immediately
      if (summary.status === "completed" || summary.status === "completed_with_errors" || summary.status === "failed") {
        console.log("Scan completed, stopping polling");
        removeProgressWidget();
        stopScanSummaryPolling();
        try {
          await new Promise(resolve => setTimeout(resolve, 800));
          await refreshDashboardCharts();
        } catch (e) {
          console.warn("Failed to refresh charts after scan completion", e);
        }
      }
    } catch (e) {
      console.warn("Scan summary polling error", e);
      // Don't stop polling on error - might be temporary
    }
  }, 3000); // Poll every 3 seconds for smoother updates
  console.log("Polling interval set up");
}

function stopScanSummaryPolling() {
  if (scanSummaryInterval) {
    clearInterval(scanSummaryInterval);
    scanSummaryInterval = null;
  }
  
  // Hide live status indicator
  const statusBadge = document.getElementById("scanSummaryStatus");
  if (statusBadge) {
    statusBadge.classList.add("hidden");
    statusBadge.classList.remove("live");
  }
  
  // Preserve the last scan ID for saving completed scan results
  if (currentScanId) {
    lastScanId = currentScanId;
  }
  currentScanId = null;
}

// Manual trigger function for testing
function testScanSummary(scanId) {
  console.log("Manual test triggered for scan:", scanId);
  startScanSummaryPolling(scanId);
}

// Make it globally available for console testing
window.testScanSummary = testScanSummary;

function renderLiveOutputInSummary(scanId) {
  const container = document.getElementById("scanSummaryContainer");
  if (!container) return;

  const scanItem = liveStatus.find(item => item.scanId === scanId);
  const tools = scanItem ? (scanItem.tools || []) : [];
  const toolNames = tools.map(t => t.tool_name);

  let hasOutput = false;
  const sections = [];
  for (const tool of toolNames) {
    const key = `scan_${scanId}_${tool}`;
    const track = commandTracking[key];
    if (track && track.output && track.output.length > 0) {
      hasOutput = true;
      const status = (track.status || "running").toLowerCase();
      const statusIcon = status === "completed" ? "✓" : status === "failed" ? "✗" : "▶";
      const lines = track.output.map(o => {
        const cls = o.is_error ? "output-line error" : "output-line";
        return `<div class="${cls}">${escapeHtml(o.text)}</div>`;
      }).join("");
      sections.push(`
        <div class="tool-output-section">
          <div class="tool-name">${escapeHtml(tool)} ${statusIcon}</div>
          <div class="command-output-content real-time-output">${lines}</div>
        </div>
      `);
    }
  }

  let liveEl = container.querySelector("[data-live-output]");
  if (hasOutput) {
    if (!liveEl) {
      liveEl = document.createElement("div");
      liveEl.setAttribute("data-live-output", "true");
      liveEl.className = "summary-section summary-section-new";
      liveEl.style.animationDelay = "0s";
      container.appendChild(liveEl);
    }
    liveEl.innerHTML = `
      <div class="summary-section-header">
        <div class="summary-section-icon">📟</div>
        <h3 class="summary-section-title">Live Tool Output</h3>
      </div>
      <div class="summary-section-content">${sections.join("")}</div>
    `;
    liveEl.querySelectorAll(".real-time-output").forEach(el => {
      el.scrollTop = el.scrollHeight;
    });
  } else if (liveEl) {
    liveEl.remove();
  }
}

function renderScanSummary(summary) {
  const container = document.getElementById("scanSummaryContainer");
  if (!container) return;

  if (summary.scan_id) {
    container.dataset.scanId = String(summary.scan_id);
  }

  // Use scan's completed_at time if available, otherwise fallback to created_at or current time
  let createdAt = new Date();

  // If intelligence summary returns created_at, use it first (stable saved scan time)
  if (summary.created_at) {
    createdAt = parseDateAsUTC(summary.created_at) || new Date();
  } else if (summary.completed_at) {
    createdAt = parseDateAsUTC(summary.completed_at) || new Date();
  }

  // Try to get the actual scan completion time from stored scan data
  if (summary.scan_id) {
    const cachedScans = window.cachedTargetScans || [];
    const matchingScan = cachedScans.find(s => s.id === summary.scan_id);
    if (matchingScan) {
      if (matchingScan.created_at) {
        createdAt = parseDateAsUTC(matchingScan.created_at) || createdAt;
      } else if (matchingScan.completed_at) {
        createdAt = parseDateAsUTC(matchingScan.completed_at) || createdAt;
      }
    }
  }

  // Keep the same report timestamp after first render for a given scan.
  // This prevents rapid polling from changing the visible "Report generated" value.
  if (summary.scan_id && container.dataset.scanId && String(container.dataset.scanId) !== String(summary.scan_id)) {
    delete container.dataset.reportTimestamp;
  }

  if (container.dataset.reportTimestamp) {
    createdAt = parseDateAsUTC(container.dataset.reportTimestamp) || createdAt;
  } else {
    container.dataset.reportTimestamp = createdAt.toISOString();
  }
  
  // Clear placeholder if present
  const placeholder = container.querySelector(".scan-summary-placeholder");
  if (placeholder) {
    container.innerHTML = "";
  }
  
  // Handle case where API returns a message but no sections
  if (summary.sections && summary.sections.length === 0 && summary.message) {
    container.innerHTML = `
      <div class="summary-section">
        <div class="summary-section-header">
          <div class="summary-section-icon">ℹ️</div>
          <h3 class="summary-section-title">Scan Status</h3>
        </div>
        <div class="summary-section-content">
          <p>${summary.message}</p>
        </div>
        <div class="summary-timestamp">Report generated: ${formatDate(createdAt)}</div>
      </div>
    `;
    const scanFilter = document.getElementById("scanSummaryFilter");
    if (scanFilter && scanFilter.value) {
      const scanId = parseInt(scanFilter.value, 10);
      container.dataset.scanId = scanId;
      renderLiveOutputInSummary(scanId);
    }
    return;
  }

  // Remove any existing "All Findings" section (we no longer show it in Scanned Target Summary)
  container.querySelectorAll("[data-section-type=\"findings_table\"]").forEach(el => el.remove());

  // Collect existing timestamps to preserve them during re-render
  const existingTimestamps = {};
  container.querySelectorAll('.summary-section').forEach(section => {
    const sectionType = section.getAttribute('data-section-type');
    const timestampEl = section.querySelector('.summary-timestamp');
    if (sectionType && timestampEl) {
      existingTimestamps[sectionType] = timestampEl.textContent;
    }
  });

  // Render each section - use unique id so multiple tool_result/vulnerability sections don't overwrite each other
  summary.sections.forEach((section, index) => {
    if (section.type === "findings_table") return; // Skip All Findings section

    const sectionId = `${section.type}__${(section.title || section.content?.title || index).toString().replace(/[^a-zA-Z0-9]/g, "_")}__${index}`;
    let sectionEl = container.querySelector(`[data-section-id="${sectionId}"]`);
    // Preserve <details> open state (polling updates re-render sections)
    const preservedDetailsOpenKeys = new Set();
    const detailsKeyPrefix = sectionId;
    // Preserve selected severity filter (so it doesn't auto-reset during polling updates)
    let preservedSelectedSeverity = "";
    
    if (sectionEl) {
      // Update existing section but keep original timestamp
      sectionEl.classList.remove('summary-section-new');
      sectionEl.querySelectorAll('details[data-details-key][open]').forEach((d) => {
        const key = d.getAttribute('data-details-key');
        if (key) preservedDetailsOpenKeys.add(key);
      });
      const prevExecContent = sectionEl.querySelector('.executive-summary-content');
      if (prevExecContent && prevExecContent.dataset && prevExecContent.dataset.selectedSeverity) {
        preservedSelectedSeverity = String(prevExecContent.dataset.selectedSeverity || "").trim();
      }
    } else {
      // Create new section
      sectionEl = document.createElement("div");
      sectionEl.className = "summary-section summary-section-new";
      sectionEl.setAttribute("data-section-type", section.type);
      sectionEl.setAttribute("data-section-id", sectionId);
      
      // Add fade-in animation with delay
      sectionEl.style.animationDelay = `${index * 0.2}s`;
    }

    // Preserve horizontal scroll positions for elements inside this section (e.g., Key Findings table)
    const preservedScrollLeftByKey = new Map();
    if (sectionEl) {
      sectionEl.querySelectorAll('[data-scroll-key]').forEach((el) => {
        const k = el.getAttribute('data-scroll-key');
        if (!k) return;
        try {
          preservedScrollLeftByKey.set(k, el.scrollLeft || 0);
        } catch (_) {}
      });
    }
    
    let contentHtml = "";
    
    // Generate content based on section type
    switch (section.type) {
      case "executive_summary":
        const ex = section.content;
        const findingsBySev = ex.findings_by_severity || {};
        const dashboardSevColors = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#3b82f6', info: '#6b7280' };
        const riskLevelKey = (ex.risk_level || "na").toLowerCase().replace("/", "");
        const riskLevelColor = dashboardSevColors[riskLevelKey] || '#6b7280';

        const sevCountsFromFindingsBySev = {
          critical: Array.isArray(findingsBySev.critical) ? findingsBySev.critical.length : Number(findingsBySev.critical || 0),
          high: Array.isArray(findingsBySev.high) ? findingsBySev.high.length : Number(findingsBySev.high || 0),
          medium: Array.isArray(findingsBySev.medium) ? findingsBySev.medium.length : Number(findingsBySev.medium || 0),
          low: Array.isArray(findingsBySev.low) ? findingsBySev.low.length : Number(findingsBySev.low || 0),
          info: Array.isArray(findingsBySev.info) ? findingsBySev.info.length : Number(findingsBySev.info || 0),
        };

        const reportSeverityCounts = coerceSeverityCounts(
          Object.keys(sevCountsFromFindingsBySev).some((k) => typeof sevCountsFromFindingsBySev[k] === 'number')
            ? sevCountsFromFindingsBySev
            : {
                critical: Number(ex.critical || 0),
                high: Number(ex.high || 0),
                medium: Number(ex.medium || 0),
                low: Number(ex.low || 0),
                info: Number(ex.info || 0),
              }
        );

        const sevData = [
          { key: "critical", count: reportSeverityCounts.critical, label: "Critical", color: dashboardSevColors.critical },
          { key: "high", count: reportSeverityCounts.high, label: "High", color: dashboardSevColors.high },
          { key: "medium", count: reportSeverityCounts.medium, label: "Medium", color: dashboardSevColors.medium },
          { key: "low", count: reportSeverityCounts.low, label: "Low", color: dashboardSevColors.low },
          { key: "info", count: reportSeverityCounts.info, label: "Info", color: dashboardSevColors.info },
        ];
        contentHtml = `
          <div class="summary-section-header">
            <div class="summary-section-icon">${section.icon}</div>
            <h3 class="summary-section-title">${section.title}</h3>
          </div>
          <div class="summary-section-content executive-summary-content" data-findings-by-severity="${encodeURIComponent(JSON.stringify(findingsBySev))}">
            <div class="executive-grid">
              <div class="executive-item executive-item-target">
                <span class="executive-label">Target:</span>
                <span class="executive-value executive-value-target" title="${escapeHtml(ex.target || "")}">${escapeHtml(ex.target || "-")}</span>
              </div>
              <div class="executive-item">
                <span class="executive-label">Status:</span>
                <span class="executive-value exec-status-${(ex.status || "").toLowerCase()}">${ex.status || "-"}</span>
              </div>
              <div class="executive-item">
                <span class="executive-label">Total Findings:</span>
                <span class="executive-value">${ex.total_findings || 0}</span>
              </div>
              <div class="executive-item">
                <span class="executive-label">Risk Level:</span>
                <span class="executive-value risk-badge risk-${riskLevelKey}" style="background-color:${riskLevelColor}; color:#fff">${ex.risk_level || "N/A"}</span>
              </div>
              <div class="executive-item">
                <span class="executive-label">Tools:</span>
                <span class="executive-value">${ex.tools_completed || 0}/${ex.tools_total || 0} completed</span>
              </div>
              ${((ex.status || '').toLowerCase() === 'completed' || (ex.status || '').toLowerCase() === 'completed_with_errors') ? `
              <div class="executive-item">
                <span class="executive-label">Risk Score:</span>
                <span class="executive-value">${ex.risk_score != null ? ex.risk_score + '/100' : 'N/A'}</span>
              </div>
              ` : ''}
              ${(ex.tools_failed_names || []).length > 0 ? `
              <div class="executive-item executive-item-full">
                <span class="executive-label">Failed/Timeout:</span>
                <span class="executive-value failed-tools-list">${(ex.tools_failed_names || []).join(", ")}</span>
              </div>
              ` : ""}
              ${ex.clues_summary ? `
              <div class="executive-item executive-item-full">
                <span class="executive-label">Clues:</span>
                <span class="executive-value clues-summary">
                  ${escapeHtml(ex.clues_summary)}
                  ${ex.clues ? `
                    <details class="exec-clues-details" data-details-key="exec-clues">
                      <summary>View clues</summary>
                      ${(() => {
                        const c = ex.clues || {};
                        const openPorts = Array.isArray(c.open_ports) ? c.open_ports : [];
                        const ips = Array.isArray(c.ip_addresses) ? c.ip_addresses : [];
                        const services = Array.isArray(c.http_services) ? c.http_services : [];
                        const servers = Array.isArray(c.server_headers) ? c.server_headers : [];
                        const titles = Array.isArray(c.page_titles) ? c.page_titles : [];
                        const codes = Array.isArray(c.status_codes) ? c.status_codes : [];
                        const tech = Array.isArray(c.technologies) ? c.technologies : [];
                        const maxLen = Math.max(openPorts.length, ips.length, services.length, servers.length, titles.length, codes.length, tech.length, 1);
                        const at = (arr, i) => (arr && arr[i] != null && String(arr[i]).trim() !== "") ? escapeHtml(String(arr[i])) : "—";
                        const rows = Array.from({ length: maxLen }).map((_, i) => `
                          <tr>
                            <td>${at(openPorts, i)}</td>
                            <td>${at(ips, i)}</td>
                            <td>${at(services, i)}</td>
                            <td>${at(codes, i)}</td>
                            <td>${at(titles, i)}</td>
                            <td>${at(servers, i)}</td>
                            <td>${at(tech, i)}</td>
                          </tr>
                        `).join("");
                        return `
                          <div class="exec-clues-table-wrap">
                            <table class="exec-clues-table">
                              <thead>
                                <tr>
                                  <th>Open ports</th>
                                  <th>IP found</th>
                                  <th>HTTP services</th>
                                  <th>Status codes</th>
                                  <th>Page titles</th>
                                  <th>Server</th>
                                  <th>Technologies</th>
                                </tr>
                              </thead>
                              <tbody>${rows}</tbody>
                            </table>
                          </div>
                        `;
                      })()}
                    </details>
                  ` : ""}
                </span>
              </div>
              ` : ""}
            </div>
            <div class="executive-severity-row">
              ${sevData.map(s => `
                <button type="button" class="sev-badge ${s.key}" data-severity="${s.key}" data-count="${s.count}" title="Click to show ${s.label} findings" style="background-color:${s.color}; color:#fff; border-color:${s.color}">${s.count} ${s.label}</button>
              `).join("")}
            </div>
            ${ex.severity_combined_note ? `<p class="executive-severity-note">Severity distribution: ${ex.severity_combined_note}</p>` : ""}
            <div class="executive-findings-filtered" style="display: none;">
              <p class="executive-subtitle"><strong>Key Findings for <span class="filtered-severity-label"></span>:</strong></p>
              <div class="executive-findings-filtered-container"></div>
            </div>
            ${(() => {
              // Preferred Key Findings table (professional fixed columns)
              const v2Cols = ex.key_findings_v2_columns;
              const v2Rows = ex.key_findings_v2_rows;
              if (Array.isArray(v2Cols) && v2Cols.length > 0 && Array.isArray(v2Rows) && v2Rows.length > 0) {
                const cols = v2Cols.filter(c => c != null && String(c).trim() !== '');
                const escape = (v) => {
                  if (v == null || v === '') return '—';
                  const s = String(v).substring(0, 800);
                  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
                };
                const headerCells = cols.map(h => `<th>${escape(h)}</th>`).join('');
                const bodyRows = v2Rows.map(row => {
                  if (!row || typeof row !== 'object') return '';
                  return `<tr>${cols.map(c => `<td class="key-find-col">${escape(row[c])}</td>`).join('')}</tr>`;
                }).filter(Boolean).join('');
                if (bodyRows) {
                  return `
            <div class="executive-findings-default">
              <p class="executive-subtitle"><strong>Key Findings:</strong></p>
              ${ex.key_findings_note ? `<p class="executive-findings-note">${escapeHtml(ex.key_findings_note)}</p>` : ""}
              <div class="key-findings-table-wrap" data-scroll-key="key-findings">
                <table class="key-findings-table">
                  <thead><tr>${headerCells}</tr></thead>
                  <tbody>${bodyRows}</tbody>
                </table>
              </div>
            </div>
            `;
                }
              }
              const kft = ex.key_findings_table;
              if (kft && Array.isArray(kft.columns) && kft.columns.length > 0 && Array.isArray(kft.rows) && kft.rows.length > 0) {
                const cols = kft.columns.filter(c => c != null && String(c).trim() !== '');
                if (cols.length > 0) {
                  const escape = (v) => {
                    if (v == null || v === '') return '—';
                    const s = String(v).substring(0, 500);
                    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
                  };
                  const headerCells = cols.map(h => `<th>${escape(h)}</th>`).join('');
                  const bodyRows = kft.rows.map(row => {
                    if (!row || typeof row !== 'object') return '';
                    return `<tr>${cols.map(c => `<td class="key-find-col">${escape(row[c])}</td>`).join('')}</tr>`;
                  }).filter(Boolean).join('');
                  if (bodyRows) {
                    return `
            <div class="executive-findings-default">
              <p class="executive-subtitle"><strong>Key Findings:</strong></p>
              ${ex.key_findings_note ? `<p class="executive-findings-note">${escapeHtml(ex.key_findings_note)}</p>` : ""}
              <div class="key-findings-table-wrap" data-scroll-key="key-findings">
                <table class="key-findings-table">
                  <thead><tr>${headerCells}</tr></thead>
                  <tbody>${bodyRows}</tbody>
                </table>
              </div>
            </div>
            `;
                  }
                }
              }
              const findings = ex.top_findings || [];
              if (findings.length === 0) return '';
              const tool = (t) => (t || '').toLowerCase();
              const isServiceRow = (f) => {
                const t = tool(f.tool);
                const typ = (f.type || '').toLowerCase();
                const desc = (f.description || '');
                return t === 'httpx' || (typ === 'information' && (desc.startsWith('HTTP service') || desc.includes(' - ')));
              };
              function looksLikeIpOrSubdomain(d) {
                if (!d || !d.trim()) return false;
                if (/^Subdomain discovered:/i.test(d.trim())) return true;
                if (/^IP:\s*[0-9a-fA-F.:]+$/im.test(d.trim())) return true;
                if (/^[0-9a-fA-F.:]+$/.test(d.trim()) && (d.includes('.') || d.includes(':'))) return true;
                return false;
              }
              function extractIpFound(d) {
                if (!d || !d.trim()) return '—';
                const trimmed = d.trim();
                const ipMatch = trimmed.match(/IP:\s*([0-9a-fA-F.:]+)/i);
                if (ipMatch) return ipMatch[1].trim();
                if (/^[0-9a-fA-F.:]+$/.test(trimmed) && (trimmed.includes('.') || trimmed.includes(':'))) return trimmed;
                return '—';
              }
              const hasService = findings.some(isServiceRow);
              const hasTemplate = findings.some(f => {
                const t = tool(f.tool);
                if (t === 'naabu' || isServiceRow(f)) return false;
                return (f.description || '').trim() && !looksLikeIpOrSubdomain(f.description || '');
              });
              const headers = ['Tool name', 'Open ports', 'IP found', ...(hasService ? ['Service'] : []), ...(hasTemplate ? ['Template'] : [])];
              return `
            <div class="executive-findings-default">
              <p class="executive-subtitle"><strong>Key Findings:</strong></p>
              ${ex.key_findings_note ? `<p class="executive-findings-note">${escapeHtml(ex.key_findings_note)}</p>` : ""}
              <div class="key-findings-table-wrap" data-scroll-key="key-findings">
                <table class="key-findings-table">
                  <thead>
                    <tr>
                      ${headers.map(h => `<th>${h}</th>`).join('')}
                    </tr>
                  </thead>
                  <tbody>
                    ${findings.map(f => {
                      const loc = (f.location || '').trim();
                      const desc = (f.description || '').replace(/</g, '&lt;').replace(/\n/g, ' ');
                      const t = tool(f.tool);
                      let openPorts = '—';
                      let ipFound = '—';
                      let service = '—';
                      if (t === 'naabu') {
                        if (loc) {
                          const port = loc.includes(':') ? loc.split(':').pop() : loc;
                          openPorts = port || loc;
                        }
                        const ipMatch = (f.description || '').match(/IP:\s*([0-9a-fA-F.:]+)/i);
                        ipFound = ipMatch ? ipMatch[1].trim() : '—';
                      } else {
                        openPorts = loc || '—';
                        if (isServiceRow(f)) {
                          service = desc || '—';
                        } else {
                          ipFound = extractIpFound(f.description || '');
                        }
                      }
                      // Avoid duplicating URL in Template when description is "Historical URL: <url>" and location is that url
                      let template = '—';
                      if (!isServiceRow(f) && t !== 'naabu' && (f.description || '').trim() && !looksLikeIpOrSubdomain(f.description || '')) {
                        const d = (f.description || '').trim();
                        if (/^Historical URL:\s*/i.test(d) && loc && d.replace(/^Historical URL:\s*/i, '').trim() === loc) {
                          template = 'Historical URL';
                        } else {
                          template = desc;
                        }
                      }
                      const cells = [
                        `<td><span class="sev-mini severity-${f.severity}">${f.severity}</span> ${f.tool}</td>`,
                        `<td class="key-find-col">${openPorts}</td>`,
                        `<td class="key-find-col">${ipFound}</td>`,
                        ...(hasService ? [`<td class="key-find-col">${service}</td>`] : []),
                        ...(hasTemplate ? [`<td class="key-find-col">${template}</td>`] : [])
                      ];
                      return `<tr>${cells.join('')}</tr>`;
                    }).join('')}
                  </tbody>
                </table>
              </div>
            </div>
            `;
            })()}
          </div>
          <div class="summary-timestamp">Report generated: ${formatDate(createdAt)}</div>
        `;
        break;
        
      case "findings_table":
        const ft = section.content;
        const allRows = ft.rows || [];
        const rows = allRows.filter(r => !isSublist3rNoiseRow(r));
        const totalDisplayed = rows.length;
        const totalFindings = Math.max(ft.total ?? 0, totalDisplayed);
        contentHtml = `
          <div class="summary-section-header">
            <div class="summary-section-icon">${section.icon}</div>
            <h3 class="summary-section-title">${section.title} (${totalDisplayed} of ${totalFindings})</h3>
          </div>
          <div class="summary-section-content">
            <div class="findings-table-wrapper">
              <table class="findings-data-table">
                <thead>
                  <tr>
                    <th>Tool</th>
                    <th>Type</th>
                    <th>Severity</th>
                    <th>Location</th>
                    <th>Description</th>
                  </tr>
                </thead>
                <tbody>
                  ${rows.length > 0 ? rows.map(r => `
                    <tr>
                      <td>${r.tool}</td>
                      <td>${r.type}</td>
                      <td><span class="sev-cell severity-${r.severity}">${r.severity}</span></td>
                      <td class="location-cell" title="${r.location}">${r.location}</td>
                      <td class="desc-cell" title="${r.description}">${r.description}</td>
                    </tr>
                  `).join("") : `
                    <tr><td colspan="5">No findings recorded</td></tr>
                  `}
                </tbody>
              </table>
            </div>
          </div>
          ${ft.severity_info ? `<p class="severity-info-hint"><small>${ft.severity_info}</small></p>` : ''}
          <div class="summary-timestamp">${totalFindings ? `${totalDisplayed} of ${totalFindings} findings shown` : 'No findings'}</div>
        `;
        break;
        
      case "configuration":
        contentHtml = `
          <div class="summary-section-header">
            <div class="summary-section-icon">${section.icon}</div>
            <h3 class="summary-section-title">${section.title}</h3>
          </div>
          <div class="summary-section-content">
            <p>Target: <span class="summary-highlight">${section.content.target}</span></p>
            <p>Attack Type: <span class="summary-highlight">${section.content.attack_type}</span></p>
            <p>User Selected Tools: <span class="summary-highlight">${section.content.user_selected_tools.join(", ")}</span></p>
          </div>
          <div class="summary-timestamp">Report generated: ${formatDate(createdAt)}</div>
        `;
        break;
        
      case "attack_relevance":
        const ar = section.content;
        const arClass = ar.can_support_attack ? "attack-relevance-exploitable" : "attack-relevance-recon";
        contentHtml = `
          <div class="summary-section-header">
            <div class="summary-section-icon">${section.icon}</div>
            <h3 class="summary-section-title">${section.title}</h3>
          </div>
          <div class="summary-section-content ${arClass}">
            <p><strong>Attack type assessed:</strong> <span class="summary-highlight">${ar.attack_type}</span></p>
            <p class="attack-relevance-summary">${ar.relevance_summary}</p>
            <ul class="attack-relevance-bullets">
              ${(ar.detail_bullets || []).map(b => `<li>${b}</li>`).join("")}
            </ul>
            ${ar.can_support_attack ? "<p class=\"attack-relevance-warn\">⚠️ Findings from the tools above could support this attack type. Remediate vulnerabilities to reduce risk.</p>" : "<p class=\"attack-relevance-info\">No direct vulnerabilities for this attack type were identified. Findings are useful for reconnaissance only.</p>"}
          </div>
          <div class="summary-timestamp">Report generated: ${formatDate(createdAt)}</div>
        `;
        break;
        
      case "clues":
        const stats = section.content.statistics || {};
        const riskAssessment = section.content.risk_assessment || {};
        // Detailed Findings table removed from UI per requirement
        const findingsByTool = stats.findings_by_tool || [];
        
        contentHtml = `
          <div class="summary-section-header">
            <div class="summary-section-icon">${section.icon}</div>
            <h3 class="summary-section-title">${section.title}</h3>
          </div>
          <div class="summary-section-content recon-findings-content">
            <p class="recon-description">${section.content.description}</p>
            
            <div class="recon-metrics-row">
              <div class="summary-stats-grid">
                <div class="summary-stat-card">
                  <div class="summary-stat-value">${stats.total_findings || 0}</div>
                  <div class="summary-stat-label">Total Findings</div>
                </div>
                <div class="summary-stat-card">
                  <div class="summary-stat-value">${stats.tools_executed || 0}</div>
                  <div class="summary-stat-label">Tools Executed</div>
                </div>
                <div class="summary-stat-card">
                  <div class="summary-stat-value">${riskAssessment.score ?? 0}/100</div>
                  <div class="summary-stat-label">Risk Score</div>
                </div>
              </div>
            </div>
            
            ${stats.severity_breakdown ? `
            <div class="recon-severity-section">
              <h5 class="recon-subtitle">Severity Distribution (all tools combined)</h5>
              ${stats.severity_combined_note ? `<p class="recon-severity-note">${stats.severity_combined_note}</p>` : ""}
              <div class="severity-bars compact">
                ${Object.entries(stats.severity_breakdown).map(([sev, count]) => {
                  const total = Object.values(stats.severity_breakdown).reduce((a,b) => a+b, 0);
                  const pct = total > 0 ? (count / total * 100) : 0;
                  const colors = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#3b82f6', info: '#6b7280' };
                  const barColor = colors[sev] || '#6b7280';
                  return `
                    <div class="severity-bar-row">
                      <span class="sev-label">${sev.toUpperCase()}</span>
                      <div class="sev-bar-wrap"><div class="sev-bar-fill severity-${sev}" style="width:${pct}%; background-color:${barColor}"></div></div>
                      <span class="sev-count">${count}</span>
                    </div>`;
                }).join('')}
              </div>
            </div>
            ` : ''}
            
            ${findingsByTool.length > 0 ? `
            <div class="recon-tools-section">
              <h5 class="recon-subtitle">Findings by Tool</h5>
              <div class="summary-table-wrap">
                <table class="summary-table recon-tools-table recon-tools-by-row">
                  <thead><tr>${findingsByTool.map(t => `<th>${t.tool}</th>`).join('')}</tr></thead>
                  <tbody><tr>${findingsByTool.map(t => `<td>${t.count}</td>`).join('')}</tr></tbody>
                </table>
              </div>
            </div>
            ` : ''}
            
            ${riskAssessment.level ? `
            <div class="risk-assessment-box recon-risk">
              <span class="risk-label">Risk Level:</span>
              <span class="risk-level-badge risk-${(riskAssessment.level || "N/A").toLowerCase().replace("/", "")}">${riskAssessment.level || "N/A"}</span>
              <span class="risk-impact">${riskAssessment.business_impact || ''}</span>
            </div>
            ` : ''}
            
            <p class="recon-insight">${section.content.intelligence_insight}</p>
          </div>
          <div class="summary-timestamp">Report generated: ${formatDate(createdAt)}</div>
        `;
        break;
        
      case "ai_decision":
        const dec = section.content.decision || {};
        const analysisList = (section.content.analysis || []).map(a => `<li>${a}</li>`).join("");
        const toolsRunList = (dec.tools_to_run || []).map(t => `<li>${t}</li>`).join("");
        const toolsSkipped = dec.tools_skipped || [];
        const skippedList = toolsSkipped.map(s => {
          const tool = typeof s === 'object' ? s.tool : s;
          const reason = typeof s === 'object' ? s.reason : '';
          return `<li>${tool}${reason ? ` - ${reason}` : ''}</li>`;
        }).join("");
        contentHtml = `
          <div class="summary-section-header">
            <div class="summary-section-icon">${section.icon}</div>
            <h3 class="summary-section-title">${section.title}</h3>
          </div>
          <div class="summary-section-content">
            ${analysisList ? `<p><strong>AI Analysis:</strong></p><ul class="summary-findings-list">${analysisList}</ul>` : ""}
            <p><strong>Tools Executed:</strong></p>
            <ul class="summary-findings-list">
              ${toolsRunList || "<li>None</li>"}
            </ul>
            ${skippedList ? `<p><strong>Tools Skipped (with reason):</strong></p><ul class="summary-findings-list">${skippedList}</ul>` : ""}
            <p><strong>Reason:</strong> ${dec.reason || "Based on initial reconnaissance clues."}</p>
          </div>
          <div class="summary-timestamp">Report generated: ${formatDate(createdAt)}</div>
        `;
        break;
        
      case "dns_validation":
      case "port_exposure":
      case "vulnerability":
      case "http_service":
      case "subdomain":
      case "tool_result":
        contentHtml = `
          <div class="summary-section-header">
            <div class="summary-section-icon">${section.icon}</div>
            <h3 class="summary-section-title">${section.title}</h3>
          </div>
          <div class="summary-section-content">
            <p><strong>Command Executed:</strong></p>
            <div class="summary-command">${section.content.command}</div>
            <p><strong>Output:</strong></p>
        `;
        const readableOutput = section.content.readable_output;
        if (section.type === "vulnerability" && section.content.findings) {
          const f = section.content.findings;
          contentHtml += `
            <div class="summary-stats-grid" style="margin-bottom: 12px;">
              <div class="summary-stat-card"><div class="summary-stat-value">${f.critical ?? 0}</div><div class="summary-stat-label">Critical</div></div>
              <div class="summary-stat-card"><div class="summary-stat-value">${f.high ?? 0}</div><div class="summary-stat-label">High</div></div>
              <div class="summary-stat-card"><div class="summary-stat-value">${f.medium ?? 0}</div><div class="summary-stat-label">Medium</div></div>
              <div class="summary-stat-card"><div class="summary-stat-value">${f.low ?? 0}</div><div class="summary-stat-label">Low</div></div>
              <div class="summary-stat-card"><div class="summary-stat-value">${f.info ?? 0}</div><div class="summary-stat-label">Info</div></div>
            </div>
          `;
        }
        // Output rendering:
        // - Show first 10 lines by default
        // - "View more" expands to show ALL remaining lines
        // - Prefer raw_output (full tool output file) when available, so long outputs are not capped
        if (readableOutput && Array.isArray(readableOutput) && readableOutput.length > 0) {
          let outputLines = readableOutput;
          if (section.content.raw_output) {
            const rawLines = String(section.content.raw_output).split(/\r?\n/);
            // Keep the "Findings: N" header from readable_output if raw output file doesn't include it
            let header = (readableOutput[0] || "").trim();
            if (header && /^Findings:\s*\d+/i.test(header) && !(rawLines[0] || "").includes("Findings:")) {
              // If raw output contains more URLs than parsed findings, reflect the real count in the header.
              const toolHint = ((section.title || "") + " " + (section.content.command || "")).toLowerCase();
              if (toolHint.includes("cewl")) {
                header = "Findings: Wordlist";
                outputLines = [header, ...rawLines];
              } else {
              const trimmedLines = rawLines.map(l => (l || "").trim());
              const httpLines = trimmedLines.filter(l => l.toLowerCase().startsWith("http"));
              // GAU/Katana/GoSpider often include duplicate URLs; count unique URLs so totals align with deduped findings.
              // GoSpider may embed URLs inside other log lines; extract via regex for accurate unique counts.
              let urlCount = httpLines.length;
              if (toolHint.includes("gau") || toolHint.includes("katana")) {
                urlCount = new Set(httpLines).size;
              } else if (toolHint.includes("gospider")) {
                const urlSet = new Set();
                const re = /https?:\/\/[^\s]+/g;
                for (const line of trimmedLines) {
                  const matches = line.match(re);
                  if (matches && matches.length) {
                    matches.forEach(u => urlSet.add(u));
                  }
                }
                urlCount = urlSet.size;
              }
              if (urlCount > 0) header = `Findings: ${urlCount}`;
              outputLines = [header, ...rawLines];
              }
            } else {
              outputLines = rawLines;
            }
            // Drop any empty trailing lines
            while (outputLines.length > 0 && String(outputLines[outputLines.length - 1]).trim() === "") {
              outputLines.pop();
            }
            // GoSpider output often includes many empty lines between URL groups.
            // Rendering empty lines creates visible "gaps" (blank space) in the UI.
            // Filter only for GoSpider so other tools' formatting remains unchanged.
            const toolHint = ((section.title || "") + " " + (section.content.command || "")).toLowerCase();
            if (toolHint.includes("gospider")) {
              outputLines = outputLines.filter((ln) => (ln || "").toString().trim() !== "");
            }
          }

          const previewLines = outputLines.slice(0, 10);
          const remainingLines = outputLines.slice(10);
          const hasMore = remainingLines.length > 0;
          const detailsKey = `tool-output-${detailsKeyPrefix}`;
          contentHtml += `
            <div class="tool-output-lines">
              ${previewLines.map(line => `<div class="tool-output-line">${escapeHtml(line)}</div>`).join("")}
              ${hasMore ? `
                <details class="tool-output-details" data-details-key="${detailsKey}">
                  <summary>View more</summary>
                  <div class="tool-output-more">
                    ${remainingLines.map(line => `<div class="tool-output-line">${escapeHtml(line)}</div>`).join("")}
                    <button type="button" class="tool-output-less">View less</button>
                  </div>
                </details>
              ` : ""}
            </div>
          `;
        } else if (section.type === "dns_validation") {
          contentHtml += `
            <ul class="summary-findings-list">
              <li>${section.content.result.valid_subdomains} valid subdomains confirmed</li>
              <li>${section.content.result.wildcard_entries} wildcard entries filtered</li>
              <li>${section.content.result.hidden_subdomains} new hidden subdomains identified</li>
            </ul>
          `;
        } else if (section.type === "port_exposure") {
          contentHtml += `
            <ul class="summary-findings-list">
              ${(section.content.result.open_ports || []).map(p => `<li>${escapeHtml(p)}</li>`).join("")}
            </ul>
          `;
        } else if (section.type === "vulnerability") {
          const issues = section.content.detected_issues || [];
          contentHtml += `
            <ul class="summary-findings-list">
              ${issues.length ? issues.map(i => `<li>${escapeHtml(i)}</li>`).join("") : "<li>No issues detected.</li>"}
            </ul>
          `;
        } else if (section.content.result) {
          const status = section.content.status || section.content.result.status;
          const isFailed = status === "failed" || status === "timeout";
          const issues = section.content.detected_issues || [];
          contentHtml += `
            <ul class="summary-findings-list">
              ${Object.entries(section.content.result).map(([key, value]) =>
                `<li>${escapeHtml(String(key).replace(/_/g, " "))}: ${escapeHtml(String(value))}</li>`
              ).join("")}
            </ul>
            ${issues.length > 0 ? `<ul class="summary-findings-list">${issues.map(i => `<li>${escapeHtml(i)}</li>`).join("")}</ul>` : ""}
          `;
        }
        if (section.content.impact) {
          const status = section.content.status || section.content.result?.status;
          const isFailed = status === "failed" || status === "timeout";
          contentHtml += `<p class="tool-impact"><strong>${isFailed ? "Details" : "Impact"}:</strong> ${escapeHtml(section.content.impact)}</p>`;
        }
        if (section.content.risk_indicator) {
          contentHtml += `<p><span class="summary-risk-indicator summary-risk-${String(section.content.risk_indicator).toLowerCase()}">Risk: ${escapeHtml(section.content.risk_indicator)}</span></p>`;
        }
        if (section.content.error_message) {
          contentHtml += `<p class="tool-error-msg"><strong>Error:</strong> ${escapeHtml(section.content.error_message)}</p>`;
        }
        contentHtml += `
          </div>
          <div class="summary-timestamp">Report generated: ${formatDate(createdAt)}</div>
        `;
        break;
        
      case "combined_summary":
        const riskAssessmentData = section.content.risk_assessment || {};
        const technicalFindings = section.content.technical_findings || {};
        const actionableIntelligence = section.content.actionable_intelligence || {};
        
        contentHtml = `
          <div class="summary-section-header">
            <div class="summary-section-icon">${section.icon}</div>
            <h3 class="summary-section-title">${section.title}</h3>
          </div>
          <div class="summary-section-content">
            <p><strong>${section.content.status}</strong></p>
            
            <!-- Technical Findings -->
            ${technicalFindings.infrastructure_exposure || technicalFindings.security_posture ? `
            <div class="technical-findings-section">
              <h4>🔧 Technical Findings</h4>
              ${technicalFindings.infrastructure_exposure ? `
              <div class="infrastructure-exposure">
                <h5>Infrastructure Exposure</h5>
                <div class="summary-stats-grid">
                  <div class="summary-stat-card">
                    <div class="summary-stat-value">${technicalFindings.infrastructure_exposure.total_subdomains || 0}</div>
                    <div class="summary-stat-label">Subdomains</div>
                  </div>
                  <div class="summary-stat-card">
                    <div class="summary-stat-value">${technicalFindings.infrastructure_exposure.valid_endpoints || 0}</div>
                    <div class="summary-stat-label">Endpoints</div>
                  </div>
                  <div class="summary-stat-card">
                    <div class="summary-stat-value">${technicalFindings.infrastructure_exposure.open_ports || 0}</div>
                    <div class="summary-stat-label">Open Ports</div>
                  </div>
                </div>
              </div>
              ` : ''}
              
              ${technicalFindings.security_posture ? `
              <div class="security-posture">
                <h5>Security Posture</h5>
                <div class="summary-stats-grid">
                  <div class="summary-stat-card">
                    <div class="summary-stat-value">${technicalFindings.security_posture.vulnerabilities || 0}</div>
                    <div class="summary-stat-label">Vulnerabilities</div>
                  </div>
                  <div class="summary-stat-card">
                    <div class="summary-stat-value">${technicalFindings.security_posture.misconfigurations || 0}</div>
                    <div class="summary-stat-label">Misconfigurations</div>
                  </div>
                  <div class="summary-stat-card">
                    <div class="summary-stat-value">${technicalFindings.security_posture.informational_findings || 0}</div>
                    <div class="summary-stat-label">Info Findings</div>
                  </div>
                </div>
              </div>
              ` : ''}
            </div>
            ` : ''}
            
            <!-- Actionable Intelligence -->
            ${(actionableIntelligence && (actionableIntelligence.priority_recommendations?.length > 0 || actionableIntelligence.next_steps?.length > 0)) ? `
            <div class="actionable-intelligence">
              <h4>💡 Actionable Intelligence</h4>
              
              ${(actionableIntelligence.priority_recommendations || []).length > 0 ? `
              <div class="recommendations-section">
                <h5>Priority Recommendations</h5>
                <ul class="recommendations-list">
                  ${actionableIntelligence.priority_recommendations.map(rec => `<li>${rec}</li>`).join('')}
                </ul>
              </div>
              ` : ''}
              
              ${(actionableIntelligence.next_steps || []).length > 0 ? `
              <div class="next-steps-section">
                <h5>Next Steps</h5>
                <ol class="next-steps-list">
                  ${actionableIntelligence.next_steps.map(step => `<li>${step}</li>`).join('')}
                </ol>
              </div>
              ` : ''}
            </div>
            ` : ''}
          </div>
          <div class="summary-timestamp">Report generated: ${formatDate(createdAt)}</div>
        `;
        break;
    }
    
    sectionEl.innerHTML = contentHtml;
    
    // Restore preserved <details> open state after re-render (prevents auto-collapse during polling)
    if (preservedDetailsOpenKeys.size > 0) {
      preservedDetailsOpenKeys.forEach((key) => {
        const d = sectionEl.querySelector(`details[data-details-key="${key}"]`);
        if (d) d.open = true;
      });
    }

    // Restore preserved horizontal scroll positions after re-render
    if (preservedScrollLeftByKey.size > 0) {
      preservedScrollLeftByKey.forEach((left, key) => {
        const el = sectionEl.querySelector(`[data-scroll-key="${key}"]`);
        if (!el) return;
        try {
          el.scrollLeft = left;
        } catch (_) {}
      });
    }

    // Restore selected severity filter (re-apply after polling re-render)
    if (preservedSelectedSeverity) {
      const execContent = sectionEl.querySelector('.executive-summary-content');
      if (execContent) {
        execContent.dataset.selectedSeverity = preservedSelectedSeverity;
        const btn = execContent.querySelector(`.sev-badge[data-severity="${preservedSelectedSeverity}"]`);
        // Trigger the existing click handler to rebuild the filtered view.
        if (btn && !btn.classList.contains('active')) {
          try { btn.click(); } catch (_) {}
        }
      }
    }
    
    // Preserve existing timestamp if this is an update
    if (existingTimestamps[section.type]) {
      const timestampEl = sectionEl.querySelector('.summary-timestamp');
      if (timestampEl) {
        timestampEl.textContent = existingTimestamps[section.type];
      }
    }
    
    // Only append if it's a new section
    if (!container.contains(sectionEl)) {
      container.appendChild(sectionEl);
      
      // Only auto-scroll to bottom if user is near the bottom and not actively scrolling
      // Check if user is within 100px of the bottom
      const isNearBottom = (container.scrollHeight - container.scrollTop - container.clientHeight) < 100;
      if (isNearBottom && !isUserScrolling) {
        container.scrollTop = container.scrollHeight;
      }
    } else {
      // For existing sections, don't change scroll position
      // This prevents jumping when updating content
    }
  });

  // Handle "View less" for tool outputs (collapse without affecting other sections)
  container.querySelectorAll(".tool-output-less").forEach((btn) => {
    if (btn.dataset.bound === "1") return;
    btn.dataset.bound = "1";
    btn.addEventListener("click", (e) => {
      e.preventDefault();
      const details = btn.closest("details");
      if (details) details.open = false;
    });
  });

  // Append live output section when selected scan is running
  const scanFilter = document.getElementById("scanSummaryFilter");
  if (scanFilter && scanFilter.value) {
    const scanId = parseInt(scanFilter.value, 10);
    container.dataset.scanId = scanId;
    renderLiveOutputInSummary(scanId);
  }
}

// Add event listeners for scan summary controls
// Track user scroll interaction
document.addEventListener('DOMContentLoaded', function() {
  const refreshButton = document.getElementById('refreshScanSummary');
  const scanFilter = document.getElementById('scanSummaryFilter');
  const container = document.getElementById('scanSummaryContainer');
  
  // Track if user is manually scrolling
  let isUserScrolling = false;
  let scrollTimeout;
  
  if (container) {
    container.addEventListener('scroll', function() {
      isUserScrolling = true;
      clearTimeout(scrollTimeout);
      // Reset after 2 seconds of no scrolling
      scrollTimeout = setTimeout(() => {
        isUserScrolling = false;
      }, 2000);
    });
    // Severity badge click: show filtered key findings (click again to show all)
    container.addEventListener('click', function(e) {
      const btn = e.target.closest('.sev-badge[data-severity]');
      if (!btn) return;
      const content = btn.closest('.executive-summary-content');
      if (!content) return;
      const filteredDiv = content.querySelector('.executive-findings-filtered');
      const defaultDiv = content.querySelector('.executive-findings-default');
      const listEl = content.querySelector('.executive-findings-filtered-container');
      const labelEl = content.querySelector('.filtered-severity-label');
      if (!filteredDiv || !listEl || !labelEl) return;
      const wasActive = btn.classList.contains('active');
      content.querySelectorAll('.sev-badge[data-severity]').forEach(b => b.classList.remove('active'));
      if (wasActive) {
        content.dataset.selectedSeverity = "";
        filteredDiv.style.display = 'none';
        if (defaultDiv) defaultDiv.style.display = '';
        return;
      }
      const severity = btn.dataset.severity;
      const count = parseInt(btn.dataset.count || 0, 10);
      const dataAttr = content.dataset.findingsBySeverity;
      if (!dataAttr) return;
      let findingsBySev = {};
      try {
        findingsBySev = JSON.parse(decodeURIComponent(dataAttr));
      } catch (_) { return; }
      const findings = findingsBySev[severity] || [];
      btn.classList.add('active');
      content.dataset.selectedSeverity = severity;
      if (count === 0 || findings.length === 0) {
        labelEl.textContent = severity.charAt(0).toUpperCase() + severity.slice(1);
        listEl.innerHTML = '<p class="no-findings-msg">No findings for this severity.</p>';
      } else {
        labelEl.textContent = severity.charAt(0).toUpperCase() + severity.slice(1);
        // Build a Key Findings-style table for this severity
        const tool = (t) => (t || '').toLowerCase();
        const looksLikeIpOrSubdomain = (d) => {
          if (!d || !d.trim()) return false;
          const trimmed = d.trim();
          if (/^Subdomain discovered:/i.test(trimmed)) return true;
          if (/^IP:\s*[0-9a-fA-F.:]+$/im.test(trimmed)) return true;
          if (/^[0-9a-fA-F.:]+$/.test(trimmed) && (trimmed.includes('.') || trimmed.includes(':'))) return true;
          return false;
        };
        const extractIpFound = (d) => {
          if (!d || !d.trim()) return '—';
          const trimmed = d.trim();
          const ipMatch = trimmed.match(/IP:\s*([0-9a-fA-F.:]+)/i);
          if (ipMatch) return ipMatch[1].trim();
          if (/^[0-9a-fA-F.:]+$/.test(trimmed) && (trimmed.includes('.') || trimmed.includes(':'))) return trimmed;
          return '—';
        };
        const isServiceRow = (f) => {
          const t = tool(f.tool);
          const typ = (f.type || '').toLowerCase();
          const desc = (f.description || '');
          return t === 'httpx' || (typ === 'information' && (desc.startsWith('HTTP service') || desc.includes(' - ')));
        };
        const escape = (v) => {
          if (v == null || v === '') return '—';
          const s = String(v).substring(0, 500);
          return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
        };
        const bodyRows = findings.map(f => {
          const loc = (f.location || '').trim();
          const descRaw = (f.description || '');
          const desc = descRaw.replace(/</g, '&lt;').replace(/\n/g, ' ');
          return `<tr>
            <td><span class="sev-mini severity-${f.severity}">${escape(f.severity)}</span> ${escape(f.tool)}</td>
            <td class="key-find-col finding-location">${escape(loc || '—')}</td>
            <td class="key-find-col finding-desc">${escape(descRaw ? desc : '—')}</td>
          </tr>`;
        }).join('');
        listEl.innerHTML = `
          <p class="executive-filtered-note">Showing only <strong>${severity.charAt(0).toUpperCase() + severity.slice(1)}</strong> findings (${findings.length} ${findings.length === 1 ? 'finding' : 'findings'}).</p>
          <div class="key-findings-filtered-wrap">
            <table class="key-findings-table key-findings-filtered-table">
              <thead>
                <tr><th>Tool</th><th>Location</th><th>Description</th></tr>
              </thead>
              <tbody>
                ${bodyRows}
              </tbody>
            </table>
          </div>
        `;
      }
      filteredDiv.style.display = 'block';
      if (defaultDiv) defaultDiv.style.display = 'none';
    });
  }
  
  if (refreshButton) {
    refreshButton.addEventListener('click', async function() {
      // Clear the current summary display without loading another
      const container = document.getElementById("scanSummaryContainer");
      if (container) {
        container.innerHTML = `
          <div class="scan-summary-placeholder">
            <div class="summary-placeholder-icon">🔍</div>
            <div class="summary-placeholder-text">Run a scan to see real-time intelligence summary</div>
          </div>`;
      }
      // Stop any existing polling
      stopScanSummaryPolling();
      
      // Reset the scan selection in the dropdown
      if (scanFilter) {
        scanFilter.value = '';
      }
    });
  }
  
  const saveButton = document.getElementById('saveScanSummary');
  
  // Add event listener for the save summary button
  if (saveButton) {
    saveButton.addEventListener('click', async function() {
      const container = document.getElementById("scanSummaryContainer");
      // Use the scan whose summary is currently displayed (no need to select from dropdown)
      let scanIdToSave = container?.dataset?.scanId || scanFilter?.value || currentScanId || lastScanId;
      if (!scanIdToSave && container && container.innerHTML.trim() !== "" && !container.querySelector('.scan-summary-placeholder')) {
        scanIdToSave = currentScanId || lastScanId;
      }

      if (!scanIdToSave) {
          showStyledPopup('No scan available to save. Run a scan first.');
          return;
        }
        
        try {
          // Show loading state
          saveButton.textContent = 'Saving...';
          saveButton.disabled = true;
          
          // Mark the scan as saved using the new API endpoint
          const response = await apiRequest(API_ROUTES.markScanSaved(scanIdToSave), { method: "POST" });
          if (response) {
            showStyledPopup('Scan summary saved successfully!');
            
            // Refresh Saved Reports immediately so it appears in the table
            try {
              if (typeof refreshSavedReports === "function") {
                await refreshSavedReports();
              }
            } catch (e) {
              console.warn("Failed to refresh Saved Reports after save", e);
            }
            
            // Also refresh general scan views/dropdowns (non-blocking)
            setTimeout(() => {
              try {
                if (typeof refreshScansViews === 'function') {
                  refreshScansViews();
                }
                const scanFilter = document.getElementById('scanSummaryFilter');
                if (scanFilter && typeof populateScanFilterOptions === 'function') {
                  populateScanFilterOptions(scanFilter);
                }
              } catch (e) {
                console.warn("Post-save refresh failed", e);
              }
            }, 300); // Small delay to ensure save is processed
                      
            // Update the severity distribution chart with the new data
            setTimeout(() => {
              updateSeverityScope('all');
              if (severityChart) {
                severityChart.update();
              }
            }, 1000); // Slightly longer delay to allow for data propagation
          } else {
            throw new Error('Failed to mark scan as saved');
          }
        } catch (error) {
          console.error('Error saving scan summary:', error);
          showStyledPopup('Failed to save scan summary. Please try again.');
        } finally {
          // Restore button state
          saveButton.textContent = 'Save Summary';
          saveButton.disabled = false;
        }
    });
  }

  const generatePdfBtn = document.getElementById('generatePdfReport');
  if (generatePdfBtn) {
    generatePdfBtn.addEventListener('click', async function() {
      const selectedScanId = scanFilter?.value;
      let scanIdToUse = selectedScanId || currentScanId;
      if (!scanIdToUse) {
        const container = document.getElementById("scanSummaryContainer");
        if (container && container.innerHTML.trim() !== "" && !container.querySelector('.scan-summary-placeholder')) {
          scanIdToUse = container.dataset.scanId || currentScanId || lastScanId;
        }
      }
      if (!scanIdToUse) {
        showStyledPopup('No scan available. Run a scan or select one from the dropdown first.');
        return;
      }
      try {
        generatePdfBtn.disabled = true;
        generatePdfBtn.textContent = 'Generating...';
        const res = await fetch(getApiUrl(API_ROUTES.reportPdf(scanIdToUse)));
        if (!res.ok) throw new Error(res.statusText || 'PDF generation failed');
        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `IRS_Scan_${scanIdToUse}_Report.pdf`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        showStyledPopup('PDF report downloaded successfully!');
      } catch (err) {
        showStyledPopup('Failed to generate PDF: ' + (err.message || 'Unknown error'));
      } finally {
        generatePdfBtn.disabled = false;
        generatePdfBtn.textContent = 'Generate PDF';
      }
    });
  }
  
  if (scanFilter) {
    // Populate scan filter dropdown with available scans
    populateScanFilterOptions(scanFilter);
    
    // Add event listener for when user selects a scan from the dropdown
    scanFilter.addEventListener('change', function() {
      const selectedValue = this.value;
      if (selectedValue) {
        const scanId = parseInt(selectedValue, 10);
        console.log('Loading summary for scan:', scanId);
          
        // Stop any existing polling for previous scan
        stopScanSummaryPolling();
        currentScanId = scanId;
          
        // Clear container and show loading state immediately
        const container = document.getElementById("scanSummaryContainer");
        if (container) {
          container.innerHTML = `
            <div class="scan-summary-placeholder">
              <div class="summary-placeholder-icon">⏳</div>
              <div class="summary-placeholder-text">Loading scan #${scanId}…</div>
              <div class="summary-placeholder-subtext">Fetching intelligence summary...</div>
            </div>`;
          container.dataset.scanId = String(scanId);
          delete container.dataset.reportTimestamp;
        }
          
        // Immediately fetch the summary
        apiRequest(API_ROUTES.scanIntelligence(scanId), { method: "GET" })
          .then(data => {
            console.log("Dropdown selection fetch successful:", data);
            if (data && (data.sections || data.message)) {
              renderScanSummary(data);
            } else {
              // No data available yet
              container.innerHTML = `
                <div class="scan-summary-placeholder">
                  <div class="summary-placeholder-icon">ℹ️</div>
                  <div class="summary-placeholder-text">No intelligence summary available for scan #${scanId}</div>
                  <div class="summary-placeholder-subtext">The scan may still be running or has no AI analysis yet.</div>
                </div>`;
            }
          })
          .catch(error => {
            console.error("Dropdown selection fetch failed:", error);
            if (container) {
              container.innerHTML = `
                <div class="scan-summary-placeholder">
                  <div class="summary-placeholder-icon">⚠️</div>
                  <div class="summary-placeholder-text">Could not load scan #${scanId}</div>
                  <div class="summary-placeholder-subtext">Error: ${error.message || 'Unknown error'}</div>
                </div>`;
            }
          });
      }
    });
  }
});

// Popup when launch is blocked by a running scan; offers to cancel the stuck scan
function showRunningScanBlockedPopup(runningScanId) {
  const existingPopup = document.querySelector('.styled-popup-overlay');
  if (existingPopup) existingPopup.remove();

  const overlay = document.createElement('div');
  overlay.className = 'styled-popup-overlay';
  overlay.style.cssText = 'position:fixed;top:0;left:0;width:100vw;height:100vh;background:rgba(0,0,0,0.7);display:flex;justify-content:center;align-items:center;z-index:10000;';

  const popup = document.createElement('div');
  popup.className = 'styled-popup';
  popup.style.cssText = 'background:#1e293b;padding:24px;border-radius:12px;box-shadow:0 20px 25px -5px rgba(0,0,0,0.3);max-width:520px;width:90%;color:#f9fafb;font-family:system-ui,sans-serif;';

  const messageEl = document.createElement('p');
  messageEl.textContent = `Another scan (Scan #${runningScanId}) is still running. You can cancel it to start a new scan, or wait for it to finish.`;
  messageEl.style.cssText = 'margin:0 0 16px 0;font-size:16px;white-space:pre-line;';

  const btnWrap = document.createElement('div');
  btnWrap.style.cssText = 'display:flex;gap:10px;justify-content:flex-end;margin-top:16px;';

  const okBtn = document.createElement('button');
  okBtn.textContent = 'OK';
  okBtn.style.cssText = 'background:#64748b;color:#fff;border:none;padding:8px 16px;border-radius:6px;cursor:pointer;font-size:14px;';
  okBtn.addEventListener('click', () => overlay.remove());

  const cancelScanBtn = document.createElement('button');
  cancelScanBtn.textContent = 'Cancel stuck scan';
  cancelScanBtn.style.cssText = 'background:#38bdf8;color:#020617;border:none;padding:8px 16px;border-radius:6px;cursor:pointer;font-size:14px;font-weight:500;';
  cancelScanBtn.addEventListener('click', async () => {
    cancelScanBtn.disabled = true;
    cancelScanBtn.textContent = 'Cancelling…';
    try {
      const res = await fetch(getApiUrl(`/api/scans/${runningScanId}/mark-failed`), { method: 'POST' });
      if (res.ok) {
        if (typeof showNotification === 'function') showNotification('Stuck scan cancelled. You can start a new scan.', 'success');
        else showStyledPopup('Stuck scan cancelled. You can start a new scan now.');
        overlay.remove();
      } else {
        const err = await res.json().catch(() => ({}));
        cancelScanBtn.textContent = 'Cancel stuck scan';
        cancelScanBtn.disabled = false;
        showStyledPopup(err.detail || 'Failed to cancel scan.');
      }
    } catch (e) {
      cancelScanBtn.textContent = 'Cancel stuck scan';
      cancelScanBtn.disabled = false;
      showStyledPopup('Failed to cancel scan: ' + (e.message || 'Network error'));
    }
  });

  btnWrap.appendChild(okBtn);
  btnWrap.appendChild(cancelScanBtn);
  popup.appendChild(messageEl);
  popup.appendChild(btnWrap);
  overlay.appendChild(popup);
  document.body.appendChild(overlay);
}

// Function to show a styled popup
function showStyledPopup(message) {
  // Remove any existing popups
  const existingPopup = document.querySelector('.styled-popup-overlay');
  if (existingPopup) {
    existingPopup.remove();
  }
  
  // Create overlay
  const overlay = document.createElement('div');
  overlay.className = 'styled-popup-overlay';
  overlay.style.position = 'fixed';
  overlay.style.top = '0';
  overlay.style.left = '0';
  overlay.style.width = '100vw';
  overlay.style.height = '100vh';
  overlay.style.backgroundColor = 'rgba(0, 0, 0, 0.7)';
  overlay.style.display = 'flex';
  overlay.style.justifyContent = 'center';
  overlay.style.alignItems = 'center';
  overlay.style.zIndex = '10000';
  
  // Create popup container
  const popup = document.createElement('div');
  popup.className = 'styled-popup';
  popup.style.backgroundColor = '#1e293b';
  popup.style.padding = '24px';
  popup.style.borderRadius = '12px';
  popup.style.boxShadow = '0 20px 25px -5px rgba(0, 0, 0, 0.3), 0 10px 10px -5px rgba(0, 0, 0, 0.2)';
  popup.style.textAlign = 'left';
  popup.style.maxWidth = '520px';
  popup.style.width = '90%';
  popup.style.color = '#f9fafb';
  popup.style.fontFamily = 'system-ui, -apple-system, sans-serif';
  
  // Create message
  const messageEl = document.createElement('p');
  messageEl.textContent = message;
  messageEl.style.margin = '0 0 16px 0';
  messageEl.style.fontSize = '16px';
  // Preserve line breaks in multi-line messages
  messageEl.style.whiteSpace = 'pre-line';
  messageEl.style.textAlign = 'left';
  
  // Create OK button
  const okButton = document.createElement('button');
  okButton.textContent = 'OK';
  okButton.style.backgroundColor = '#38bdf8';
  okButton.style.color = '#020617';
  okButton.style.border = 'none';
  okButton.style.padding = '8px 16px';
  okButton.style.borderRadius = '6px';
  okButton.style.cursor = 'pointer';
  okButton.style.fontSize = '14px';
  okButton.style.fontWeight = '500';
  okButton.style.transition = 'background-color 0.2s';
  
  okButton.addEventListener('click', function() {
    overlay.remove();
  });
  
  okButton.addEventListener('mouseenter', function() {
    this.style.backgroundColor = '#0ea5e9';
  });
  
  okButton.addEventListener('mouseleave', function() {
    this.style.backgroundColor = '#38bdf8';
  });
  
  popup.appendChild(messageEl);
  popup.appendChild(okButton);
  overlay.appendChild(popup);
  
  document.body.appendChild(overlay);
}

// Show tool command in a popup when user clicks "Run [Tool Name]" in Tool Library
async function showToolCommand(toolName) {
  const existing = document.querySelector(".styled-popup-overlay");
  if (existing) existing.remove();

  const overlay = document.createElement("div");
  overlay.className = "styled-popup-overlay";
  overlay.style.cssText = "position:fixed;top:0;left:0;width:100vw;height:100vh;background:rgba(0,0,0,0.7);display:flex;justify-content:center;align-items:center;z-index:10000;";

  const popup = document.createElement("div");
  popup.className = "styled-popup";
  popup.style.cssText = "background:#1e293b;padding:24px;border-radius:12px;box-shadow:0 20px 25px -5px rgba(0,0,0,0.3);max-width:560px;width:90%;color:#f9fafb;font-family:system-ui,sans-serif;text-align:left;";
  popup.innerHTML = `
    <div style="margin-bottom:12px;font-weight:600;font-size:18px;">Run ${escapeHtml(toolName)}</div>
    <div style="margin-bottom:8px;font-size:13px;color:#94a3b8;">Command (target: example.com):</div>
    <pre id="toolCommandPre" style="background:#0f172a;padding:12px;border-radius:8px;overflow-x:auto;font-size:13px;margin:0 0 16px 0;white-space:pre-wrap;word-break:break-all;">Loading...</pre>
    <button type="button" class="tool-command-ok" style="background:#38bdf8;color:#020617;border:none;padding:8px 16px;border-radius:6px;cursor:pointer;font-size:14px;">OK</button>
  `;

  overlay.appendChild(popup);
  document.body.appendChild(overlay);

  popup.querySelector(".tool-command-ok").onclick = () => overlay.remove();
  overlay.addEventListener("click", (e) => { if (e.target === overlay) overlay.remove(); });

  try {
    const url = getApiUrl(API_ROUTES.toolCommand(toolName));
    const res = await fetch(url);
    const data = res.ok ? await res.json() : null;
    const pre = popup.querySelector("#toolCommandPre");
    if (res.ok && data && data.command) {
      pre.textContent = data.command;
    } else {
      pre.textContent = "Could not load command. " + (data && data.detail ? data.detail : "Check backend.");
    }
  } catch (err) {
    popup.querySelector("#toolCommandPre").textContent = "Failed to fetch command: " + (err.message || "Network error");
  }
}

// Function to populate scan filter options (only saved reports). Prevents duplicate options on re-open.
let populateScanFilterOptionsInProgress = false;
async function populateScanFilterOptions(filterElement) {
  if (!filterElement) return;
  if (populateScanFilterOptionsInProgress) return;
  populateScanFilterOptionsInProgress = true;
  const previousValue = filterElement.value;
  try {
    // Fetch ONLY saved scans (saved reports) for the dropdown
    const response = await fetchScans({}, false); // includeUnsaved=false: only saved scans
    if (response && response.scans) {
      // Remove all options first so we never show duplicates
      while (filterElement.options.length) {
        filterElement.remove(0);
      }
      const placeholder = document.createElement('option');
      placeholder.value = '';
      placeholder.textContent = 'Select a scan';
      filterElement.appendChild(placeholder);

      const sortedScans = response.scans.sort(
        (a, b) => parseDateAsUTC(b.created_at) - parseDateAsUTC(a.created_at)
      );
      sortedScans.forEach(scan => {
        const option = document.createElement('option');
        option.value = scan.id;
        const statusLabel = (scan.status || 'unknown').toLowerCase() === 'running' ? '🔄 Running' : scan.status;
        option.textContent = `#${scan.id} - ${scan.target} (${scan.owasp_category_name || scan.owasp_category}) - ${statusLabel}`;
        filterElement.appendChild(option);
      });
      if (previousValue && filterElement.querySelector(`option[value="${previousValue}"]`)) {
        filterElement.value = previousValue;
      }
    }
  } catch (error) {
    console.error('Error populating scan filter:', error);
  } finally {
    populateScanFilterOptionsInProgress = false;
  }
}

// Update the scan filter when new scans are added
function updateScanFilter() {
  const scanFilter = document.getElementById('scanSummaryFilter');
  if (scanFilter) {
    populateScanFilterOptions(scanFilter);
  }
}

// Modify the existing refreshScansViews function to also update the scan filter
const originalRefreshScansViews = refreshScansViews;
refreshScansViews = async function() {
  await originalRefreshScansViews();
  updateScanFilter(); // Update the scan filter options
};

// Modify startScanSummaryPolling to set filter when scan is in dropdown (saved OR running scans)
const originalStartScanSummaryPolling = startScanSummaryPolling;
startScanSummaryPolling = function(scanId) {
  originalStartScanSummaryPolling(scanId);
  
  const scanFilter = document.getElementById('scanSummaryFilter');
  if (scanFilter) {
    // Always try to set the selection for the current scan
    // This works for both saved scans (in dropdown) and running scans (may not be in dropdown yet)
    const optionExists = scanFilter.querySelector(`option[value="${scanId}"]`);
    if (optionExists) {
      scanFilter.value = scanId;
    } else {
      // Scan not in dropdown yet (running scan, not saved), but still show it
      // The dropdown only shows saved scans, but we can still display running scans
      console.log(`Scan ${scanId} not in dropdown (not saved yet), but displaying anyway`);
    }
  }
};


/* ===== FETCH SCANS + STATS ===== */
async function fetchScans(query = {}, includeUnsaved = true) {
  const params = new URLSearchParams();
  if (query.target) params.set("target", query.target);
  if (query.status) params.set("status", query.status);
  if (query.page) params.set("page", query.page);
  if (query.page_size) params.set("page_size", query.page_size);
  if (includeUnsaved !== undefined) params.set("include_unsaved", includeUnsaved);
  const path = API_ROUTES.listScans() + (params.toString() ? `?${params}` : "");
  return await apiRequest(path, { method: "GET" });
}

function summarizeStats(scans) {
  const targets = new Set();
  const criticalTargets = new Set();
  const cleanAssets = new Set();
  const sevCounts = { critical: 0, high: 0, medium: 0, low: 0 };

  scans.forEach((scan) => {
    if (scan.target) targets.add(scan.target);
    const findings = scan.findings || [];
    let worst = 0;

    if (Array.isArray(findings) && findings.length > 0) {
      findings.forEach((f) => {
        const sev = (f.severity || "").toLowerCase();
        if (sev === "critical") {
          sevCounts.critical++;
          worst = Math.max(worst, 4);
        } else if (sev === "high") {
          sevCounts.high++;
          worst = Math.max(worst, 3);
        } else if (sev === "medium") {
          sevCounts.medium++;
          worst = Math.max(worst, 2);
        } else if (sev === "low") {
          sevCounts.low++;
          worst = Math.max(worst, 1);
        }
      });
    } else {
      // GET /api/scans does not embed findings; use finding_count + highest_severity per scan
      const fc = scan.finding_count;
      if (fc === 0) {
        worst = 0;
      } else if (scan.highest_severity) {
        const hs = String(scan.highest_severity).toLowerCase();
        if (hs === "critical") worst = 4;
        else if (hs === "high") worst = 3;
        else if (hs === "medium") worst = 2;
        else if (hs === "low") worst = 1;
        else worst = 0;
      }
    }

    const scanStatus = (scan.status || "").toLowerCase();
    const isCompleted = scanStatus === "completed" || scanStatus === "completed_with_errors";

    if (worst >= 3) {
      criticalTargets.add(scan.target);
    } else if (isCompleted && worst < 2) {
      // Clean: no medium+ (no findings, or only info/low). Info-only often reports as highest low from API.
      cleanAssets.add(scan.target);
    }
  });

  return {
    uniqueTargets: targets.size,
    criticalTargets: criticalTargets.size,
    cleanAssets: cleanAssets.size,
    uniqueTargetList: Array.from(targets).sort(),
    criticalTargetList: Array.from(criticalTargets).sort(),
    cleanAssetsList: Array.from(cleanAssets).sort(),
    sevCounts,
  };
}

let lastDashboardSummary = { uniqueTargetList: [], criticalTargetList: [], cleanAssetsList: [] };

function updateDashboardScheduledScansCard(scheduleList) {
  const list = Array.isArray(scheduleList) ? scheduleList : [];
  const total = list.length;
  const on = list.filter((s) => s && s.enabled === true).length;
  const off = list.filter((s) => s && s.enabled === false).length;

  const totalEl = document.getElementById("statScheduledScans");
  const onEl = document.getElementById("statScheduledScansOn");
  const offEl = document.getElementById("statScheduledScansOff");
  if (totalEl) totalEl.textContent = total;
  if (onEl) onEl.textContent = on;
  if (offEl) offEl.textContent = off;
}

function renderDashboardStats(summary) {
  document.getElementById("statUniqueTargets").textContent = summary.uniqueTargets;
  document.getElementById("statCriticalTargets").textContent = summary.criticalTargets;
  document.getElementById("statCleanAssets").textContent = summary.cleanAssets;
  const el = document.getElementById("statScheduledScans");
  if (el) el.textContent = summary.scheduledScans ?? 0;
  const onEl = document.getElementById("statScheduledScansOn");
  const offEl = document.getElementById("statScheduledScansOff");
  if (onEl) onEl.textContent = summary.scheduledScansOn ?? 0;
  if (offEl) offEl.textContent = summary.scheduledScansOff ?? 0;
  lastDashboardSummary = summary;
}

function showTargetsListModal(title, items) {
  const escapeHtml = (s) => {
    const div = document.createElement("div");
    div.textContent = s;
    return div.innerHTML;
  };
  const list = Array.isArray(items) && items.length ? items : [];
  const overlay = document.createElement("div");
  overlay.className = "modal-backdrop";
  overlay.setAttribute("role", "dialog");
  overlay.setAttribute("aria-label", title);
  overlay.innerHTML = `
    <div class="modal stat-list-modal">
      <div class="modal-header">
        <div class="modal-title">${title}</div>
        <button type="button" class="modal-close" aria-label="Close">&times;</button>
      </div>
      <div class="modal-body">
        ${list.length ? `<ul class="stat-target-list">${list.map((t) => `<li><code>${escapeHtml(t)}</code></li>`).join("")}</ul>` : "<p class=\"stat-list-empty\">No targets</p>"}
      </div>
      <div class="modal-footer" style="padding: 12px 20px;">
        <button type="button" class="btn-ghost close-targets-list-btn">Close</button>
      </div>
    </div>
  `;
  function close() {
    overlay.remove();
    document.removeEventListener("keydown", onKey);
  }
  function onKey(e) {
    if (e.key === "Escape") close();
  }
  overlay.querySelector(".modal-close").addEventListener("click", close);
  overlay.querySelector(".close-targets-list-btn").addEventListener("click", close);
  overlay.addEventListener("click", (e) => { if (e.target === overlay) close(); });
  document.addEventListener("keydown", onKey);
  document.body.appendChild(overlay);
}

/* ===== CHARTS ===== */
function initCharts() {
  const trendCanvas = document.getElementById("trendChart");
  if (!trendCanvas || !trendCanvas.getContext) {
    return;
  }
  const trendCtx = trendCanvas.getContext("2d");
  const axisColor = getAxisColor();

  function trendGradient(ctx, chartArea, datasetIndex) {
    if (!chartArea || chartArea.bottom <= chartArea.top) return null;
    const gradient = ctx.createLinearGradient(0, chartArea.top, 0, chartArea.bottom);
    if (datasetIndex === 0) {
      gradient.addColorStop(0, "rgba(56, 189, 248, 0.92)");
      gradient.addColorStop(0.4, "rgba(56, 189, 248, 0.35)");
      gradient.addColorStop(0.7, "rgba(56, 189, 248, 0.08)");
      gradient.addColorStop(1, "rgba(56, 189, 248, 0)");
    } else if (datasetIndex === 1) {
      gradient.addColorStop(0, "rgba(251, 113, 133, 0.95)");
      gradient.addColorStop(0.3, "rgba(251, 113, 133, 0.6)");
      gradient.addColorStop(0.6, "rgba(251, 113, 133, 0.35)");
      gradient.addColorStop(1, "rgba(251, 113, 133, 0.45)");
    }
    return gradient;
  }

  trendChart = new Chart(trendCtx, {
    type: "line",
    data: {
      labels: [],  // Will be populated from API
      dates: [],
      dateKeys: [],  // YYYY-MM-DD per index for modal
      datasets: [
        {
          label: "Findings",
          data: [0, 0, 0, 0, 0, 0, 0],
          borderColor: "#38bdf8",
          backgroundColor: function (context) {
            const chart = context.chart;
            const ctx = chart.ctx;
            const area = chart.chartArea;
            return trendGradient(ctx, area, 0) || "rgba(56, 189, 248, 0.28)";
          },
          fill: "origin",
          tension: 0.4,
          borderWidth: 2.5,
          pointRadius: 0,
          pointHoverRadius: 6,
          pointBorderWidth: 0,
          pointBackgroundColor: "#38bdf8",
        },
        {
          label: "Vulnerabilities",
          data: [0, 0, 0, 0, 0, 0, 0],
          borderColor: "#fb7185",
          backgroundColor: function (context) {
            const chart = context.chart;
            const ctx = chart.ctx;
            const area = chart.chartArea;
            return trendGradient(ctx, area, 1) || "rgba(251, 113, 133, 0.28)";
          },
          fill: "origin",
          tension: 0.4,
          borderWidth: 2.5,
          pointRadius: 0,
          pointHoverRadius: 6,
          pointBorderWidth: 0,
          pointBackgroundColor: "#fb7185",
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: {
        mode: 'index',
        intersect: false,
      },
      plugins: {
        legend: { display: false },
        tooltip: {
          enabled: true,
          backgroundColor: 'rgba(2, 6, 23, 0.95)',
          borderColor: '#38bdf8',
          borderWidth: 2,
          padding: 14,
          titleColor: '#f9fafb',
          bodyColor: '#e5e7eb',
          bodyFont: {
            size: 13,
            weight: '500',
          },
          titleFont: {
            size: 14,
            weight: '600',
          },
          boxPadding: 10,
          displayColors: true,
          caretPadding: 15,
          cornerRadius: 8,
          animation: false,
          mode: 'index',
          intersect: false,
          axis: 'x',
          position: 'average',
          callbacks: {
            title: function (ctx) {
              const date = ctx[0].label;
              return `📅 ${date}`;
            },
            label: function (ctx) {
              const dataset = ctx.dataset.label;
              const value = ctx.parsed.y;
              if (dataset === 'Findings') {
                return `🔵 Findings: ${value}`;
              } else {
                return `🔴 Vulnerabilities: ${value}`;
              }
            },
            afterBody: function (ctx) {
              return [
                '',
                `💡 Click to view Details`,
              ];
            },
          },
        },
      },
      scales: {
        x: {
          ticks: { 
            color: axisColor, 
            font: { size: 12, weight: '500' },
            padding: 12,
            callback: function(value) {
              // Show day name
              return trendChart.data.labels[value] || '';
            }
          },
          grid: { 
            color: "rgba(148,163,184,0.1)",
            drawBorder: false,
          },
        },
        y: {
          beginAtZero: true,
          ticks: { 
            color: axisColor, 
            font: { size: 11 },
            stepSize: 5,
          },
          grid: { 
            display: false,
            color: "rgba(148,163,184,0.15)",
            drawBorder: false,
          },
        },
      },
    },
    plugins: [
      {
      id: 'autoScaleY',
      afterDatasetsDraw(chart) {
        const yScale = chart.scales && chart.scales.y;
        if (!yScale) return;
        const ds0 = chart.data?.datasets?.[0]?.data || [];
        const ds1 = chart.data?.datasets?.[1]?.data || [];
        const maxData = Math.max(...ds0, ...ds1, 1);
        const newMax = Math.ceil(Math.max(maxData, 1) / 5) * 5 + 5;
        if (yScale.max === newMax) return;

        // Prevent infinite recursive updates:
        // afterDatasetsDraw -> chart.update -> afterDatasetsDraw -> chart.update ...
        // Schedule the update once per frame instead of calling update immediately.
        if (chart.$autoScaleYScheduled) return;
        chart.$autoScaleYScheduled = true;
        yScale.max = newMax;
        requestAnimationFrame(() => {
          chart.$autoScaleYScheduled = false;
          try { chart.update('none'); } catch (_) {}
        });
      }
    },
    {
      id: 'dateLabels',
      afterDatasetsDraw(chart) {
        // Draw date labels below day labels
        const ctx = chart.ctx;
        const xScale = chart.scales.x;
        const yScale = chart.scales.y;
        
        if (!chart.data.dates || chart.data.dates.length === 0) return;
        
        ctx.save();
        ctx.font = '10px system-ui';
        ctx.fillStyle = 'rgba(148, 163, 184, 0.6)';
        ctx.textAlign = 'center';
        
        const xOffset = xScale.left;
        const yOffset = yScale.bottom + 18;
        const xWidth = xScale.width / (chart.data.dates.length - 1 || 1);
        
        chart.data.dates.forEach((date, index) => {
          const x = xOffset + (index * xWidth);
          ctx.fillText(date, x, yOffset);
        });
        
        ctx.restore();
      }
    }]
  });

  // Add click handler to trend chart - click on line to view details
  trendCtx.canvas.addEventListener('click', async (e) => {
    const canvasPosition = Chart.helpers.getRelativePosition(e, trendChart);
    const dataX = trendChart.scales.x.getValueForPixel(canvasPosition.x);
    const dayIndex = Math.round(dataX);
    
    if (dayIndex >= 0 && dayIndex < trendChart.data.labels.length) {
      const dayLabel = trendChart.data.labels[dayIndex];
      await showTrendDetailModal(dayLabel, dayIndex);
    }
  });

  const emptySeverityPlugin = {
    id: "emptySeverityRing",
    beforeDraw(chart, args, opts) {
      const ds = chart?.data?.datasets?.[0];
      const data = Array.isArray(ds?.data) ? ds.data : [];
      const total = data.reduce((sum, v) => sum + (Number(v) || 0), 0);
      
      // Don't show empty ring if we have our LOW risk visualization (1 in LOW segment)
      if (total > 0) return;

      const { ctx, chartArea } = chart;
      if (!ctx || !chartArea) return;
      const w = chartArea.right - chartArea.left;
      const h = chartArea.bottom - chartArea.top;
      if (w <= 0 || h <= 0) return;

      const x = chartArea.left + w / 2;
      const y = chartArea.top + h / 2;
      const r = Math.min(w, h) / 2;
      const thickness = Math.max(10, r * 0.26);

      ctx.save();
      ctx.beginPath();
      ctx.arc(x, y, r - thickness / 2, 0, Math.PI * 2);
      ctx.lineWidth = thickness;
      ctx.strokeStyle = (opts && opts.ringColor) || "rgba(148,163,184,0.25)";
      ctx.stroke();

      ctx.fillStyle = (opts && opts.textColor) || "rgba(148,163,184,0.9)";
      ctx.font = "12px system-ui";
      ctx.textAlign = "center";
      ctx.textBaseline = "middle";
      ctx.fillText((opts && opts.text) || "No findings yet", x, y);
      ctx.restore();
    },
  };
  /**
   * Build the severity donut only after the container has a real size.
   * This avoids a blank/zero-size chart in external browsers where layout
   * can be resolved slightly later than in the embedded webview.
   */
  function buildSeverityChartWhenReady() {
    if (severityChart) return;
    const canvas = document.getElementById("severityChart");
    if (!canvas) {
      requestAnimationFrame(buildSeverityChartWhenReady);
      return;
    }
    const container = canvas.closest(".severity-chart-wrap") || canvas.parentElement;
    const rect = container && container.getBoundingClientRect ? container.getBoundingClientRect() : null;
    if (!rect || rect.width === 0 || rect.height === 0) {
      // Container not laid out yet – try again on next frame
      requestAnimationFrame(buildSeverityChartWhenReady);
      return;
    }

    const sevCtx = canvas.getContext("2d");
    if (!sevCtx) return;

    severityChart = new Chart(sevCtx, {
      type: "doughnut",
      data: {
        labels: ["Critical", "High", "Medium", "Low", "Info"],
        datasets: [
          {
            data: [0, 0, 0, 0, 0],
            backgroundColor: ["#ef4444", "#f97316", "#eab308", "#3b82f6", "#6b7280"],
            borderColor: "#020617",
            borderWidth: 1,
            borderRadius: 4,
            hoverBorderColor: "#ffffff",
            hoverBorderWidth: 2,
            spacing: 4,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        aspectRatio: 1,
        layout: {
          padding: 12,
        },
        plugins: {
          legend: { display: false },
          tooltip: {
            enabled: true,
            callbacks: {
              label: function (context) {
                const total = context.dataset.data.reduce(function (a, b) { return a + b; }, 0);
                const value = context.raw || 0;
                const pct = total > 0 ? ((value / total) * 100).toFixed(1) : "0";
                return [
                  context.label,
                  value + " " + (value === 1 ? "finding" : "findings") + " (" + pct + "%)",
                  "From all scanned targets",
                ];
              },
            },
            displayColors: true,
            padding: 10,
            titleFont: { size: 13 },
            bodyFont: { size: 12 },
          },
          emptySeverityRing: {
            text: "No findings yet",
          },
        },
        cutout: "68%",
        rotation: -90,
      },
      plugins: [emptySeverityPlugin],
    });

    // Chart is ready: load severity data now (avoids race where fetch finished before chart existed)
    fetchSeverityStats()
      .then((sev) => {
        console.log("Global severity stats received:", sev);
        updateSeverityChart({
          critical: sev.critical || 0,
          high: sev.high || 0,
          medium: sev.medium || 0,
          low: sev.low || 0,
          info: sev.info || 0,
        });
      })
      .catch((e) => console.error("Failed to load severity stats", e));
  }

  buildSeverityChartWhenReady();

  // Keep severity donut correctly sized on viewport changes
  window.addEventListener("resize", () => {
    if (!severityChart) return;
    const container = document.querySelector(".severity-chart-wrap");
    const rect = container && container.getBoundingClientRect ? container.getBoundingClientRect() : null;
    if (rect && rect.width > 0 && rect.height > 0) {
      severityChart.resize();
    }
  });

  // Security Trend: default dates and initial load
  const trendStartDate = document.getElementById("trendStartDate");
  const trendEndDate = document.getElementById("trendEndDate");
  const today = new Date();
  const defaultEnd = today.toISOString().split("T")[0];
  const defaultStart = new Date(today);
  defaultStart.setDate(defaultStart.getDate() - 6);
  const defaultStartStr = defaultStart.toISOString().split("T")[0];
  if (trendStartDate) trendStartDate.value = defaultStartStr;
  if (trendEndDate) trendEndDate.value = defaultEnd;

  updateTrendFromApi(defaultStartStr, defaultEnd).catch((e) => console.error("Failed to load trend stats", e));
}

function computeScanCountsForRange(rangeKey, labels) {
  // Single date: YYYY-MM-DD
  if (/^\d{4}-\d{2}-\d{2}$/.test(rangeKey)) {
    const start = new Date(rangeKey + "T00:00:00");
    return { days: 1, start, dateKeys: [rangeKey] };
  }
  // Custom range: "startDate,endDate"
  const rangeMatch = typeof rangeKey === "string" && rangeKey.indexOf(",") !== -1 && rangeKey.split(",");
  if (rangeMatch && rangeMatch.length === 2) {
    const startStr = rangeMatch[0].trim();
    const endStr = rangeMatch[1].trim();
    if (/^\d{4}-\d{2}-\d{2}$/.test(startStr) && /^\d{4}-\d{2}-\d{2}$/.test(endStr)) {
      const start = new Date(startStr + "T00:00:00");
      const end = new Date(endStr + "T00:00:00");
      if (start > end) return computeScanCountsForRange(`${endStr},${startStr}`, labels);
      const dateKeys = [];
      const d = new Date(start);
      while (d <= end) {
        dateKeys.push(d.toISOString().split("T")[0]);
        d.setDate(d.getDate() + 1);
      }
      return { days: dateKeys.length, start, dateKeys };
    }
  }
  // Preset range: 7d, 30d, 90d
  const days = labels.length || (rangeKey === "30d" ? 30 : rangeKey === "90d" ? 90 : 7);
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const start = new Date(today);
  start.setDate(start.getDate() - (days - 1));
  const dateKeys = [];
  for (let i = 0; i < days; i++) {
    const d = new Date(start);
    d.setDate(start.getDate() + i);
    dateKeys.push(d.toISOString().split("T")[0]);
  }
  return { days, start, dateKeys };
}

function buildScanSeries(scans, rangeKey, labels) {
  const { dateKeys, start } = computeScanCountsForRange(rangeKey, labels);
  const isSingleDate = /^\d{4}-\d{2}-\d{2}$/.test(rangeKey);
  const isCustomRange = typeof rangeKey === "string" && rangeKey.indexOf(",") !== -1;
  const end = new Date(start);
  if (isSingleDate) end.setDate(end.getDate() + 1);
  else if (isCustomRange && dateKeys.length > 0) {
    const lastKey = dateKeys[dateKeys.length - 1];
    end.setTime(new Date(lastKey + "T00:00:00").getTime());
    end.setDate(end.getDate() + 1);
  } else {
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    end.setTime(today.getTime());
    end.setDate(end.getDate() + 1);
  }

  const countByDate = {};
  scans.forEach((scan) => {
    if (!scan.created_at) return;
    const d = parseDateAsUTC(scan.created_at);
    if (!d || isNaN(d.getTime()) || d < start || d >= end) return;
    const key = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
    countByDate[key] = (countByDate[key] || 0) + 1;
  });

  return dateKeys.map((key) => countByDate[key] || 0);
}

/**
 * @param {string} startDateOrRange - "YYYY-MM-DD", "start,end", or "7d"|"30d"|"90d"
 * @param {string} [endDate] - when set, use start_date + end_date for the chart
 */
async function updateTrendFromApi(startDateOrRange, endDate) {
  if (!trendChart) return;

  const rangeKey = endDate && /^\d{4}-\d{2}-\d{2}$/.test(startDateOrRange) && /^\d{4}-\d{2}-\d{2}$/.test(endDate)
    ? `${startDateOrRange},${endDate}`
    : startDateOrRange;

  try {
    const stats = await fetchTrendStats(startDateOrRange, endDate);

    trendChart.data.labels = stats.labels || [];
    trendChart.data.dates = stats.dates || [];
    trendChart.data.dateKeys = stats.date_keys || [];
    trendChart.data.datasets[0].data = stats.findings || [];
    trendChart.data.datasets[1].data = stats.vuln_targets || [];

    const singleDay = trendChart.data.labels.length === 1;
    trendChart.data.datasets.forEach((ds) => {
      ds.pointRadius = singleDay ? 6 : 0;
      ds.pointHoverRadius = singleDay ? 8 : 0;
    });

    trendChart.currentRange = rangeKey;
    trendChart.update();
  } catch (e) {
    console.error("Failed to load trend stats", e);
    trendChart.data.datasets[0].data = [0, 0, 0, 0, 0, 0, 0];
    trendChart.data.datasets[1].data = [0, 0, 0, 0, 0, 0, 0];
    trendChart.update();
  }
}

const SEVERITY_LABELS = ["Critical", "High", "Medium", "Low", "Info"];
const SEVERITY_COLORS = ["#ef4444", "#f97316", "#eab308", "#3b82f6", "#6b7280"];

// Prevent re-entrant severity chart updates during initial load/polling.
// This avoids Chart.js crashes like "Maximum call stack size exceeded" when
// multiple callers trigger updates simultaneously.
let severityScopeInFlight = false;
let severityScopeQueued = false;
// Track when we last refreshed trend analytics during active polling, to avoid too-frequent network calls.
let lastTrendUpdateAt = 0;

function updateSeverityChart(sevCounts) {
  if (!severityChart) return;
  console.log("=== UPDATE SEVERITY CHART ===");
  console.log("Raw data received:", sevCounts);
  const c = coerceSeverityCounts(sevCounts);
  console.log("Coerced counts:", c);
  const totalCount = c.critical + c.high + c.medium + c.low + c.info;
  console.log("Total count:", totalCount);

  const counts = [c.critical, c.high, c.medium, c.low, c.info];
  const singleSeverityIndex = totalCount > 0 ? counts.findIndex((n) => n > 0) : -1;
  const isSingleSeverity = singleSeverityIndex >= 0 && counts.filter((n) => n > 0).length === 1;

  let chartData, chartLabels, chartColors;
  if (totalCount === 0) {
    chartData = [0, 0, 0, 0, 0];
    chartLabels = SEVERITY_LABELS;
    chartColors = SEVERITY_COLORS;
    console.log("Zero findings detected - showing empty chart state");
  } else if (isSingleSeverity) {
    chartData = [counts[singleSeverityIndex]];
    chartLabels = [SEVERITY_LABELS[singleSeverityIndex]];
    chartColors = [SEVERITY_COLORS[singleSeverityIndex]];
    console.log("Single severity - ring joined at top middle:", chartLabels[0]);
  } else {
    chartData = counts;
    chartLabels = SEVERITY_LABELS;
    chartColors = SEVERITY_COLORS;
  }

  severityChart.data.labels = chartLabels;
  severityChart.data.datasets[0].data = chartData;
  severityChart.data.datasets[0].backgroundColor = chartColors;
  // No gap when only one severity (ring connects); small gap between slices when multiple severities
  severityChart.data.datasets[0].spacing = isSingleSeverity ? 0 : 4;
  console.log("Dataset data set to:", chartData);

  // Update legend counts - each severity its own row
  document.getElementById("sevCriticalCount").textContent = c.critical;
  document.getElementById("sevHighCount").textContent = c.high;
  document.getElementById("sevMediumCount").textContent = c.medium;
  document.getElementById("sevLowCount").textContent = c.low;
  document.getElementById("sevInfoCount").textContent = c.info;
  document.getElementById("totalFindingsCount").textContent = totalCount;

  severityChart.update();
  console.log("Legend - Critical:", c.critical, "High:", c.high, "Medium:", c.medium, "Low:", c.low, "Info:", c.info, "Total:", totalCount);
  console.log("=== CHART UPDATE COMPLETE ===");
}

async function updateSeverityScope(scopeValue) {
  if (severityScopeInFlight) {
    severityScopeQueued = true;
    return;
  }
  severityScopeInFlight = true;
  console.log("=== UPDATE SEVERITY SCOPE CALLED ===");
  console.log("Scope value:", scopeValue);
  try {
    // Always show cumulative severity distribution of ALL scans
    // Ignore any specific scan selection - always use global view
    const sev = await fetchSeverityStats();
    console.log("Global severity stats received:", sev);
    console.log("Processing data for chart update...");
    updateSeverityChart({
      critical: sev.critical || 0,
      high: sev.high || 0,
      medium: sev.medium || 0,
      low: sev.low || 0,
      info: sev.info || 0,
    });
    console.log("=== UPDATE SEVERITY SCOPE COMPLETE ===");
  } finally {
    severityScopeInFlight = false;
    if (severityScopeQueued) {
      severityScopeQueued = false;
      // Avoid synchronous recursion (prevents call-stack issues). Run after paint.
      setTimeout(() => {
        updateSeverityScope(scopeValue).catch(() => {});
      }, 0);
    }
  }
}

/**
 * Refresh Security Trend and Severity Distribution charts (e.g. after delete scan or new scan added).
 */
async function refreshDashboardCharts() {
  try {
    if (severityChart) {
      const sev = await fetchSeverityStats();
      updateSeverityChart({
        critical: sev.critical || 0,
        high: sev.high || 0,
        medium: sev.medium || 0,
        low: sev.low || 0,
        info: sev.info || 0,
      });
    }
    if (trendChart) {
      const trendStart = document.getElementById("trendStartDate");
      const trendEnd = document.getElementById("trendEndDate");
      const startVal = trendStart && trendStart.value ? trendStart.value : new Date(Date.now() - 6 * 24 * 60 * 60 * 1000).toISOString().split("T")[0];
      const endVal = trendEnd && trendEnd.value ? trendEnd.value : new Date().toISOString().split("T")[0];
      await updateTrendFromApi(startVal, endVal);
    }
  } catch (e) {
    console.warn("refreshDashboardCharts:", e);
  }
}

async function showTrendDetailModal(dayLabel, dayIndex) {
  // Use the chart's date for this index (supports custom range; fallback to "last 7 days" logic)
  let dateStr = null;
  if (trendChart && trendChart.data.dateKeys && trendChart.data.dateKeys[dayIndex]) {
    dateStr = trendChart.data.dateKeys[dayIndex];
  }
  if (!dateStr) {
    const today = new Date();
    const daysAgo = (trendChart && trendChart.data.labels ? trendChart.data.labels.length - 1 : 6) - dayIndex;
    const targetDate = new Date(today);
    targetDate.setDate(targetDate.getDate() - daysAgo);
    dateStr = targetDate.toISOString().split('T')[0];
  }

  // Fetch findings for this day from the API (list_scans does not include findings)
  let dayFindings = [];
  let sevCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  let affectedTargets = 0;
  try {
    const res = await apiRequest(`/api/scans/stats/trend/day-detail?date=${encodeURIComponent(dateStr)}`, { method: "GET" });
    dayFindings = res.findings || [];
    sevCounts = res.severity_counts || sevCounts;
    affectedTargets = res.affected_targets != null ? res.affected_targets : 0;
  } catch (e) {
    console.error("Failed to load day detail for", dateStr, e);
  }
  
  // Create modal content
  const modal = document.createElement('div');
  modal.className = 'modal-backdrop';
  modal.innerHTML = `
    <div class="modal trend-day-detail-modal" style="max-height: 85vh; overflow-y: auto; max-width: min(96vw, 1200px); width: 92%;">
      <div class="modal-header">
        <div>
          <div class="modal-title">📊 ${dayLabel} - Findings Report</div>
          <div class="modal-subtitle">${dateStr} · Total Findings: ${dayFindings.length} · Affected Targets: ${affectedTargets}</div>
        </div>
        <button class="modal-close">&times;</button>
      </div>
      <div class="modal-body">
        <div style="display: grid; grid-template-columns: repeat(5, 1fr); gap: 10px; margin-bottom: 20px;">
          <div style="background: rgba(239, 68, 68, 0.1); border-radius: 8px; padding: 10px; text-align: center; border-left: 3px solid #ef4444;">
            <div style="font-size: 20px; font-weight: bold; color: #ef4444;">${sevCounts.critical}</div>
            <div style="font-size: 11px; color: #64748b;">Critical</div>
          </div>
          <div style="background: rgba(249, 115, 22, 0.1); border-radius: 8px; padding: 10px; text-align: center; border-left: 3px solid #f97316;">
            <div style="font-size: 20px; font-weight: bold; color: #f97316;">${sevCounts.high}</div>
            <div style="font-size: 11px; color: #64748b;">High</div>
          </div>
          <div style="background: rgba(234, 179, 8, 0.1); border-radius: 8px; padding: 10px; text-align: center; border-left: 3px solid #eab308;">
            <div style="font-size: 20px; font-weight: bold; color: #eab308;">${sevCounts.medium}</div>
            <div style="font-size: 11px; color: #64748b;">Medium</div>
          </div>
          <div style="background: rgba(59, 130, 246, 0.1); border-radius: 8px; padding: 10px; text-align: center; border-left: 3px solid #3b82f6;">
            <div style="font-size: 20px; font-weight: bold; color: #3b82f6;">${sevCounts.low}</div>
            <div style="font-size: 11px; color: #64748b;">Low</div>
          </div>
          <div style="background: rgba(100, 116, 139, 0.1); border-radius: 8px; padding: 10px; text-align: center; border-left: 3px solid #94a3b8;">
            <div style="font-size: 20px; font-weight: bold; color: #94a3b8;">${sevCounts.info}</div>
            <div style="font-size: 11px; color: #64748b;">Info</div>
          </div>
        </div>
        
        ${dayFindings.length === 0 ? `
          <div style="text-align: center; padding: 40px; color: #64748b; background: rgba(255,255,255,0.02); border-radius: 8px;">
            <div style="font-size: 16px; margin-bottom: 8px;">✓ No findings recorded for this day</div>
            <div style="font-size: 12px;">All scanned targets were secure</div>
          </div>
        ` : `
          <div class="trend-day-detail-table-wrap">
          <table class="data-table trend-day-detail-table" style="width: 100%; font-size: 12px;">
            <thead>
              <tr>
                <th>Tool</th>
                <th>Type</th>
                <th>Severity</th>
                <th>Location</th>
                <th>Description</th>
              </tr>
            </thead>
            <tbody>
              ${dayFindings.map(f => {
                const typ = f.type ? String(f.type).charAt(0).toUpperCase() + String(f.type).slice(1) : '-';
                return `
                <tr>
                  <td style="font-weight: 500;">${escapeHtml(String(f.tool_name || '-'))}</td>
                  <td>${escapeHtml(typ)}</td>
                  <td><span class="tag tag-${(f.severity || 'low').toLowerCase()}">${escapeHtml(String((f.severity || 'unknown').toUpperCase()))}</span></td>
                  <td class="trend-day-detail-cell-location">${escapeHtml(String(f.location != null ? f.location : '-'))}</td>
                  <td class="trend-day-detail-cell-desc">${escapeHtml(String(f.description != null ? f.description : '-'))}</td>
                </tr>
              `;
              }).join('')}
            </tbody>
          </table>
          </div>
        `}
      </div>
    </div>
  `;
  
  document.body.appendChild(modal);
  
  // Close modal handler
  modal.querySelector('.modal-close').addEventListener('click', () => {
    modal.remove();
  });
  
  modal.addEventListener('click', (e) => {
    if (e.target === modal) {
      modal.remove();
    }
  });
}

/* ===== SAVED REPORTS (Security Reports Registry) ===== */
let savedReportsScans = [];
let currentFilteredReportsScans = [];

function applyReportsFilters() {
  const targetInput = document.getElementById("reportsFilterTarget");
  const owaspSelect = document.getElementById("reportsFilterOwasp");
  const statusSelect = document.getElementById("reportsFilterStatus");
  const targetVal = (targetInput && targetInput.value || "").trim().toLowerCase();
  const owaspVal = (owaspSelect && owaspSelect.value || "").trim();
  const statusVal = (statusSelect && statusSelect.value || "").trim().toLowerCase();

  const filtered = savedReportsScans.filter((s) => {
    if (targetVal && !(s.target || "").toLowerCase().includes(targetVal)) return false;
    if (owaspVal && (s.owasp_category || "").trim() !== owaspVal) return false;
    if (statusVal && (s.status || "").toLowerCase() !== statusVal) return false;
    return true;
  });
  currentFilteredReportsScans = filtered;
  renderReportsTable(filtered);
}

function initSavedReportsFilters() {
  const targetInput = document.getElementById("reportsFilterTarget");
  const owaspSelect = document.getElementById("reportsFilterOwasp");
  const statusSelect = document.getElementById("reportsFilterStatus");
  if (targetInput) targetInput.addEventListener("input", applyReportsFilters);
  if (owaspSelect) owaspSelect.addEventListener("change", applyReportsFilters);
  if (statusSelect) statusSelect.addEventListener("change", applyReportsFilters);
}

/* ===== TABLE RENDERING ===== */
function renderReportsTable(scans) {
  const tbody = document.getElementById("reportsTableBody");
  if (!tbody) return;
  tbody.innerHTML = "";
  (scans || []).forEach((scan) => {
    const tr = document.createElement("tr");
    const topSeverity =
      (scan.highest_severity ||
        scan.highestSeverity ||
        scan.top_severity ||
        ""
      ).toLowerCase();
    const count =
      scan.finding_count ??
      scan.findings_count ??
      (scan.findings ? scan.findings.length : 0);

    let sevClass = "tag-low";
    if (topSeverity === "critical") sevClass = "tag-critical";
    else if (topSeverity === "high") sevClass = "tag-high";
    else if (topSeverity === "medium") sevClass = "tag-medium";

    let statusClass = "badge-running";
    const status = (scan.status || "").toLowerCase();
    if (status === "completed") statusClass = "badge-completed";
    else if (status === "failed") statusClass = "badge-failed";

    tr.innerHTML = `
      <td>${scan.id}</td>
      <td>${scan.target || "-"}</td>
      <td>${scan.owasp_category_name || getOwaspCategoryName(scan.owasp_category) || "-"}</td>
      <td><span class="tag ${sevClass}">${scan.highest_severity || "N/A"}</span></td>
      <td>${count}</td>
      <td><span class="badge-status ${statusClass}">${scan.status || "-"}</span></td>
      <td>
        <div class="actions-cell">
          <button class="tool-run-btn" data-action="view-html" data-id="${scan.id}">View Report</button>
          <button class="tool-run-btn delete-btn" data-action="delete-scan" data-id="${scan.id}" title="Delete this scan">🗑️</button>
        </div>
      </td>
    `;
    tbody.appendChild(tr);
  });

  tbody.querySelectorAll("button").forEach((btn) => {
    btn.addEventListener("click", () => {
      const scanId = btn.dataset.id;
      const action = btn.dataset.action;
      
      if (action === "delete-scan") {
        const target = btn.closest("tr")?.cells[1]?.textContent || "unknown";
        deleteScan(scanId, target);
      } else {
        window.open(getApiUrl(API_ROUTES.reportHtml(scanId)), "_blank");
      }
    });
  });
}

function normalizeTargetKey(t) {
  if (!t || typeof t !== "string") return "unknown";
  let s = t.trim().toLowerCase();
  s = s.replace(/^https?:\/\//, "").replace(/\/.*$/, "").split("?")[0];
  if (s.startsWith("www.")) s = s.slice(4);
  return s || "unknown";
}

function updateTargetsSelectAllState() {
  const tbody = document.getElementById("targetsTableBody");
  const selectAll = document.getElementById("targetsSelectAll");
  if (!tbody || !selectAll) return;
  const checkboxes = tbody.querySelectorAll(".target-row-select");
  const checked = tbody.querySelectorAll(".target-row-select:checked").length;
  selectAll.checked = checkboxes.length > 0 && checked === checkboxes.length;
  selectAll.indeterminate = checked > 0 && checked < checkboxes.length;
}

function updateDeleteSelectedButtonState() {
  const tbody = document.getElementById("targetsTableBody");
  const btn = document.getElementById("deleteSelectedTargetsBtn");
  if (!tbody || !btn) return;
  const checked = tbody.querySelectorAll(".target-row-select:checked").length;
  btn.style.display = checked > 0 ? "" : "none";
}

async function deleteSelectedTargets() {
  const tbody = document.getElementById("targetsTableBody");
  if (!tbody) return;
  const checked = tbody.querySelectorAll(".target-row-select:checked");
  const targets = Array.from(checked).map((cb) => cb.dataset.target);
  if (targets.length === 0) return;
  showDeleteConfirmModal(
    "Delete Selected Targets?",
    `<strong>${targets.length} target(s) selected.</strong><br><br>All scans, findings, and data for these targets will be permanently removed.`,
    async () => {
      try {
        const response = await fetch(getApiUrl("/api/scans"));
        const data = await response.json();
        const scans = Array.isArray(data) ? data : data.scans || [];
        const toDelete = scans.filter((s) => targets.includes(normalizeTargetKey(s.target))).map((s) => s.id);
        let deleted = 0;
        for (const scanId of toDelete) {
          try {
            const res = await fetch(getApiUrl(`/api/scans/${scanId}`), { method: "DELETE" });
            if (res.ok) deleted++;
          } catch (e) {
            console.error("Error deleting scan", scanId, e);
          }
        }
        showNotification(`✓ Deleted ${deleted} scan(s) for ${targets.length} target(s)`, "success");
        await refreshScansViews();
        await refreshDashboardCharts();
      } catch (error) {
        console.error("Error deleting selected targets:", error);
        showNotification(`✗ Error: ${error.message}`, "error");
      }
    }
  );
}

function renderTargetsTable(scans) {
  const tbody = document.getElementById("targetsTableBody");
  if (!tbody) return;
  tbody.innerHTML = "";

  const byTarget = new Map();
  scans.forEach((scan) => {
    const raw = scan.target || "unknown";
    const key = normalizeTargetKey(raw);
    if (!byTarget.has(key)) byTarget.set(key, []);
    byTarget.get(key).push(scan);
  });

  byTarget.forEach((list, normalizedKey) => {
    const runs = list.length;
    let latestDate = "-";
    let topSeverity = "Low";
    let sevWeight = 0;

    list.forEach((scan) => {
      if (scan.created_at) {
        latestDate = scan.created_at;
      }
      const sev = (scan.highest_severity || "").toLowerCase();
      const weight =
        sev === "critical" ? 4 : sev === "high" ? 3 : sev === "medium" ? 2 : 1;
      if (weight > sevWeight) {
        sevWeight = weight;
        topSeverity = scan.highest_severity || "Low";
      }
    });

    let sevClass = "tag-low";
    if (topSeverity.toLowerCase() === "critical") sevClass = "tag-critical";
    else if (topSeverity.toLowerCase() === "high") sevClass = "tag-high";
    else if (topSeverity.toLowerCase() === "medium") sevClass = "tag-medium";

    const displayTarget = list[0]?.target || normalizedKey;
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td class="td-select"><input type="checkbox" class="target-row-select" data-target="${normalizedKey.replace(/"/g, '&quot;')}" aria-label="Select ${displayTarget.replace(/"/g, '&quot;')}"/></td>
      <td>${displayTarget}</td>
      <td><span class="tag ${sevClass}">${topSeverity}</span></td>
      <td>${runs}</td>
      <td>${new Date(latestDate).toISOString().split('T')[0]}</td>
      <td>
        <div class="actions-cell">
          <button class="tool-run-btn" data-action="view-details" data-target="${displayTarget.replace(/"/g, '&quot;')}">Details</button>
          <button class="tool-run-btn delete-btn" data-action="delete-all-target" data-target="${normalizedKey}" title="Delete all scans for this target">🗑️</button>
        </div>
      </td>
    `;
    tbody.appendChild(tr);
  });

  updateTargetsSelectAllState();
  updateDeleteSelectedButtonState();

  const selectAllEl = document.getElementById("targetsSelectAll");
  if (selectAllEl && !selectAllEl.dataset.wired) {
    selectAllEl.dataset.wired = "1";
    selectAllEl.addEventListener("change", function () {
      const checked = this.checked;
      document.querySelectorAll("#targetsTableBody .target-row-select").forEach((cb) => { cb.checked = checked; });
      updateDeleteSelectedButtonState();
    });
  }

  tbody.querySelectorAll(".target-row-select").forEach((cb) => {
    cb.addEventListener("change", () => {
      updateTargetsSelectAllState();
      updateDeleteSelectedButtonState();
    });
  });

  const deleteSelectedBtn = document.getElementById("deleteSelectedTargetsBtn");
  if (deleteSelectedBtn && !deleteSelectedBtn.dataset.wired) {
    deleteSelectedBtn.dataset.wired = "1";
    deleteSelectedBtn.addEventListener("click", deleteSelectedTargets);
  }
  
  // Add event listeners for delete all target button
  tbody.querySelectorAll('[data-action="delete-all-target"]').forEach(btn => {
    btn.addEventListener("click", async () => {
      const target = btn.dataset.target;
      const count = btn.closest("tr")?.cells[2]?.textContent || "?";
      
      showDeleteConfirmModal(
        "Delete All Scans for Target?",
        `<strong>Target:</strong> ${target}<br><strong>Total Scans:</strong> ${count}<br><br>All scans, findings, and data for this target will be permanently removed.`,
        async () => {
          try {
            // Get all scan IDs for this target
            const response = await fetch(getApiUrl("/api/scans?page=1&page_size=100"));
            const data = await response.json();
            // Handle both array and object with 'scans' property
            const scans = Array.isArray(data) ? data : data.scans || [];
            const scanIds = scans
              .filter(s => normalizeTargetKey(s.target) === target)
              .map(s => s.id);
            
            let deleted = 0;
            for (const scanId of scanIds) {
              try {
                const res = await fetch(getApiUrl(`/api/scans/${scanId}`), {
                  method: "DELETE"
                });
                if (res.ok) deleted++;
              } catch (e) {
                console.error("Error deleting scan", scanId, e);
              }
            }
            
            const message = deleted === scanIds.length 
              ? `✓ Deleted ${deleted} scans for "${target}"`
              : `✓ Deleted ${deleted}/${scanIds.length} scans for "${target}"`;
            showNotification(message, deleted === scanIds.length ? "success" : "info");
            await refreshScansViews();
            await refreshDashboardCharts();
          } catch (error) {
            console.error("Error deleting target scans:", error);
            showNotification(`✗ Error: ${error.message}`, "error");
          }
        }
      );
    });
  });
  
  // Add event listeners for target detail modal
  tbody.querySelectorAll('[data-action="view-details"]').forEach(btn => {
    if (!btn.getAttribute('data-listener-added')) {
      btn.addEventListener("click", async () => {
        const target = btn.dataset.target;
        await openTargetDetailModal(target);
      });
      btn.setAttribute('data-listener-added', 'true');
    }
  });
}

// Date formatting utility function — API datetimes are naive UTC; parse as UTC so local display matches wall clock.
function formatDate(value) {
  const date = parseDateAsUTC(value);
  if (!date || isNaN(date.getTime())) {
    if (value == null || value === "") return "—";
    return "Invalid Date";
  }
  // Local calendar/time (browser timezone) after correct UTC instant
  const month = date.getMonth() + 1;
  const day = date.getDate();
  const year = date.getFullYear();
  let hours = date.getHours();
  const minutes = date.getMinutes().toString().padStart(2, "0");
  const ampm = hours >= 12 ? "PM" : "AM";
  hours = hours % 12;
  hours = hours ? hours : 12;
  return `${month}/${day}/${year} ${hours}:${minutes} ${ampm}`;
}

// Format current time in Kathmandu timezone for note section
function formatKathmanduTime(date) {
  const d = date || new Date();
  return d.toLocaleDateString('en-US', { timeZone: 'Asia/Kathmandu' }) + ' ' + 
         d.toLocaleTimeString('en-US', { timeZone: 'Asia/Kathmandu', hour: '2-digit', minute: '2-digit' });
}

// Parse API datetime as UTC when the server sends naive ISO (no Z). Otherwise JS treats it as local and times are wrong.
function parseDateAsUTC(value) {
  if (value instanceof Date) return isNaN(value.getTime()) ? null : value;
  if (value == null || value === "") return null;
  const s = String(value).trim();
  if (!s) return null;
  if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/.test(s) && !/Z|[+-]\d{2}:?\d{2}$/.test(s)) {
    return new Date(s + "Z");
  }
  return new Date(s);
}

// User's local date + time (browser locale and timezone) — for schedule page columns
function formatDateLocal(date) {
  const d = date instanceof Date ? date : parseDateAsUTC(date);
  if (!d || isNaN(d.getTime())) return "—";
  return d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

/* ===== TARGET DETAIL MODAL FUNCTIONS ===== */

// Store current target scans so Combined Findings severity filter can re-render
let currentTargetDetailScans = [];

async function fetchTargetScans(target) {
  try {
    // Get all scans for the specific target
    const response = await fetch(getApiUrl("/api/scans?page=1&page_size=100"));
    const data = await response.json();
    
    // Handle both array and object with 'scans' property
    const allScans = Array.isArray(data) ? data : data.scans || [];
    
    // Normalize the target key for comparison
    const normalizedTarget = normalizeTargetKey(target);
    
    // Filter scans for the specific target using normalized comparison
    const targetScans = allScans.filter(scan => {
      const scanTarget = normalizeTargetKey(scan.target || "");
      return scanTarget === normalizedTarget;
    });
    
    // Sort by creation date, newest first
    targetScans.sort((a, b) => parseDateAsUTC(b.created_at) - parseDateAsUTC(a.created_at));
    
    // For each scan, fetch its findings
    for (const scan of targetScans) {
      try {
        if (scan.id) {  // Only fetch findings if scan has an ID
          // Ensure scan.id is a string before using it in the URL
          const scanId = String(scan.id);
          
          // First try the dedicated findings endpoint
          let findingsResponse = await fetch(getApiUrl(`/api/scans/${scanId}/findings`));
          
          if (findingsResponse.ok) {
            // If findings endpoint works, use that data
            const findingsData = await findingsResponse.json();
            scan.findings = Array.isArray(findingsData) ? findingsData : findingsData.findings || [];
          } else {
            // If findings endpoint doesn't work, try getting findings from the main scan detail
            console.warn(`Findings API returned ${findingsResponse.status} for scan ${scanId}, trying main scan endpoint`);
            
            const scanResponse = await fetch(getApiUrl(`/api/scans/${scanId}`));
            if (scanResponse.ok) {
              const scanData = await scanResponse.json();
              // Look for findings in the scan data (could be in various fields)
              scan.findings = scanData.findings || scanData.results || scanData.data || [];
            } else {
              scan.findings = [];
              console.warn(`Main scan API also failed for scan ${scanId}`);
            }
          }
        } else {
          scan.findings = [];
          console.warn('Scan missing ID, skipping findings fetch:', scan);
        }
      } catch (e) {
        console.error(`Error fetching findings for scan ${scan.id || 'unknown'}:`, e);
        scan.findings = [];
      }
    }
    
    return targetScans;
  } catch (error) {
    console.error("Error fetching target scans:", error);
    throw error;
  }
}

// Open target detail modal function
async function openTargetDetailModal(target) {
  try {
    // Show loading state
    document.getElementById("targetDetailTitle").textContent = target;
    document.getElementById("targetTotalScans").textContent = "Loading...";
    document.getElementById("targetHighestSeverity").textContent = "Loading...";
    document.getElementById("targetTotalFindings").textContent = "Loading...";
    document.getElementById("targetLastScan").textContent = "Loading...";
    
    // Show the modal
    document.getElementById("targetDetailModal").classList.remove("hidden");
    
    // Fetch target scans and findings
    const targetScans = await fetchTargetScans(target);
    
    // Validate and clean scan data
    const validatedScans = targetScans.filter(scan => {
      if (!scan || typeof scan !== 'object') {
        console.warn('Invalid scan object:', scan);
        return false;
      }
      return true;
    }).map(scan => {
      // Ensure scan has required properties
      return {
        ...scan,
        id: scan.id || 'unknown',
        created_at: scan.created_at || '',
        status: scan.status || 'unknown',
        highest_severity: scan.highest_severity || 'Low',
        tool: scan.tool || 'Unknown',
        owasp_category: scan.owasp_category || 'N/A',
        findings: Array.isArray(scan.findings) ? scan.findings : []
      };
    });
    
    // Populate the modal with aggregated data
    populateTargetDetailModal(target, validatedScans);
    
    // Initialize tabs first
    initializeTargetDetailTabs();
    
    // Initialize charts
    initializeTargetCharts(validatedScans);
    
    // Initialize comparison selectors
    initializeComparisonSelectors(validatedScans);
    
  } catch (error) {
    console.error("Error opening target detail modal:", error);
    showNotification("Error loading target details: " + error.message, "error");
  }
}

// Function to close target detail modal
function closeTargetDetailModal() {
  // Hide the modal
  document.getElementById('targetDetailModal').classList.add('hidden');
  
  // Clean up charts to prevent memory leaks
  if (window.targetSeverityChart && typeof window.targetSeverityChart.destroy === 'function') {
    window.targetSeverityChart.destroy();
    window.targetSeverityChart = null;
  }
  if (window.targetCategoryChart && typeof window.targetCategoryChart.destroy === 'function') {
    window.targetCategoryChart.destroy();
    window.targetCategoryChart = null;
  }
  if (window.targetTrendChart && typeof window.targetTrendChart.destroy === 'function') {
    window.targetTrendChart.destroy();
    window.targetTrendChart = null;
  }
}

// Initialize target detail tabs
function initializeTargetDetailTabs() {
  const tabButtons = document.querySelectorAll('[data-target-detail-tab]');
  const tabPanels = document.querySelectorAll('.tab-panel');
  
  // First, make sure the default 'overview' tab is active
  document.querySelectorAll('[data-target-detail-tab]').forEach(btn => {
    btn.classList.remove('active');
  });
  document.querySelectorAll('.tab-panel').forEach(panel => {
    panel.classList.add('hidden');
  });
  
  // Activate the overview tab by default
  const overviewButton = document.querySelector('[data-target-detail-tab="overview"]');
  const overviewPanel = document.getElementById('overviewTab');
  
  if (overviewButton) {
    overviewButton.classList.add('active');
  }
  if (overviewPanel) {
    overviewPanel.classList.remove('hidden');
  }
  
  tabButtons.forEach(button => {
    button.addEventListener('click', () => {
      const tabName = button.getAttribute('data-target-detail-tab');
      
      // Remove active class from all buttons and panels
      tabButtons.forEach(btn => btn.classList.remove('active'));
      tabPanels.forEach(panel => panel.classList.add('hidden'));
      
      // Add active class to clicked button
      button.classList.add('active');
      
      // Show corresponding panel
      const targetPanel = document.getElementById(`${tabName}Tab`);
      if (targetPanel) {
        targetPanel.classList.remove('hidden');
      }
    });
  });
  
  // Add event listener for PDF generation
  const pdfButton = document.getElementById('generateTargetPdfBtn');
  if (pdfButton && !pdfButton.getAttribute('data-listener-added')) {
    pdfButton.addEventListener('click', async () => {
      try {
        const target = document.getElementById("targetDetailTitle").textContent;
        // We need to fetch the scans again to have the data for PDF generation
        const targetScans = await fetchTargetScans(target);
        await generateTargetPdfReport(target, targetScans);
      } catch (error) {
        console.error('Error generating PDF:', error);
        showNotification('Error generating PDF: ' + error.message, 'error');
      }
    });
    pdfButton.setAttribute('data-listener-added', 'true');
  }
  
  // Add event listeners for closing the modal
  const closeButtons = [
    document.getElementById('closeTargetDetailModalBtn'),
    document.getElementById('closeTargetDetailModalFooterBtn')
  ];
  
  closeButtons.forEach(button => {
    if (button) {
      // Remove any existing listeners to avoid duplicates
      if (button.getAttribute('data-listener-added')) {
        // Update the cloned button approach - simpler to just reassign
        button.removeEventListener('click', closeTargetDetailModal);
      }
      button.addEventListener('click', closeTargetDetailModal);
      button.setAttribute('data-listener-added', 'true');
    }
  });
  
  // Also add click listener to the modal backdrop to close when clicking outside
  const modalBackdrop = document.getElementById('targetDetailModal');
  if (modalBackdrop) {
    // Check if we already have a backdrop click listener
    if (!modalBackdrop.getAttribute('data-backdrop-listener')) {
      modalBackdrop.addEventListener('click', function(event) {
        // Close if clicking directly on the backdrop (not on the modal content)
        if (event.target === modalBackdrop) {
          closeTargetDetailModal();
        }
      });
      modalBackdrop.setAttribute('data-backdrop-listener', 'true');
    }
  }
}

// Function to populate target detail modal with aggregated data
function populateTargetDetailModal(target, targetScans) {
  // Update title
  document.getElementById("targetDetailTitle").textContent = target;
  
  // Calculate aggregated stats
  const totalScans = targetScans.length;
  const totalFindings = targetScans.reduce((sum, scan) => sum + (scan.findings ? scan.findings.length : 0), 0);
  
  // Find highest severity across all scans
  let highestSeverity = "Low";
  let maxSeverityValue = 1; // Low = 1, Medium = 2, High = 3, Critical = 4
  
  targetScans.forEach(scan => {
    const sev = (scan.highest_severity || "").toLowerCase();
    const weight = sev === "critical" ? 4 : sev === "high" ? 3 : sev === "medium" ? 2 : 1;
    if (weight > maxSeverityValue) {
      maxSeverityValue = weight;
      highestSeverity = scan.highest_severity || "Low";
    }
  });
  
  // Get last scan date
  let lastScanDate = "-";
  if (targetScans.length > 0 && targetScans[0].created_at) {
    lastScanDate = formatDate(targetScans[0].created_at);
  }
  
  // Update stats
  document.getElementById("targetTotalScans").textContent = totalScans;
  document.getElementById("targetHighestSeverity").textContent = highestSeverity;
  document.getElementById("targetTotalFindings").textContent = totalFindings;
  document.getElementById("targetLastScan").textContent = lastScanDate;
  
  // Update subtitle
  document.getElementById("targetDetailSubtitle").innerHTML = 
    `Total scans: ${totalScans} · Total findings: ${totalFindings} · Highest severity: ${highestSeverity}`;
  
  currentTargetDetailScans = targetScans;
  // Cache scans globally for timestamp lookup in renderScanSummary
  window.cachedTargetScans = targetScans;
  const severitySel = document.getElementById("findingsSeverityFilter");
  if (severitySel) severitySel.value = "all";
  populateFindingsAttackTypeDropdown();
  const attackTypeSel = document.getElementById("findingsAttackTypeFilter");
  if (attackTypeSel) attackTypeSel.value = "all";
  populateFindingsScanIdDropdown(targetScans);
  const scanIdSel = document.getElementById("findingsScanIdFilter");
  if (scanIdSel) scanIdSel.value = "all";
  populateFindingsTable(targetScans, "all", "all", "all");
  wireFindingsFiltersOnce();
  
  // Make sure the overview tab content is populated
  if (targetScans.length > 0) {
    document.getElementById("targetScanSummary").innerHTML = `
      <p><strong>Target:</strong> ${target}</p>
      <p><strong>Total Scans:</strong> ${totalScans}</p>
      <p><strong>Total Findings:</strong> ${totalFindings}</p>
      <p><strong>Highest Severity:</strong> ${highestSeverity}</p>
      <p><strong>Last Scan:</strong> ${lastScanDate}</p>
      <p><strong>First Scan:</strong> ${targetScans.length > 0 ? formatDate(targetScans[targetScans.length - 1].created_at) : '-'}</p>
    `;
  } else {
    document.getElementById("targetScanSummary").innerHTML = `<p>No scan data available for this target.</p>`;
  }

  populateTargetDetailDeleteTab(targetScans, target);
}

function populateTargetDetailDeleteTab(targetScans, target) {
  const tbody = document.getElementById("targetDetailDeleteScanList");
  const emptyEl = document.getElementById("targetDetailDeleteEmpty");
  if (!tbody) return;
  tbody.innerHTML = "";
  if (emptyEl) emptyEl.classList.add("hidden");
  if (!targetScans || targetScans.length === 0) {
    if (emptyEl) emptyEl.classList.remove("hidden");
    return;
  }
  targetScans.forEach(scan => {
    const dateStr = scan.created_at ? formatDate(scan.created_at) : "—";
    const attackName = getOwaspCategoryName(scan.owasp_category) || scan.owasp_category || "—";
    const findingCount = (scan.findings && scan.findings.length) || 0;
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>Scan #${scan.id}</td>
      <td>${dateStr}</td>
      <td>${attackName}</td>
      <td>${findingCount}</td>
      <td class="th-details-col">
        <button type="button" class="tool-run-btn delete-btn" data-action="delete-scan-detail" data-id="${scan.id}" title="Delete this scan">Delete</button>
      </td>
    `;
    tbody.appendChild(tr);
  });
  tbody.querySelectorAll("[data-action=\"delete-scan-detail\"]").forEach(btn => {
    btn.addEventListener("click", () => handleDeleteScanFromDetailModal(btn.getAttribute("data-id")));
  });
}

async function handleDeleteScanFromDetailModal(scanId) {
  const target = document.getElementById("targetDetailTitle")?.textContent || "";
  const scan = currentTargetDetailScans.find(s => String(s.id) === String(scanId));
  const findingCount = (scan && scan.findings && scan.findings.length) || 0;
  showDeleteConfirmModal(
    "Delete Scan?",
    `<strong>Target:</strong> ${target}<br><strong>Scan ID:</strong> #${scanId}<br><strong>Findings:</strong> ${findingCount}<br><br>All scan data, findings, and reports will be permanently removed.`,
    async () => {
      try {
        const response = await fetch(getApiUrl(`/api/scans/${scanId}`), { method: "DELETE", headers: { "Content-Type": "application/json" } });
        if (!response.ok) {
          const err = await response.json();
          throw new Error(err.detail || "Failed to delete scan");
        }
        showNotification(`✓ Scan #${scanId} deleted successfully`, "success");
        
        // Wait briefly to ensure database commit completes
        await new Promise(resolve => setTimeout(resolve, 300));
        
        // Refresh all views
        await refreshScansViews();
        await refreshDashboardCharts();
        
        // Fetch updated scans for this target and refresh modal content
        const remaining = await fetchTargetScans(target);
        if (remaining.length === 0) {
          // No scans left, close modal
          closeTargetDetailModal();
          return;
        }
        
        const validatedScans = remaining.filter(s => s && typeof s === "object").map(s => ({
          ...s,
          id: s.id || "unknown",
          created_at: s.created_at || "",
          status: s.status || "unknown",
          target: s.target || target,
          owasp_category: s.owasp_category,
          findings: s.findings || [],
          highest_severity: s.highest_severity,
          tool_runs: s.tool_runs || []
        }));
        
        // Update modal with fresh data
        populateTargetDetailModal(target, validatedScans);
        initializeTargetCharts(validatedScans);
        initializeComparisonSelectors(validatedScans);
      } catch (err) {
        console.error("Error deleting scan:", err);
        showNotification(`✗ ${err.message}`, "error");
      }
    }
  );
}

function populateFindingsAttackTypeDropdown() {
  const sel = document.getElementById("findingsAttackTypeFilter");
  if (!sel) return;
  sel.innerHTML = "";
  const allOpt = document.createElement("option");
  allOpt.value = "all";
  allOpt.textContent = "All Attack Types";
  sel.appendChild(allOpt);
  OWASP_MAP.forEach(cat => {
    const opt = document.createElement("option");
    opt.value = cat.id;
    opt.textContent = cat.name;
    sel.appendChild(opt);
  });
}

function populateFindingsScanIdDropdown(targetScans) {
  const sel = document.getElementById("findingsScanIdFilter");
  if (!sel) return;
  sel.innerHTML = "";
  const allOpt = document.createElement("option");
  allOpt.value = "all";
  allOpt.textContent = "All Scans";
  sel.appendChild(allOpt);
  (targetScans || []).forEach(scan => {
    const opt = document.createElement("option");
    opt.value = String(scan.id);
    const dateTime = scan.created_at ? formatDate(scan.created_at) : "—";
    const attackName = getOwaspCategoryName(scan.owasp_category) || scan.owasp_category || "—";
    opt.textContent = `#${scan.id} · ${dateTime} · ${attackName}`;
    sel.appendChild(opt);
  });
}

function wireFindingsFiltersOnce() {
  const severitySel = document.getElementById("findingsSeverityFilter");
  const attackSel = document.getElementById("findingsAttackTypeFilter");
  const scanIdSel = document.getElementById("findingsScanIdFilter");
  if (!severitySel || !attackSel || !scanIdSel || severitySel.dataset.findingsWired === "1") return;
  severitySel.dataset.findingsWired = "1";
  attackSel.dataset.findingsWired = "1";
  scanIdSel.dataset.findingsWired = "1";
  function applyFindingsFilters() {
    const sev = severitySel.value || "all";
    const attack = attackSel.value || "all";
    const scanId = scanIdSel.value || "all";
    populateFindingsTable(currentTargetDetailScans, sev, attack, scanId);
  }
  severitySel.addEventListener("change", applyFindingsFilters);
  attackSel.addEventListener("change", applyFindingsFilters);
  scanIdSel.addEventListener("change", applyFindingsFilters);
}

// Function to populate the findings table
function populateFindingsTable(targetScans, severityFilter, attackTypeFilter, scanIdFilter) {
  const tbody = document.getElementById("targetFindingsTableBody");
  if (!tbody) return;
  tbody.innerHTML = "";
  
  const allFindings = [];
  (targetScans || []).forEach(scan => {
    if (scan.findings && Array.isArray(scan.findings)) {
      const attackTypeName = getOwaspCategoryName(scan.owasp_category) || scan.owasp_category || "N/A";
      const owaspId = scan.owasp_category || "";
      scan.findings.forEach(finding => {
        allFindings.push({
          ...finding,
          scan_date: scan.created_at,
          scan_id: scan.id,
          tool_used: finding.tool_name || finding.tool_used || "Unknown",
          attack_type: attackTypeName,
          owasp_category: owaspId
        });
      });
    }
  });
  
  const severityOrder = { "critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1 };
  let toShow = severityFilter && severityFilter !== "all"
    ? allFindings.filter(f => (f.severity || "").toLowerCase() === severityFilter)
    : allFindings;
  if (attackTypeFilter && attackTypeFilter !== "all") {
    toShow = toShow.filter(f => (f.owasp_category || "") === attackTypeFilter);
  }
  if (scanIdFilter && scanIdFilter !== "all") {
    toShow = toShow.filter(f => String(f.scan_id) === String(scanIdFilter));
  }
  toShow = [...toShow].sort((a, b) =>
    (severityOrder[b.severity?.toLowerCase()] || 0) - (severityOrder[a.severity?.toLowerCase()] || 0)
  );
  
  toShow.forEach(finding => {
    const tr = document.createElement("tr");
    const isNuclei = (finding.tool_used || "").toLowerCase() === "nuclei";
    const hasTemplateDetails = isNuclei && (finding.template_id || finding.extracted_results);
    
    // Calculate severity class
    const sev = (finding.severity || "").toLowerCase();
    let sevClass = "tag-low";
    if (sev === "critical") sevClass = "tag-critical";
    else if (sev === "high") sevClass = "tag-high";
    else if (sev === "medium") sevClass = "tag-medium";
    
    // Build enhanced content for Nuclei findings with template details
    let cellContent = "";
    if (hasTemplateDetails) {
      // Enhanced Nuclei finding card layout
      const severityIcon = {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🔵",
        "info": "⚪"
      }[sev] || "⚪";
      
      cellContent = `
        <div class="nuclei-finding-card">
          <div class="nuclei-finding-header">
            <span class="nuclei-severity-icon ${sevClass}">${severityIcon}</span>
            <strong class="nuclei-description">${escapeHtml(finding.description)}</strong>
          </div>
          
          ${finding.template_id ? `
            <div class="nuclei-template-section">
              <span class="nuclei-template-badge">🏷️ Template: ${escapeHtml(finding.template_id)}</span>
              ${finding.matcher_name ? `
                <span class="nuclei-matcher-badge">Match: ${escapeHtml(finding.matcher_name)}</span>
              ` : ''}
            </div>
          ` : ''}
          
          ${finding.extracted_results ? `
            <div class="nuclei-extracted-results">
              <strong>Extracted:</strong> 
              <code>${escapeHtml(finding.extracted_results)}</code>
            </div>
          ` : ''}
          
          <div class="nuclei-finding-meta">
            <span class="nuclei-location">📍 ${escapeHtml(finding.location)}</span>
          </div>
        </div>
      `;
    } else {
      // Standard layout for non-Nuclei or simple findings
      const findingText = finding.location || finding.description || finding.title || finding.name || "—";
      cellContent = String(findingText).replace(/</g, "&lt;").replace(/>/g, "&gt;").trim() || "—";
    }
    
    tr.innerHTML = `
      <td title="${(finding.description || "").replace(/"/g, "&quot;")}">${cellContent}</td>
      <td><span class="tag ${sevClass}">${finding.severity || "N/A"}</span></td>
      <td>${finding.attack_type || "N/A"}</td>
      <td>${finding.tool_used || "N/A"}</td>
      <td>${finding.scan_date ? formatDate(finding.scan_date) : "N/A"}</td>
    `;
    tbody.appendChild(tr);
  });
}

// Function to initialize and render the scan timeline
function renderTargetTimeline(targetScans) {
  const timelineContainer = document.getElementById("targetTimeline");
  if (!timelineContainer) return;

  timelineContainer.innerHTML = "";

  if (!targetScans || targetScans.length === 0) {
    timelineContainer.innerHTML = "<div class='timeline-empty'>No scans available for this target.</div>";
    return;
  }

  // Sort scans by date (oldest first for timeline)
  const sortedScans = [...targetScans].sort((a, b) => parseDateAsUTC(a.created_at) - parseDateAsUTC(b.created_at));

  const timeline = document.createElement("div");
  timeline.className = "timeline-inner";

  sortedScans.forEach((scan) => {
    const timelineItem = document.createElement("div");
    timelineItem.className = "timeline-item";

    let sevColor = "#22c55e"; // green for low
    const sev = (scan.highest_severity || "").toLowerCase();
    if (sev === "critical") sevColor = "#ef4444";
    else if (sev === "high") sevColor = "#f97316";
    else if (sev === "medium") sevColor = "#eab308";
    else if (sev === "low" || sev === "info") sevColor = "#22c55e";

    const status = (scan.status || "").toLowerCase();
    const statusClass = status === "completed" || status === "completed_with_errors" ? "tag-success" : status === "running" ? "tag-warning" : "tag-error";
    const attackTypeName = getOwaspCategoryName(scan.owasp_category) || scan.owasp_category || "N/A";
    const sevTagClass = sev === "critical" ? "tag-critical" : sev === "high" ? "tag-high" : sev === "medium" ? "tag-medium" : "tag-low";

    timelineItem.innerHTML = `
      <div class="timeline-marker" style="background-color: ${sevColor};">
        <div class="timeline-marker-dot"></div>
      </div>
      <div class="timeline-content">
        <div class="timeline-date">${formatDate(scan.created_at)}</div>
        <div class="timeline-title">Scan #${scan.id != null ? scan.id : "N/A"} · ${attackTypeName}</div>
        <div class="timeline-description timeline-tags">
          <span class="tag ${statusClass}">${scan.status || "Unknown"}</span>
          <span class="tag tag-info">Multiple Tools</span>
          <span class="tag tag-purple">${scan.owasp_category || "N/A"}</span>
          <span class="tag ${sevTagClass}">${scan.highest_severity || "N/A"}</span>
        </div>
        <div class="timeline-findings">Findings: ${scan.findings ? scan.findings.length : 0}</div>
      </div>
    `;
    timeline.appendChild(timelineItem);
  });

  timelineContainer.appendChild(timeline);
}

// Function to initialize and render target charts
function initializeTargetCharts(targetScans) {
  // Render severity distribution chart
  renderTargetSeverityChart(targetScans);
  
  // Render category chart
  renderTargetCategoryChart(targetScans);
  
  // Render timeline
  renderTargetTimeline(targetScans);
  
  // Render trend chart
  renderTargetTrendChart(targetScans);
}

// Function to initialize comparison selectors
function initializeComparisonSelectors(targetScans) {
  const firstSelect = document.getElementById("firstScanSelect");
  const secondSelect = document.getElementById("secondScanSelect");
  
  // Clear existing options
  firstSelect.innerHTML = "<option value=\"\">Select first scan</option>";
  secondSelect.innerHTML = "<option value=\"\">Select second scan</option>";
  
  // Add options: scan id, date/time, attack type name (so user knows which target/type is compared)
  targetScans.forEach(scan => {
    const dateTime = formatDate(scan.created_at);
    const attackTypeName = getOwaspCategoryName(scan.owasp_category) || scan.owasp_category || "N/A";
    const optionText = `#${scan.id} · ${dateTime} · ${attackTypeName}`;

    const firstOption = document.createElement("option");
    firstOption.value = scan.id;
    firstOption.textContent = optionText;
    firstSelect.appendChild(firstOption);

    const secondOption = document.createElement("option");
    secondOption.value = scan.id;
    secondOption.textContent = optionText;
    secondSelect.appendChild(secondOption);
  });
  
  // Add event listeners to trigger comparison when both are selected
  firstSelect.addEventListener("change", performScanComparison);
  secondSelect.addEventListener("change", performScanComparison);
}

// Function to generate and download PDF report
async function generateTargetPdfReport(target, targetScans) {
  try {
    // Show processing notification
    showNotification("Generating PDF report...", "info");
    
    // Use html2pdf library to generate the report
    if (typeof html2pdf === 'undefined') {
      // If html2pdf is not loaded, load it dynamically
      await loadScript('https://cdnjs.cloudflare.com/ajax/libs/html2pdf.js/0.10.1/html2pdf.bundle.min.js');
    }
    
    // Create a temporary element to hold the PDF content
    const tempElement = document.createElement('div');
    tempElement.id = 'temp-pdf-content';
    tempElement.style.display = 'none';
    tempElement.style.width = '210mm';
    tempElement.style.padding = '20mm';
    tempElement.style.backgroundColor = 'white';
    tempElement.style.color = 'black';
    tempElement.style.fontFamily = 'Arial, sans-serif';
    
    // Generate the content for the PDF
    tempElement.innerHTML = `
      <div style="margin-bottom: 20px;">
        <h1 style="color: #1f2937; border-bottom: 2px solid #e5e7eb; padding-bottom: 10px;">Security Scan Report</h1>
        <h2 style="color: #4b5563; margin-top: 10px;">Target: ${target}</h2>
        <p style="color: #6b7280; margin: 5px 0;">Generated on: ${new Date().toLocaleString()}</p>
      </div>
      
      <div style="margin: 20px 0;">
        <h3 style="color: #374151; border-bottom: 1px solid #e5e7eb; padding-bottom: 5px;">Executive Summary</h3>
        <div style="display: flex; gap: 15px; margin-top: 10px;">
          <div style="flex: 1; padding: 10px; border: 1px solid #e5e7eb; border-radius: 4px;">
            <div style="font-weight: bold; color: #4b5563;">Total Scans</div>
            <div style="font-size: 24px; color: #1f2937;">${targetScans.length}</div>
          </div>
          <div style="flex: 1; padding: 10px; border: 1px solid #e5e7eb; border-radius: 4px;">
            <div style="font-weight: bold; color: #4b5563;">Total Findings</div>
            <div style="font-size: 24px; color: #1f2937;">${targetScans.reduce((sum, scan) => sum + (scan.findings ? scan.findings.length : 0), 0)}</div>
          </div>
          <div style="flex: 1; padding: 10px; border: 1px solid #e5e7eb; border-radius: 4px;">
            <div style="font-weight: bold; color: #4b5563;">Highest Severity</div>
            <div style="font-size: 24px; color: #dc2626; font-weight: bold;">${targetScans.length > 0 ? targetScans[0].highest_severity || 'N/A' : 'N/A'}</div>
          </div>
        </div>
      </div>
      
      <div style="margin: 20px 0;">
        <h3 style="color: #374151; border-bottom: 1px solid #e5e7eb; padding-bottom: 5px;">Scan History</h3>
        <table style="width: 100%; border-collapse: collapse; margin-top: 10px;">
          <thead>
            <tr style="background-color: #f3f4f6;">
              <th style="padding: 8px; border: 1px solid #d1d5db; text-align: left;">Scan ID</th>
              <th style="padding: 8px; border: 1px solid #d1d5db; text-align: left;">Date</th>
              <th style="padding: 8px; border: 1px solid #d1d5db; text-align: left;">Status</th>
              <th style="padding: 8px; border: 1px solid #d1d5db; text-align: left;">Highest Severity</th>
              <th style="padding: 8px; border: 1px solid #d1d5db; text-align: left;">Findings</th>
            </tr>
          </thead>
          <tbody>
            ${targetScans.map(scan => `
              <tr>
                <td style="padding: 8px; border: 1px solid #d1d5db;">${scan.id?.substring(0, 8) || 'N/A'}</td>
                <td style="padding: 8px; border: 1px solid #d1d5db;">${formatDate(scan.created_at)}</td>
                <td style="padding: 8px; border: 1px solid #d1d5db;">${scan.status || 'N/A'}</td>
                <td style="padding: 8px; border: 1px solid #d1d5db;">
                  <span style="padding: 2px 6px; border-radius: 12px; background-color: ${scan.highest_severity?.toLowerCase() === 'critical' ? '#fee2e2' : scan.highest_severity?.toLowerCase() === 'high' ? '#fed7aa' : scan.highest_severity?.toLowerCase() === 'medium' ? '#fef3c7' : '#e5e7eb'};">
                    ${scan.highest_severity || 'N/A'}
                  </span>
                </td>
                <td style="padding: 8px; border: 1px solid #d1d5db;">${scan.findings ? scan.findings.length : 0}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
      
      <div style="margin: 20px 0;">
        <h3 style="color: #374151; border-bottom: 1px solid #e5e7eb; padding-bottom: 5px;">Top Findings</h3>
        <div style="margin-top: 10px;">
          ${(() => {
            const allFindings = [];
            targetScans.forEach(scan => {
              if (scan.findings && Array.isArray(scan.findings)) {
                scan.findings.forEach(finding => {
                  allFindings.push({
                    ...finding,
                    scan_date: scan.created_at,
                    scan_id: scan.id,
                    tool_used: scan.tool || "Unknown"
                  });
                });
              }
            });
            
            // Sort by severity (critical first)
            allFindings.sort((a, b) => {
              const severityOrder = { "critical": 4, "high": 3, "medium": 2, "low": 1 };
              return (severityOrder[b.severity?.toLowerCase()] || 0) - (severityOrder[a.severity?.toLowerCase()] || 0);
            });
            
            return allFindings.slice(0, 10).map(finding => `
              <div style="margin-bottom: 10px; padding: 10px; border: 1px solid #e5e7eb; border-radius: 4px;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 5px;">
                  <strong style="color: ${finding.severity?.toLowerCase() === 'critical' ? '#dc2626' : finding.severity?.toLowerCase() === 'high' ? '#ea580c' : finding.severity?.toLowerCase() === 'medium' ? '#d97706' : '#4b5563'};">${finding.title || finding.name || 'N/A'}</strong>
                  <span style="padding: 2px 6px; border-radius: 12px; background-color: ${finding.severity?.toLowerCase() === 'critical' ? '#fee2e2' : finding.severity?.toLowerCase() === 'high' ? '#fed7aa' : finding.severity?.toLowerCase() === 'medium' ? '#fef3c7' : '#e5e7eb'};">
                    ${finding.severity || 'N/A'}
                  </span>
                </div>
                <div style="font-size: 14px; color: #6b7280; margin-bottom: 5px;">
                  Tool: ${finding.tool_used || 'N/A'} | Date: ${formatDate(finding.scan_date)}
                </div>
                <div style="font-size: 14px; color: #4b5563;">
                  ${finding.description || finding.details || 'No description provided.'}
                </div>
              </div>
            `).join('');
          })()}
        </div>
      </div>
      
      <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #e5e7eb; font-size: 12px; color: #6b7280;">
        <p>This report was automatically generated by Intelligence Recon System (IRS).</p>
        <p>Report generated on: ${new Date().toLocaleString()}</p>
      </div>
    `;
    
    // Add the temp element to the body
    document.body.appendChild(tempElement);
    
    // Options for PDF generation
    const options = {
      margin: 10,
      filename: `security-report-${target.replace(/[^a-zA-Z0-9]/g, '_')}-${new Date().toISOString().split('T')[0]}.pdf`,
      image: { type: 'jpeg', quality: 0.98 },
      html2canvas: { scale: 2, useCORS: true },
      jsPDF: { unit: 'mm', format: 'a4', orientation: 'portrait' }
    };
    
    // Generate and download the PDF
    html2pdf().set(options).from(tempElement).save().then(() => {
      // Clean up the temp element after a delay
      setTimeout(() => {
        if (document.contains(tempElement)) {
          document.body.removeChild(tempElement);
        }
      }, 2000);
      
      showNotification("PDF report generated successfully!", "success");
    }).catch(error => {
      console.error('Error generating PDF:', error);
      showNotification("Error generating PDF: " + error.message, "error");
      
      // Clean up the temp element
      if (document.contains(tempElement)) {
        document.body.removeChild(tempElement);
      }
    });
    
  } catch (error) {
    console.error('Error in generateTargetPdfReport:', error);
    showNotification("Error generating PDF report: " + error.message, "error");
  }
}

// Helper function to load external script dynamically
function loadScript(src) {
  return new Promise((resolve, reject) => {
    // Check if script is already loaded
    if (document.querySelector(`script[src="${src}"]`)) {
      resolve();
      return;
    }
    
    const script = document.createElement('script');
    script.src = src;
    script.onload = resolve;
    script.onerror = reject;
    document.head.appendChild(script);
  });
}

const severityOrder = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };

function normalizeFindingValue(value) {
  return (value || "").toString().trim().toLowerCase().replace(/\s+/g, " ");
}

function getFindingKey(f) {
  const location = normalizeFindingValue(f.location);
  const description = normalizeFindingValue(f.description);
  const type = normalizeFindingValue(f.type);
  const severity = normalizeFindingValue(f.severity);

  if (location || description) {
    return `${location}||${description}`;
  }
  return `${type}||${severity}||${normalizeFindingValue(f.tool_name)}`;
}

function dedupeFindingsByKey(findings) {
  const seen = new Map();
  findings.forEach(f => {
    const key = getFindingKey(f);
    const toolName = (f.tool_name || "Unknown").toString().trim();
    const existing = seen.get(key);
    if (!existing) {
      seen.set(key, {
        ...f,
        tool_name: toolName,
        tool_names: [toolName]
      });
      return;
    }

    if (!existing.tool_names.includes(toolName)) {
      existing.tool_names.push(toolName);
      existing.tool_name = existing.tool_names.join(" / ");
    }

    const existingSeverityRank = severityOrder[(existing.severity || "").toLowerCase()] || 0;
    const newSeverityRank = severityOrder[(f.severity || "").toLowerCase()] || 0;
    if (newSeverityRank > existingSeverityRank) {
      existing.severity = f.severity;
    }
  });
  return Array.from(seen.values());
}

function sortFindingsBySeverity(findings, desc = true) {
  return findings.slice().sort((a, b) => {
    const aRank = severityOrder[(a.severity || "").toLowerCase()] || 0;
    const bRank = severityOrder[(b.severity || "").toLowerCase()] || 0;
    return desc ? bRank - aRank : aRank - bRank;
  });
}

function buildComparisonState(firstFindings, secondFindings) {
  const firstMap = new Map(firstFindings.map(f => [getFindingKey(f), f]));
  const secondMap = new Map(secondFindings.map(f => [getFindingKey(f), f]));
  const commonFindings = [];
  const uniqueToFirst = [];
  const uniqueToSecond = [];

  firstMap.forEach((firstFinding, key) => {
    const secondFinding = secondMap.get(key);
    if (secondFinding) {
      const mergedToolNames = Array.from(new Set([...(firstFinding.tool_names || [firstFinding.tool_name]), ...(secondFinding.tool_names || [secondFinding.tool_name])]));
      commonFindings.push({
        ...firstFinding,
        tool_name: mergedToolNames.join(" / "),
        tool_names: mergedToolNames,
        severity: severityOrder[(secondFinding.severity || "").toLowerCase()] > severityOrder[(firstFinding.severity || "").toLowerCase()] ? secondFinding.severity : firstFinding.severity
      });
    } else {
      uniqueToFirst.push(firstFinding);
    }
  });

  secondMap.forEach((secondFinding, key) => {
    if (!firstMap.has(key)) {
      uniqueToSecond.push(secondFinding);
    }
  });

  return {
    commonFindings: sortFindingsBySeverity(commonFindings),
    uniqueToFirst: sortFindingsBySeverity(uniqueToFirst),
    uniqueToSecond: sortFindingsBySeverity(uniqueToSecond),
    hasNewHighCritical: uniqueToSecond.some(f => ["critical", "high"].includes((f.severity || "").toLowerCase()))
  };
}

function getComparisonTableRows(findings) {
  return findings.map(f => {
    const formattedDescription = formatComparisonDescription(f.description, f.location);
    return `
      <tr>
        <td>
          <span class="tag ${f.severity?.toLowerCase() === 'critical' ? 'tag-critical' : f.severity?.toLowerCase() === 'high' ? 'tag-high' : f.severity?.toLowerCase() === 'medium' ? 'tag-medium' : f.severity?.toLowerCase() === 'low' ? 'tag-low' : 'tag-info'}">
            ${f.severity || 'N/A'}
          </span>
        </td>
        <td>${escapeHtml(f.tool_name || 'N/A')}</td>
        <td><code class="finding-location">${escapeHtml(f.location || '')}</code></td>
        <td>${escapeHtml(formattedDescription)}</td>
        <td>${getRiskExplanationForSeverity(f.severity)}</td>
      </tr>
    `;
  }).join('');
}


// Function to perform scan comparison
async function performScanComparison() {
  const firstSelect = document.getElementById("firstScanSelect");
  const secondSelect = document.getElementById("secondScanSelect");
  const resultDiv = document.getElementById("scanComparisonResult");
  
  const firstScanId = firstSelect.value;
  const secondScanId = secondSelect.value;
  
  if (!firstScanId || !secondScanId) {
    resultDiv.innerHTML = "Select two scans to compare their findings...";
    return;
  }
  
  if (firstScanId === secondScanId) {
    resultDiv.innerHTML = "Please select two different scans to compare.";
    return;
  }
  
  try {
    // Get the scan details
    const firstResponse = await fetch(getApiUrl(`/api/scans/${firstScanId}`));
    const secondResponse = await fetch(getApiUrl(`/api/scans/${secondScanId}`));
    
    const firstScan = await firstResponse.json();
    const secondScan = await secondResponse.json();

    // Only allow comparison when same target and same attack type
    const firstTarget = firstScan.target || "";
    const secondTarget = secondScan.target || "";
    const firstCategory = firstScan.owasp_category || "";
    const secondCategory = secondScan.owasp_category || "";

    if (firstTarget !== secondTarget || firstCategory !== secondCategory) {
      const msgLines = [
        "Scan comparison is only available when both scans have:",
        "• The same target (domain/IP)",
        "• The same OWASP attack type"
      ];
      showStyledPopup(msgLines.join("\n"));
      resultDiv.innerHTML = "Select two compatible scans (same target and attack type) to see comparison.";
      return;
    }
    
    // Get findings for both scans
    const firstFindingsResponse = await fetch(getApiUrl(`/api/scans/${firstScanId}/findings`));
    const secondFindingsResponse = await fetch(getApiUrl(`/api/scans/${secondScanId}/findings`));
    
    const firstFindings = await firstFindingsResponse.json();
    const secondFindings = await secondFindingsResponse.json();
    
    // Normalize findings arrays
    const firstFindingsArray = Array.isArray(firstFindings) ? firstFindings : firstFindings.findings || [];
    const secondFindingsArray = Array.isArray(secondFindings) ? secondFindings : secondFindings.findings || [];

    const firstDeduped = dedupeFindingsByKey(firstFindingsArray);
    const secondDeduped = dedupeFindingsByKey(secondFindingsArray);
    const comparisonData = buildComparisonState(firstDeduped, secondDeduped);
    
    // Build per-tool output summaries from findings for each scan
    const firstToolOutputs = buildToolOutputsFromFindings(firstDeduped);
    const secondToolOutputs = buildToolOutputsFromFindings(secondDeduped);
    
    // Render comparison results
    renderComparisonResults(firstScan, secondScan, comparisonData, firstToolOutputs, secondToolOutputs);
    
  } catch (error) {
    console.error("Error comparing scans:", error);
    resultDiv.innerHTML = `<div class="alert alert-error">Error comparing scans: ${error.message}</div>`;
  }
}

// Helper: turn findings into per-tool output lists (locations/descriptions)
function buildToolOutputsFromFindings(findingsArray) {
  const outputsByTool = {};
  findingsArray.forEach(f => {
    const tool = f.tool_name || "Unknown";
    const loc = (f.location || "").toString().trim();
    const desc = (f.description || "").toString().trim();
    let line = "";
    if (loc && desc) {
      const lowerLoc = loc.toLowerCase();
      const lowerDesc = desc.toLowerCase();
      const subdomainMatch = desc.match(/^subdomain discovered:\s*(.+)$/i);
      if (subdomainMatch && normalizeFindingValue(subdomainMatch[1]) === normalizeFindingValue(loc)) {
        line = loc;
      } else if ((lowerDesc.includes(lowerLoc) || lowerLoc.includes(lowerDesc)) && !lowerDesc.startsWith("open port:")) {
        line = loc;
      } else {
        line = `${loc} – ${desc}`;
      }
    } else if (loc) {
      line = loc;
    } else if (desc) {
      line = desc;
    } else {
      line = f.id || "";
    }
    if (!line) return;
    if (!outputsByTool[tool]) outputsByTool[tool] = [];
    // Avoid exact duplicates
    if (!outputsByTool[tool].includes(line)) {
      outputsByTool[tool].push(line);
    }
  });
  return outputsByTool;
}

function formatComparisonDescription(desc, location) {
  const normalizedLocation = normalizeFindingValue(location);
  const cleaned = (desc || "").toString().trim();
  const subdomainMatch = cleaned.match(/^subdomain discovered:\s*(.+)$/i);
  if (subdomainMatch) {
    const found = normalizeFindingValue(subdomainMatch[1]);
    if (found === normalizedLocation) {
      return "Subdomain";
    }
  }
  if (normalizedLocation && normalizeFindingValue(cleaned) === normalizedLocation) {
    return "Subdomain";
  }
  return cleaned;
}

function renderToolOutputList(lines) {
  if (!lines || lines.length === 0) {
    return `<span class="tool-output-empty">No output recorded</span>`;
  }
  return `<ul class="tool-output-list">${lines.map(line => `<li class="tool-output-item"><code>${escapeHtml(line)}</code></li>`).join('')}</ul>`;
}

function renderScanComparisonChart(findingsByTool, canvasId, findingsContainerId) {
  const canvas = document.getElementById(canvasId);
  const container = document.getElementById(findingsContainerId);
  if (!canvas || !container) return;
  container.dataset.activeTool = '';
  container.innerHTML = '';

  const labels = Object.keys(findingsByTool);
  const data = labels.map(tool => findingsByTool[tool].length);
  const backgroundColor = [
    '#2563eb', '#16a34a', '#f97316', '#e11d48', '#1d4ed8', '#0ea5e9', '#7c3aed', '#64748b'
  ];

  if (!window.scanComparisonCharts) {
    window.scanComparisonCharts = {};
  }
  if (window.scanComparisonCharts[canvasId]) {
    window.scanComparisonCharts[canvasId].destroy();
  }

  const chart = new Chart(canvas, {
    type: 'doughnut',
    data: {
      labels,
      datasets: [{
        data,
        backgroundColor: labels.map((_, idx) => backgroundColor[idx % backgroundColor.length]),
        borderColor: '#0f172a',
        borderWidth: 2,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: 'bottom',
          labels: {
            boxWidth: 12,
            padding: 12,
            color: '#e5e7eb',
          },
          onClick: (evt, legendItem, chartInstance) => {
            const toolName = chartInstance.data.labels[legendItem.index];
            toggleScanComparisonToolSelection(toolName, findingsByTool, findingsContainerId);
          }
        },
        tooltip: {
          callbacks: {
            label: (context) => `${context.label}: ${context.parsed} findings`
          }
        }
      },
      onClick: (evt, elements) => {
        if (!elements.length) return;
        const index = elements[0].index;
        const toolName = chart.data.labels[index];
        toggleScanComparisonToolSelection(toolName, findingsByTool, findingsContainerId);
      }
    }
  });

  window.scanComparisonCharts[canvasId] = chart;
}

function toggleScanComparisonToolSelection(toolName, findingsByTool, findingsContainerId) {
  const container = document.getElementById(findingsContainerId);
  if (!container) return;

  const activeTool = container.dataset.activeTool === toolName ? '' : toolName;
  container.dataset.activeTool = activeTool;

  if (!activeTool) {
    container.innerHTML = '';
    return;
  }

  const lines = findingsByTool[activeTool] || [];
  container.innerHTML = `
    <div class="scan-chart-findings-header">
      <strong>${escapeHtml(activeTool)}</strong> · ${lines.length} ${lines.length === 1 ? 'finding' : 'findings'}
    </div>
    ${renderToolOutputList(lines)}
  `;
}

// Helper: human-readable risk explanation based on severity
function getRiskExplanationForSeverity(severity) {
  const sev = (severity || "").toString().toLowerCase();
  switch (sev) {
    case "critical":
      return "Critical risk – likely exploitable and can lead to full compromise. Fix immediately.";
    case "high":
      return "High risk – serious issue that attackers may exploit. Prioritize remediation.";
    case "medium":
      return "Medium risk – could be exploited under some conditions. Plan to fix.";
    case "low":
      return "Low risk – limited impact. Fix during normal maintenance.";
    case "info":
      return "Informational – used for reconnaissance or mapping, not a direct vulnerability.";
    default:
      return "Risk level not clearly defined for this finding.";
  }
}

// Function to render comparison results
function renderComparisonResults(firstScan, secondScan, comparisonData, firstToolOutputs, secondToolOutputs) {
  const resultDiv = document.getElementById("scanComparisonResult");
  
  const firstDate = formatDate(firstScan.created_at);
  const secondDate = formatDate(secondScan.created_at);
  const firstAttackType = firstScan.owasp_category_name || firstScan.owasp_category || "N/A";
  const secondAttackType = secondScan.owasp_category_name || secondScan.owasp_category || "N/A";
  
  resultDiv.innerHTML = `
    <div class="comparison-header">
      <div class="comparison-section">
        <h4>Scan Comparison Results</h4>
        <div class="comparison-dates">
          <span class="comparison-date">Scan 1: ${firstDate}</span>
          <span class="comparison-date">Scan 2: ${secondDate}</span>
        </div>
      </div>
    </div>
    
    <div class="grid grid-3">
      <div class="comparison-stat-card">
        <div class="stat-label">Common Findings</div>
        <div class="stat-value" style="color: #3b82f6;">${comparisonData.commonFindings.length}</div>
        <div class="stat-foot">Identical findings</div>
      </div>
      <div class="comparison-stat-card">
        <div class="stat-label">New in Scan 2</div>
        <div class="stat-value" style="color: #ef4444;">${comparisonData.uniqueToSecond.length}</div>
        <div class="stat-foot">Findings introduced</div>
      </div>
      <div class="comparison-stat-card">
        <div class="stat-label">Not detected in Scan 2</div>
        <div class="stat-value" style="color: #10b981;">${comparisonData.uniqueToFirst.length}</div>
        <div class="stat-foot">Coverage gap / no longer detected</div>
      </div>
    </div>

    ${!comparisonData.hasNewHighCritical && comparisonData.uniqueToSecond.length ? `<div class="comparison-note">No high/critical new findings were introduced in Scan 2.</div>` : ''}

    <div class="comparison-scan-summary">
      <h5>Scan Details</h5>
      <div class="scan-comparison-chart-row">
        <div class="scan-chart-card">
          <div class="scan-chart-card-header">
            <div>
              <div class="scan-chart-card-title">Scan 1 — ${firstAttackType}</div>
              <div class="scan-chart-card-meta">${firstDate} · ${firstScan.status || "N/A"} · ${(firstScan.tool_runs || []).length} tools</div>
            </div>
          </div>
          <div class="scan-chart-body">
            <div class="scan-chart-canvas-wrap"><canvas id="scanComparisonChart1"></canvas></div>
            <div class="scan-chart-note">Click a slice or legend item to expand that tool's findings below the chart.</div>
            <div class="scan-chart-findings" id="scanComparisonFindings1">Select a tool slice on the chart above.</div>
          </div>
        </div>

        <div class="scan-chart-card">
          <div class="scan-chart-card-header">
            <div>
              <div class="scan-chart-card-title">Scan 2 — ${secondAttackType}</div>
              <div class="scan-chart-card-meta">${secondDate} · ${secondScan.status || "N/A"} · ${(secondScan.tool_runs || []).length} tools</div>
            </div>
          </div>
          <div class="scan-chart-body">
            <div class="scan-chart-canvas-wrap"><canvas id="scanComparisonChart2"></canvas></div>
            <div class="scan-chart-note">Click a slice or legend item to expand that tool's findings below the chart.</div>
            <div class="scan-chart-findings" id="scanComparisonFindings2">Select a tool slice on the chart above.</div>
          </div>
        </div>
      </div>
    </div>

    <div class="comparison-details">
      <div class="comparison-section">
        <h5>Common Findings (${comparisonData.commonFindings.length})</h5>
        <div class="comparison-table-wrapper">
          <table class="recon-findings-table comparison-findings-table">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Tool</th>
                <th>Location</th>
                <th>Description</th>
                <th>Risk Explanation</th>
              </tr>
            </thead>
            <tbody id="comparisonCommonBody"></tbody>
          </table>
          ${comparisonData.commonFindings.length === 0 ? '<div class="no-findings">No common findings</div>' : ''}
        </div>
      </div>
      
      <div class="comparison-section">
        <h5>New in Second Scan (${comparisonData.uniqueToSecond.length})</h5>
        <div class="comparison-table-wrapper">
          <table class="recon-findings-table comparison-findings-table">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Tool</th>
                <th>Location</th>
                <th>Description</th>
                <th>Risk Explanation</th>
              </tr>
            </thead>
            <tbody id="comparisonNewBody"></tbody>
          </table>
          ${comparisonData.uniqueToSecond.length === 0 ? '<div class="no-findings">No new findings in second scan</div>' : ''}
        </div>
      </div>
      
      <div class="comparison-section">
        <h5>Not detected in Scan 2 (${comparisonData.uniqueToFirst.length})</h5>
        <div class="comparison-table-wrapper">
          <table class="recon-findings-table comparison-findings-table">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Tool</th>
                <th>Location</th>
                <th>Description</th>
                <th>Risk Explanation</th>
              </tr>
            </thead>
            <tbody id="comparisonNotDetectedBody"></tbody>
          </table>
          ${comparisonData.uniqueToFirst.length === 0 ? '<div class="no-findings">No findings not detected in Scan 2</div>' : ''}
        </div>
      </div>
    </div>
  `;

  document.getElementById("comparisonCommonBody").innerHTML = getComparisonTableRows(comparisonData.commonFindings);
  document.getElementById("comparisonNewBody").innerHTML = getComparisonTableRows(comparisonData.uniqueToSecond);
  document.getElementById("comparisonNotDetectedBody").innerHTML = getComparisonTableRows(comparisonData.uniqueToFirst);

  renderScanComparisonChart(firstToolOutputs, 'scanComparisonChart1', 'scanComparisonFindings1');
  renderScanComparisonChart(secondToolOutputs, 'scanComparisonChart2', 'scanComparisonFindings2');
}

// Function to render severity distribution chart
function renderTargetSeverityChart(targetScans) {
  const canvas = document.getElementById("targetSeverityChart");
  if (!canvas) return;
  
  const ctx = canvas.getContext("2d");
  
  // Destroy existing chart if it exists
  if (window.targetSeverityChart && typeof window.targetSeverityChart.destroy === 'function') {
    window.targetSeverityChart.destroy();
  }
  
  // Count severity occurrences across all findings (include info)
  const severityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  
  (targetScans || []).forEach(scan => {
    if (scan.findings && Array.isArray(scan.findings)) {
      scan.findings.forEach(finding => {
        const sev = (finding.severity || "").toLowerCase();
        if (severityCounts.hasOwnProperty(sev)) {
          severityCounts[sev]++;
        }
      });
    }
  });
  
  const total = Object.values(severityCounts).reduce((a, b) => a + b, 0);
  const data = [
    severityCounts.critical,
    severityCounts.high,
    severityCounts.medium,
    severityCounts.low,
    severityCounts.info
  ];

  window.targetSeverityChart = new Chart(ctx, {
    type: "doughnut",
    data: {
      labels: ["Critical", "High", "Medium", "Low", "Info"],
      datasets: [{
        data: data,
        backgroundColor: [
          "#ef4444",
          "#f97316",
          "#eab308",
          "#3b82f6",
          "#6b7280"
        ],
        borderColor: "#0f172a",
        borderWidth: 2,
        hoverBorderWidth: 3,
        hoverBorderColor: "#f8fafc",
        hoverOffset: 18,
        hoverBackgroundColor: [
          "#f87171",
          "#fb923c",
          "#facc15",
          "#60a5fa",
          "#9ca3af"
        ],
        spacing: 2
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: "68%",
      animation: {
        animateRotate: true,
        animateScale: true,
        duration: 600
      },
      layout: {
        padding: 8
      },
      interaction: {
        intersect: false,
        mode: "nearest"
      },
      plugins: {
        legend: {
          position: "right",
          labels: {
            usePointStyle: true,
            padding: 12,
            pointStyle: "circle"
          }
        },
        tooltip: {
          enabled: true,
          backgroundColor: "rgba(15, 23, 42, 0.95)",
          titleColor: "#f8fafc",
          bodyColor: "#e2e8f0",
          borderColor: "#334155",
          borderWidth: 1,
          padding: 12,
          displayColors: true,
          callbacks: {
            label: function(context) {
              const value = context.raw || 0;
              const pct = total > 0 ? ((100 * value) / total).toFixed(1) : 0;
              return `${context.label}: ${value} finding${value !== 1 ? "s" : ""} (${pct}%)`;
            }
          }
        }
      }
    }
  });
}

// Function to render category chart
function renderTargetCategoryChart(targetScans) {
  const canvas = document.getElementById("targetCategoryChart");
  if (!canvas) return;
  
  const ctx = canvas.getContext("2d");
  
  // Destroy existing chart if it exists
  if (window.targetCategoryChart && typeof window.targetCategoryChart.destroy === 'function') {
    window.targetCategoryChart.destroy();
  }
  
  // Count findings by tool (real scan data: tool_name from API)
  const categoryCounts = {};
  
  (targetScans || []).forEach(scan => {
    if (scan.findings && Array.isArray(scan.findings)) {
      scan.findings.forEach(finding => {
        const category = finding.tool_name || finding.tool || finding.category || "Unknown";
        categoryCounts[category] = (categoryCounts[category] || 0) + 1;
      });
    }
  });
  
  // Prepare data for chart (sort by count descending)
  const entries = Object.entries(categoryCounts).sort((a, b) => b[1] - a[1]);
  const labels = entries.map(e => e[0]);
  const data = entries.map(e => e[1]);
  
  window.targetCategoryChart = new Chart(ctx, {
    type: "bar",
    data: {
      labels: labels,
      datasets: [{
        label: "Findings Count",
        data: data,
        backgroundColor: "#3b82f6",
        borderColor: "#2563eb",
        borderWidth: 1
      }]
    },
    options: {
      indexAxis: "y", // Horizontal bar chart
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          display: false
        },
        tooltip: {
          callbacks: {
            label: function(context) {
              return `${context.parsed.x} findings`;
            }
          }
        }
      },
      scales: {
        x: {
          beginAtZero: true,
          title: {
            display: true,
            text: 'Number of Findings'
          }
        }
      }
    }
  });
}

// Function to render trend chart
function renderTargetTrendChart(targetScans) {
  const canvas = document.getElementById("targetTrendChart");
  const container = document.querySelector(".target-trend-chart-wrap");
  const inner = document.querySelector(".target-trend-chart-inner");
  if (!canvas || !container || !inner) return;

  const ctx = canvas.getContext("2d");
  if (!ctx) return;

  if (window.targetTrendChart && typeof window.targetTrendChart.destroy === 'function') {
    window.targetTrendChart.destroy();
  }

  // Build severity counts per day (YYYY-MM-DD)
  const countsByDate = {};
  (targetScans || []).forEach(scan => {
    const scanDate = parseDateAsUTC(scan.created_at);
    if (!scanDate || isNaN(scanDate.getTime())) return;
    const key = `${scanDate.getFullYear()}-${String(scanDate.getMonth()+1).padStart(2, '0')}-${String(scanDate.getDate()).padStart(2, '0')}`;
    if (!countsByDate[key]) countsByDate[key] = { critical: 0, high: 0, medium: 0, low: 0 };

    (scan.findings || []).forEach(finding => {
      const sev = (finding.severity || '').toLowerCase();
      if (sev === 'critical') countsByDate[key].critical += 1;
      else if (sev === 'high') countsByDate[key].high += 1;
      else if (sev === 'medium') countsByDate[key].medium += 1;
      else if (sev === 'low') countsByDate[key].low += 1;
    });
  });

  // Default date window: show the most recent 10 days; allow scrolling if more than 10 days available.
  const today = new Date();
  today.setHours(0,0,0,0);
  const defaultWindowDays = 10;

  const allDateKeys = Object.keys(countsByDate)
    .map(d => new Date(d + 'T00:00:00'))
    .filter(d => !isNaN(d.getTime()))
    .sort((a,b)=>a-b);

  let dateKeys = [];
  if (allDateKeys.length === 0) {
    // no data, generate last 10 days labels
    for (let i = defaultWindowDays - 1; i >= 0; i--) {
      const d = new Date(today);
      d.setDate(today.getDate() - i);
      dateKeys.push(`${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`);
    }
  } else {
    const firstScanDate = allDateKeys[0];
    const lastScanDate = allDateKeys[allDateKeys.length-1];
    const endDate = new Date(Math.max(lastScanDate.getTime(), today.getTime()));
    endDate.setHours(0,0,0,0);

    const startDate = new Date(endDate);
    startDate.setDate(endDate.getDate() - (defaultWindowDays - 1));

    // if older data exists beyond 10-day default window, keep it for horizontal scroll
    const earliestDate = firstScanDate < startDate ? firstScanDate : startDate;
    let iter = new Date(earliestDate);
    iter.setHours(0,0,0,0);

    const lastLimit = new Date(endDate);
    while (iter <= lastLimit) {
      dateKeys.push(`${iter.getFullYear()}-${String(iter.getMonth()+1).padStart(2,'0')}-${String(iter.getDate()).padStart(2,'0')}`);
      iter.setDate(iter.getDate() + 1);
    }
  }

  const labels = dateKeys.map(d => {
    const parts = d.split('-');
    if (parts.length !== 3) return d;
    return `${parts[1]}/${parts[2]}`;
  });

  const criticalData = dateKeys.map(d => (countsByDate[d] ? countsByDate[d].critical : 0));
  const highData = dateKeys.map(d => (countsByDate[d] ? countsByDate[d].high : 0));
  const mediumData = dateKeys.map(d => (countsByDate[d] ? countsByDate[d].medium : 0));
  const lowData = dateKeys.map(d => (countsByDate[d] ? countsByDate[d].low : 0));

  // Set inner width to stable cell size and 10-day default viewport
  const cellWidth = 70;
  const targetWidth = Math.max(dateKeys.length * cellWidth, defaultWindowDays * cellWidth);
  inner.style.width = `${targetWidth}px`;

  window.targetTrendChart = new Chart(ctx, {
    type: "line",
    data: {
      labels: labels,
      datasets: [
        { label: "Critical", data: criticalData, borderColor: "#ef4444", backgroundColor: "rgba(239, 68, 68, 0.15)", tension: 0.3, fill: true, pointRadius: 3 },
        { label: "High", data: highData, borderColor: "#f97316", backgroundColor: "rgba(249, 115, 22, 0.15)", tension: 0.3, fill: true, pointRadius: 3 },
        { label: "Medium", data: mediumData, borderColor: "#eab308", backgroundColor: "rgba(234, 179, 8, 0.15)", tension: 0.3, fill: true, pointRadius: 3 },
        { label: "Low", data: lowData, borderColor: "#64748b", backgroundColor: "rgba(100, 116, 139, 0.15)", tension: 0.3, fill: true, pointRadius: 3 }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { position: "top" },
        tooltip: { mode: "index", intersect: false }
      },
      scales: {
        y: { beginAtZero: true, title: { display: true, text: 'Number of Findings' } },
        x: { title: { display: true, text: 'Date' }, ticks: { autoSkip: false } }
      }
    }
  });

  // Ensure view defaults to latest date range (last 10 days) for horizontal scroll
  if (dateKeys.length > defaultWindowDays) {
    container.scrollLeft = container.scrollWidth;
  } else {
    container.scrollLeft = 0;
  }
}

/* ===== TOOLS & OWASP TABS ===== */
function initToolLibrary() {
  const grid = document.getElementById("toolCardGrid");
  grid.innerHTML = "";

  TOOL_LIST.forEach((name) => {
    const card = document.createElement("div");
    card.className = "tool-card";

    const header = document.createElement("div");
    header.className = "tool-card-header";
    const title = document.createElement("div");
    title.className = "tool-card-title";
    title.textContent = name;
    const meta = document.createElement("div");
    meta.className = "tool-card-meta";
    meta.textContent = "Recon · CLI tool";
    header.appendChild(title);
    header.appendChild(meta);

    const desc = document.createElement("div");
    desc.className = "tool-card-desc";
    desc.textContent = "Use Launch Recon Scan to run this tool against a target.";

    const footer = document.createElement("div");
    footer.className = "tool-card-footer";
    const btn = document.createElement("button");
    btn.className = "tool-run-btn";
    btn.textContent = `Run ${name}`;
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      showToolCommand(name);
    });

    footer.appendChild(btn);
    card.appendChild(header);
    card.appendChild(desc);
    card.appendChild(footer);
    grid.appendChild(card);
  });

  const mappingBody = document.getElementById("owaspMappingBody");
  mappingBody.innerHTML = "";
  OWASP_MAP.forEach((row) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${row.id}</td>
      <td>${row.name}</td>
      <td>${row.tools.join(", ")}</td>
    `;
    mappingBody.appendChild(tr);
  });

  const tabs = document.querySelectorAll(".tab");
  const libPanel = document.getElementById("toolLibraryPanel");
  const mapPanel = document.getElementById("owaspMappingPanel");
  tabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      tabs.forEach((t) => t.classList.remove("active"));
      tab.classList.add("active");
      const mode = tab.dataset.toolsTab;
      libPanel.classList.toggle("hidden", mode !== "library");
      mapPanel.classList.toggle("hidden", mode !== "owasp");
    });
  });
}

/* ===== SETTINGS & HEALTH ===== */
async function refreshHealth() {
  const pill = document.getElementById("apiHealthPill");
  const label = document.getElementById("apiHealthLabel");
  try {
    await apiRequest(API_ROUTES.health(), { method: "GET" });
    pill.classList.remove("status-offline");
    pill.classList.add("status-online");
    label.textContent = "LIVE";
  } catch {
    pill.classList.remove("status-online");
    pill.classList.add("status-offline");
    label.textContent = "OFFLINE";
  }
}

async function loadSettings() {
  // API base is fetched from backend config via initializeApiConfig()
  // Frontend cannot use localStorage to override it - enforced server-side only
  const input = document.getElementById("apiBaseInput");
  input.value = defaultApiBase;
  input.readOnly = true;
  input.disabled = true;
  await refreshHealth();
  await loadAlertEmailSettings();
}

function initSettings() {
  const input = document.getElementById("apiBaseInput");
  const saveBtn = document.getElementById("saveSettingsBtn");
  const purgeBtn = document.getElementById("purgeDatabaseBtn");

  // SECURITY: API endpoint input is READ-ONLY
  // Frontend cannot edit or save API endpoint changes
  input.readOnly = true;
  input.disabled = true;
  
  // Prevent any modification of the API endpoint field
  input.addEventListener("change", (e) => {
    e.preventDefault();
    input.value = defaultApiBase;
  });
  
  input.addEventListener("input", (e) => {
    e.preventDefault();
    input.value = defaultApiBase;
  });

  saveBtn.addEventListener("click", async () => {
    // Only other settings can be saved (notifications, etc.)
    // API endpoint is managed server-side via environment variables only
    // Do NOT allow: apiBase = input.value.trim() || defaultApiBase;
    // Do NOT allow: localStorage.setItem("irs_api_base", apiBase);
    await refreshHealth();
  });

  purgeBtn.addEventListener("click", () => {
    showDeleteConfirmModal(
      "Purge Database?",
      `This will purge all scans and targets from the local database.<br><br>Are you sure you want to continue?`,
      async () => {
        try {
          const res = await fetch(getApiUrl(API_ROUTES.purgeScans()), { method: "DELETE" });
          const data = res.ok ? await res.json().catch(() => ({})) : null;
          if (res.ok) {
            showNotification(`✓ ${data?.message || "All scans and targets purged"}`, "success");
            await refreshScansViews();
            await refreshDashboardCharts();
          } else {
            const err = data?.detail || data?.message || `HTTP ${res.status}`;
            throw new Error(err);
          }
        } catch (e) {
          showNotification(`✗ Failed to purge: ${e.message}`, "error");
        }
      }
    );
  });

  initAlertEmailSettings();
}

/* ===== ALERT EMAIL SETTINGS ===== */
const ALERT_EMAIL_API = "/api/settings/alert-email";
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function syncAlertEmailToggleLabel() {
  const toggle = document.getElementById("alertEmailEnabled");
  const label = document.querySelector(".alert-email-toggle-label");
  if (!toggle || !label) return;
  label.textContent = toggle.checked ? "Disable" : "Enable";
}

async function loadAlertEmailSettings() {
  const toggle = document.getElementById("alertEmailEnabled");
  const manageBtn = document.getElementById("alertEmailManageBtn");
  if (!toggle || !manageBtn) return;
  try {
    const data = await apiRequest(ALERT_EMAIL_API, { method: "GET" });
    toggle.checked = !!data.enabled;
    manageBtn.classList.toggle("hidden", !data.enabled);
    syncAlertEmailToggleLabel();
  } catch (e) {
    console.warn("Failed to load alert email settings", e);
    toggle.checked = false;
    manageBtn.classList.add("hidden");
    syncAlertEmailToggleLabel();
  }
}

function openAlertEmailModal(initialEmails) {
  const wrap = document.getElementById("alertEmailFieldsWrap");
  const modal = document.getElementById("alertEmailModal");
  const errEl = document.getElementById("alertEmailError");
  if (!wrap || !modal || !errEl) return;
  wrap.innerHTML = "";
  const emails = Array.isArray(initialEmails) && initialEmails.length ? initialEmails : [""];
  emails.forEach((email, i) => {
    const row = document.createElement("div");
    row.className = "alert-email-row";
    const input = document.createElement("input");
    input.type = "email";
    input.className = "alert-email-input";
    input.placeholder = "email@example.com";
    input.autocomplete = "email";
    input.value = typeof email === "string" ? email : "";
    const addBtn = document.createElement("button");
    addBtn.type = "button";
    addBtn.className = "alert-email-add-btn";
    addBtn.title = "Add another email";
    addBtn.setAttribute("aria-label", "Add another email");
    addBtn.textContent = "+";
    addBtn.addEventListener("click", () => addAlertEmailRow(wrap));
    row.appendChild(input);
    row.appendChild(addBtn);
    wrap.appendChild(row);
  });
  errEl.classList.add("hidden");
  errEl.textContent = "";
  modal.classList.remove("hidden");
  modal.setAttribute("aria-hidden", "false");
  const firstInput = wrap.querySelector(".alert-email-input");
  if (firstInput) firstInput.focus();
}

function addAlertEmailRow(wrap) {
  if (!wrap) return;
  const row = document.createElement("div");
  row.className = "alert-email-row";
  const input = document.createElement("input");
  input.type = "email";
  input.className = "alert-email-input";
  input.placeholder = "email@example.com";
  input.autocomplete = "email";
  const addBtn = document.createElement("button");
  addBtn.type = "button";
  addBtn.className = "alert-email-add-btn";
  addBtn.title = "Add another email";
  addBtn.setAttribute("aria-label", "Add another email");
  addBtn.textContent = "+";
  addBtn.addEventListener("click", () => addAlertEmailRow(wrap));
  row.appendChild(input);
  row.appendChild(addBtn);
  wrap.appendChild(row);
  input.focus();
}

function closeAlertEmailModal() {
  const modal = document.getElementById("alertEmailModal");
  if (modal) {
    modal.classList.add("hidden");
    modal.setAttribute("aria-hidden", "true");
  }
}

function collectAlertEmailValues() {
  const wrap = document.getElementById("alertEmailFieldsWrap");
  if (!wrap) return [];
  const inputs = wrap.querySelectorAll(".alert-email-input");
  return Array.from(inputs)
    .map((el) => (el.value || "").trim().toLowerCase())
    .filter((v) => v.length > 0);
}

function validateAlertEmails(emails) {
  const invalid = emails.filter((e) => !EMAIL_REGEX.test(e));
  return invalid.length === 0 ? null : invalid;
}

function initAlertEmailSettings() {
  const toggle = document.getElementById("alertEmailEnabled");
  const manageBtn = document.getElementById("alertEmailManageBtn");
  const modal = document.getElementById("alertEmailModal");
  const closeBtn = document.getElementById("alertEmailModalClose");
  const cancelBtn = document.getElementById("alertEmailCancelBtn");
  const saveBtn = document.getElementById("alertEmailSaveBtn");
  const addBtn = document.querySelector(".alert-email-add-btn");
  const wrap = document.getElementById("alertEmailFieldsWrap");

  if (!toggle) return;

  toggle.addEventListener("change", async () => {
    syncAlertEmailToggleLabel();
    if (toggle.checked) {
      const data = await apiRequest(ALERT_EMAIL_API, { method: "GET" }).catch(() => ({ enabled: false, emails: [] }));
      openAlertEmailModal(data.emails && data.emails.length ? data.emails : [""]);
    } else {
      try {
        await apiRequest(ALERT_EMAIL_API, {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ enabled: false, emails: [] }),
        });
        document.getElementById("alertEmailManageBtn").classList.add("hidden");
        showNotification("Alert email disabled.", "success");
      } catch (e) {
        showNotification(`Failed to save: ${e.message}`, "error");
        toggle.checked = true;
        syncAlertEmailToggleLabel();
      }
    }
  });

  if (manageBtn) {
    manageBtn.addEventListener("click", async () => {
      try {
        const data = await apiRequest(ALERT_EMAIL_API, { method: "GET" });
        openAlertEmailModal(data.emails && data.emails.length ? data.emails : [""]);
      } catch (e) {
        openAlertEmailModal([""]);
      }
    });
  }

  function onSave() {
    const errEl = document.getElementById("alertEmailError");
    const emails = collectAlertEmailValues();
    const invalid = validateAlertEmails(emails);
    if (invalid && invalid.length) {
      errEl.textContent = "Please enter valid email addresses.";
      errEl.classList.remove("hidden");
      return;
    }
    if (emails.length === 0) {
      errEl.textContent = "Add at least one email address to receive alerts.";
      errEl.classList.remove("hidden");
      return;
    }
    saveBtn.disabled = true;
    apiRequest(ALERT_EMAIL_API, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ enabled: true, emails }),
    })
      .then(() => {
        closeAlertEmailModal();
        loadAlertEmailSettings();
        showNotification("Email addresses saved. You will receive alerts when a scan finishes.", "success");
      })
      .catch((e) => {
        errEl.textContent = e.message || "Failed to save.";
        errEl.classList.remove("hidden");
      })
      .finally(() => {
        saveBtn.disabled = false;
        syncAlertEmailToggleLabel();
      });
  }

  if (saveBtn) saveBtn.addEventListener("click", onSave);
  if (cancelBtn) cancelBtn.addEventListener("click", closeAlertEmailModal);
  if (closeBtn) closeBtn.addEventListener("click", closeAlertEmailModal);
  if (modal) {
    modal.addEventListener("click", (e) => {
      if (e.target === modal) closeAlertEmailModal();
    });
  }
  if (wrap && addBtn) {
    addBtn.addEventListener("click", () => addAlertEmailRow(wrap));
  }
}

/* ===== HIGH-LEVEL REFRESH ===== */
async function refreshScansViews() {
  try {
    // Fetch all scans (including unsaved) for dashboard
    const result = await fetchScans({ page_size: 100 }, true);
    const scans = Array.isArray(result) ? result : result.scans || result.items || [];
    
    // Always keep charts visible and persistent - they show real data from API
    const chartCards = document.querySelectorAll(".dashboard-chart-card");
    chartCards.forEach(card => {
      card.classList.add("visible");
      card.style.display = "block";
      card.style.opacity = "1";
      card.style.visibility = "visible";
    });
    
    const summary = summarizeStats(scans);
    try {
      const scheduleList = await fetchScheduledScans();
      const list = Array.isArray(scheduleList) ? scheduleList : [];
      summary.scheduledScans = list.length;
      summary.scheduledScansOn = list.filter((s) => s && s.enabled === true).length;
      summary.scheduledScansOff = list.filter((s) => s && s.enabled === false).length;
      // Keep the dashboard card in sync even if user is on Scheduled Scans page
      updateDashboardScheduledScansCard(list);
    } catch (e) {
      summary.scheduledScans = 0;
      summary.scheduledScansOn = 0;
      summary.scheduledScansOff = 0;
      updateDashboardScheduledScansCard([]);
    }
    renderDashboardStats(summary);
    renderTargetsTable(scans);

    // Always show cumulative severity distribution of all scans - disable single-scan selection
    const sevSelect = document.getElementById("severityScanSelect");
    if (sevSelect) {
      // Clear the dropdown and only show the "All scans" option
      sevSelect.innerHTML = "";
      const allOption = document.createElement("option");
      allOption.value = "all";
      allOption.textContent = "All scans (global)";
      allOption.selected = true;  // Always keep this option selected
      sevSelect.appendChild(allOption);
      
      // Always update to show global view
      updateSeverityScope("all").catch((e) =>
        console.warn("Failed to sync severity scope", e),
      );
    }
    
    // Also refresh the saved reports section
    await refreshSavedReports();
  } catch (e) {
    console.error("Failed to refresh scans", e);
  }
}

/* ===== REFRESH SAVED REPORTS ===== */
async function refreshSavedReports() {
  try {
    const result = await fetchScans({ page_size: 100 }, false);
    savedReportsScans = Array.isArray(result) ? result : result.scans || result.items || [];
    applyReportsFilters();
  } catch (e) {
    console.error("Failed to refresh saved reports", e);
  }
}

/* ===== INIT ===== */
function initLaunchForm() {
  const form = document.getElementById("launchForm");
  const clearBtn = document.getElementById("clearLaunchBtn");
  const disconnectBtn = document.getElementById("disconnectWsBtn");
  
  form.addEventListener("submit", handleLaunchScan);
  clearBtn.addEventListener("click", clearLaunchForm);
  
  if (disconnectBtn) {
    disconnectBtn.addEventListener("click", function() {
      disconnectWebSocket();
      console.log("WebSocket manually disconnected");
    });
  }
}
/* ===== DELETE OPERATIONS ===== */
function showDeleteConfirmModal(title, message, onConfirm) {
  const modal = document.createElement("div");
  modal.className = "delete-modal-overlay";
  modal.innerHTML = `
    <div class="delete-modal">
      <div class="delete-modal-header">
        <div class="delete-modal-icon">
          <svg width="24" height="24" viewBox="0 0 48 48" fill="none">
            <circle cx="24" cy="24" r="22" fill="#fff" fill-opacity="0.08" stroke="#ef4444" stroke-width="2"/>
            <path d="M24 14v12" stroke="#ef4444" stroke-width="3" stroke-linecap="round"/>
            <circle cx="24" cy="32" r="2.5" fill="#ef4444"/>
          </svg>
        </div>
        <h2>${title}</h2>
        <button class="delete-modal-close" aria-label="Close">&times;</button>
      </div>
      <div class="delete-modal-body">
        <div class="delete-modal-warning">
          <div>
            <p class="delete-modal-message">${message}</p>
            <p class="delete-modal-note">This action cannot be undone.</p>
          </div>
        </div>
      </div>
      <div class="delete-modal-footer">
        <button class="delete-modal-cancel">Cancel</button>
        <button class="delete-modal-confirm">Delete</button>
      </div>
    </div>
  `;
  
  document.body.appendChild(modal);
  
  // Handle close button
  modal.querySelector(".delete-modal-close").addEventListener("click", () => {
    modal.remove();
  });
  
  // Handle cancel button
  modal.querySelector(".delete-modal-cancel").addEventListener("click", () => {
    modal.remove();
  });
  
  // Handle confirm button
  modal.querySelector(".delete-modal-confirm").addEventListener("click", async () => {
    modal.querySelector(".delete-modal-confirm").disabled = true;
    modal.querySelector(".delete-modal-confirm").textContent = "Deleting...";
    await onConfirm();
    modal.remove();
  });
  
  // Close on escape key
  const handleEscape = (e) => {
    if (e.key === "Escape") {
      modal.remove();
      document.removeEventListener("keydown", handleEscape);
    }
  };
  document.addEventListener("keydown", handleEscape);
  
  // Close on overlay click
  modal.addEventListener("click", (e) => {
    if (e.target === modal) {
      modal.remove();
    }
  });
}

async function deleteScan(scanId, target) {
  const findingCount = document.querySelector(`[data-action="delete-scan"][data-id="${scanId}"]`)?.closest("tr")?.cells[4]?.textContent || "?";
  
  showDeleteConfirmModal(
    "Delete Scan?",
    `<strong>Target:</strong> ${target}<br><strong>Scan ID:</strong> #${scanId}<br><strong>Findings:</strong> ${findingCount}<br><br>All scan data, findings, and reports will be permanently removed.`,
    async () => {
      try {
        const response = await fetch(getApiUrl(`/api/scans/${scanId}`), {
          method: "DELETE",
          headers: { "Content-Type": "application/json" }
        });
        
        if (!response.ok) {
          const error = await response.json();
          throw new Error(error.detail || "Failed to delete scan");
        }
        
        showNotification(`✓ Scan #${scanId} deleted successfully`, "success");
        await refreshScansViews();
        await refreshDashboardCharts();
      } catch (error) {
        console.error("Error deleting scan:", error);
        showNotification(`✗ Error: ${error.message}`, "error");
      }
    }
  );
}

async function deleteReport(scanId, format) {
  showDeleteConfirmModal(
    `Delete ${format.toUpperCase()} Report?`,
    `<strong>Scan ID:</strong> #${scanId}<br><strong>Format:</strong> ${format.toUpperCase()}<br><br>The report file will be permanently removed.`,
    async () => {
      try {
        const response = await fetch(getApiUrl(`/api/scans/${scanId}/report?format=${format}`), {
          method: "DELETE",
          headers: { "Content-Type": "application/json" }
        });
        
        if (!response.ok) {
          const error = await response.json();
          throw new Error(error.detail || "Failed to delete report");
        }
        
        showNotification(`✓ ${format.toUpperCase()} report deleted`, "success");
        await refreshScansViews();
      } catch (error) {
        console.error("Error deleting report:", error);
        showNotification(`✗ Error: ${error.message}`, "error");
      }
    }
  );
}

function showNotification(message, type = "info") {
  const notification = document.createElement("div");
  notification.className = `notification notification-${type}`;
  const icon = type === "success" ? "✓ " : type === "error" ? "✗ " : "";
  notification.textContent = icon + message;
  notification.style.cssText = `
    position: fixed;
    top: 20px;
    right: 20px;
    padding: 16px 24px;
    background: ${type === "error" ? "#dc2626" : type === "success" ? "#16a34a" : "#2563eb"};
    color: white;
    border-radius: 8px;
    box-shadow: 0 4px 20px rgba(0,0,0,0.2);
    z-index: 10000;
    font-weight: 500;
    font-size: 0.9375rem;
    animation: slideIn 0.3s ease-out;
  `;
  document.body.appendChild(notification);
  const duration = type === "success" ? 4000 : 3000;
  setTimeout(() => {
    notification.style.animation = "slideOut 0.3s ease-out forwards";
    setTimeout(() => notification.remove(), 300);
  }, duration);
}

/* ===== SCHEDULED SCANS PAGE ===== */
let scheduleChosenNextRunAt = null; // ISO string or null

function getScheduleSelectedTools() {
  const pills = document.querySelectorAll("#scheduleToolGrid .schedule-tool-pill.active");
  const selected = [];
  pills.forEach((p) => { const t = p.getAttribute("data-tool"); if (t) selected.push(t); });
  return selected;
}

function getScheduleRepeatType() {
  const active = document.querySelector(".schedule-repeat-pill.active");
  return (active && active.getAttribute("data-repeat")) || "once";
}

function isScheduleToggleOn() {
  const btn = document.getElementById("scheduleToggleBtn");
  return btn && btn.getAttribute("aria-checked") === "true";
}

async function fetchScheduledScans() {
  const url = getApiUrl("/api/scheduled-scans");
  const res = await fetch(url);
  if (!res.ok) throw new Error(res.statusText);
  return res.json();
}

async function fetchScheduledScanResults() {
  const url = getApiUrl("/api/scheduled-scans/scan-results");
  const res = await fetch(url);
  if (!res.ok) throw new Error(res.statusText);
  return res.json();
}

/** IDs of completed scheduled scans we've already refreshed dashboard charts for (one-time refresh per completion). */
const scheduledCompletedScanIdsChartsRefreshed = new Set();

/**
 * Check scheduled scan results for newly completed scans; if any, refresh dashboard charts once and mark as done.
 * Run every 1s so charts update within ~1s of completion (Dashboard or Schedule tab).
 */
async function checkScheduledCompletionAndRefreshChartsOnce() {
  try {
    const resultsList = await fetchScheduledScanResults();
    const list = Array.isArray(resultsList) ? resultsList : [];
    for (const scan of list) {
      const status = String(scan.status || "").toLowerCase();
      if (status !== "completed" && status !== "completed_with_errors") continue;
      const id = scan.id;
      if (id == null) continue;
      if (scheduledCompletedScanIdsChartsRefreshed.has(id)) continue;
      scheduledCompletedScanIdsChartsRefreshed.add(id);
      await refreshDashboardCharts();
      return; // one refresh per check
    }
  } catch (e) {
    // ignore; next tick will retry
  }
}

/** Refresh only the "Scheduled scan results" table once (e.g. after any change in "Your schedules"). */
async function refreshScheduledScanResultsOnce() {
  const emptyResults = document.getElementById("scheduledScanResultsEmpty");
  const resultsBody = document.getElementById("scheduledScanResultsBody");
  try {
    const resultsList = await fetchScheduledScanResults();
    renderScheduledScanResultsTable(resultsList);
  } catch (e) {
    if (resultsBody) resultsBody.innerHTML = "";
    if (emptyResults) {
      emptyResults.classList.remove("hidden");
      const textEl = emptyResults.querySelector(".schedule-empty-text");
      if (textEl) textEl.textContent = "Failed to load results. " + (e?.message || "Unknown error");
    }
  }
}

function renderScheduledScanResultsTable(list) {
  const tbody = document.getElementById("scheduledScanResultsBody");
  const emptyEl = document.getElementById("scheduledScanResultsEmpty");
  if (!tbody) return;
  tbody.innerHTML = "";
  if (emptyEl) emptyEl.classList.toggle("hidden", (list && list.length) > 0);

  (list || []).forEach((scan) => {
    const tr = document.createElement("tr");
    const sev = (scan.highest_severity || "").toLowerCase();
    let sevClass = "tag-low";
    if (sev === "critical") sevClass = "tag-critical";
    else if (sev === "high") sevClass = "tag-high";
    else if (sev === "medium") sevClass = "tag-medium";
    const statusClass = (scan.status || "").toLowerCase() === "completed" || (scan.status || "").toLowerCase() === "completed_with_errors" ? "badge-completed" : "badge-running";
    const created = scan.created_at ? formatDateLocal(scan.created_at) : "—";
    const isCompleted = (scan.status || "").toLowerCase() === "completed" || (scan.status || "").toLowerCase() === "completed_with_errors";
    const isSaved = scan.is_saved === true;
    const saveBtn = isCompleted
      ? (isSaved
          ? '<span class="tool-run-btn tool-run-btn-saved" title="Saved to Saved Reports">✓ Saved</span>'
          : '<button type="button" class="tool-run-btn save-report-btn" data-action="save-scan-report" data-id="' + scan.id + '" title="Save to Saved Reports">Save Report</button>')
      : "";
    tr.innerHTML = `
      <td style="min-width: 100px; white-space: nowrap;">${scan.id}</td>
      <td style="min-width: 200px; white-space: nowrap;" title="${scan.target || ""}">${scan.target || "—"}</td>
      <td style="min-width: 250px; white-space: nowrap;" title="${getOwaspCategoryName(scan.owasp_category) || scan.owasp_category || ""}">${getOwaspCategoryName(scan.owasp_category) || scan.owasp_category}</td>
      <td style="min-width: 150px; white-space: nowrap;"><span class="tag ${sevClass}">${scan.highest_severity || "—"}</span></td>
      <td style="min-width: 80px; text-align: center; white-space: nowrap;">${scan.finding_count ?? 0}</td>
      <td style="min-width: 180px; white-space: nowrap;"><span class="badge-status ${statusClass}">${scan.status || "—"}</span></td>
      <td style="min-width: 240px; white-space: nowrap;" title="${created}">${created}</td>
      <td style="min-width: 280px; white-space: nowrap;">
        <div class="actions-cell">
          <a href="${getApiUrl(API_ROUTES.reportHtml(scan.id))}" target="_blank" rel="noopener" class="tool-run-btn">View Report</a>
          ${saveBtn}
          <button type="button" class="tool-run-btn delete-btn" data-action="delete-scan-result" data-id="${scan.id}" title="Delete this scan">🗑️</button>
        </div>
      </td>
    `;
    tbody.appendChild(tr);
  });

  tbody.querySelectorAll('[data-action="save-scan-report"]').forEach((btn) => {
    btn.addEventListener("click", async () => {
      const id = btn.dataset.id;
      try {
        const res = await fetch(getApiUrl(API_ROUTES.markScanSaved(id)), { method: "POST" });
        if (res.ok) {
          showNotification("Report saved to Saved Reports.", "success");
          await loadScheduledScansPage();
          if (typeof refreshSavedReports === "function") await refreshSavedReports();
          if (typeof updateScanFilter === "function") updateScanFilter();
          await refreshDashboardCharts();
        } else {
          const err = await res.json().catch(() => ({}));
          showNotification(err.detail || "Failed to save report.", "error");
        }
      } catch (e) {
        showNotification("Error: " + e.message, "error");
      }
    });
  });

  tbody.querySelectorAll('[data-action="delete-scan-result"]').forEach((btn) => {
    btn.addEventListener("click", () => {
      const id = btn.dataset.id;
      showDeleteConfirmModal(
        "Delete scan result",
        "Remove this scheduled scan result from the list?",
        async () => {
          try {
            const res = await fetch(getApiUrl(`/api/scans/${id}`), { method: "DELETE" });
            if (res.ok) {
              showNotification("Scan result deleted successfully.", "success");
              await loadScheduledScansPage();
              await refreshDashboardCharts();
            } else {
              const err = await res.json().catch(() => ({}));
              showNotification(err.detail || "Failed to delete scan.", "error");
            }
          } catch (e) {
            showNotification("Error: " + e.message, "error");
          }
        }
      );
    });
  });
}

function renderScheduledScansTable(list) {
  const tbody = document.getElementById("scheduledScansTableBody");
  const emptyEl = document.getElementById("scheduledScansEmpty");
  if (!tbody) return;
  tbody.innerHTML = "";
  if (emptyEl) emptyEl.classList.toggle("hidden", (list && list.length) > 0);

  (list || []).forEach((s) => {
    const tr = document.createElement("tr");
    const lastRun = s.last_run_at ? formatDateLocal(s.last_run_at) : "—";
    let nextRun = "—";
    if (s.next_run_at) nextRun = formatDateLocal(s.next_run_at);
    const toolsStr = Array.isArray(s.selected_tools) ? s.selected_tools.join(", ") : (s.selected_tools || "—");
    tr.innerHTML = `
      <td>${s.target || "—"}</td>
      <td>${getOwaspCategoryName(s.owasp_category) || s.owasp_category}</td>
      <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${toolsStr}">${toolsStr}</td>
      <td>${(s.frequency || "weekly").charAt(0).toUpperCase() + (s.frequency || "weekly").slice(1)}</td>
      <td class="schedule-date-cell">${lastRun}</td>
      <td class="schedule-date-cell">${nextRun}</td>
      <td><span class="badge-status ${s.enabled ? "badge-completed" : "badge-failed"}">${s.enabled ? "On" : "Off"}</span></td>
      <td>
        <div class="actions-cell">
          <button type="button" class="tool-run-btn schedule-toggle-btn" data-id="${s.id}" data-enabled="${s.enabled}">${s.enabled ? "Turn off" : "Turn on"}</button>
          <button type="button" class="tool-run-btn delete-btn" data-action="delete-schedule" data-id="${s.id}" title="Delete schedule">🗑️</button>
        </div>
      </td>
    `;
    tbody.appendChild(tr);
  });

  tbody.querySelectorAll(".schedule-toggle-btn").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const id = btn.dataset.id;
      const currentlyEnabled = btn.dataset.enabled === "true";
      try {
        const url = getApiUrl(`/api/scheduled-scans/${id}`);
        const res = await fetch(url, {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ enabled: !currentlyEnabled }),
        });
        if (res.ok) {
          await loadScheduledScansPage();
          await refreshScheduledScanResultsOnce();
          setTimeout(() => refreshScheduledScanResultsOnce(), 3000);
        } else showNotification("Failed to update schedule", "error");
      } catch (e) {
        showNotification("Error: " + e.message, "error");
      }
    });
  });
  tbody.querySelectorAll('[data-action="delete-schedule"]').forEach((btn) => {
    btn.addEventListener("click", () => {
      const id = btn.dataset.id;
      showDeleteConfirmModal(
        "Delete schedule",
        "Remove this scheduled scan? Future runs will be cancelled.",
        async () => {
          try {
            const res = await fetch(getApiUrl(`/api/scheduled-scans/${id}`), { method: "DELETE" });
            if (res.ok) {
              showNotification("Schedule deleted successfully.", "success");
              await loadScheduledScansPage();
              await refreshScheduledScanResultsOnce();
            } else showNotification("Failed to delete schedule.", "error");
          } catch (e) {
            showNotification("Error: " + e.message, "error");
          }
        }
      );
    });
  });
}

function formatScheduledLoadError(e) {
  if (!e || typeof e.message !== "string") return "Unknown error";
  const msg = e.message.trim();
  if (msg.includes("404")) return "Endpoint not found (404). Is the backend up to date?";
  if (msg.includes("500")) return "Server error (500). Check backend logs and database.";
  if (msg.includes("Failed to fetch") || msg.includes("NetworkError") || msg.includes("Load failed")) return "Cannot reach server. Is the backend running?";
  return msg.length > 80 ? msg.slice(0, 77) + "…" : msg;
}

async function loadScheduledScansPage() {
  const emptySchedules = document.getElementById("scheduledScansEmpty");
  const emptyResults = document.getElementById("scheduledScanResultsEmpty");
  const tbody = document.getElementById("scheduledScansTableBody");
  const resultsBody = document.getElementById("scheduledScanResultsBody");
  let scheduleList = [];

  try {
    scheduleList = await fetchScheduledScans();
    renderScheduledScansTable(scheduleList);
    if (emptySchedules) emptySchedules.classList.add("hidden");
    // Whenever Scheduled Scans page refreshes, update Dashboard card counts too
    updateDashboardScheduledScansCard(scheduleList);
  } catch (e) {
    console.error("Failed to load scheduled scans", e);
    if (tbody) tbody.innerHTML = "";
    if (emptySchedules) {
      emptySchedules.classList.remove("hidden");
      emptySchedules.textContent = "Failed to load schedules. " + formatScheduledLoadError(e);
    }
    updateDashboardScheduledScansCard([]);
  }

  let resultsList = [];
  try {
    resultsList = await fetchScheduledScanResults();
    renderScheduledScanResultsTable(resultsList);
    if (emptyResults) emptyResults.classList.add("hidden");
  } catch (e) {
    console.error("Failed to load scheduled scan results", e);
    if (resultsBody) resultsBody.innerHTML = "";
    if (emptyResults) {
      emptyResults.classList.remove("hidden");
      emptyResults.textContent = "Failed to load results. " + formatScheduledLoadError(e);
    }
  }

  const hasRunningScan = Array.isArray(resultsList) && resultsList.some(
    (r) => String(r.status || "").toLowerCase() === "running"
  );
  return { hasRunningScan };
}

function initScheduledScansPage() {
  const owaspSel = document.getElementById("scheduleOwasp");
  if (owaspSel) {
    owaspSel.innerHTML = "";
    OWASP_MAP.forEach((cat) => {
      const opt = document.createElement("option");
      opt.value = cat.id;
      opt.textContent = `${cat.id} – ${cat.name}`;
      owaspSel.appendChild(opt);
    });
  }
  const toolGrid = document.getElementById("scheduleToolGrid");
  if (toolGrid) {
    toolGrid.innerHTML = "";
    TOOL_LIST.forEach((tool) => {
      const pill = document.createElement("button");
      pill.type = "button";
      pill.className = "schedule-tool-pill";
      pill.setAttribute("data-tool", tool);
      pill.textContent = tool;
      pill.addEventListener("click", () => pill.classList.toggle("active"));
      toolGrid.appendChild(pill);
    });
  }
  const form = document.getElementById("scheduledScanForm");
  if (form) {
    // Add input listeners to validate and update button state
    const targetInput = document.getElementById("scheduleTarget");
    const owaspSel = document.getElementById("scheduleOwasp");
    const toolGrid = document.getElementById("scheduleToolGrid");
    const submitBtn = document.querySelector(".schedule-submit-btn");
    
    // Function to validate form and update button state
    function validateScheduleForm() {
      const target = (targetInput?.value || "").trim();
      const owasp = owaspSel?.value;
      const tools = getScheduleSelectedTools();
      const frequency = getScheduleRepeatType();
      const scheduleOn = isScheduleToggleOn();
      
      let isValid =
        target &&
        owasp &&
        tools.length > 0 &&
        isValidTarget(target);

      // One-time and monthly need date/time set
      if (isValid && (frequency === "once" || frequency === "monthly")) {
        isValid = scheduleOn && scheduleChosenNextRunAt;
      }
      
      // Update button appearance
      if (submitBtn) {
        if (isValid) {
          submitBtn.style.background = "linear-gradient(135deg, #3b82f6, #2563eb)";
          submitBtn.style.boxShadow = "0 12px 22px rgba(59, 130, 246, 0.7)";
          submitBtn.disabled = false;
        } else {
          submitBtn.style.background = "linear-gradient(135deg, #1d283a, #2a3a52)";
          submitBtn.style.boxShadow = "0 12px 22px rgba(15, 23, 42, 0.7)";
          submitBtn.disabled = true;
        }
      }
      
      return isValid;
    }
    
    // Add event listeners for real-time validation
    targetInput?.addEventListener("input", validateScheduleForm);
    owaspSel?.addEventListener("change", validateScheduleForm);
    toolGrid?.addEventListener("click", (e) => {
      if (e.target.classList.contains("schedule-tool-pill")) {
        setTimeout(validateScheduleForm, 10);
      }
    });
    
    // Listen for repeat pill changes
    document.querySelectorAll(".schedule-repeat-pill").forEach(pill => {
      pill.addEventListener("click", () => {
        setTimeout(validateScheduleForm, 10);
      });
    });
    
    // Listen for schedule toggle changes
    const scheduleToggle = document.getElementById("scheduleToggleBtn");
    scheduleToggle?.addEventListener("click", () => {
      setTimeout(validateScheduleForm, 100);
    });
    
    // Initial validation
    validateScheduleForm();
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const rawTarget = (document.getElementById("scheduleTarget")?.value || "").trim();
      const owasp = document.getElementById("scheduleOwasp")?.value;
      const tools = getScheduleSelectedTools();
      const frequency = getScheduleRepeatType();
      const scheduleOn = isScheduleToggleOn();
      if (!rawTarget || !owasp || tools.length === 0) {
        showNotification("Enter target, select category, and at least one tool.", "error");
        return;
      }
      if (!isValidTarget(rawTarget)) {
        showNotification("Please enter a valid target (domain, IP, or URL).", "error");
        return;
      }
      let target = rawTarget.toLowerCase();
      target = target.replace(/^https?:\/\//, "").replace(/\/$/, "");
      const needsDateTime = frequency === "once" || frequency === "monthly";
      if (needsDateTime && (!scheduleOn || !scheduleChosenNextRunAt)) {
        showNotification("One-time and Monthly need a date & time. Turn on Schedule, set when to run, then click \"Set schedule\".", "error");
        return;
      }
      if (scheduleOn && !scheduleChosenNextRunAt) {
        showNotification("Turn on Schedule, open the picker, set date & time, then click \"Set schedule\".", "error");
        return;
      }
      const body = { target, owasp_category: owasp, selected_tools: tools, frequency: (frequency || "weekly").toLowerCase() };
      if (scheduleOn && scheduleChosenNextRunAt) body.next_run_at = scheduleChosenNextRunAt;
      try {
        const res = await fetch(getApiUrl("/api/scheduled-scans"), {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
          const detail = Array.isArray(data.detail) ? data.detail.map((d) => d.msg || d.loc?.join(".")).join("; ") : (data.detail || res.statusText);
          throw new Error(detail);
        }
        if (frequency === "once") {
          const runAt = scheduleChosenNextRunAt ? new Date(scheduleChosenNextRunAt) : null;
          const when = runAt ? runAt.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" }) : "at the scheduled time";
          showNotification("Schedule added successfully. Scan will run " + when + ".", "success");
        } else {
          showNotification("Schedule added successfully.", "success");
        }
        form.reset();
        document.querySelectorAll("#scheduleToolGrid .schedule-tool-pill").forEach((p) => p.classList.remove("active"));
        scheduleChosenNextRunAt = null;
        document.getElementById("scheduleToggleBtn")?.setAttribute("aria-checked", "false");
        document.getElementById("scheduleNextRunPreview")?.classList.add("hidden");
        await loadScheduledScansPage();
        await refreshScheduledScanResultsOnce();
        setTimeout(() => refreshScheduledScanResultsOnce(), 3000);
      } catch (err) {
        showNotification("Failed to add schedule: " + (err.message || "Unknown error"), "error");
      }
    });
  }

  initScheduleDateTimePicker();

  const section = document.getElementById("scheduled-scans");
  if (section) {
    let scheduledScansRefreshInterval = null;
    const stopPolling = () => {
      if (scheduledScansRefreshInterval) {
        clearInterval(scheduledScansRefreshInterval);
        scheduledScansRefreshInterval = null;
      }
    };
    const tick = () => {
      loadScheduledScansPage().then(({ hasRunningScan }) => {
        if (!document.getElementById("scheduled-scans")?.classList.contains("visible")) {
          stopPolling();
          return;
        }
        if (scheduledScansRefreshInterval) clearInterval(scheduledScansRefreshInterval);
        // Check for newly completed scheduled scans and refresh dashboard charts once (no per-second polling)
        checkScheduledCompletionAndRefreshChartsOnce().catch(() => {});
        // Refresh every 5s while Schedule section is visible
        scheduledScansRefreshInterval = setInterval(tick, 5000);
      }).catch(() => {
        stopPolling();
      });
    };
    const startPolling = () => {
      // Prime set with current completed IDs so we only refresh for scans that complete after opening tab
      fetchScheduledScanResults().then((list) => {
        const arr = Array.isArray(list) ? list : [];
        arr.forEach((scan) => {
          const s = String(scan.status || "").toLowerCase();
          if ((s === "completed" || s === "completed_with_errors") && scan.id != null) {
            scheduledCompletedScanIdsChartsRefreshed.add(scan.id);
          }
        });
      }).catch(() => {});
      tick(); // immediate refresh once when section becomes visible
    };
    const observer = new MutationObserver((mutations) => {
      mutations.forEach((m) => {
        if (m.target.classList) {
          if (m.target.classList.contains("visible")) {
            startPolling();
          } else {
            stopPolling();
          }
        }
      });
    });
    observer.observe(section, { attributes: true, attributeFilter: ["class"] });
    if (section.classList.contains("visible")) {
      startPolling();
    }
  }
  loadScheduledScansPage();
}

const SCHEDULE_PICKER_ITEM_HEIGHT = 36;
const SCHEDULE_PICKER_COPIES = 99; // repeat options for infinite scroll (hour, ampm)
const SCHEDULE_PICKER_COPIES_MINUTE = 21; // smaller list so minute column behaves like hour (no scroll/layout quirks)
const SCHEDULE_DATE_COPIES_ONCE = 3;
const SCHEDULE_DATE_COPIES_WEEKLY = 100;
const SCHEDULE_DATE_COPIES_MONTHLY = 50;

function initScheduleDateTimePicker() {
  const repeatPills = document.querySelectorAll(".schedule-repeat-pill");
  const toggleBtn = document.getElementById("scheduleToggleBtn");
  const modal = document.getElementById("scheduleDateTimeModal");
  const backdrop = modal?.querySelector(".schedule-datetime-backdrop");
  const closeBtn = modal?.querySelector(".schedule-datetime-close");
  const cancelBtn = modal?.querySelector(".schedule-datetime-cancel");
  const confirmBtn = document.getElementById("scheduleDateTimeConfirm");
  const dateScroll = document.getElementById("scheduleDateScroll");
  const dateList = document.getElementById("scheduleDateList");
  const timeScroll = document.getElementById("scheduleTimeScroll");
  const timeList = document.getElementById("scheduleTimeList");
  const minuteScroll = document.getElementById("scheduleMinuteScroll");
  const minuteList = document.getElementById("scheduleMinuteList");
  const ampmScroll = document.getElementById("scheduleAmpmScroll");
  const ampmList = document.getElementById("scheduleAmpmList");
  const previewEl = document.getElementById("scheduleDateTimePreview");
  const nextRunPreview = document.getElementById("scheduleNextRunPreview");
  const nextRunText = document.getElementById("scheduleNextRunText");
  const dateColumn = document.getElementById("scheduleDateColumn");

  repeatPills?.forEach((pill) => {
    pill.addEventListener("click", () => {
      repeatPills.forEach((p) => p.classList.remove("active"));
      pill.classList.add("active");
      if (modal && !modal.classList.contains("hidden")) {
        schedulePickerBuildLists();
      }
    });
  });

  const pickerWrap = modal?.querySelector(".schedule-datetime-picker-wrap");

  function openScheduleModal() {
    if (!modal) return;
    document.body.classList.add("schedule-modal-open");
    modal.classList.remove("hidden");
    pickerWrap?.classList.add("schedule-picker-loading");
    requestAnimationFrame(() => schedulePickerBuildLists());
  }

  function closeScheduleModal(cancelled) {
    modal?.classList.add("hidden");
    document.body.classList.remove("schedule-modal-open");
    if (cancelled) {
      toggleBtn?.setAttribute("aria-checked", "false");
      scheduleChosenNextRunAt = null;
      nextRunPreview?.classList.add("hidden");
    }
  }

  toggleBtn?.addEventListener("click", () => {
    const on = toggleBtn.getAttribute("aria-checked") === "true";
    if (!on) {
      toggleBtn.setAttribute("aria-checked", "true");
      openScheduleModal();
    } else {
      toggleBtn.setAttribute("aria-checked", "false");
      scheduleChosenNextRunAt = null;
      nextRunPreview?.classList.add("hidden");
      closeScheduleModal(false);
    }
  });

  backdrop?.addEventListener("click", () => closeScheduleModal(true));
  closeBtn?.addEventListener("click", () => closeScheduleModal(true));
  cancelBtn?.addEventListener("click", () => closeScheduleModal(true));

  const dayNames = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
  const monthNames = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

  function schedulePickerBuildLists() {
    const repeat = getScheduleRepeatType();
    const now = new Date();

    function appendDateOnce() {
      dateList.dataset.optionCount = "365";
      dateList.dataset.repeat = "once";
      const base = new Date(now.getFullYear(), now.getMonth(), now.getDate());
      const frag = document.createDocumentFragment();
      for (let copy = 0; copy < SCHEDULE_DATE_COPIES_ONCE; copy++) {
        for (let i = 0; i < 365; i++) {
          const d = new Date(base);
          d.setDate(d.getDate() + i);
          const label = `${dayNames[d.getDay()]} ${monthNames[d.getMonth()]} ${d.getDate()}`;
          const item = document.createElement("div");
          item.className = "schedule-picker-item";
          item.textContent = label;
          item.dataset.date = d.toISOString();
          item.dataset.offset = i.toString();
          frag.appendChild(item);
        }
      }
      dateList.appendChild(frag);
    }
    function appendDateWeekly() {
      dateList.dataset.optionCount = "7";
      dateList.dataset.repeat = "weekly";
      const frag = document.createDocumentFragment();
      for (let copy = 0; copy < SCHEDULE_DATE_COPIES_WEEKLY; copy++) {
        dayNames.forEach((name, i) => {
          const item = document.createElement("div");
          item.className = "schedule-picker-item";
          item.textContent = name;
          item.dataset.dow = i.toString();
          frag.appendChild(item);
        });
      }
      dateList.appendChild(frag);
    }
    function appendDateMonthly() {
      dateList.dataset.optionCount = "31";
      dateList.dataset.repeat = "monthly";
      const frag = document.createDocumentFragment();
      for (let copy = 0; copy < SCHEDULE_DATE_COPIES_MONTHLY; copy++) {
        for (let i = 1; i <= 31; i++) {
          const item = document.createElement("div");
          item.className = "schedule-picker-item";
          item.textContent = i.toString();
          item.dataset.day = i.toString();
          frag.appendChild(item);
        }
      }
      dateList.appendChild(frag);
    }

    if (repeat === "once") {
      dateColumn?.classList.remove("hidden");
      dateList.innerHTML = "";
      appendDateOnce();
    } else if (repeat === "daily") {
      dateColumn?.classList.add("hidden");
      dateList.innerHTML = "";
      dateList.dataset.optionCount = "1";
      dateList.dataset.repeat = "daily";
      const item = document.createElement("div");
      item.className = "schedule-picker-item selected";
      item.textContent = "Every day";
      item.dataset.date = now.toISOString();
      dateList.appendChild(item);
    } else if (repeat === "weekly") {
      dateColumn?.classList.remove("hidden");
      dateList.innerHTML = "";
      appendDateWeekly();
    } else {
      dateColumn?.classList.remove("hidden");
      dateList.innerHTML = "";
      appendDateMonthly();
    }

    timeList.innerHTML = "";
    timeList.dataset.optionCount = "12";
    const timeFrag = document.createDocumentFragment();
    for (let copy = 0; copy < SCHEDULE_PICKER_COPIES; copy++) {
      for (let h = 1; h <= 12; h++) {
        const item = document.createElement("div");
        item.className = "schedule-picker-item";
        item.textContent = h.toString();
        item.dataset.hour = h.toString();
        timeFrag.appendChild(item);
      }
    }
    timeList.appendChild(timeFrag);

    minuteList.innerHTML = "";
    minuteList.dataset.optionCount = "60";
    const minFrag = document.createDocumentFragment();
    for (let copy = 0; copy < SCHEDULE_PICKER_COPIES_MINUTE; copy++) {
      for (let m = 0; m < 60; m++) {
        const item = document.createElement("div");
        item.className = "schedule-picker-item";
        item.textContent = m.toString().padStart(2, "0");
        item.dataset.minute = m.toString();
        minFrag.appendChild(item);
      }
    }
    minuteList.appendChild(minFrag);

    ampmList.innerHTML = "";
    ampmList.dataset.optionCount = "2";
    ["AM", "PM"].forEach((ap, i) => {
      const item = document.createElement("div");
      item.className = "schedule-picker-item";
      item.textContent = ap;
      item.dataset.ampm = ap;
      item.dataset.ampmIndex = i.toString();
      ampmList.appendChild(item);
    });

    const n = new Date();
    const dateStartIndex = repeat === "once" ? 0
      : repeat === "weekly" ? Math.floor(SCHEDULE_DATE_COPIES_WEEKLY / 2) * 7 + n.getDay()
      : repeat === "monthly" ? Math.floor(SCHEDULE_DATE_COPIES_MONTHLY / 2) * 31 + (n.getDate() - 1)
      : 0;
    const h12 = n.getHours() % 12 || 12;
    const timeStartIndex = Math.floor(SCHEDULE_PICKER_COPIES / 2) * 12 + (h12 - 1);
    const minStartIndex = Math.floor(SCHEDULE_PICKER_COPIES_MINUTE / 2) * 60 + n.getMinutes();
    const ampmStartIndex = n.getHours() >= 12 ? 1 : 0;

    requestAnimationFrame(() => {
      schedulePickerSnapAll();
      if (dateScroll) {
        dateScroll.style.scrollBehavior = "auto";
        if (repeat === "once" || repeat === "weekly" || repeat === "monthly") {
          schedulePickerSetScrollTop(dateScroll, dateStartIndex);
        }
        dateScroll.style.scrollBehavior = "";
      }
      if (timeScroll) {
        timeScroll.style.scrollBehavior = "auto";
        schedulePickerSetScrollTop(timeScroll, timeStartIndex);
        timeScroll.style.scrollBehavior = "";
      }
      if (minuteScroll) {
        minuteScroll.style.scrollBehavior = "auto";
        schedulePickerSetScrollTop(minuteScroll, minStartIndex);
        minuteScroll.style.scrollBehavior = "";
      }
      schedulePickerSetScrollTop(ampmScroll, ampmStartIndex);
      schedulePickerUpdateSelected();
      schedulePickerUpdatePreview();
      pickerWrap?.classList.remove("schedule-picker-loading");
    });
  }

  function schedulePickerSnapAll() {
    const h = SCHEDULE_PICKER_ITEM_HEIGHT;
    const scrollHeight = 200;
    const centerPad = Math.max(0, scrollHeight / 2 - h / 2);
    [dateScroll, timeScroll, minuteScroll, ampmScroll].forEach((el) => {
      if (!el) return;
      const list = el.querySelector(".schedule-picker-list");
      if (!list) return;
      const items = list.querySelectorAll(".schedule-picker-item");
      if (items.length === 0) return;
      list.style.paddingTop = centerPad + "px";
      list.style.paddingBottom = centerPad + "px";
    });
  }

  function schedulePickerGetSelectedIndex(scrollEl) {
    if (!scrollEl) return 0;
    const list = scrollEl.querySelector(".schedule-picker-list");
    const items = list?.querySelectorAll(".schedule-picker-item");
    if (!items || items.length === 0) return 0;
    const h = SCHEDULE_PICKER_ITEM_HEIGHT;
    const scrollTop = scrollEl.scrollTop;
    const index = Math.round(scrollTop / h);
    return Math.max(0, Math.min(index, items.length - 1));
  }

  function schedulePickerUpdateSelected() {
    [dateScroll, timeScroll, minuteScroll, ampmScroll].forEach((scrollEl) => {
      if (!scrollEl) return;
      const list = scrollEl.querySelector(".schedule-picker-list");
      const items = list?.querySelectorAll(".schedule-picker-item");
      if (!items) return;
      const idx = schedulePickerGetSelectedIndex(scrollEl);
      items.forEach((it, i) => it.classList.toggle("selected", i === idx));
    });
  }

  function schedulePickerUpdatePreview() {
    const dateIdx = schedulePickerGetSelectedIndex(dateScroll);
    const timeIdx = schedulePickerGetSelectedIndex(timeScroll);
    const minuteIdx = schedulePickerGetSelectedIndex(minuteScroll);
    const ampmIdx = schedulePickerGetSelectedIndex(ampmScroll);
    const dateItems = dateList?.querySelectorAll(".schedule-picker-item");
    const timeItems = timeList?.querySelectorAll(".schedule-picker-item");
    const minuteItems = minuteList?.querySelectorAll(".schedule-picker-item");
    const ampmItems = ampmList?.querySelectorAll(".schedule-picker-item");
    const hour = timeItems?.[timeIdx]?.dataset?.hour || "12";
    const minute = minuteItems?.[minuteIdx]?.dataset?.minute ?? "0";
    const ampm = ampmItems?.[ampmIdx]?.textContent || "AM";
    const dateLabel = dateItems?.[dateIdx]?.textContent || "";
    const hour12 = parseInt(hour, 10);
    const minStr = minute.padStart(2, "0");
    if (previewEl) previewEl.textContent = `${dateLabel} ${hour12}:${minStr} ${ampm}`;
  }

  function schedulePickerSetScrollTop(scrollEl, index) {
    if (!scrollEl) return;
    const list = scrollEl.querySelector(".schedule-picker-list");
    const items = list?.querySelectorAll(".schedule-picker-item");
    if (!items || items.length === 0) return;
    const h = SCHEDULE_PICKER_ITEM_HEIGHT;
    scrollEl.scrollTop = index * h;
  }

  function schedulePickerScrollToIndex(scrollEl, index, instant) {
    if (!scrollEl) return;
    const list = scrollEl.querySelector(".schedule-picker-list");
    const items = list?.querySelectorAll(".schedule-picker-item");
    if (!items || items.length === 0) return;
    const h = SCHEDULE_PICKER_ITEM_HEIGHT;
    const target = index * h;
    scrollEl.scrollTo({ top: target, behavior: instant ? "auto" : "smooth" });
  }

  function schedulePickerOnScrollEnd(scrollEl) {
    schedulePickerUpdateSelected();
    schedulePickerUpdatePreview();
    const idx = schedulePickerGetSelectedIndex(scrollEl);
    schedulePickerScrollToIndex(scrollEl, idx, true);
  }

  [dateScroll, timeScroll, minuteScroll, ampmScroll].forEach((scrollEl) => {
    if (!scrollEl) return;
    let scrollEndTimer;
    const onScroll = () => {
      schedulePickerUpdateSelected();
      schedulePickerUpdatePreview();
      clearTimeout(scrollEndTimer);
      scrollEndTimer = setTimeout(() => schedulePickerOnScrollEnd(scrollEl), 120);
    };
    scrollEl.addEventListener("scroll", onScroll, { passive: true });
    scrollEl.addEventListener("scrollend", () => {
      clearTimeout(scrollEndTimer);
      schedulePickerOnScrollEnd(scrollEl);
    });
  });

  confirmBtn?.addEventListener("click", () => {
    const repeat = getScheduleRepeatType();
    const dateIdx = schedulePickerGetSelectedIndex(dateScroll);
    const timeIdx = schedulePickerGetSelectedIndex(timeScroll);
    const minuteIdx = schedulePickerGetSelectedIndex(minuteScroll);
    const ampmIdx = schedulePickerGetSelectedIndex(ampmScroll);
    const dateItems = dateList?.querySelectorAll(".schedule-picker-item");
    const timeItems = timeList?.querySelectorAll(".schedule-picker-item");
    const minuteItems = minuteList?.querySelectorAll(".schedule-picker-item");
    const ampmItems = ampmList?.querySelectorAll(".schedule-picker-item");
    const hour12 = parseInt(timeItems?.[timeIdx]?.dataset?.hour || "12", 10);
    const minute = parseInt(minuteItems?.[minuteIdx]?.dataset?.minute ?? "0", 10);
    const ampm = ampmItems?.[ampmIdx]?.textContent || "AM";
    let hour24 = hour12;
    if (ampm === "PM" && hour12 !== 12) hour24 += 12;
    if (ampm === "AM" && hour12 === 12) hour24 = 0;

    const now = new Date();
    let runAt;

    if (repeat === "once") {
      const dateStr = dateItems?.[dateIdx]?.dataset?.date;
      if (!dateStr) return;
      runAt = new Date(dateStr);
      runAt.setHours(hour24, minute, 0, 0);
    } else if (repeat === "daily") {
      runAt = new Date(now);
      runAt.setHours(hour24, minute, 0, 0);
      if (runAt <= now) runAt.setDate(runAt.getDate() + 1);
    } else if (repeat === "weekly") {
      const dow = parseInt(dateItems?.[dateIdx]?.dataset?.dow ?? "0", 10);
      runAt = new Date(now);
      runAt.setHours(hour24, minute, 0, 0);
      let diff = dow - runAt.getDay();
      if (diff < 0) diff += 7;
      if (diff === 0 && runAt <= now) diff = 7;
      runAt.setDate(runAt.getDate() + diff);
    } else {
      const day = parseInt(dateItems?.[dateIdx]?.dataset?.day ?? "1", 10);
      runAt = new Date(now.getFullYear(), now.getMonth(), day, hour24, minute, 0, 0);
      if (runAt <= now) runAt.setMonth(runAt.getMonth() + 1);
    }

    scheduleChosenNextRunAt = runAt.toISOString();
    if (nextRunText) nextRunText.textContent = formatDateLocal(runAt);
    nextRunPreview?.classList.remove("hidden");
    closeScheduleModal(false);
  });

  window.addEventListener("resize", schedulePickerSnapAll);
}

async function initApp() {
  await initializeApiConfig();
  initNavigation();
  initQuickSearch();
  initThemeModal();
  renderToolCheckboxes();
  initCharts();
  initToolLibrary();
  initLaunchForm();
  initSettings();
  initSavedReportsFilters();
  initScheduledScansPage();

  // Severity scope selector wiring
  // Severity scan selection has been removed - always showing cumulative view for all scans
  // Update the subtitle to indicate this
  const subtitle = document.getElementById("severitySubtitle");
  if (subtitle) {
    subtitle.textContent = "Showing cumulative severity distribution for all scans";
  }
  
  // Always update to show global view
  const initialSeverityPromise = updateSeverityScope("all").catch((e) =>
    console.warn("Failed to update severity scope", e),
  );

  // Security Trend Apply: use delegation and resolve inputs from button's card (works even if DOM order differs)
  document.body.addEventListener("click", function onTrendApplyClick(e) {
    const btn = e.target && e.target.closest ? e.target.closest("#trendApplyBtn") : null;
    if (!btn) return;
    e.preventDefault();
    e.stopPropagation();
    const card = btn.closest(".dashboard-chart-card") || btn.closest(".card");
    const startEl = card ? card.querySelector("#trendStartDate") : document.getElementById("trendStartDate");
    const endEl = card ? card.querySelector("#trendEndDate") : document.getElementById("trendEndDate");
    const today = new Date();
    const defaultEnd = today.toISOString().split("T")[0];
    const defaultStart = new Date(today);
    defaultStart.setDate(defaultStart.getDate() - 6);
    const defaultStartStr = defaultStart.toISOString().split("T")[0];
    let startVal = (startEl && startEl.value ? startEl.value.trim() : null) || defaultStartStr;
    let endVal = (endEl && endEl.value ? endEl.value.trim() : null) || defaultEnd;
    if (startVal > endVal) {
      [startVal, endVal] = [endVal, startVal];
      if (startEl) startEl.value = startVal;
      if (endEl) endEl.value = endVal;
    }
    const originalText = btn.textContent;
    btn.disabled = true;
    btn.textContent = "Applying…";
    updateTrendFromApi(startVal, endVal)
      .then(() => { btn.disabled = false; btn.textContent = originalText; })
      .catch((err) => {
        console.error("Failed to load trend stats", err);
        btn.disabled = false;
        btn.textContent = "Error – try again";
        setTimeout(() => { btn.textContent = originalText; }, 3000);
      });
  });

  await loadSettings();
  const initialScansPromise = refreshScansViews();

  // Ensure trend chart has at least one loaded dataset before revealing UI
  const trendStartDate = document.getElementById("trendStartDate");
  const trendEndDate = document.getElementById("trendEndDate");
  const initialTrendPromise = (trendStartDate && trendEndDate && trendStartDate.value && trendEndDate.value)
    ? updateTrendFromApi(trendStartDate.value, trendEndDate.value).catch((e) => console.warn("Failed to load trend stats", e))
    : Promise.resolve();

  await Promise.allSettled([initialScansPromise, initialSeverityPromise, initialTrendPromise]);

  // Scheduled scan results and completion checks run only when Schedule section is visible (see initScheduledScansSection)

  // Remove initial loading state to avoid a brief "empty UI" flash on refresh
  document.body.classList.remove("app-loading");
}

// Add missing WebSocket handler functions
function handleScanStatusUpdate(message) {
  const { scan_id, status, message: msg_text, log_message, timestamp } = message;
  
  // Add the log message to live status tracking
  if (log_message) {
    if (!commandTracking["scan_status"]) {
      commandTracking["scan_status"] = {
        command: "",
        status: "running",
        output: [],
        lastUpdate: timestamp
      };
    }
    commandTracking["scan_status"].output.push({
      text: log_message,
      is_error: false,
      timestamp: timestamp
    });
  }
  
  // Update UI
  renderLiveStatus();
}

function handleToolStartUpdate(message) {
  const { scan_id, tool_name, command, log_message, timestamp } = message;
  
  // Initialize tracking for this tool if needed
  if (!commandTracking[tool_name]) {
    commandTracking[tool_name] = {
      command: command,
      status: "running",
      output: [],
      lastUpdate: timestamp
    };
  } else {
    commandTracking[tool_name].command = command;
    commandTracking[tool_name].status = "running";
    commandTracking[tool_name].lastUpdate = timestamp;
  }
  
  // Add the log message to the output
  if (log_message) {
    commandTracking[tool_name].output.push({
      text: log_message,
      is_error: false,
      timestamp: timestamp
    });
  }
  
  // Update UI
  renderLiveStatus();
}

function handleToolOutputUpdate(message) {
  const { scan_id, tool_name, output, is_error, log_message, timestamp } = message;
  
  // Initialize tracking for this tool if needed
  if (!commandTracking[tool_name]) {
    commandTracking[tool_name] = {
      command: "",
      status: "running",
      output: [],
      lastUpdate: timestamp
    };
  }
  
  // Add output line
  if (log_message) {
    commandTracking[tool_name].output.push({
      text: log_message,
      is_error: is_error,
      timestamp: timestamp
    });
  } else {
    commandTracking[tool_name].output.push({
      text: output,
      is_error: is_error,
      timestamp: timestamp
    });
  }
  
  // Keep only last 100 lines to prevent memory issues
  if (commandTracking[tool_name].output.length > 100) {
    commandTracking[tool_name].output = commandTracking[tool_name].output.slice(-100);
  }
  
  // Update UI
  renderLiveStatus();
}

function handleToolCompleteUpdate(message) {
  const { scan_id, tool_name, success, summary, log_message, timestamp } = message;
  
  // Update tool status
  toolStatus[tool_name] = {
    status: success ? "completed" : "failed",
    details: { summary: summary },
    timestamp: timestamp
  };
  
  // Update command tracking
  if (commandTracking[tool_name]) {
    commandTracking[tool_name].status = success ? "completed" : "failed";
    commandTracking[tool_name].lastUpdate = timestamp;
    
    // Add completion log message
    if (log_message) {
      commandTracking[tool_name].output.push({
        text: log_message,
        is_error: false,
        timestamp: timestamp
      });
    }
  }
  
  // Update UI
  renderLiveStatus();
}

function handlePhaseUpdate(message) {
  const { scan_id, phase, message: phase_message, log_message, timestamp } = message;
  
  // Add phase log message to tracking
  if (log_message) {
    if (!commandTracking[`phase_${phase}`]) {
      commandTracking[`phase_${phase}`] = {
        command: "",
        status: "running",
        output: [],
        lastUpdate: timestamp
      };
    }
    commandTracking[`phase_${phase}`].output.push({
      text: log_message,
      is_error: false,
      timestamp: timestamp
    });
  }
  
  // Update UI
  renderLiveStatus();
}

document.addEventListener("DOMContentLoaded", initApp);
