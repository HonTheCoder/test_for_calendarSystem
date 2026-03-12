// LGU Legislative Management System — Enhanced

const STORAGE_KEYS = {
  USERS: "sbp_users",
  MEETINGS: "sbp_meetings",
  CURRENT_USER: "sbp_current_user",
  NOTIFICATIONS: "sbp_notifications",
  SESSION_EXPIRY: "sbp_session_expiry",
};

const ROLES = {
  ADMIN: "Admin",
  VICE_MAYOR: "Vice Mayor",
  COUNCILOR: "Councilor",
  RESEARCHER: "Researcher",
  SECRETARY: "Secretary",
};

const ROLE_LIMITS = {
  [ROLES.COUNCILOR]: 10,
  [ROLES.RESEARCHER]: 10,
  [ROLES.VICE_MAYOR]: 1,
  [ROLES.SECRETARY]: 1,
};

// Roles that are special accounts (not full admins) routed to user.html
const SPECIAL_ROLES = [ROLES.VICE_MAYOR, ROLES.SECRETARY];

const WORK_START_HOUR = 8;
const WORK_END_HOUR = 17;
let SLOT_DURATION_HOURS = 3;

// ---------------------------------------------------------------------------
// XSS Prevention — always use h() when rendering user-supplied data into HTML
// ---------------------------------------------------------------------------
function h(str) {
  if (str == null) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#x27;");
}

// Session timeout: 30 minutes of inactivity
const SESSION_TIMEOUT_MS = 30 * 60 * 1000;

// Table pagination
const MEETINGS_PAGE_SIZE = 10;
let adminMeetingsPage = 1;
let myMeetingsPage = 1;
let usersPage = 1;

// ---------------------------------------------------------------------------
// Philippine Holiday System — fetched live from Nager.Date API
// Falls back to known holidays if offline
// ---------------------------------------------------------------------------

const PH_HOLIDAY_FALLBACK = {
  "2025": [
    "2025-01-01","2025-01-29","2025-04-09","2025-04-17","2025-04-18",
    "2025-05-01","2025-06-12","2025-08-21","2025-08-25","2025-11-01",
    "2025-11-30","2025-12-08","2025-12-24","2025-12-25","2025-12-30","2025-12-31",
  ],
  "2026": [
    "2026-01-01","2026-02-05","2026-04-02","2026-04-03","2026-05-01",
    "2026-06-12","2026-08-21","2026-08-31","2026-11-01","2026-11-30",
    "2026-12-08","2026-12-24","2026-12-25","2026-12-30","2026-12-31",
  ],
};

// Cache: { "YYYY": [{ date, localName, name, type }] }
const _phHolidayCache = {};
// Separate map: { "YYYY-MM-DD": { localName, name, type } } for fast lookup
const _phHolidayMap = {};

async function loadPHHolidays(year) {
  const y = String(year);
  if (_phHolidayCache[y]) return; // already loaded
  try {
    const res = await fetch(`https://date.nager.at/api/v3/PublicHolidays/${y}/PH`);
    if (!res.ok) throw new Error("API error");
    const data = await res.json();
    _phHolidayCache[y] = data;
    data.forEach(h => {
      _phHolidayMap[h.date] = { localName: h.localName, name: h.name, type: h.types?.[0] || "Public" };
    });
  } catch {
    // Fallback to known list
    const fallback = PH_HOLIDAY_FALLBACK[y] || [];
    _phHolidayCache[y] = fallback.map(d => ({ date: d, localName: "Public Holiday", name: "Public Holiday", types: ["Public"] }));
    fallback.forEach(d => {
      if (!_phHolidayMap[d]) _phHolidayMap[d] = { localName: "Public Holiday", name: "Public Holiday", type: "Public" };
    });
  }
}

function isHolidayISO(isoDate) {
  return !!_phHolidayMap[isoDate];
}

function getHolidayInfo(isoDate) {
  return _phHolidayMap[isoDate] || null;
}

// ---------------------------------------------------------------------------
// SHA-256 Password Hashing (native WebCrypto)
// ---------------------------------------------------------------------------

async function hashPassword(password) {
  const msgBuffer = new TextEncoder().encode(password);
  const hashBuffer = await crypto.subtle.digest("SHA-256", msgBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
}

async function verifyPassword(password, hash) {
  const hashed = await hashPassword(password);
  return hashed === hash;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => Array.from(document.querySelectorAll(selector));

function load(key, fallback) {
  try {
    const raw = localStorage.getItem(key);
    return raw ? JSON.parse(raw) : fallback;
  } catch { return fallback; }
}

function save(key, value) {
  localStorage.setItem(key, JSON.stringify(value));
}

function showToast(message, type = "info") {
  let toast = $(".toast");
  if (!toast) {
    toast = document.createElement("div");
    toast.className = "toast";
    document.body.appendChild(toast);
  }
  toast.textContent = message;
  toast.classList.remove("toast-error", "toast-success", "toast-warning");
  if (type === "error") toast.classList.add("toast-error");
  else if (type === "success") toast.classList.add("toast-success");
  else if (type === "warning") toast.classList.add("toast-warning");
  toast.classList.add("toast-visible");
  setTimeout(() => toast.classList.remove("toast-visible"), 3500);
}

function showStorageFallbackWarning() {
  const banner = document.createElement("div");
  banner.style.cssText = `
    position:fixed;bottom:0;left:0;right:0;z-index:9999;
    background:#92400e;color:#fff;padding:10px 20px;
    font-size:0.82rem;display:flex;align-items:center;gap:12px;
    box-shadow:0 -2px 10px rgba(0,0,0,0.2);
  `;
  banner.innerHTML = `
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
    <span><strong>Offline mode:</strong> Firebase is unavailable. Your data is being saved locally on this device only and will not sync across devices.</span>
    <button onclick="this.parentElement.remove()" style="margin-left:auto;background:none;border:1px solid rgba(255,255,255,0.4);color:#fff;padding:3px 10px;border-radius:4px;cursor:pointer;">Dismiss</button>
  `;
  document.body.appendChild(banner);
}

// ---------------------------------------------------------------------------
// Session Timeout
// Bug fix: use sessionStorage for the expiry so it resets when the browser/tab
// is closed — prevents a stale localStorage timestamp from keeping a session
// alive across browser restarts. Current-user identity remains in localStorage
// (intentional: survives page reload within same inactivity window).
// ---------------------------------------------------------------------------

function refreshSession() {
  try { sessionStorage.setItem(STORAGE_KEYS.SESSION_EXPIRY, String(Date.now() + SESSION_TIMEOUT_MS)); } catch(e) {}
}

function checkSessionExpiry() {
  try {
    const expiry = parseInt(sessionStorage.getItem(STORAGE_KEYS.SESSION_EXPIRY) || "0", 10);
    if (expiry && Date.now() > expiry) {
      setCurrentUser(null);
      sessionStorage.removeItem(STORAGE_KEYS.SESSION_EXPIRY);
      localStorage.removeItem(STORAGE_KEYS.SESSION_EXPIRY); // clean up any legacy localStorage value
      window.location.href = "./index.html?timeout=1";
      return false;
    }
  } catch(e) {}
  return true;
}

function initSessionTimeout() {
  refreshSession();
  ["click", "keypress", "mousemove", "touchstart"].forEach(evt => {
    document.addEventListener(evt, refreshSession, { passive: true });
  });
  setInterval(() => {
    if (!checkSessionExpiry()) return;
  }, 60 * 1000);
}

// ---------------------------------------------------------------------------
// Notifications
// ---------------------------------------------------------------------------

function getNotifications(userId) {
  const all = load(STORAGE_KEYS.NOTIFICATIONS, []);
  return all.filter(n => n.userId === userId);
}

function addNotification(userId, message, type = "info", section = null) {
  if (!userId) return;
  const all = load(STORAGE_KEYS.NOTIFICATIONS, []);
  all.unshift({
    id: `notif_${Math.random().toString(36).slice(2, 9)}`,
    userId,
    message,
    type,
    section,   // which page section to navigate to on click
    read: false,
    createdAt: new Date().toISOString(),
  });
  // Keep last 50 per user
  const mine = all.filter(n => n.userId === userId).slice(0, 50);
  const others = all.filter(n => n.userId !== userId);
  save(STORAGE_KEYS.NOTIFICATIONS, [...others, ...mine]);
}

function markAllNotificationsRead(userId) {
  const all = load(STORAGE_KEYS.NOTIFICATIONS, []);
  all.forEach(n => { if (n.userId === userId) n.read = true; });
  save(STORAGE_KEYS.NOTIFICATIONS, all);
  updateNotificationBadge(userId);
}

function updateNotificationBadge(userId) {
  const badge = document.getElementById("notif-badge");
  if (!badge) return;
  const unread = getNotifications(userId).filter(n => !n.read).length;
  badge.textContent = unread > 9 ? "9+" : String(unread);
  badge.style.display = unread > 0 ? "flex" : "none";

  // Also update pending badge on meeting-logs nav link (admin only)
  const pendingBadge = document.getElementById("pending-badge");
  if (pendingBadge) {
    const safeMeetings = (typeof meetings !== "undefined" && Array.isArray(meetings)) ? meetings : [];
    const pendingCount = safeMeetings.filter(m => m.status === "Pending" || m.status === "Cancellation Requested").length;
    pendingBadge.textContent = String(pendingCount);
    pendingBadge.style.display = pendingCount > 0 ? "flex" : "none";
  }
}

function renderNotificationPanel(userId) {
  const list = document.getElementById("notif-list");
  if (!list) return;

  const notifs = getNotifications(userId);
  const isDark = document.documentElement.getAttribute("data-theme") === "dark";

  const readBg   = isDark ? "#1e293b" : "#ffffff";
  const unreadBg = isDark ? "#1e3a5f" : "#eff6ff";
  const textCol  = isDark ? "#f1f5f9" : "#111827";
  const timeCol  = isDark ? "#94a3b8" : "#9ca3af";
  const divCol   = isDark ? "#334155" : "#f3f4f6";

  const TYPE_ICONS = {
    success: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#16a34a" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>`,
    error:   `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#dc2626" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>`,
    warning: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#f59e0b" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`,
    info:    `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#3b82f6" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>`,
  };

  if (!notifs.length) {
    list.innerHTML = `
      <div style="display:flex;flex-direction:column;align-items:center;justify-content:center;padding:32px 20px;gap:10px;">
        <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="${isDark ? "#475569" : "#d1d5db"}" stroke-width="1.5">
          <path d="M18 8A6 6 0 006 8c0 7-3 9-3 9h18s-3-2-3-9"/>
          <path d="M13.73 21a2 2 0 01-3.46 0"/>
        </svg>
        <div style="font-size:0.82rem;font-weight:600;color:${isDark ? "#94a3b8" : "#6b7280"}">No notifications yet</div>
        <div style="font-size:0.75rem;color:${isDark ? "#64748b" : "#9ca3af"};text-align:center">You'll see updates about your meeting requests here.</div>
      </div>`;
    return;
  }

  const unreadCount = notifs.filter(n => !n.read).length;
  const header = unreadCount > 0
    ? `<div style="padding:8px 14px 6px;font-size:0.72rem;color:${isDark ? "#94a3b8" : "#6b7280"};border-bottom:1px solid ${divCol}">${unreadCount} unread</div>`
    : "";

  list.innerHTML = header + notifs.map(n => {
    const when = (() => {
      const d = new Date(n.createdAt);
      const diffMs = Date.now() - d.getTime();
      const diffMin = Math.floor(diffMs / 60000);
      if (diffMin < 1) return "Just now";
      if (diffMin < 60) return `${diffMin}m ago`;
      const diffH = Math.floor(diffMin / 60);
      if (diffH < 24) return `${diffH}h ago`;
      return d.toLocaleDateString("en-PH", { month: "short", day: "numeric" });
    })();
    const clickable = !!n.section;
    const cursorStyle = clickable ? "cursor:pointer;" : "";
    const hoverAttr = clickable ? `data-section="${n.section}" data-notif-nav="1"` : "";
    return `
      <div ${hoverAttr} style="padding:11px 14px;border-bottom:1px solid ${divCol};display:flex;gap:10px;align-items:flex-start;background:${n.read ? readBg : unreadBg};transition:background 0.15s;${cursorStyle}${clickable ? "user-select:none;" : ""}">
        <span style="margin-top:3px;flex-shrink:0">${TYPE_ICONS[n.type] || TYPE_ICONS.info}</span>
        <div style="flex:1;min-width:0">
          <div style="font-size:0.8rem;color:${textCol};line-height:1.5">${n.message}</div>
          <div style="font-size:0.7rem;color:${timeCol};margin-top:3px;display:flex;align-items:center;gap:6px">
            <span>${when}</span>
            ${clickable ? `<span style="color:${isDark ? "#60a5fa" : "#3b82f6"};font-weight:500">View &rsaquo;</span>` : ""}
          </div>
        </div>
        ${!n.read ? `<span style="flex-shrink:0;width:7px;height:7px;border-radius:50%;background:#3b82f6;margin-top:5px"></span>` : ""}
      </div>`;
  }).join("");
}

function initNotificationBell(user) {
  const userId = user.id || user.username;
  const bellBtn = document.getElementById("notif-bell");
  const notifPanel = document.getElementById("notif-panel");
  if (!bellBtn || !notifPanel) return;

  bellBtn.addEventListener("click", (e) => {
    e.stopPropagation();
    const isOpen = notifPanel.classList.toggle("notif-panel-open");
    if (isOpen) {
      renderNotificationPanel(userId);
      setTimeout(() => {
        markAllNotificationsRead(userId);
        updateNotificationBadge(userId);
      }, 800);
    }
  });

  // Handle clicking a notification item that has a section target
  notifPanel.addEventListener("click", (e) => {
    e.stopPropagation();
    const item = e.target.closest("[data-notif-nav='1']");
    if (!item) return;
    const section = item.dataset.section;
    if (!section) return;

    // Close the panel
    notifPanel.classList.remove("notif-panel-open");

    // Use the page's switchSection function (defined in the inline script of each HTML page)
    if (typeof switchSection === "function") {
      switchSection(section);
    } else {
      // Fallback: fire a click on the matching nav link
      const navLink = document.querySelector(`.nav-link[data-section="${section}"]`) ||
                      document.querySelector(`.bottom-nav-item[data-section="${section}"]`);
      if (navLink) navLink.click();
    }
  });

  // Close when clicking outside
  document.addEventListener("click", (e) => {
    if (!notifPanel.contains(e.target) && e.target !== bellBtn) {
      notifPanel.classList.remove("notif-panel-open");
    }
  });

  updateNotificationBadge(userId);
}

// ---------------------------------------------------------------------------
// Default admin (hashed password on first run)
// ---------------------------------------------------------------------------

async function ensureDefaultAdmin() {
  if (window.api && window.api.mode === "firestore") return;
  let users = load(STORAGE_KEYS.USERS, []);
  if (!users.some(u => u.username === "sb_adminpolangui")) {
    const hashed = await hashPassword("admin12345");
    users.push({
      id: "admin",
      username: "sb_adminpolangui",
      password: hashed,
      role: ROLES.ADMIN,
      name: "System Administrator",
    });
    save(STORAGE_KEYS.USERS, users);
  }
}

function getCurrentUser() {
  return load(STORAGE_KEYS.CURRENT_USER, null);
}

function setCurrentUser(user) {
  if (!user) {
    localStorage.removeItem(STORAGE_KEYS.CURRENT_USER);
    localStorage.removeItem(STORAGE_KEYS.SESSION_EXPIRY);
  } else {
    save(STORAGE_KEYS.CURRENT_USER, user);
    refreshSession();
  }
}

function formatDateDisplay(dateStr) {
  const d = new Date(dateStr);
  if (Number.isNaN(d.getTime())) return dateStr;
  return d.toLocaleDateString("en-PH", { year: "numeric", month: "short", day: "numeric" });
}

function minutesFromTimeStr(timeStr) {
  const [h, m] = timeStr.split(":").map(Number);
  return h * 60 + (m || 0);
}

function formatTimeRange(startStr, durationHours) {
  const dur = Number.isFinite(durationHours) ? durationHours : SLOT_DURATION_HOURS;
  const start = minutesFromTimeStr(startStr);
  const end = start + dur * 60;
  return `${formatTime12h(start)} – ${formatTime12h(end)}`;
}

function formatTime12h(mins) {
  const h = Math.floor(mins / 60);
  const m = mins % 60;
  const d = new Date();
  d.setHours(h, m, 0, 0);
  return d.toLocaleTimeString("en-PH", { hour: "2-digit", minute: "2-digit", hour12: true });
}

function isWeekend(dateObj) {
  const day = dateObj.getDay();
  return day === 0 || day === 6;
}

// isHolidayISO and getHolidayInfo are defined above in the holiday system block

function getStartTimeOptionsWithDisabled(durationHours, isoDate) {
  const dur = Number.isFinite(durationHours) ? durationHours : SLOT_DURATION_HOURS;
  // Get approved meetings for this date to block conflicting slots
  const approvedOnDate = isoDate
    ? meetings.filter(m => m.date === isoDate && m.status === "Approved")
    : [];

  return [8,9,10,11,12,13,14,15,16].map(h => {
    const startMin = h * 60;
    const endMin   = startMin + dur * 60;

    // Block if goes past work hours
    if (endMin > WORK_END_HOUR * 60) {
      return { value: `${String(h).padStart(2,"0")}:00`, text: formatTime12h(startMin), hour: h, disabled: true, reason: "exceeds office hours" };
    }

    // Block if overlaps any approved meeting
    const conflict = approvedOnDate.find(m => {
      const s = minutesFromTimeStr(m.timeStart);
      const e = s + (m.durationHours || SLOT_DURATION_HOURS) * 60;
      return startMin < e && endMin > s;
    });

    return {
      value: `${String(h).padStart(2,"0")}:00`,
      text: formatTime12h(startMin),
      hour: h,
      disabled: !!conflict,
      reason: conflict ? `conflicts with "${conflict.eventName}"` : "",
      conflict: conflict || null,
    };
  });
}

function populateTimeOptions(isoDate) {
  const timeSelect = $("#meeting-time");
  if (!timeSelect) return;
  const durEl = $("#meeting-duration");
  const dur = durEl ? parseInt(durEl.value || String(SLOT_DURATION_HOURS), 10) : SLOT_DURATION_HOURS;
  const date = isoDate || $("#meeting-date")?.value || null;
  const options = getStartTimeOptionsWithDisabled(dur, date);
  const current = timeSelect.value;

  timeSelect.innerHTML = '<option value="">Select start time</option>' +
    options.map(o => {
      const label = o.disabled
        ? `${o.text} — ${o.reason || "unavailable"}`
        : o.text;
      return `<option value="${o.value}" ${o.disabled ? "disabled" : ""} ${o.disabled ? 'style="color:#9ca3af"' : ""}>${label}</option>`;
    }).join("");

  if (current && Array.from(timeSelect.options).some(op => op.value === current && !op.disabled)) {
    timeSelect.value = current;
  } else {
    const first = Array.from(timeSelect.options).find(op => op.value && !op.disabled);
    if (first) timeSelect.value = first.value;
  }

  // Show availability summary below the select
  updateTimeSlotAvailabilityHint(options, date);
}

function meetingStatusBadge(status) {
  const base = "badge badge-pill";
  const map = {
    "Approved": "badge-approved", "Pending": "badge-pending",
    "Cancelled": "badge-cancelled", "Rejected": "badge-rejected",
    "Done": "badge-info", "Cancellation Requested": "badge-warning",
  };
  return `<span class="${base} ${map[status] || "badge-info"}">${status === "Cancellation Requested" ? "Cancel Requested" : status}</span>`;
}

function statusColorForCalendar(status, isAdminCreated, isMine) {
  if (isMine) {
    // User's own meetings — gold highlight regardless of who scheduled
    const mineMap = {
      "Approved": "calendar-badge calendar-badge-mine-approved",
      "Pending":  "calendar-badge calendar-badge-mine-pending",
      "Cancellation Requested": "calendar-badge calendar-badge-mine-pending",
    };
    return mineMap[status] || "calendar-badge calendar-badge-mine-approved";
  }
  // Everyone else's meetings — simple green/yellow/grey, muted opacity via CSS
  const map = {
    "Approved": "calendar-badge calendar-badge-approved",
    "Pending": "calendar-badge calendar-badge-pending",
    "Cancelled": "calendar-badge calendar-badge-cancelled",
    "Rejected": "calendar-badge calendar-badge-cancelled",
    "Cancellation Requested": "calendar-badge calendar-badge-pending",
    "Done": "calendar-badge calendar-badge-cancelled",
  };
  return map[status] || "calendar-badge calendar-badge-other";
}

function getManilaNow() {
  const now = new Date();
  return new Date(now.toLocaleString("en-US", { timeZone: "Asia/Manila" }));
}

function getTodayISOManila() {
  const d = getManilaNow();
  return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,"0")}-${String(d.getDate()).padStart(2,"0")}`;
}

// Role chip colors for user table
function roleChipClass(role) {
  const map = {
    "Admin": "chip-role chip-role-admin",
    "Councilor": "chip-role chip-role-councilor",
    "Researcher": "chip-role chip-role-researcher",
    "Vice Mayor": "chip-role chip-role-vicemayor",
    "Secretary": "chip-role chip-role-secretary",
  };
  return map[role] || "chip-role";
}

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------

let users = [];
let meetings = [];
let historyEntries = [];
let calendarYear, calendarMonth;
let unsubscribeMeetings = null;
let unsubscribeHistory = null;

// Search state
let adminMeetingsSearch = "";
let myMeetingsSearch = "";
let usersSearch = "";

// ---------------------------------------------------------------------------
// Auth & Guards
// ---------------------------------------------------------------------------

function requireAuth({ allowAdmin, allowCouncilor, allowResearcher, onFail }) {
  const user = getCurrentUser();
  if (!user) {
    if (onFail === "button") { showAccessDeniedPage("Please sign in to access this page."); return null; }
    window.location.href = "./index.html";
    return null;
  }
  if (!checkSessionExpiry()) return null;
  const role = user.role;
  const ok = (role === ROLES.ADMIN && allowAdmin) ||
              (role === ROLES.COUNCILOR && allowCouncilor) ||
              (role === ROLES.RESEARCHER && allowResearcher) ||
              (role === ROLES.VICE_MAYOR && allowCouncilor) ||
              (role === ROLES.SECRETARY && allowCouncilor);
  if (!ok) {
    if (onFail === "button") { showAccessDeniedPage("Your role cannot access this page."); return null; }
    window.location.href = "./index.html";
    return null;
  }
  return user;
}

function showAccessDeniedPage(msg) {
  document.body.innerHTML = `
    <div style="min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;">
      <div style="max-width:480px;width:100%;text-align:center;background:#fff;border-radius:12px;padding:32px;box-shadow:0 4px 20px rgba(0,0,0,0.08);">
        <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#dc2626" stroke-width="1.5" style="margin-bottom:16px"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>
        <h2 style="margin:0 0 8px;font-size:1.2rem">Access Denied</h2>
        <p style="margin:0 0 20px;color:#6b7280;font-size:0.9rem">${msg}</p>
        <a href="./index.html" class="btn btn-primary">Go to Login</a>
      </div>
    </div>`;
}

function attachCommonHeader(user) {
  const welcomeEl = $("#welcome-text");
  const sidebarUser = $("#sidebar-user");
  const sidebarRole = $("#sidebar-role");
  const logoutBtn = $("#logout-btn");

  if (welcomeEl) {
    welcomeEl.textContent = user.role === ROLES.RESEARCHER
      ? `Welcome, ${user.name} (Researcher)` : `Welcome, ${user.name}`;
  }
  if (sidebarUser) sidebarUser.textContent = user.name;
  if (sidebarRole) sidebarRole.textContent = user.role;
  if (logoutBtn) {
    logoutBtn.addEventListener("click", () => {
      const doLogout = () => { setCurrentUser(null); window.location.href = "./index.html"; };
      if (window.innerWidth <= 768 && typeof window.openLogoutDrawer === "function") {
        window.openLogoutDrawer(doLogout);
      } else {
        openConfirmModal(
          "Sign Out",
          "Are you sure you want to sign out? Any unsaved changes will be lost.",
          doLogout
        );
      }
    });
  }

  // Wire notification bell
  initNotificationBell(user);
}

// ---------------------------------------------------------------------------
// Data loading
// ---------------------------------------------------------------------------

async function initDataLayer() {
  await ensureDefaultAdmin();
  if (!window.api) {
    window.api = {
      mode: "local",
      init: () => Promise.resolve(),
      getUsers: () => Promise.resolve(load(STORAGE_KEYS.USERS, [])),
      getMeetings: () => Promise.resolve(load(STORAGE_KEYS.MEETINGS, [])),
      getCalendarHistory: () => Promise.resolve(load("sbp_calendar_history", [])),
      subscribeMeetings: (cb) => { cb(load(STORAGE_KEYS.MEETINGS, [])); return () => {}; },
      subscribeCalendarHistory: (cb) => { cb(load("sbp_calendar_history", [])); return () => {}; },
      exportAndArchivePreviousMonth: () => Promise.resolve({ archived: 0 }),
    };
  }
  await window.api.init();
  users = await window.api.getUsers();
  meetings = await window.api.getMeetings();
  historyEntries = (await (window.api.getCalendarHistory ? window.api.getCalendarHistory() : Promise.resolve([]))) || [];

  // Warn if fell back to local
  if (window.api.mode === "local" && typeof firebase !== "undefined") {
    showStorageFallbackWarning();
  }

  if (unsubscribeMeetings) { try { unsubscribeMeetings(); } catch {} }
  unsubscribeMeetings = window.api.subscribeMeetings((arr) => {
    meetings = arr || [];
    const currentUser = getCurrentUser();
    renderCalendar();
    renderAdminMeetingsTable();
    renderMyMeetingsTable(currentUser);
    updateStatistics();
    // HIGH PRIORITY FIX #3: keep user dashboard charts in sync with live data
    if (typeof window.renderUserDashboardCharts === "function") {
      window.renderUserDashboardCharts();
    }
    if (typeof window.renderDashboardCharts === "function") {
      window.renderDashboardCharts();
    }
    // Refresh time slot availability if booking modal is open
    const meetingModal = $("#meeting-modal");
    if (meetingModal && meetingModal.classList.contains("modal-open")) {
      const dateVal = $("#meeting-date")?.value;
      if (dateVal) populateTimeOptions(dateVal);
    }
  });

  if (unsubscribeHistory) { try { unsubscribeHistory(); } catch {} }
  if (window.api.subscribeCalendarHistory) {
    unsubscribeHistory = window.api.subscribeCalendarHistory((arr) => {
      historyEntries = arr || [];
      renderCalendar();
    });
  }
}

function persistUsers() { save(STORAGE_KEYS.USERS, users); }
function persistMeetings() { save(STORAGE_KEYS.MEETINGS, meetings); }

// ---------------------------------------------------------------------------
// Force Password Change Modal (mustChangePassword flag)
// ---------------------------------------------------------------------------

function openForcePasswordChangeModal(account) {
  // Remove any existing instance
  document.getElementById("force-pw-modal")?.remove();

  const modal = document.createElement("div");
  modal.id = "force-pw-modal";
  modal.className = "modal-backdrop modal-open";
  modal.innerHTML = `
    <div class="modal" style="max-width:420px">
      <div class="modal-header">
        <div class="modal-title">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
          Change Your Password
        </div>
      </div>
      <div class="modal-body section-stack">
        <div style="background:#fef3c7;border:1px solid #fcd34d;border-radius:8px;padding:10px 14px;font-size:0.82rem;color:#92400e;display:flex;gap:8px;align-items:flex-start;">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" style="flex-shrink:0;margin-top:1px"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
          <span>This is your first login. You must set a new password before continuing.</span>
        </div>
        <div>
          <label class="field-label" for="force-pw-new">New Password</label>
          <input id="force-pw-new" type="password" class="field" placeholder="Minimum 6 characters" />
        </div>
        <div>
          <label class="field-label" for="force-pw-confirm">Confirm New Password</label>
          <input id="force-pw-confirm" type="password" class="field" placeholder="Re-enter new password" />
        </div>
        <div id="force-pw-error" style="color:#dc2626;font-size:0.8rem;min-height:1.2em"></div>
      </div>
      <div class="modal-footer">
        <button id="force-pw-submit" class="btn btn-primary" style="width:100%">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><polyline points="20 6 9 17 4 12"/></svg>
          Set Password &amp; Continue
        </button>
      </div>
    </div>`;
  document.body.appendChild(modal);

  document.getElementById("force-pw-submit").addEventListener("click", async () => {
    const newPwd = document.getElementById("force-pw-new").value;
    const confirmPwd = document.getElementById("force-pw-confirm").value;
    const errEl = document.getElementById("force-pw-error");

    if (newPwd.length < 6) { errEl.textContent = "Password must be at least 6 characters."; return; }
    if (newPwd !== confirmPwd) { errEl.textContent = "Passwords do not match."; return; }
    errEl.textContent = "";

    const submitBtn = document.getElementById("force-pw-submit");
    submitBtn.disabled = true;
    submitBtn.textContent = "Saving…";

    try {
      const hashed = await hashPassword(newPwd);
      if (window.api && window.api.updateUserPassword) {
        await window.api.updateUserPassword(account.id, hashed);
      } else {
        const allUsers = load(STORAGE_KEYS.USERS, []);
        const u = allUsers.find(x => x.id === account.id);
        if (u) { u.password = hashed; u.mustChangePassword = false; save(STORAGE_KEYS.USERS, allUsers); }
      }
      modal.remove();
      showToast("Password updated. Welcome!", "success");
      const current = { id: account.id, username: account.username, role: account.role, name: account.name || account.username };
      setCurrentUser(current);
      try { sessionStorage.setItem('sbp_just_logged_in', '1'); } catch(e) {}
      window.location.href = current.role === ROLES.ADMIN ? "./admin.html" : "./user.html";
    } catch (err) {
      errEl.textContent = "Failed to update password. Please try again.";
      submitBtn.disabled = false;
      submitBtn.innerHTML = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><polyline points="20 6 9 17 4 12"/></svg> Set Password & Continue`;
    }
  });
}

// ---------------------------------------------------------------------------
// Login Page
// ---------------------------------------------------------------------------

async function initLoginPage() {
  await ensureDefaultAdmin();

  // Show timeout message if redirected after session expiry
  const params = new URLSearchParams(window.location.search);
  if (params.get("timeout") === "1") {
    const errorEl = $("#login-error");
    if (errorEl) {
      errorEl.textContent = "Your session expired due to inactivity. Please sign in again.";
      errorEl.classList.add("auth-error-visible");
    }
  }

  const existing = getCurrentUser();
  if (existing && checkSessionExpiry()) {
    window.location.href = existing.role === ROLES.ADMIN ? "./admin.html" : "./user.html";
    return;
  }

  const form = $("#login-form");
  const errorEl = $("#login-error");
  if (!form) return;

  // ── Bug fix: brute-force lockout ─────────────────────────────────────────
  // Track failed attempts in sessionStorage (resets on browser close).
  // After 5 failures, lock the form for 30 seconds.
  const LOCKOUT_MAX   = 5;
  const LOCKOUT_MS    = 30 * 1000;
  const LS_ATTEMPTS   = "sbp_login_attempts";
  const LS_LOCKOUT_TS = "sbp_login_lockout_ts";

  function getAttempts()  { return parseInt(sessionStorage.getItem(LS_ATTEMPTS)  || "0", 10); }
  function getLockoutTs() { return parseInt(sessionStorage.getItem(LS_LOCKOUT_TS) || "0", 10); }

  function isLockedOut() {
    const ts = getLockoutTs();
    if (!ts) return false;
    if (Date.now() < ts) return true;
    // Lockout expired — clear it
    sessionStorage.removeItem(LS_ATTEMPTS);
    sessionStorage.removeItem(LS_LOCKOUT_TS);
    return false;
  }

  function recordFailedAttempt() {
    const next = getAttempts() + 1;
    sessionStorage.setItem(LS_ATTEMPTS, String(next));
    if (next >= LOCKOUT_MAX) {
      sessionStorage.setItem(LS_LOCKOUT_TS, String(Date.now() + LOCKOUT_MS));
    }
    return next;
  }

  function clearAttempts() {
    sessionStorage.removeItem(LS_ATTEMPTS);
    sessionStorage.removeItem(LS_LOCKOUT_TS);
  }

  // Show remaining lockout time and re-enable once expired
  function showLockoutError() {
    const remaining = Math.ceil((getLockoutTs() - Date.now()) / 1000);
    if (errorEl) {
      errorEl.textContent = `Too many failed attempts. Please wait ${remaining}s before trying again.`;
      errorEl.classList.add("auth-error-visible");
    }
    const loginBtn = $("#login-btn");
    if (loginBtn) { loginBtn.disabled = true; }
    const interval = setInterval(() => {
      if (!isLockedOut()) {
        clearInterval(interval);
        if (errorEl) errorEl.classList.remove("auth-error-visible");
        if (loginBtn) { loginBtn.disabled = false; }
      } else {
        const rem = Math.ceil((getLockoutTs() - Date.now()) / 1000);
        if (errorEl) errorEl.textContent = `Too many failed attempts. Please wait ${rem}s before trying again.`;
      }
    }, 1000);
  }

  // If page loaded while still locked out, show immediately
  if (isLockedOut()) showLockoutError();
  // ─────────────────────────────────────────────────────────────────────────

  form.addEventListener("submit", async (e) => {
    e.preventDefault();

    // Lockout guard
    if (isLockedOut()) { showLockoutError(); return; }

    const username = $("#login-username").value.trim();
    const password = $("#login-password").value;

    // Fix 13: Show loading state, prevent double-submit
    const loginBtn = $("#login-btn");
    if (loginBtn) { loginBtn.classList.add("loading"); loginBtn.disabled = true; }
    if (errorEl) errorEl.classList.remove("auth-error-visible");

    const setError = (msg) => {
      if (errorEl) { errorEl.textContent = msg; errorEl.classList.add("auth-error-visible"); }
      showToast(msg, "error");
      if (loginBtn) { loginBtn.classList.remove("loading"); loginBtn.disabled = false; }
    };

    let account = null;
    try {
      if (window.api && window.api.signIn) {
        // For Firestore mode — passwords may still be plain (legacy)
        account = await window.api.signIn(username, password);
        // If not found, try hashed
        if (!account) {
          const hashed = await hashPassword(password);
          account = await window.api.signIn(username, hashed);
        }
      } else {
        const allUsers = load(STORAGE_KEYS.USERS, []);
        // Try hashed match first
        for (const u of allUsers) {
          if (u.username !== username) continue;
          if (await verifyPassword(password, u.password)) { account = u; break; }
          // Legacy plain text fallback (migrates on next password change)
          if (u.password === password) { account = u; break; }
        }
      }
    } catch (err) {
      setError("A connection error occurred. Please try again.");
      return;
    }

    if (!account) {
      const attempts = recordFailedAttempt();
      const remaining = LOCKOUT_MAX - attempts;
      if (isLockedOut()) {
        showLockoutError();
      } else {
        setError(`Invalid username or password.${remaining > 0 ? ` (${remaining} attempt${remaining !== 1 ? "s" : ""} remaining)` : ""}`);
      }
      return;
    }

    // Fix 14: Check mustChangePassword flag — force password change before proceeding
    if (account.mustChangePassword) {
      if (loginBtn) { loginBtn.classList.remove("loading"); loginBtn.disabled = false; }
      // Do NOT set a session yet — only set it after the password is successfully changed
      openForcePasswordChangeModal(account);
      return;
    }

    clearAttempts(); // successful login — reset the counter
    const current = { id: account.id, username: account.username, role: account.role, name: account.name || account.username };
    setCurrentUser(current);
    try { sessionStorage.setItem('sbp_just_logged_in', '1'); } catch(e) {}
    window.location.href = current.role === ROLES.ADMIN ? "./admin.html" : "./user.html";
  });
}

// ---------------------------------------------------------------------------
// User Management
// ---------------------------------------------------------------------------

function countUsersByRole(role) {
  return users.filter(u => u.role === role).length;
}

function renderUsersTable() {
  const tbody = $("#user-table-body");
  const specialTbody = $("#special-accounts-table-body");

  let list = [...users].filter(u => u.role !== ROLES.ADMIN);
  if (usersSearch) {
    const q = usersSearch.toLowerCase();
    list = list.filter(u =>
      (u.username || "").toLowerCase().includes(q) ||
      (u.name || "").toLowerCase().includes(q) ||
      (u.role || "").toLowerCase().includes(q)
    );
  }

  const specialRoles = [ROLES.VICE_MAYOR, ROLES.SECRETARY];
  const regularList = list.filter(u => !specialRoles.includes(u.role));
  const specialList = list.filter(u => specialRoles.includes(u.role));

  // Render special accounts table (Vice Mayor, Secretary)
  if (specialTbody) {
    if (!specialList.length) {
      specialTbody.innerHTML = '<tr><td colspan="4" class="text-muted" style="text-align:center;padding:20px">No special accounts created yet.</td></tr>';
    } else {
      specialTbody.innerHTML = specialList.map(u => `<tr>
        <td>${h(u.username)}</td>
        <td>${h(u.name || "")}</td>
        <td><span class="${roleChipClass(u.role)}">${u.role}</span></td>
        <td>
          <button class="btn btn-sm btn-ghost" data-action="view-user" data-user-id="${u.id}">View</button>
          <button class="btn btn-sm btn-ghost" data-action="change-password" data-user-id="${u.id}">Change Password</button>
          <button class="btn btn-sm btn-ghost" data-action="remove-user" data-user-id="${u.id}">Remove</button>
        </td>
      </tr>`).join("");
    }
  }

  // Render regular users with pagination
  if (!tbody) return;
  const totalPages = Math.max(1, Math.ceil(regularList.length / MEETINGS_PAGE_SIZE));
  if (usersPage > totalPages) usersPage = totalPages;
  const paginated = regularList.slice((usersPage - 1) * MEETINGS_PAGE_SIZE, usersPage * MEETINGS_PAGE_SIZE);

  if (!paginated.length) {
    tbody.innerHTML = '<tr><td colspan="4" class="text-muted" style="text-align:center;padding:20px">No regular user accounts found.</td></tr>';
  } else {
    tbody.innerHTML = paginated.map(u => `<tr>
      <td>${h(u.username)}</td>
      <td>${h(u.name || "")}</td>
      <td><span class="${roleChipClass(u.role)}">${u.role}</span></td>
      <td>
        <button class="btn btn-sm btn-ghost" data-action="view-user" data-user-id="${u.id}">View</button>
        <button class="btn btn-sm btn-ghost" data-action="change-password" data-user-id="${u.id}">Change Password</button>
        <button class="btn btn-sm btn-ghost" data-action="remove-user" data-user-id="${u.id}">Remove</button>
      </td>
    </tr>`).join("");
  }

  renderPagination("users-pagination", totalPages, usersPage, (p) => { usersPage = p; renderUsersTable(); });
  // Keep system settings user-selects in sync
  populateEditUserSelect();
}


// Returns the role-based username prefix, e.g. "Councilor" → "councilor_"
function getRolePrefix(role) {
  const map = {
    [ROLES.COUNCILOR]:  "councilor_",
    [ROLES.RESEARCHER]: "researcher_",
    [ROLES.VICE_MAYOR]: "vicemayor_",
    [ROLES.SECRETARY]:  "secretary_",
  };
  return map[role] || "";
}

// Build the final username: prefix + sanitised input (strip existing prefix if user typed it)
function buildPrefixedUsername(rawInput, role) {
  const prefix = getRolePrefix(role);
  if (!prefix) return rawInput.toLowerCase().replace(/\s+/g, "_");
  // Strip the prefix if the user already typed it (case-insensitive)
  const stripped = rawInput.toLowerCase().replace(/\s+/g, "_");
  const withoutPrefix = stripped.startsWith(prefix) ? stripped.slice(prefix.length) : stripped;
  return prefix + withoutPrefix;
}

// Show a polished success popup confirming the generated username
function showUsernameCreatedPopup(finalUsername, role, name) {
  const old = document.getElementById("username-created-popup");
  if (old) old.remove();

  const popup = document.createElement("div");
  popup.id = "username-created-popup";
  popup.style.cssText = `
    position:fixed;inset:0;z-index:9000;
    display:flex;align-items:center;justify-content:center;
    padding:20px;
    background:rgba(7,15,34,0.65);
    backdrop-filter:blur(5px);
    animation:fadeInBg 0.2s ease both;
  `;

  popup.innerHTML = `
    <style>
      @keyframes fadeInBg  { from{opacity:0} to{opacity:1} }
      @keyframes popIn     { from{opacity:0;transform:scale(0.88) translateY(16px)} to{opacity:1;transform:scale(1) translateY(0)} }
      @keyframes checkDraw { from{stroke-dashoffset:40} to{stroke-dashoffset:0} }
      #username-created-popup .popup-card {
        background:var(--color-surface);border-radius:20px;padding:28px 28px 22px;
        width:100%;max-width:380px;text-align:center;
        box-shadow:0 28px 64px rgba(0,0,0,0.35);
        border:1px solid var(--color-border);
        animation:popIn 0.28s cubic-bezier(0.34,1.56,0.64,1) both;
        display:flex;flex-direction:column;align-items:center;
      }
      #username-created-popup .popup-icon {
        width:60px;height:60px;border-radius:50%;background:rgba(22,163,74,0.1);
        display:flex;align-items:center;justify-content:center;margin-bottom:12px;
      }
      #username-created-popup .popup-icon svg circle { fill:none;stroke:#16a34a;stroke-width:2; }
      #username-created-popup .popup-icon svg polyline {
        fill:none;stroke:#16a34a;stroke-width:2.5;stroke-linecap:round;stroke-linejoin:round;
        stroke-dasharray:40;stroke-dashoffset:40;animation:checkDraw 0.4s 0.2s ease forwards;
      }
      #username-created-popup .popup-title { font-family:var(--font-display);font-size:1.1rem;font-weight:800;color:var(--color-text);margin-bottom:3px; }
      #username-created-popup .popup-sub { font-size:0.78rem;color:var(--color-text-muted);margin-bottom:16px;line-height:1.5; }
      #username-created-popup .popup-cred-box {
        background:var(--color-bg);border:1.5px solid var(--color-border);border-radius:12px;
        padding:14px 16px;width:100%;margin-bottom:14px;
      }
      #username-created-popup .popup-cred-row {
        display:flex;align-items:center;justify-content:space-between;gap:8px;
        padding:5px 0;border-bottom:1px solid var(--color-border-soft);
      }
      #username-created-popup .popup-cred-row:last-child { border-bottom:none; }
      #username-created-popup .popup-cred-label {
        font-size:0.65rem;font-weight:700;letter-spacing:0.09em;text-transform:uppercase;
        color:var(--color-text-muted);min-width:70px;text-align:left;
      }
      #username-created-popup .popup-cred-val {
        font-family:var(--font-display);font-size:0.92rem;font-weight:700;
        color:var(--brand-blue);word-break:break-all;text-align:left;flex:1;
      }
      #username-created-popup .popup-copy-btn {
        padding:4px 10px;border:1px solid var(--color-border);border-radius:6px;
        background:var(--color-surface);color:var(--color-text-muted);
        font-size:0.68rem;font-weight:700;cursor:pointer;white-space:nowrap;
        transition:all 0.15s;display:flex;align-items:center;gap:4px;
      }
      #username-created-popup .popup-copy-btn:hover { background:var(--color-border-soft);color:var(--color-text); }
      #username-created-popup .popup-copy-btn.copied { background:#dcfce7;color:#16a34a;border-color:#86efac; }
      #username-created-popup .popup-copy-all-btn {
        width:100%;padding:9px 16px;border:1.5px dashed var(--color-border);border-radius:10px;
        background:transparent;color:var(--color-text-muted);font-size:0.8rem;font-weight:600;
        cursor:pointer;margin-bottom:10px;transition:all 0.15s;display:flex;align-items:center;justify-content:center;gap:7px;
      }
      #username-created-popup .popup-copy-all-btn:hover { border-color:var(--brand-blue);color:var(--brand-blue);background:rgba(27,75,138,0.04); }
      #username-created-popup .popup-copy-all-btn.copied { border-color:#16a34a;color:#16a34a;background:#f0fdf4; }
      #username-created-popup .popup-ok-btn {
        width:100%;padding:11px 16px;border:none;border-radius:10px;
        background:linear-gradient(135deg,var(--brand-blue-mid),var(--brand-blue));
        color:#fff;font-size:0.9rem;font-weight:800;cursor:pointer;
        font-family:var(--font-display);box-shadow:0 4px 14px rgba(27,75,138,0.3);
        transition:transform 0.12s,box-shadow 0.15s;
      }
      #username-created-popup .popup-ok-btn:hover { transform:translateY(-1px);box-shadow:0 6px 18px rgba(27,75,138,0.4); }
    </style>
    <div class="popup-card">
      <div class="popup-icon">
        <svg width="34" height="34" viewBox="0 0 24 24">
          <circle cx="12" cy="12" r="10"/>
          <polyline points="7 13 10 16 17 9"/>
        </svg>
      </div>
      <div class="popup-title">Account Created!</div>
      <div class="popup-sub"><strong>${h(name)}</strong>'s account is ready.<br>Share these credentials securely:</div>

      <div class="popup-cred-box">
        <div class="popup-cred-row">
          <span class="popup-cred-label">Username</span>
          <span class="popup-cred-val" id="popup-username-val">${h(finalUsername)}</span>
          <button class="popup-copy-btn" id="popup-copy-username" title="Copy username">
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>
            Copy
          </button>
        </div>
        <div class="popup-cred-row">
          <span class="popup-cred-label">Role</span>
          <span class="popup-cred-val"><span class="${roleChipClass(role)}">${h(role)}</span></span>
          <span style="width:60px"></span>
        </div>
      </div>

      <button class="popup-copy-all-btn" id="popup-copy-all">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>
        Copy credentials to clipboard
      </button>

      <button class="popup-ok-btn" id="popup-ok-btn">Done</button>
    </div>
  `;

  const closePopup = () => popup.remove();
  popup.addEventListener("click", (e) => { if (e.target === popup) closePopup(); });
  document.body.appendChild(popup);

  const copyText = (text, btn) => {
    navigator.clipboard.writeText(text).then(() => {
      const orig = btn.innerHTML;
      btn.innerHTML = '<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg> Copied!';
      btn.classList.add("copied");
      setTimeout(() => { btn.innerHTML = orig; btn.classList.remove("copied"); }, 2000);
    }).catch(() => {
      // Fallback for older browsers
      const ta = document.createElement("textarea");
      ta.value = text; ta.style.position = "fixed"; ta.style.opacity = "0";
      document.body.appendChild(ta); ta.select();
      document.execCommand("copy"); document.body.removeChild(ta);
      showToast("Copied!", "success");
    });
  };

  popup.querySelector("#popup-copy-username")?.addEventListener("click", (e) => {
    e.stopPropagation();
    copyText(finalUsername, popup.querySelector("#popup-copy-username"));
  });

  popup.querySelector("#popup-copy-all")?.addEventListener("click", (e) => {
    e.stopPropagation();
    const text = `Username: ${finalUsername}\nRole: ${role}\nName: ${name}`;
    copyText(text, popup.querySelector("#popup-copy-all"));
  });

  popup.querySelector("#popup-ok-btn")?.addEventListener("click", closePopup);
}

async function handleUserFormSubmit(e) {
  e.preventDefault();
  const rawUsername = $("#user-username").value.trim();
  const name        = $("#user-name").value.trim();
  const password    = $("#user-password").value;
  const confirm     = $("#user-confirm").value;
  const role        = $("#user-role").value;
  const msg         = $("#user-form-message");

  // Build prefixed username
  const username = buildPrefixedUsername(rawUsername, role);

  if (!rawUsername || !name) { msg.textContent = "Username and full name are required."; showToast("Username and full name are required.", "error"); return; }
  if (password.length < 6)   { msg.textContent = "Password must be at least 6 characters."; showToast("Password too short.", "error"); return; }
  if (password !== confirm)  { msg.textContent = "Passwords do not match."; showToast("Passwords do not match.", "error"); return; }
  if (users.some(u => u.username === username)) { msg.textContent = `Username "${username}" already exists.`; showToast("Username already exists.", "error"); return; }

  const limit = ROLE_LIMITS[role];
  if (limit != null && countUsersByRole(role) >= limit) {
    msg.textContent = `Role limit reached for ${role}.`;
    showToast(`Role limit reached for ${role}.`, "error");
    return;
  }

  const hashedPwd = await hashPassword(password);
  const newUser = {
    id: `user_${Math.random().toString(36).slice(2, 9)}`,
    username, name, password: hashedPwd, role,
  };

  const onDone = () => {
    $("#user-form").reset();
    msg.textContent = "";
    renderUsersTable();
    updateStatistics();
    showUsernameCreatedPopup(username, role, name);
  };

  if (window.api && window.api.createUser) {
    window.api.createUser(newUser).then(async () => {
      users = await window.api.getUsers();
      onDone();
    });
  } else {
    users.push(newUser);
    persistUsers();
    onDone();
  }
}

async function handleSpecialAccountFormSubmit(e) {
  e.preventDefault();
  const rawUsername = $("#special-username").value.trim();
  const name        = $("#special-name").value.trim();
  const password    = $("#special-password").value;
  const confirm     = $("#special-confirm").value;
  const role        = $("#special-role").value;
  const msg         = $("#special-form-message");

  // Build prefixed username
  const username = buildPrefixedUsername(rawUsername, role);

  if (!rawUsername || !name) { msg.textContent = "Username and full name are required."; showToast("Username and full name are required.", "error"); return; }
  if (password.length < 6)   { msg.textContent = "Password must be at least 6 characters."; showToast("Password too short.", "error"); return; }
  if (password !== confirm)  { msg.textContent = "Passwords do not match."; showToast("Passwords do not match.", "error"); return; }
  if (users.some(u => u.username === username)) { msg.textContent = `Username "${username}" already exists.`; showToast("Username already exists.", "error"); return; }

  const limit = ROLE_LIMITS[role];
  if (limit != null && countUsersByRole(role) >= limit) {
    msg.textContent = `A ${role} account already exists. Remove it first to create a new one.`;
    showToast(`${role} account already exists.`, "error");
    return;
  }

  const hashedPwd = await hashPassword(password);
  const newUser = {
    id: `user_${Math.random().toString(36).slice(2, 9)}`,
    username, name, password: hashedPwd, role,
  };

  const onDone = async () => {
    $("#special-account-form").reset();
    msg.textContent = "";
    renderUsersTable();
    updateStatistics();
    showUsernameCreatedPopup(username, role, name);
  };

  if (window.api && window.api.createUser) {
    window.api.createUser(newUser).then(async () => {
      users = await window.api.getUsers();
      onDone();
    });
  } else {
    users.push(newUser);
    persistUsers();
    onDone();
  }
}

function handleUserTableClick(e) {
  const btn = e.target.closest("button[data-action]");
  if (!btn) return;
  const action = btn.dataset.action;
  const userId = btn.dataset.userId;
  const user = users.find(u => u.id === userId);
  if (!user) return;

  if (action === "view-user") {
    openUserDrawer(userId);
    return;
  }

  if (action === "remove-user") {
    openConfirmModal(
      "Remove User Account",
      `Are you sure you want to remove <strong>${h(user.name)}</strong>? This cannot be undone. Their pending/approved meetings will be cancelled.`,
      () => {
        // Cancel all active meetings belonging to this user before deleting
        const userMeetings = meetings.filter(m =>
          (m.createdBy === user.id || m.createdBy === user.username) &&
          ["Pending", "Approved", "Cancellation Requested"].includes(m.status)
        );
        userMeetings.forEach(m => {
          m.status = "Cancelled";
          m.adminNote = `Account removed — ${user.name}`;
          if (window.api && window.api.updateMeetingStatus) {
            window.api.updateMeetingStatus(m.id, "Cancelled", m.adminNote).then(() => {});
          }
        });
        if (userMeetings.length) persistMeetings();

        if (window.api && window.api.deleteUser) {
          window.api.deleteUser(user.id || userId).then(async () => {
            users = await window.api.getUsers();
            renderUsersTable(); renderAdminMeetingsTable(); renderCalendar(); updateStatistics();
            showToast(`User removed. ${userMeetings.length ? userMeetings.length + " meeting(s) cancelled." : ""}`, "success");
          });
        } else {
          users = users.filter(u => u.id !== userId);
          persistUsers(); renderUsersTable(); renderAdminMeetingsTable(); renderCalendar(); updateStatistics();
          showToast(`User removed. ${userMeetings.length ? userMeetings.length + " meeting(s) cancelled." : ""}`, "success");
        }
      }
    );
  } else if (action === "change-password") {
    openPasswordModal(userId);
  }
}

// ---------------------------------------------------------------------------
// Confirm Modal (replaces browser confirm())
// ---------------------------------------------------------------------------

function openConfirmModal(title, bodyHtml, onConfirm, onCancel) {
  let modal = document.getElementById("confirm-modal");
  if (!modal) {
    modal = document.createElement("div");
    modal.id = "confirm-modal";
    modal.className = "modal-backdrop";
    modal.innerHTML = `
      <div class="modal" style="max-width:440px">
        <div class="modal-header">
          <div class="modal-title" id="confirm-modal-title"></div>
          <button id="confirm-modal-close" class="btn btn-ghost btn-sm">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
          </button>
        </div>
        <div class="modal-body" id="confirm-modal-body-wrap"><div id="confirm-modal-body" class="confirm-modal-body-inner"></div></div>
        <div class="modal-footer">
          <button id="confirm-modal-cancel" class="btn btn-ghost btn-sm">Cancel</button>
          <button id="confirm-modal-ok" class="btn btn-primary btn-sm">Confirm</button>
        </div>
      </div>`;
    // Force it to always sit on top of everything and truly center in the viewport
    modal.style.cssText = "display:none;position:fixed;inset:0;z-index:9999;align-items:center;justify-content:center;padding:20px;background:rgba(7,15,34,0.7);backdrop-filter:blur(5px);";
    document.body.appendChild(modal);
  }

  document.getElementById("confirm-modal-title").textContent = title;
  document.getElementById("confirm-modal-body").innerHTML = bodyHtml;

  // Reset scroll to top every time modal opens
  const bodyWrap = document.getElementById("confirm-modal-body-wrap");
  if (bodyWrap) bodyWrap.scrollTop = 0;

  // Re-trigger animation by removing and re-adding the class
  const modalInner = modal.querySelector(".modal");
  if (modalInner) { modalInner.style.animation = "none"; requestAnimationFrame(() => { modalInner.style.animation = ""; }); }

  modal.style.display = "flex";

  const close = (cancelled) => {
    modal.style.display = "none";
    if (cancelled && typeof onCancel === "function") onCancel();
  };

  // Backdrop click — defined after close so no ReferenceError
  modal.onclick = (e) => { if (e.target === modal) close(true); };
  document.getElementById("confirm-modal-close").onclick = () => close(true);
  document.getElementById("confirm-modal-cancel").onclick = () => close(true);
  document.getElementById("confirm-modal-ok").onclick = () => { close(false); onConfirm(); };
}

// ---------------------------------------------------------------------------
// Change Password Modal
// ---------------------------------------------------------------------------

function openPasswordModal(userId) {
  $("#password-user-id").value = userId;
  $("#password-new").value = "";
  $("#password-confirm").value = "";
  $("#password-form-message").textContent = "";
  const backdrop = $("#password-modal");
  if (backdrop) backdrop.classList.add("modal-open");
}

function closePasswordModal() {
  const backdrop = $("#password-modal");
  if (backdrop) backdrop.classList.remove("modal-open");
}

async function handlePasswordSubmit(e) {
  e.preventDefault();
  const userId = $("#password-user-id").value;
  const pwd = $("#password-new").value;
  const confirmPwd = $("#password-confirm").value;
  const msg = $("#password-form-message");

  if (pwd.length < 6) { msg.textContent = "Password must be at least 6 characters."; return; }
  if (pwd !== confirmPwd) { msg.textContent = "Passwords do not match."; showToast("Passwords do not match.", "error"); return; }

  const user = users.find(u => u.id === userId);
  if (!user) { msg.textContent = "User not found."; return; }

  const hashedPwd = await hashPassword(pwd);

  if (window.api && window.api.updateUserPassword) {
    window.api.updateUserPassword(user.id, hashedPwd).then(async () => {
      users = await window.api.getUsers();
      msg.textContent = "Password updated.";
      showToast("Password updated.", "success");
      setTimeout(closePasswordModal, 700);
    });
  } else {
    user.password = hashedPwd;
    persistUsers();
    msg.textContent = "Password updated.";
    showToast("Password updated.", "success");
    setTimeout(closePasswordModal, 700);
  }
}

// ---------------------------------------------------------------------------
// Meetings & Scheduling
// ---------------------------------------------------------------------------

function meetingBelongsToUser(meeting, user) {
  if (!user) return false;
  if (user.role === ROLES.ADMIN) return true;
  if (user.role === ROLES.COUNCILOR) return meeting.councilor === user.name || meeting.createdBy === user.username;
  if (user.role === ROLES.RESEARCHER) return meeting.researcher === user.name || meeting.createdBy === user.username;
  if (user.role === ROLES.VICE_MAYOR) return meeting.createdBy === user.username;
  if (user.role === ROLES.SECRETARY) return meeting.createdBy === user.username;
  return false;
}

function renderMyMeetingsTable(currentUser) {
  const tbody = $("#my-meetings-body");
  if (!tbody || !currentUser) return;

  let mine = meetings.filter(m => meetingBelongsToUser(m, currentUser));
  if (myMeetingsSearch) {
    const q = myMeetingsSearch.toLowerCase();
    mine = mine.filter(m =>
      (m.eventName || "").toLowerCase().includes(q) ||
      (m.type || m.meetingType || "").toLowerCase().includes(q) ||
      (m.status || "").toLowerCase().includes(q) ||
      (m.venue || "").toLowerCase().includes(q)
    );
  }
  mine.sort((a, b) => (a.date + a.timeStart).localeCompare(b.date + b.timeStart));

  const totalPages = Math.max(1, Math.ceil(mine.length / MEETINGS_PAGE_SIZE));
  if (myMeetingsPage > totalPages) myMeetingsPage = totalPages;
  const paginated = mine.slice((myMeetingsPage - 1) * MEETINGS_PAGE_SIZE, myMeetingsPage * MEETINGS_PAGE_SIZE);

  if (!paginated.length) {
    tbody.innerHTML = '<tr><td colspan="6" class="text-muted">No meetings found.</td></tr>';
    renderPagination("my-meetings-pagination", totalPages, myMeetingsPage, (p) => { myMeetingsPage = p; renderMyMeetingsTable(currentUser); });
    return;
  }

  tbody.innerHTML = paginated.map(m => {
    const canRequestCancel = currentUser.role !== ROLES.ADMIN && ["Pending", "Approved"].includes(m.status);
    const noteTitle = m.adminNote ? ` title="${h(m.adminNote)}"` : "";
    const noteHint = m.adminNote ? `<div style="font-size:0.72rem;color:#6b7280;margin-top:3px;max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${h(m.adminNote)}">Note: ${h(m.adminNote)}</div>` : "";
    const createdAt = m.createdAt ? new Date(m.createdAt) : null;
    const msElapsed = createdAt ? (new Date() - createdAt) : Infinity;
    const within24h = msElapsed < 24 * 60 * 60 * 1000;
    const msLeft = within24h ? (24 * 60 * 60 * 1000 - msElapsed) : 0;
    const hoursLeft = Math.floor(msLeft / (60 * 60 * 1000));
    const minsLeft  = Math.floor((msLeft % (60 * 60 * 1000)) / 60000);
    const countdownStr = hoursLeft > 0 ? `${hoursLeft}h ${minsLeft}m` : `${minsLeft}m`;

    let cancelBtn = "";
    if (canRequestCancel) {
      if (within24h) {
        cancelBtn = `
          <div style="display:flex;flex-direction:column;gap:3px;align-items:flex-start">
            <button class="btn btn-sm cancel-btn-free" data-action="request-cancel" data-meeting-id="${m.id}"
              style="background:rgba(22,163,74,0.1);color:#166534;border:1px solid rgba(22,163,74,0.25);font-weight:600;display:flex;align-items:center;gap:5px">
              <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
              Cancel (Free)
            </button>
            <span class="cancel-countdown" data-created="${m.createdAt}" style="font-size:0.67rem;font-weight:600;color:#16a34a;display:flex;align-items:center;gap:3px">
              <svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
              ${countdownStr} left
            </span>
          </div>`;
      } else {
        cancelBtn = `
          <button class="btn btn-sm btn-ghost" data-action="request-cancel" data-meeting-id="${m.id}"
            style="display:flex;align-items:center;gap:5px">
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
            Request Cancel
          </button>`;
      }
    }

    const cancelReasonHint = m.cancelReason ? `<div style="font-size:0.72rem;color:#9ca3af;margin-top:2px" title="${h(m.cancelReason)}">Reason: ${h(m.cancelReason)}</div>` : "";
    return `<tr>
      <td>${h(m.eventName)}</td>
      <td>${formatDateDisplay(m.date)}</td>
      <td>${formatTimeRange(m.timeStart, m.durationHours || SLOT_DURATION_HOURS)}</td>
      <td>${m.type || m.meetingType || "—"}</td>
      <td${noteTitle}>${meetingStatusBadge(m.status)}${noteHint}${cancelReasonHint}</td>
      <td style="display:flex;gap:6px;flex-wrap:wrap;align-items:center">
        ${cancelBtn}
        <button class="btn btn-sm btn-ghost" data-action="export-pdf" data-meeting-id="${m.id}">Export PDF</button>
      </td>
    </tr>`;
  }).join("");

  renderPagination("my-meetings-pagination", totalPages, myMeetingsPage, (p) => { myMeetingsPage = p; renderMyMeetingsTable(currentUser); });

  // Live-tick countdown timers for the 24h free-cancel window
  _startCancelCountdownTick(currentUser);
}

// ---------------------------------------------------------------------------
// 24-hour Cancel Countdown Ticker
// Refreshes the countdown labels in My Meetings every 60s without re-rendering the full table
// ---------------------------------------------------------------------------
let _cancelCountdownInterval = null;
function _startCancelCountdownTick(currentUser) {
  if (_cancelCountdownInterval) { clearInterval(_cancelCountdownInterval); _cancelCountdownInterval = null; }
  const tbody = document.getElementById("my-meetings-body");
  if (!tbody) return;
  // Check if any free-cancel rows exist at all
  const hasCountdowns = tbody.querySelectorAll(".cancel-countdown").length > 0;
  if (!hasCountdowns) return;
  _cancelCountdownInterval = setInterval(() => {
    const spans = tbody.querySelectorAll(".cancel-countdown[data-created]");
    if (!spans.length) { clearInterval(_cancelCountdownInterval); return; }
    let anyLeft = false;
    spans.forEach(span => {
      const created = new Date(span.dataset.created);
      const msLeft = 24 * 60 * 60 * 1000 - (new Date() - created);
      if (msLeft <= 0) {
        // Window expired — re-render to switch button to "Request Cancel"
        clearInterval(_cancelCountdownInterval);
        renderMyMeetingsTable(currentUser);
        return;
      }
      anyLeft = true;
      const h = Math.floor(msLeft / (60 * 60 * 1000));
      const m = Math.floor((msLeft % (60 * 60 * 1000)) / 60000);
      span.lastChild.textContent = ` ${h > 0 ? h + "h " : ""}${m}m left`;
    });
    if (!anyLeft) clearInterval(_cancelCountdownInterval);
  }, 60000); // tick every 1 minute
}

function renderAdminMeetingsTable() {
  const tbody = $("#admin-meetings-body");
  if (!tbody) return;

  const filterType = $("#filter-type-admin")?.value || "all";
  const filterStatus = $("#filter-status-admin")?.value || "all";
  let list = [...meetings];
  if (filterType !== "all") list = list.filter(m => (m.type || m.meetingType) === filterType);
  if (filterStatus !== "all") list = list.filter(m => m.status === filterStatus);
  if (adminMeetingsSearch) {
    const q = adminMeetingsSearch.toLowerCase();
    list = list.filter(m =>
      (m.eventName || "").toLowerCase().includes(q) ||
      (m.createdBy || "").toLowerCase().includes(q) ||
      (m.councilor || "").toLowerCase().includes(q) ||
      (m.venue || "").toLowerCase().includes(q)
    );
  }
  list.sort((a, b) => (a.date + a.timeStart).localeCompare(b.date + b.timeStart));

  const totalPages = Math.max(1, Math.ceil(list.length / MEETINGS_PAGE_SIZE));
  if (adminMeetingsPage > totalPages) adminMeetingsPage = totalPages;
  const paginated = list.slice((adminMeetingsPage - 1) * MEETINGS_PAGE_SIZE, adminMeetingsPage * MEETINGS_PAGE_SIZE);

  if (!paginated.length) {
    tbody.innerHTML = '<tr><td colspan="7" class="text-muted">No meetings found.</td></tr>';
    renderPagination("admin-meetings-pagination", totalPages, adminMeetingsPage, (p) => { adminMeetingsPage = p; renderAdminMeetingsTable(); });
    return;
  }

  tbody.innerHTML = paginated.map(m => {
    const isCancelRequest = m.status === "Cancellation Requested";
    const isAdminCreated = m.createdByRole === ROLES.ADMIN;
    const printBtn = m.status === "Approved"
      ? `<button class="btn btn-sm btn-ghost" data-action="print" data-meeting-id="${m.id}">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 6 2 18 2 18 9"/><path d="M6 18H4a2 2 0 01-2-2v-5a2 2 0 012-2h16a2 2 0 012 2v5a2 2 0 01-2 2h-2"/><rect x="6" y="14" width="12" height="8"/></svg>
          PDF</button>` : "";

    // Admin-created meetings: show "Referred" badge instead of Approve button
    const referredBadge = `<span style="font-size:0.72rem;color:#1e40af;font-weight:600;display:inline-flex;align-items:center;gap:4px;background:#dbeafe;border:1px solid #93c5fd;border-radius:6px;padding:3px 8px;">
      <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
      Referred
    </span>`;

    // Fix 15: When cancellation is requested, show a clear prominent action instead of generic buttons
    const actionButtons = isCancelRequest
      ? `<div style="display:flex;flex-wrap:wrap;gap:4px;align-items:center;">
          <span style="font-size:0.72rem;color:#c2410c;font-weight:600;display:inline-flex;align-items:center;gap:4px;background:#fff7ed;border:1px solid #fed7aa;border-radius:6px;padding:3px 8px;">
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/></svg>
            Cancellation Requested
          </span>
          <button class="action-btn action-btn-cancel" data-action="status" data-status="Cancelled" data-meeting-id="${m.id}" style="font-weight:700;">
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>Confirm Cancel
          </button>
          <button class="action-btn action-btn-approve" data-action="status" data-status="Approved" data-meeting-id="${m.id}">
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>Deny Request
          </button>
        </div>`
      : `<div style="display:flex;flex-wrap:wrap;gap:4px;align-items:center;">
          ${isAdminCreated && m.status === "Pending" ? referredBadge : !isAdminCreated ? `<button class="action-btn action-btn-approve" data-action="status" data-status="Approved" data-meeting-id="${m.id}">
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>Approve
          </button>` : ""}
          ${!isAdminCreated ? `<button class="action-btn action-btn-reject" data-action="status" data-status="Rejected" data-meeting-id="${m.id}">
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>Reject
          </button>` : ""}
          <button class="action-btn action-btn-cancel" data-action="status" data-status="Cancelled" data-meeting-id="${m.id}">
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>Cancel
          </button>
          <button class="action-btn action-btn-done" data-action="status" data-status="Done" data-meeting-id="${m.id}">
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>Done
          </button>
          ${printBtn}
        </div>`;
    const cancelReasonCell = m.cancelReason ? `<div style="font-size:0.7rem;color:#9ca3af;margin-top:2px;font-style:italic" title="${h(m.cancelReason)}">Reason: ${h(m.cancelReason)}</div>` : "";
    const createdAt = m.createdAt ? new Date(m.createdAt) : null;
    const msElapsedAdmin = createdAt ? (new Date() - createdAt) : Infinity;
    const within24hAdmin = msElapsedAdmin < 24 * 60 * 60 * 1000;
    const msLeftAdmin = within24hAdmin ? (24 * 60 * 60 * 1000 - msElapsedAdmin) : 0;
    const hoursLeftAdmin = Math.floor(msLeftAdmin / (60 * 60 * 1000));
    const minsLeftAdmin  = Math.floor((msLeftAdmin % (60 * 60 * 1000)) / 60000);
    const adminWindowTag = (["Pending","Approved"].includes(m.status) && within24hAdmin)
      ? `<div style="margin-top:3px;display:inline-flex;align-items:center;gap:3px;font-size:0.65rem;font-weight:700;color:#16a34a;background:rgba(22,163,74,0.1);border:1px solid rgba(22,163,74,0.2);border-radius:999px;padding:1px 7px">
           <svg width="8" height="8" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
           Free cancel: ${hoursLeftAdmin > 0 ? hoursLeftAdmin + "h " : ""}${minsLeftAdmin}m left
         </div>` : "";
    return `<tr${isCancelRequest ? ' style="background:rgba(249,115,22,0.04)"' : ''}>
      <td>${h(m.eventName)}</td>
      <td>${formatDateDisplay(m.date)}</td>
      <td>${formatTimeRange(m.timeStart, m.durationHours || SLOT_DURATION_HOURS)}</td>
      <td>${h(m.type || m.meetingType || "—")}</td>
      <td>${meetingStatusBadge(m.status)}${cancelReasonCell}${adminWindowTag}</td>
      <td>${h(m.createdBy)}</td>
      <td>${actionButtons}</td>
    </tr>`;
  }).join("");

  renderPagination("admin-meetings-pagination", totalPages, adminMeetingsPage, (p) => { adminMeetingsPage = p; renderAdminMeetingsTable(); });
}

// ---------------------------------------------------------------------------
// Pagination renderer
// ---------------------------------------------------------------------------

function renderPagination(containerId, totalPages, currentPage, onPageChange) {
  const container = document.getElementById(containerId);
  if (!container) return;
  if (totalPages <= 1) { container.innerHTML = ""; return; }
  const pages = [];
  for (let i = 1; i <= totalPages; i++) {
    pages.push(`<button class="btn btn-sm ${i === currentPage ? "btn-primary" : "btn-ghost"}" data-page="${i}">${i}</button>`);
  }
  container.innerHTML = `<div style="display:flex;gap:4px;align-items:center;justify-content:flex-end;margin-top:10px;flex-wrap:wrap">
    <span style="font-size:0.75rem;color:#6b7280;margin-right:6px">Page ${currentPage} of ${totalPages}</span>
    ${pages.join("")}
  </div>`;
  container.querySelectorAll("button[data-page]").forEach(btn => {
    btn.addEventListener("click", () => onPageChange(Number(btn.dataset.page)));
  });
}

// ---------------------------------------------------------------------------
// Meeting status actions with confirmation + required note for reject
// ---------------------------------------------------------------------------

function handleAdminMeetingsClick(e) {
  const btn = e.target.closest("button[data-action]");
  if (!btn) return;

  // Prevent double-click: if already processing, ignore
  if (btn.disabled || btn.dataset.processing === "1") return;

  const action = btn.dataset.action;
  const id = btn.dataset.meetingId;
  const status = btn.dataset.status;
  const mtg = meetings.find(m => m.id === id);
  if (!mtg) return;

  if (action === "print") { generateMeetingPdf(mtg); return; }

  // Disable button row immediately to prevent double-click
  const row = btn.closest("tr");
  if (row) {
    row.querySelectorAll("button[data-action='status']").forEach(b => {
      b.disabled = true;
      b.dataset.processing = "1";
    });
  }

  const reenable = () => {
    if (row) row.querySelectorAll("button[data-action='status']").forEach(b => {
      b.disabled = false;
      b.dataset.processing = "0";
    });
  };

  const adminUser = getCurrentUser();
  const adminId = adminUser ? (adminUser.id || adminUser.username) : null;

  if (status === "Rejected" || status === "Cancelled") {
    openNoteModal(
      status === "Rejected" ? "Reject Meeting" : "Cancel Meeting",
      status === "Rejected"
        ? "Please provide a reason for rejection (required):"
        : "Please provide a reason for cancellation (required):",
      true,
      (note) => applyMeetingStatus(mtg, status, note, adminId),
      reenable
    );
  } else if (status === "Approved") {
    openNoteModal(
      "Approve Meeting",
      "Optional message to the requester:",
      false,
      (note) => applyMeetingStatus(mtg, status, note, adminId),
      reenable
    );
  } else {
    applyMeetingStatus(mtg, status, "", adminId);
  }
}

function openNoteModal(title, prompt, required, onSubmit, onCancel) {
  let modal = document.getElementById("note-modal");
  if (!modal) {
    modal = document.createElement("div");
    modal.id = "note-modal";
    modal.className = "modal-backdrop";
    modal.innerHTML = `
      <div class="modal" style="max-width:440px">
        <div class="modal-header">
          <div class="modal-title" id="note-modal-title"></div>
          <button id="note-modal-close" class="btn btn-ghost btn-sm">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
          </button>
        </div>
        <div class="modal-body section-stack" id="note-modal-body-wrap">
          <div id="note-modal-prompt" class="confirm-modal-body-inner" style="font-size:0.88rem"></div>
          <textarea id="note-modal-input" class="field" rows="3" style="resize:vertical"></textarea>
          <div id="note-modal-error" style="color:#dc2626;font-size:0.8rem;min-height:1.2em"></div>
        </div>
        <div class="modal-footer">
          <button id="note-modal-cancel" class="btn btn-ghost btn-sm">Cancel</button>
          <button id="note-modal-submit" class="btn btn-primary btn-sm">Confirm</button>
        </div>
      </div>`;
    document.body.appendChild(modal);
  }

  document.getElementById("note-modal-title").textContent = title;
  document.getElementById("note-modal-prompt").innerHTML = prompt;
  document.getElementById("note-modal-input").value = "";
  document.getElementById("note-modal-error").textContent = "";

  // Reset scroll to top every time
  const bodyWrap = document.getElementById("note-modal-body-wrap");
  if (bodyWrap) bodyWrap.scrollTop = 0;

  // Re-trigger animation
  const modalInner = modal.querySelector(".modal");
  if (modalInner) { modalInner.style.animation = "none"; requestAnimationFrame(() => { modalInner.style.animation = ""; }); }

  modal.classList.add("modal-open");

  const close = (cancelled) => {
    modal.classList.remove("modal-open");
    if (cancelled && typeof onCancel === "function") onCancel();
  };

  modal.onclick = (e) => { if (e.target === modal) close(true); };
  document.getElementById("note-modal-close").onclick = () => close(true);
  document.getElementById("note-modal-cancel").onclick = () => close(true);
  const submitBtn = document.getElementById("note-modal-submit");
  submitBtn.textContent = "";
  submitBtn.textContent = "Confirm";
  document.getElementById("note-modal-submit").onclick = () => {
    const note = document.getElementById("note-modal-input").value.trim();
    if (required && !note) {
      document.getElementById("note-modal-error").textContent = "A reason is required.";
      return;
    }
    const validationError = onSubmit(note);
    if (validationError) {
      document.getElementById("note-modal-error").textContent = validationError;
      return;
    }
    close(false);
  };
}

function applyMeetingStatus(mtg, status, note, adminId) {
  mtg.status = status;
  mtg.adminNote = note;

  if (window.api && window.api.updateMeetingStatus) {
    window.api.updateMeetingStatus(mtg.id, status, note).then(() => {});
  } else {
    persistMeetings();
  }

  // --- Notify the meeting owner (only for Approved, Rejected, Cancelled) ---
  const owner = users.find(u => u.username === mtg.createdBy) ||
                users.find(u => u.name === mtg.councilor) ||
                users.find(u => u.name === mtg.researcher);

  if (owner && status !== "Done") {
    const ownerId = owner.id || owner.username;
    const dateStr = formatDateDisplay(mtg.date);
    const timeStr = formatTimeRange(mtg.timeStart, mtg.durationHours || SLOT_DURATION_HOURS);
    const noteText = note ? ` — Admin note: "${note}"` : "";

    let message = "";
    let notifType = "info";
    // section the user should navigate to when clicking this notification
    const targetSection = "my-meetings";

    if (status === "Approved") {
      message = `Your meeting "<strong>${mtg.eventName}</strong>" on ${dateStr} at ${timeStr} has been <strong>approved</strong>.${noteText}`;
      notifType = "success";
    } else if (status === "Rejected") {
      message = `Your meeting "<strong>${mtg.eventName}</strong>" on ${dateStr} has been <strong>rejected</strong>.${noteText}`;
      notifType = "error";
    } else if (status === "Cancelled") {
      message = `Your meeting "<strong>${mtg.eventName}</strong>" on ${dateStr} has been <strong>cancelled</strong>.${noteText}`;
      notifType = "error";
    }

    if (message) addNotification(ownerId, message, notifType, targetSection);
  }

  // --- Auto-cancel conflicting pending meetings when one is approved ---
  if (status === "Approved") {
    const startMinutes = minutesFromTimeStr(mtg.timeStart);
    const endMinutes = startMinutes + (mtg.durationHours || SLOT_DURATION_HOURS) * 60;
    const sameDayPending = meetings.filter(m => {
      if (m.id === mtg.id || m.date !== mtg.date || m.status !== "Pending") return false;
      const s = minutesFromTimeStr(m.timeStart);
      const e = s + (m.durationHours || SLOT_DURATION_HOURS) * 60;
      return startMinutes < e && endMinutes > s;
    });
    sameDayPending.forEach(m => {
      m.status = "Cancelled";
      m.adminNote = "Auto-cancelled due to conflict with an approved meeting.";
      if (window.api && window.api.updateMeetingStatus) {
        window.api.updateMeetingStatus(m.id, "Cancelled", m.adminNote).then(() => {});
      }
      const conflictOwner = users.find(u => u.username === m.createdBy) ||
                            users.find(u => u.name === m.councilor);
      if (conflictOwner) {
        addNotification(
          conflictOwner.id || conflictOwner.username,
          `Your meeting "<strong>${m.eventName}</strong>" on ${formatDateDisplay(m.date)} was automatically <strong>cancelled</strong> due to a scheduling conflict with another approved meeting.`,
          "warning",
          "my-meetings"
        );
      }
    });
    if (!window.api || !window.api.updateMeetingStatus) persistMeetings();
    generateMeetingPdf(mtg);
  }

  renderAdminMeetingsTable();
  updateStatistics();
  renderCalendar();
  showToast(`Meeting marked as ${status}.`, "success");
}
function generateMeetingPdf(mtg) {
  try {
    const { jsPDF } = window.jspdf || {};
    if (!jsPDF) return;
    const doc = new jsPDF();
    doc.setFontSize(14);
    doc.text("Meeting Approval — SB Polangui", 10, 10);
    doc.setFontSize(10);
    const lines = [
      `Event: ${mtg.eventName}`, `Committee: ${mtg.committee || ""}`,
      `Councilor: ${mtg.councilor || ""}`, `Researcher: ${mtg.researcher || ""}`,
      `Date: ${formatDateDisplay(mtg.date)}`,
      `Time: ${formatTimeRange(mtg.timeStart, mtg.durationHours || SLOT_DURATION_HOURS)}`,
      `Type: ${mtg.type || mtg.meetingType || "—"}`, `Venue: ${mtg.venue || ""}`,
      `Requested By: ${mtg.createdBy}`, `Status: ${mtg.status}`,
      mtg.adminNote ? `Admin Note: ${mtg.adminNote}` : "",
    ].filter(Boolean);
    let y = 22;
    lines.forEach(t => { doc.text(t, 10, y); y += 8; });
    doc.save(`meeting-${mtg.id}.pdf`);
  } catch {}
}

function handleMyMeetingsClick(e) {
  const btn = e.target.closest("button[data-action]");
  if (!btn) return;
  if (btn.disabled || btn.dataset.processing === "1") return;

  const id = btn.dataset.meetingId;
  const action = btn.dataset.action;
  const mtg = meetings.find(m => m.id === id);
  if (!mtg) return;

  if (action === "export-pdf") {
    generateMeetingPdf(mtg);
    return;
  }

  if (action === "request-cancel") {
    btn.disabled = true;
    btn.dataset.processing = "1";
    const reenable = () => { btn.disabled = false; btn.dataset.processing = "0"; };

    const currentUser = getCurrentUser();
    const createdAt = mtg.createdAt ? new Date(mtg.createdAt) : null;
    const now = new Date();
    const within24h = createdAt && (now - createdAt) < 24 * 60 * 60 * 1000;

    // Use openNoteModal to collect a cancellation reason
    const promptHtml = within24h
      ? `<div style="margin-bottom:10px">
           <span style="display:inline-flex;align-items:center;gap:6px;background:#dcfce7;color:#166534;font-size:0.75rem;font-weight:700;padding:4px 10px;border-radius:999px;margin-bottom:8px">
             <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
             Within 24-hour free cancellation window
           </span>
           <div style="font-size:0.87rem;color:var(--color-text)">You are cancelling <strong>${h(mtg.eventName)}</strong> on <strong>${formatDateDisplay(mtg.date)}</strong>.</div>
           <div style="font-size:0.82rem;color:var(--color-text-muted);margin-top:4px">This will be cancelled immediately without admin approval. Please briefly state why:</div>
         </div>`
      : `<div style="margin-bottom:10px">
           <span style="display:inline-flex;align-items:center;gap:6px;background:#fef3c7;color:#92400e;font-size:0.75rem;font-weight:700;padding:4px 10px;border-radius:999px;margin-bottom:8px">
             <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
             24-hour window has passed — requires admin approval
           </span>
           <div style="font-size:0.87rem;color:var(--color-text)">You are requesting cancellation of <strong>${h(mtg.eventName)}</strong> on <strong>${formatDateDisplay(mtg.date)}</strong>.</div>
           <div style="font-size:0.82rem;color:var(--color-text-muted);margin-top:4px">The admin will review your request. Please state your reason:</div>
         </div>`;

    openNoteModal(
      within24h ? "Cancel Meeting" : "Request Cancellation",
      promptHtml,
      within24h ? "Cancel Meeting Now" : "Send to Admin for Review",
      (reason) => {
        if (!reason || !reason.trim()) return "Please provide a reason for cancellation.";

        if (within24h) {
          // Direct cancel — no admin needed
          mtg.status = "Cancelled";
          mtg.cancelReason = reason.trim();
          mtg.cancelledAt = new Date().toISOString();
          persistMeetings();
          renderMyMeetingsTable(currentUser);
          renderAdminMeetingsTable();
          renderCalendar();
          updateStatistics();
          showToast("Meeting cancelled successfully.", "success");
          if (window.innerWidth <= 768 && typeof _closeActive === "function") _closeActive();

          // Notify admins of the self-cancellation
          users.filter(u => u.role === ROLES.ADMIN).forEach(admin => {
            addNotification(
              admin.id || admin.username,
              `<strong>${h(currentUser.name)}</strong> cancelled their meeting <strong>"${h(mtg.eventName)}"</strong> on ${formatDateDisplay(mtg.date)} (within 24h). Reason: ${h(reason.trim())}`,
              "info",
              "meeting-logs"
            );
          });
        } else {
          // Admin-review path
          mtg.status = "Cancellation Requested";
          mtg.cancelReason = reason.trim();
          persistMeetings();
          renderMyMeetingsTable(currentUser);
          renderAdminMeetingsTable();
          renderCalendar();
          showToast("Cancellation request submitted to admin.", "info");
          if (window.innerWidth <= 768 && typeof _closeActive === "function") _closeActive();

          users.filter(u => u.role === ROLES.ADMIN).forEach(admin => {
            addNotification(
              admin.id || admin.username,
              `<strong>${h(currentUser.name)}</strong> requested cancellation of <strong>"${h(mtg.eventName)}"</strong> on ${formatDateDisplay(mtg.date)}. Reason: ${h(reason.trim())}`,
              "warning",
              "meeting-logs"
            );
          });

          addNotification(
            currentUser.id || currentUser.username,
            `Your cancellation request for <strong>"${h(mtg.eventName)}"</strong> on ${formatDateDisplay(mtg.date)} has been submitted and is pending admin review.`,
            "info",
            "my-meetings"
          );
          updateNotificationBadge(currentUser.id || currentUser.username);
        }
        return null; // no error
      },
      reenable
    );
  }
}

// ---------------------------------------------------------------------------
// Calendar rendering
// ---------------------------------------------------------------------------

function initCalendarDate() {
  const now = getManilaNow();
  calendarYear = now.getFullYear();
  calendarMonth = now.getMonth();
  // Pre-load holidays for current and next year
  loadPHHolidays(calendarYear).then(() => renderCalendar());
  loadPHHolidays(calendarYear + 1);
}

function jumpToToday() {
  const now = getManilaNow();
  calendarYear = now.getFullYear();
  calendarMonth = now.getMonth();
  loadPHHolidays(calendarYear).then(() => renderCalendar());
}

function changeCalendarMonth(offset) {
  calendarMonth += offset;
  if (calendarMonth < 0) { calendarMonth = 11; calendarYear -= 1; }
  else if (calendarMonth > 11) { calendarMonth = 0; calendarYear += 1; }
  // Lazy-load holidays for the newly displayed year
  loadPHHolidays(calendarYear).then(() => renderCalendar());
}

function renderCalendar() {
  const grid = $("#calendar-grid");
  const monthLabel = $("#calendar-month");
  const yearLabel = $("#calendar-year");
  if (!grid || calendarYear == null) return;

  const monthNames = ["January","February","March","April","May","June","July","August","September","October","November","December"];
  if (monthLabel) monthLabel.textContent = monthNames[calendarMonth];
  if (yearLabel) yearLabel.textContent = calendarYear;

  const first = new Date(calendarYear, calendarMonth, 1);
  const startWeekday = first.getDay();
  const daysInMonth = new Date(calendarYear, calendarMonth + 1, 0).getDate();

  grid.innerHTML = "";

  // Empty leading cells
  for (let i = 0; i < startWeekday; i++) {
    const empty = document.createElement("div");
    empty.className = "calendar-cell calendar-cell-muted";
    grid.appendChild(empty);
  }

  const currentUser = getCurrentUser();
  const todayISO = getTodayISOManila();

  for (let day = 1; day <= daysInMonth; day++) {
    const dateObj = new Date(calendarYear, calendarMonth, day);
    const isoDate = `${calendarYear}-${String(calendarMonth+1).padStart(2,"0")}-${String(day).padStart(2,"0")}`;

    const isPast = isoDate < todayISO;
    const isToday = isoDate === todayISO;
    const isWorkday = !isWeekend(dateObj);
    const holidayInfo = getHolidayInfo(isoDate);
    const isHoliday = !!holidayInfo;

    const cell = document.createElement("button");
    cell.type = "button";
    cell.className = "calendar-cell";
    if (isToday) cell.classList.add("calendar-cell-today");
    if (isHoliday) cell.classList.add("calendar-cell-holiday");

    // ── Cell header: date number + holiday/weekend label ──
    const header = document.createElement("div");
    header.className = "calendar-cell-header";

    const dateSpan = document.createElement("span");
    dateSpan.className = "calendar-cell-date";
    dateSpan.textContent = day;
    header.appendChild(dateSpan);

    if (isHoliday) {
      const hol = document.createElement("span");
      hol.className = "calendar-holiday-label";
      hol.textContent = holidayInfo.localName || "Holiday";
      hol.title = holidayInfo.name || holidayInfo.localName || "Public Holiday";
      header.appendChild(hol);
    } else if (!isWorkday) {
      const wknd = document.createElement("span");
      wknd.className = "calendar-weekend-label";
      wknd.textContent = dateObj.getDay() === 0 ? "Sun" : "Sat";
      header.appendChild(wknd);
    }
    cell.appendChild(header);

    // ── Meetings for this day ──
    const dayMeetings = meetings.filter(m => m.date === isoDate);
    const dayHistory = (historyEntries || []).filter(h => {
      if (h && h.date && typeof h.date.toDate === "function") {
        const d = h.date.toDate();
        const iso = `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,"0")}-${String(d.getDate()).padStart(2,"0")}`;
        return iso === isoDate;
      }
      if (h && typeof h.date === "string") return h.date === isoDate;
      return false;
    });

    const activeMeetings = dayMeetings
      .filter(m => ["Approved","Pending","Cancellation Requested"].includes(m.status))
      .sort((a, b) => (a.timeStart || "").localeCompare(b.timeStart || ""));

    const MAX_BADGES = 2;
    activeMeetings.slice(0, MAX_BADGES).forEach(m => {
      const isAdminCreated = m.createdByRole === ROLES.ADMIN;
      // "Mine" = the logged-in user created this meeting OR is the assigned councilor/researcher
      const isMine = currentUser && (
        m.createdBy === currentUser.username ||
        m.councilor === currentUser.name ||
        m.researcher === currentUser.name
      );
      const badge = document.createElement("div");
      badge.className = statusColorForCalendar(m.status, isAdminCreated, isMine);
      if (isMine) badge.classList.add("calendar-badge-is-mine"); // extra hook for CSS ring
      const timeLabel = m.timeStart ? `${formatTime12h(minutesFromTimeStr(m.timeStart))} ` : "";
      badge.textContent = timeLabel + (m.eventName || "Meeting");
      badge.title = `${h(m.eventName)} — ${formatTimeRange(m.timeStart, m.durationHours || SLOT_DURATION_HOURS)} [${m.status}]${isMine ? " · Your meeting" : ""}${isAdminCreated ? " · Admin scheduled" : ""}`;
      cell.appendChild(badge);
    });

    if (activeMeetings.length > MAX_BADGES) {
      const more = document.createElement("div");
      more.className = "calendar-badge calendar-badge-more";
      more.textContent = `+${activeMeetings.length - MAX_BADGES} more`;
      cell.appendChild(more);
    }

    // Show archived if no active meetings
    if (dayHistory.length && activeMeetings.length === 0) {
      const block = document.createElement("div");
      block.className = "calendar-badge";
      block.style.background = dayHistory[0].color || "#9ca3af";
      block.style.color = "#fff";
      block.textContent = "Archived";
      block.title = "Archived — read-only";
      cell.appendChild(block);
    }

    // ── Mobile dot indicators (visible only via CSS on small screens) ──
    if (activeMeetings.length || dayHistory.length) {
      const dotsRow = document.createElement("div");
      dotsRow.className = "calendar-cell-dots";

      const isFullBooked = dayMeetings
        .filter(m => m.status === "Approved")
        .reduce((s, m) => s + (m.durationHours || SLOT_DURATION_HOURS) * 60, 0) >= (WORK_END_HOUR - WORK_START_HOUR) * 60;

      if (isFullBooked && isWorkday && !isHoliday) {
        const dot = document.createElement("div");
        dot.className = "calendar-dot calendar-dot-full";
        dotsRow.appendChild(dot);
      } else {
        // One dot per unique status (max 3)
        const statusMap = { "Approved": "approved", "Pending": "pending", "Cancelled": "cancelled", "Rejected": "cancelled" };
        const seen = new Set();
        activeMeetings.slice(0, 3).forEach(m => {
          const cls = statusMap[m.status] || "other";
          if (!seen.has(cls)) {
            seen.add(cls);
            const dot = document.createElement("div");
            dot.className = `calendar-dot calendar-dot-${cls}`;
            dotsRow.appendChild(dot);
          }
        });
        if (dayHistory.length && activeMeetings.length === 0) {
          const dot = document.createElement("div");
          dot.className = "calendar-dot calendar-dot-other";
          dotsRow.appendChild(dot);
        }
      }
      cell.appendChild(dotsRow);
    }

    // ── Fully booked indicator ──
    const approvedMins = dayMeetings
      .filter(m => m.status === "Approved")
      .reduce((s, m) => s + (m.durationHours || SLOT_DURATION_HOURS) * 60, 0);
    const workMins = (WORK_END_HOUR - WORK_START_HOUR) * 60;
    if (approvedMins >= workMins && isWorkday && !isHoliday) {
      cell.classList.add("calendar-cell-full");
      const fullBadge = document.createElement("div");
      fullBadge.className = "calendar-full-badge";
      fullBadge.textContent = "Full";
      cell.appendChild(fullBadge);
    }

    // ── Interactivity ──
    const canInteract = currentUser &&
      [ROLES.ADMIN, ROLES.COUNCILOR, ROLES.RESEARCHER, ROLES.VICE_MAYOR, ROLES.SECRETARY].includes(currentUser.role);

    if (isPast || isHoliday || !isWorkday) {
      cell.classList.add("calendar-cell-muted");
      cell.disabled = true;
      // Still allow clicking past days or holidays to VIEW schedule
      if ((dayMeetings.length || dayHistory.length || isHoliday) && !isPast) {
        cell.disabled = false;
        cell.classList.remove("calendar-cell-muted");
        cell.classList.add("calendar-cell-readonly");
        cell.addEventListener("click", () => openDayScheduleModal(isoDate, true));
      }
    } else if (canInteract) {
      cell.addEventListener("click", () => openDayScheduleModal(isoDate, false));
    } else {
      cell.classList.add("calendar-cell-muted");
      cell.disabled = true;
    }

    grid.appendChild(cell);
  }
}

// ---------------------------------------------------------------------------
// Day Schedule Modal
// ---------------------------------------------------------------------------

function openDayScheduleModal(isoDate, readOnly) {
  const currentUser = getCurrentUser();
  const canBook = !readOnly && currentUser &&
    [ROLES.ADMIN, ROLES.COUNCILOR, ROLES.RESEARCHER, ROLES.VICE_MAYOR, ROLES.SECRETARY].includes(currentUser.role);

  if (window.innerWidth <= 768) { openDayDrawer(isoDate, canBook); return; }

  let modal = document.getElementById("day-schedule-modal");
  if (!modal) {
    modal = document.createElement("div");
    modal.id = "day-schedule-modal";
    modal.className = "modal-backdrop";
    modal.innerHTML = `
      <div class="modal" style="max-width:600px">
        <div class="modal-header" style="flex-direction:column;align-items:flex-start;gap:4px;flex-shrink:0">
          <div style="display:flex;align-items:center;justify-content:space-between;width:100%">
            <div class="modal-title" id="day-modal-title"></div>
            <button id="day-modal-close" class="btn btn-ghost btn-sm">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
            </button>
          </div>
          <div id="day-modal-subtitle" style="font-size:0.78rem;margin-top:2px"></div>
        </div>
        <div id="day-schedule-body" style="flex:1;min-height:0;overflow-y:auto;padding:16px 20px"></div>
        <div class="modal-footer" id="day-modal-footer" style="flex-shrink:0"></div>
      </div>`;
    document.body.appendChild(modal);
    document.getElementById("day-modal-close").addEventListener("click", () => modal.classList.remove("modal-open"));
    modal.addEventListener("click", e => { if (e.target === modal) modal.classList.remove("modal-open"); });
  }

  const d = new Date(isoDate + "T00:00:00");
  const dateDisplay = d.toLocaleDateString("en-PH", { weekday:"long", year:"numeric", month:"long", day:"numeric" });
  document.getElementById("day-modal-title").textContent = dateDisplay;

  // Holiday banner
  const holidayInfo = getHolidayInfo(isoDate);
  const subtitle = document.getElementById("day-modal-subtitle");
  if (holidayInfo) {
    subtitle.innerHTML = `<span style="display:inline-flex;align-items:center;gap:6px;background:#fef3c7;color:#92400e;border-radius:6px;padding:3px 10px;font-size:0.78rem;font-weight:600;"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="flex-shrink:0"><circle cx="12" cy="12" r="10"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/><line x1="2" y1="12" x2="22" y2="12"/></svg> PH Holiday: ${holidayInfo.localName}${holidayInfo.name !== holidayInfo.localName ? ` — ${holidayInfo.name}` : ""}</span>`;
  } else {
    subtitle.innerHTML = "";
  }

  const dayMeetings = meetings.filter(m => m.date === isoDate)
    .sort((a, b) => (a.timeStart || "").localeCompare(b.timeStart || ""));
  const approvedMeetings = dayMeetings.filter(m => m.status === "Approved");
  const approvedMins = approvedMeetings.reduce((s, m) => s + (m.durationHours || SLOT_DURATION_HOURS) * 60, 0);
  const workMins = (WORK_END_HOUR - WORK_START_HOUR) * 60;
  const isFullyBooked = approvedMins >= workMins;

  // ── Time slot visual timeline ──
  // Build timeline
  const timelineHtml = buildTimelineHTML(isoDate, dayMeetings);

  // Meeting list
  const STATUS_STYLE = {
    "Approved":               { bg:"#dcfce7", border:"#16a34a", text:"#166534" },
    "Pending":                { bg:"#fef3c7", border:"#f59e0b", text:"#92400e" },
    "Cancelled":              { bg:"#f3f4f6", border:"#d1d5db", text:"#9ca3af" },
    "Rejected":               { bg:"#f3f4f6", border:"#d1d5db", text:"#9ca3af" },
    "Done":                   { bg:"#dbeafe", border:"#3b82f6", text:"#1e40af" },
    "Cancellation Requested": { bg:"#fff7ed", border:"#f97316", text:"#c2410c" },
  };

  let meetingListHtml = "";
  if (!dayMeetings.length) {
    meetingListHtml = `<div style="text-align:center;padding:20px 0;color:var(--color-text-muted);font-size:0.84rem">
      <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="display:block;margin:0 auto 8px;opacity:.4"><rect x="3" y="4" width="18" height="18" rx="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/></svg>
      No meetings scheduled for this day.
    </div>`;
  } else {
    const statusNote = isFullyBooked
      ? `<div style="background:#fee2e2;border:1px solid #fca5a5;border-radius:8px;padding:8px 12px;font-size:0.8rem;color:#991b1b;font-weight:600;margin-bottom:10px;display:flex;align-items:center;gap:6px"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg> This day is fully booked — no available time slots.</div>`
      : approvedMeetings.length
        ? `<div style="background:#fef3c7;border:1px solid #fcd34d;border-radius:8px;padding:8px 12px;font-size:0.8rem;color:#92400e;font-weight:500;margin-bottom:10px;display:flex;align-items:center;gap:6px"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg> Some slots are taken — check the timeline above before booking.</div>`
        : "";

    meetingListHtml = statusNote + `<div style="font-size:0.71rem;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:var(--color-text-muted);margin-bottom:8px">Meetings (${dayMeetings.length})</div>
      <div style="display:flex;flex-direction:column;gap:7px">
        ${dayMeetings.map(m => {
          const c = STATUS_STYLE[m.status] || STATUS_STYLE["Cancelled"];
          const timeRange = m.timeStart ? formatTimeRange(m.timeStart, m.durationHours || SLOT_DURATION_HOURS) : "—";
          const isAdminCreated = m.createdByRole === ROLES.ADMIN;
          return `<div style="background:${c.bg};border:1px solid ${c.border};border-left:4px solid ${isAdminCreated ? "#1d4ed8" : c.border};border-radius:8px;padding:10px 12px">
            <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:8px">
              <div style="min-width:0">
                <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap">
                  <div style="font-weight:600;font-size:0.85rem;color:${c.text};overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${h(m.eventName) || "Meeting"}</div>
                  ${isAdminCreated ? `<span style="font-size:0.65rem;font-weight:700;background:#dbeafe;color:#1e40af;border:1px solid #93c5fd;border-radius:4px;padding:1px 6px;white-space:nowrap;flex-shrink:0;">Admin Scheduled</span>` : ""}
                </div>
                <div style="font-size:0.75rem;color:${c.text};opacity:.85;margin-top:3px;display:flex;flex-wrap:wrap;gap:6px">
                  <span style="display:inline-flex;align-items:center;gap:3px"><svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>${timeRange}</span>
                  <span style="display:inline-flex;align-items:center;gap:3px"><svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 22s-8-4.5-8-11.8A8 8 0 0 1 12 2a8 8 0 0 1 8 8.2c0 7.3-8 11.8-8 11.8z"/><path d="M12 7v5l3 3"/></svg>${m.durationHours || SLOT_DURATION_HOURS}h</span>
                  ${m.venue ? `<span style="display:inline-flex;align-items:center;gap:3px"><svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"/><circle cx="12" cy="10" r="3"/></svg>${h(m.venue)}</span>` : ""}
                </div>
                ${m.councilor ? `<div style="font-size:0.72rem;color:${c.text};opacity:.7;margin-top:3px;display:flex;align-items:center;gap:3px"><svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="8" r="4"/><path d="M4 20c0-4 3.6-7 8-7s8 3 8 7"/></svg>${h(m.councilor)}</div>` : ""}
                ${m.committee ? `<div style="font-size:0.72rem;color:${c.text};opacity:.7;display:flex;align-items:center;gap:3px"><svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><rect x="2" y="7" width="20" height="14" rx="1"/><path d="M16 7V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v2"/></svg>${h(m.committee)}</div>` : ""}
                ${m.adminNote ? `<div style="font-size:0.7rem;color:${c.text};opacity:.65;margin-top:4px;font-style:italic;display:flex;align-items:center;gap:3px"><svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"/></svg>${h(m.adminNote)}</div>` : ""}
              </div>
              <span style="flex-shrink:0;font-size:0.68rem;font-weight:700;background:white;color:${c.text};border:1px solid ${c.border};padding:2px 8px;border-radius:999px;white-space:nowrap">${m.status}</span>
            </div>
          </div>`;
        }).join("")}
      </div>`;
  }

  const body = document.getElementById("day-schedule-body");
  const footer = document.getElementById("day-modal-footer");

  body.scrollTop = 0;
  body.innerHTML = timelineHtml + meetingListHtml;

  // Re-trigger animation
  const modalInner = modal.querySelector(".modal");
  if (modalInner) { modalInner.style.animation = "none"; requestAnimationFrame(() => { modalInner.style.animation = ""; }); }

  // Footer
  if (canBook && !isFullyBooked && !holidayInfo) {
    footer.innerHTML = `
      <button id="day-modal-cancel-btn" class="btn btn-ghost btn-sm">Close</button>
      <button id="day-modal-book-btn" class="btn btn-primary btn-sm">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
        Book a Meeting
      </button>`;
    requestAnimationFrame(() => {
      document.getElementById("day-modal-book-btn")?.addEventListener("click", () => {
        modal.classList.remove("modal-open");
        openMeetingModal(isoDate);
      });
      document.getElementById("day-modal-cancel-btn")?.addEventListener("click", () => modal.classList.remove("modal-open"));
    });
  } else {
    const reason = holidayInfo ? "Philippine Holiday — no bookings allowed" : isFullyBooked ? "No available time slots" : "";
    footer.innerHTML = `
      ${reason ? `<div style="font-size:0.78rem;color:var(--color-text-muted);flex:1">${reason}</div>` : ""}
      <button class="btn btn-ghost btn-sm" id="day-modal-close-footer">Close</button>`;
    requestAnimationFrame(() => {
      document.getElementById("day-modal-close-footer")?.addEventListener("click", () => modal.classList.remove("modal-open"));
    });
  }

  modal.classList.add("modal-open");
}

// Build visual horizontal timeline 8AM–5PM with blocked slots highlighted
function buildTimelineHTML(isoDate, dayMeetings) {
  const approved = dayMeetings.filter(m => m.status === "Approved");
  const pending  = dayMeetings.filter(m => m.status === "Pending");
  const totalWork = (WORK_END_HOUR - WORK_START_HOUR) * 60; // 540 min

  function pct(mins) { return ((mins - WORK_START_HOUR * 60) / totalWork * 100).toFixed(2); }
  function wPct(mins) { return (mins / totalWork * 100).toFixed(2); }

  // Hour ticks (lines inside bar) and labels (outside bar, below)
  const tickLines = [];
  const tickLabels = [];
  for (let hr = WORK_START_HOUR; hr <= WORK_END_HOUR; hr++) {
    tickLines.push(`<div style="position:absolute;left:${pct(hr*60)}%;top:0;bottom:0;border-left:1px dashed rgba(0,0,0,0.1);pointer-events:none"></div>`);
    tickLabels.push(`<div style="position:absolute;left:${pct(hr*60)}%;font-size:0.58rem;color:var(--color-text-muted);transform:translateX(-50%)">${hr < 12 ? hr + 'a' : hr === 12 ? '12p' : (hr - 12) + 'p'}</div>`);
  }
  const ticks = tickLines; // only lines go inside the bar now

  // Approved blocks (solid red)
  const approvedBlocks = approved.map(m => {
    const s = minutesFromTimeStr(m.timeStart);
    const dur = (m.durationHours || SLOT_DURATION_HOURS) * 60;
    return `<div title="${h(m.eventName)} (Approved)" style="position:absolute;left:${pct(s)}%;width:${wPct(dur)}%;top:4px;bottom:4px;background:#16a34a;border-radius:4px;opacity:0.85;cursor:default"></div>`;
  }).join("");

  // Pending blocks (amber)
  const pendingBlocks = pending.map(m => {
    const s = minutesFromTimeStr(m.timeStart);
    const dur = (m.durationHours || SLOT_DURATION_HOURS) * 60;
    return `<div title="${h(m.eventName)} (Pending)" style="position:absolute;left:${pct(s)}%;width:${wPct(dur)}%;top:4px;bottom:4px;background:#f59e0b;border-radius:4px;opacity:0.75;cursor:default"></div>`;
  }).join("");

  return `
    <div style="margin-bottom:16px">
      <div style="font-size:0.71rem;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:var(--color-text-muted);margin-bottom:8px">Time Slots (8AM – 5PM)</div>
      <div style="position:relative;height:32px;background:var(--color-bg);border:1px solid var(--color-border);border-radius:8px;overflow:hidden;margin-bottom:6px">
        ${ticks.join("")}
        ${approvedBlocks}
        ${pendingBlocks}
      </div>
      <div style="position:relative;height:14px;margin-bottom:10px">${tickLabels.join("")}</div>
      <div style="display:flex;gap:12px;flex-wrap:wrap;margin-top:-14px">
        <div style="display:flex;align-items:center;gap:5px;font-size:0.72rem;color:var(--color-text-muted)">
          <span style="width:12px;height:10px;border-radius:3px;background:#16a34a;display:inline-block"></span> Approved
        </div>
        <div style="display:flex;align-items:center;gap:5px;font-size:0.72rem;color:var(--color-text-muted)">
          <span style="width:12px;height:10px;border-radius:3px;background:#f59e0b;display:inline-block"></span> Pending
        </div>
        <div style="display:flex;align-items:center;gap:5px;font-size:0.72rem;color:var(--color-text-muted)">
          <span style="width:12px;height:10px;border-radius:3px;background:var(--color-bg);border:1px solid var(--color-border);display:inline-block"></span> Available
        </div>
      </div>
    </div>`;
}

// ---------------------------------------------------------------------------
// Booking Modal
// ---------------------------------------------------------------------------

// populateTimeOptions defined above with conflict-aware logic

// ---------------------------------------------------------------------------
// Smart Councilor / Researcher field setup
// Admin → both show as dropdowns (lists registered accounts + N/A option)
// Councilor → councilor field is auto-filled & locked; researcher is dropdown
// Researcher → researcher field is auto-filled & locked; councilor is dropdown
// Vice Mayor / Secretary → both show as dropdowns
// ---------------------------------------------------------------------------
function _setupCouncilorResearcherFields(currentUser) {
  const cSelect = $("#meeting-councilor-select");
  const rSelect = $("#meeting-researcher-select");
  const cInput  = $("#meeting-councilor");
  const rInput  = $("#meeting-researcher");
  if (!cSelect || !rSelect || !cInput || !rInput) return;

  const isAdmin = currentUser.role === ROLES.ADMIN;
  const isCouncilor  = currentUser.role === ROLES.COUNCILOR;
  const isResearcher = currentUser.role === ROLES.RESEARCHER;

  // Gather registered users
  const councilors = users.filter(u => u.role === ROLES.COUNCILOR || u.role === ROLES.VICE_MAYOR);
  const researchers = users.filter(u => u.role === ROLES.RESEARCHER);

  // Helper: rebuild a <select> with given user list + N/A
  function fillSelect(sel, userList, placeholder) {
    // Keep first two options (placeholder + N/A)
    while (sel.options.length > 2) sel.remove(2);
    userList.forEach(u => {
      const opt = document.createElement("option");
      opt.value = u.name || u.username;
      opt.textContent = `${u.name || u.username} (${u.role})`;
      sel.appendChild(opt);
    });
  }

  fillSelect(cSelect, councilors, "— Select Councilor —");
  fillSelect(rSelect, researchers, "— Select Researcher —");

  // Reset visibility
  cSelect.style.display = "none"; cInput.style.display = "";
  rSelect.style.display = "none"; rInput.style.display = "";
  cInput.readOnly = false; rInput.readOnly = false;
  cInput.required = false; rInput.required = false;  // never put required on potentially-hidden inputs
  cSelect.required = false; rSelect.required = false;
  cInput.value = ""; rInput.value = "";
  cSelect.value = ""; rSelect.value = "";

  if (isCouncilor) {
    // Councilor: lock own name in councilor input, show researcher dropdown
    cInput.value = currentUser.name;
    cInput.readOnly = true;
    rInput.style.display = "none";
    rSelect.style.display = "";
    rSelect.value = "";
  } else if (isResearcher) {
    // Researcher: lock own name in researcher input, show councilor dropdown
    rInput.value = currentUser.name;
    rInput.readOnly = true;
    cInput.style.display = "none";
    cSelect.style.display = "";
    cSelect.value = "";
  } else {
    // Admin / Vice Mayor / Secretary: both as dropdowns
    cInput.style.display = "none"; cSelect.style.display = "";
    rInput.style.display = "none"; rSelect.style.display = "";
  }
}

// Read the effective councilor/researcher values from either select or input
function _getCouncilorValue() {
  const sel = $("#meeting-councilor-select");
  const inp = $("#meeting-councilor");
  if (sel && sel.style.display !== "none") return sel.value === "N/A" ? "N/A" : sel.value;
  return inp ? inp.value.trim() : "";
}
function _getResearcherValue() {
  const sel = $("#meeting-researcher-select");
  const inp = $("#meeting-researcher");
  if (sel && sel.style.display !== "none") return sel.value === "N/A" ? "N/A" : sel.value;
  return inp ? inp.value.trim() : "";
}

function openMeetingModal(isoDate) {
  const currentUser = getCurrentUser();
  if (!currentUser || ![ROLES.ADMIN, ROLES.COUNCILOR, ROLES.RESEARCHER, ROLES.VICE_MAYOR, ROLES.SECRETARY].includes(currentUser.role)) {
    showToast("Only authorized roles may book meetings.", "warning");
    return;
  }

  if (window.innerWidth <= 768) { openBookingDrawer(isoDate); return; }

  const todayISO = getTodayISOManila();
  $("#meeting-form").reset();
  $("#meeting-form-message").textContent = "";
  $("#meeting-modal-title").textContent = "Schedule Meeting";

  const dateInput = $("#meeting-date");
  if (dateInput) dateInput.min = todayISO;

  if (isoDate) {
    if (isoDate < todayISO) { showToast("Cannot schedule meetings on past dates.", "error"); return; }
    $("#meeting-date").value = isoDate;
  } else if (dateInput) {
    dateInput.value = todayISO;
  }

  // ── Smart Councilor / Researcher fields ───────────────────────────────
  _setupCouncilorResearcherFields(currentUser);

  // Reset other/venue inputs
  const typeOther = $("#meeting-type-other");
  const venueOther = $("#meeting-venue-other");
  if (typeOther) typeOther.style.display = "none";
  if (venueOther) venueOther.style.display = "none";

  const backdrop = $("#meeting-modal");
  if (backdrop) backdrop.classList.add("modal-open");
  populateDurationOptions();
  const activeDate = isoDate || todayISO;
  populateTimeOptions(activeDate);
  recalcDurationOptionsBasedOnStart(activeDate);
  updateEndTimePreview();

  // When date changes, refresh time slots
  const dateInput2 = $("#meeting-date");
  if (dateInput2) {
    dateInput2.onchange = () => {
      const d = dateInput2.value;
      populateTimeOptions(d);
      recalcDurationOptionsBasedOnStart(d);
      updateEndTimePreview();
    };
  }
}

function closeMeetingModal() {
  const backdrop = $("#meeting-modal");
  if (backdrop) backdrop.classList.remove("modal-open");
}

// ---------------------------------------------------------------------------
// Policy modal state — holds pending meeting data while user reads policies
// ---------------------------------------------------------------------------
let _pendingMeetingData = null;

function openPolicyModal(meetingData) {
  _pendingMeetingData = meetingData;
  // Fill summary
  const summary = document.getElementById("policy-meeting-summary");
  if (summary) {
    summary.innerHTML = `
      <div class="policy-summary-grid">
        <div class="policy-summary-item">
          <div class="policy-summary-label">Event</div>
          <div class="policy-summary-val">${h(meetingData.eventName)}</div>
        </div>
        <div class="policy-summary-item">
          <div class="policy-summary-label">Date</div>
          <div class="policy-summary-val">${formatDateDisplay(meetingData.date)}</div>
        </div>
        <div class="policy-summary-item">
          <div class="policy-summary-label">Time</div>
          <div class="policy-summary-val">${formatTimeRange(meetingData.timeStart, meetingData.durationHours)}</div>
        </div>
        <div class="policy-summary-item">
          <div class="policy-summary-label">Type</div>
          <div class="policy-summary-val">${h(meetingData.type)}</div>
        </div>
      </div>`;
  }
  // Reset checkbox
  const chk = document.getElementById("policy-agree-check");
  if (chk) chk.checked = false;
  const err = document.getElementById("policy-agree-error");
  if (err) err.textContent = "";
  // Open
  const backdrop = document.getElementById("policy-modal");
  if (backdrop) backdrop.classList.add("modal-open");
}

function closePolicyModal() {
  const backdrop = document.getElementById("policy-modal");
  if (backdrop) backdrop.classList.remove("modal-open");
}

function submitMeetingFromPolicy() {
  const chk = document.getElementById("policy-agree-check");
  const err = document.getElementById("policy-agree-error");
  if (!chk || !chk.checked) {
    if (err) err.textContent = "Please check the box to agree before submitting.";
    const lbl = document.getElementById("policy-agree-label");
    if (lbl) { lbl.style.animation = "none"; lbl.offsetWidth; lbl.style.animation = "policy-shake 0.35s ease"; }
    return;
  }
  if (err) err.textContent = "";
  closePolicyModal();

  const d = _pendingMeetingData;
  if (!d) return;
  _pendingMeetingData = null;

  const currentUser = getCurrentUser();
  if (!currentUser) return;

  const meeting = {
    id: `mtg_${Math.random().toString(36).slice(2, 9)}`,
    eventName: d.eventName,
    committee: d.committee,
    venue: d.venue,
    councilor: d.councilor,
    researcher: d.researcher,
    stakeholders: d.stakeholders,
    notes: d.notes,
    date: d.date,
    timeStart: d.timeStart,
    durationHours: d.durationHours,
    type: d.type,
    status: currentUser.role === ROLES.ADMIN ? "Approved" : "Pending",
    createdBy: currentUser.username,
    createdByRole: currentUser.role,
    createdAt: new Date().toISOString(),
  };

  if (window.api && window.api.addMeeting) {
    window.api.addMeeting(meeting).then(() => {});
  } else {
    meetings.push(meeting);
    persistMeetings();
  }

  // Notify all admins
  // Only notify admins if a non-admin submitted the request
  if (currentUser.role !== ROLES.ADMIN) {
    users.filter(u => u.role === ROLES.ADMIN).forEach(admin => {
      addNotification(
        admin.id || admin.username,
        `New meeting request from <strong>${currentUser.name}</strong>: <strong>"${d.eventName}"</strong> on ${formatDateDisplay(d.date)} at ${formatTimeRange(d.timeStart, d.durationHours)}. Review and take action.`,
        "info",
        "meeting-logs"
      );
    });
  }

  // If admin created this meeting, notify the assigned councilor and/or researcher
  if (currentUser.role === ROLES.ADMIN) {
    const dateStr = formatDateDisplay(d.date);
    const timeStr = formatTimeRange(d.timeStart, d.durationHours);
    if (d.councilor && d.councilor !== "N/A") {
      const cUser = users.find(u => u.name === d.councilor);
      if (cUser) {
        addNotification(
          cUser.id || cUser.username,
          `The Admin has scheduled a meeting on your behalf: <strong>"${d.eventName}"</strong> on ${dateStr} at ${timeStr}. Venue: ${d.venue}. Status: <strong>Approved</strong>.`,
          "success",
          "my-meetings"
        );
      }
    }
    if (d.researcher && d.researcher !== "N/A") {
      const rUser = users.find(u => u.name === d.researcher);
      if (rUser) {
        addNotification(
          rUser.id || rUser.username,
          `The Admin has scheduled a meeting on your behalf: <strong>"${d.eventName}"</strong> on ${dateStr} at ${timeStr}. Venue: ${d.venue}. Status: <strong>Approved</strong>.`,
          "success",
          "my-meetings"
        );
      }
    }
  }

  const toastMsg = currentUser.role === ROLES.ADMIN
    ? "Meeting scheduled and automatically approved."
    : "Meeting request submitted successfully.";
  showToast(toastMsg, "success");
  renderCalendar();
  renderMyMeetingsTable(currentUser);
  renderAdminMeetingsTable();
  updateStatistics();
}

function handleMeetingSubmit(e) {
  e.preventDefault();
  const msg = $("#meeting-form-message");
  const currentUser = getCurrentUser();
  if (!currentUser) return;

  const eventName   = $("#meeting-event")?.value.trim() || "";
  const committee   = $("#meeting-committee")?.value.trim() || "";
  const councilor   = _getCouncilorValue();
  const researcher  = _getResearcherValue();
  const stakeholders = $("#meeting-stakeholders")?.value.trim() || "";
  const notes       = $("#meeting-notes")?.value.trim() || "";
  const isoDate     = $("#meeting-date")?.value || "";
  const timeStart   = $("#meeting-time")?.value || "";
  const durationEl  = $("#meeting-duration");
  const durationHours = durationEl ? parseInt(durationEl.value || "3", 10) : SLOT_DURATION_HOURS;

  const typeRaw   = $("#meeting-type")?.value || "";
  const typeOther = $("#meeting-type-other")?.value.trim() || "";
  const venueRaw  = $("#meeting-venue")?.value || "";
  const venueOther = $("#meeting-venue-other")?.value.trim() || "";

  let type = typeRaw || "Committee Meeting";
  if (typeRaw === "Others") {
    if (!typeOther) { msg.textContent = "Please specify the type of meeting."; showToast("Please specify meeting type.", "error"); return; }
    type = typeOther;
  }

  let venue = venueRaw;
  if (venueRaw === "Others") {
    if (!venueOther) { msg.textContent = "Please specify the venue."; showToast("Please specify venue.", "error"); return; }
    venue = venueOther;
  }

  if (!eventName || !committee || !venue) {
    msg.textContent = "Please complete all required fields (*).";
    showToast("Please complete all required fields.", "error");
    return;
  }
  if (!councilor) {
    msg.textContent = "Please select a Councilor or choose N/A.";
    showToast("Please select a Councilor or choose N/A.", "error");
    return;
  }
  if (!researcher) {
    msg.textContent = "Please select a Researcher or choose N/A.";
    showToast("Please select a Researcher or choose N/A.", "error");
    return;
  }
  if (councilor === "N/A" && researcher === "N/A") {
    msg.textContent = "Councilor and Researcher cannot both be N/A.";
    showToast("At least one of Councilor or Researcher is required.", "error");
    return;
  }
  if (!isoDate || !timeStart) { msg.textContent = "Date and start time are required."; showToast("Date and start time are required.", "error"); return; }

  const dateObj = new Date(isoDate);
  if (isNaN(dateObj.getTime())) { msg.textContent = "Invalid date selected."; return; }

  const todayISO = getTodayISOManila();
  if (isoDate < todayISO) { msg.textContent = "Cannot schedule meetings on past dates."; showToast("Cannot use past dates.", "error"); return; }
  if (isWeekend(dateObj)) { msg.textContent = "Meetings can only be scheduled Monday to Friday."; showToast("Weekends are not bookable.", "error"); return; }
  if (isHolidayISO(isoDate)) { msg.textContent = "Selected date is a Philippine holiday."; showToast("Selected date is a Philippine holiday.", "error"); return; }

  const startMinutes = minutesFromTimeStr(timeStart);
  const endMinutes   = startMinutes + durationHours * 60;
  if (startMinutes < WORK_START_HOUR * 60 || endMinutes > WORK_END_HOUR * 60) {
    msg.textContent = "Meeting must be within office hours (8:00 AM – 5:00 PM).";
    showToast("Meeting must be within office hours.", "error");
    return;
  }

  const conflictingApproved = meetings.find(m => {
    if (m.date !== isoDate || m.status !== "Approved") return false;
    const s = minutesFromTimeStr(m.timeStart);
    const e2 = s + (m.durationHours || SLOT_DURATION_HOURS) * 60;
    return startMinutes < e2 && endMinutes > s;
  });
  if (conflictingApproved) {
    const ct = formatTimeRange(conflictingApproved.timeStart, conflictingApproved.durationHours || SLOT_DURATION_HOURS);
    msg.textContent = `Time overlaps with approved meeting: "${conflictingApproved.eventName}" (${ct}). Please choose another slot.`;
    showToast("Conflict with approved meeting.", "error");
    populateTimeOptions(isoDate);
    return;
  }

  const conflictingPending = meetings.find(m => {
    if (m.date !== isoDate || m.status !== "Pending") return false;
    const s = minutesFromTimeStr(m.timeStart);
    const e2 = s + (m.durationHours || SLOT_DURATION_HOURS) * 60;
    return startMinutes < e2 && endMinutes > s;
  });
  if (conflictingPending) {
    showToast(`Note: "${conflictingPending.eventName}" is also pending for this time. If both approved, yours may be auto-cancelled.`, "warning");
  }

  // All validation passed — close meeting form, open Policy modal
  msg.textContent = "";
  closeMeetingModal();
  openPolicyModal({ eventName, committee, venue, councilor, researcher, stakeholders, notes, date: isoDate, timeStart, durationHours, type });
}


// ---------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------

function animateCounter(el, target) {
  if (!el) return;
  const current = parseInt(el.textContent) || 0;
  if (current === target) { el.textContent = target; return; }
  const duration = 600;
  const start = performance.now();
  const from = current;
  function step(now) {
    const t = Math.min((now - start) / duration, 1);
    const ease = 1 - Math.pow(1 - t, 3);
    el.textContent = Math.round(from + (target - from) * ease);
    if (t < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}

function updateDashboardGreeting() {
  const greetEl = $("#dash-greeting");
  const dateEl = $("#dash-date-str");
  const nameEl = $("#dash-admin-name");
  const cu = getCurrentUser();
  if (nameEl && cu) nameEl.textContent = cu.name || "Administrator";
  if (greetEl) {
    const h = new Date().getHours();
    greetEl.textContent = h < 12 ? "Good morning," : h < 17 ? "Good afternoon," : "Good evening,";
  }
  if (dateEl) {
    dateEl.textContent = new Date().toLocaleDateString("en-PH", { weekday:"long", year:"numeric", month:"long", day:"numeric" });
  }
}

function renderUpcomingMeetingsPreview() {
  const el = $("#upcoming-meetings-preview");
  if (!el) return;
  const now = new Date();
  const in14 = new Date(now.getTime() + 14 * 24 * 60 * 60 * 1000);
  const upcoming = meetings
    .filter(m => m.status === "Approved" && new Date(m.date + "T00:00:00") >= now && new Date(m.date + "T00:00:00") <= in14)
    .sort((a, b) => a.date.localeCompare(b.date))
    .slice(0, 5);

  if (!upcoming.length) {
    el.innerHTML = `<div style="text-align:center;padding:20px 0;color:var(--color-text-muted);font-size:0.84rem">
      <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="display:block;margin:0 auto 8px;opacity:.35"><rect x="3" y="4" width="18" height="18" rx="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/></svg>
      No approved meetings in the next 14 days.
    </div>`;
    return;
  }

  const STATUS_COLORS = { "Approved": "#16a34a" };
  el.innerHTML = upcoming.map(m => {
    const dateStr = new Date(m.date + "T00:00:00").toLocaleDateString("en-PH", { weekday:"short", month:"short", day:"numeric" });
    const timeStr = m.timeStart ? formatTimeRange(m.timeStart, m.durationHours || SLOT_DURATION_HOURS) : "—";
    const daysLeft = Math.ceil((new Date(m.date + "T00:00:00") - now) / (1000 * 60 * 60 * 24));
    const daysTag = daysLeft === 0 ? "Today" : daysLeft === 1 ? "Tomorrow" : `In ${daysLeft}d`;
    return `<div class="upcoming-preview-item">
      <div style="display:flex;align-items:center;gap:10px;min-width:0">
        <div style="width:4px;height:40px;border-radius:3px;background:#16a34a;flex-shrink:0"></div>
        <div style="min-width:0">
          <div class="upcoming-preview-name">${h(m.eventName)}</div>
          <div class="upcoming-preview-meta">${dateStr} · ${timeStr}${m.venue ? ` · ${h(m.venue)}` : ""}</div>
        </div>
      </div>
      <span style="font-size:0.7rem;font-weight:700;background:${daysLeft <= 1 ? '#fee2e2' : '#dcfce7'};color:${daysLeft <= 1 ? '#991b1b' : '#166534'};padding:3px 9px;border-radius:999px;white-space:nowrap;flex-shrink:0">${daysTag}</span>
    </div>`;
  }).join("");
}

function updateStatistics() {
  const totalEl = $("#stat-total-meetings");
  const pendingEl = $("#stat-pending-meetings");
  const activeUsersEl = $("#stat-active-users");
  const upcomingEl = $("#stat-upcoming-week");

  const total = meetings.length;
  const pending = meetings.filter(m => m.status === "Pending").length;
  const activeUsers = users.filter(u => u.role !== ROLES.ADMIN).length;
  const now = new Date();
  const in7 = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);
  const upcoming = meetings.filter(m => { const d = new Date(m.date); return d >= now && d <= in7; }).length;

  animateCounter(totalEl, total);
  animateCounter(pendingEl, pending);
  animateCounter(activeUsersEl, activeUsers);
  animateCounter(upcomingEl, upcoming);

  // Pending CTA — show "Review now" if there are pending items
  const cta = $("#stat-pending-cta");
  const none = $("#stat-pending-none");
  const pendingCard = $("#stat-pending-card");
  if (cta && none) {
    if (pending > 0) {
      cta.style.display = "inline";
      none.style.display = "none";
      if (pendingCard) pendingCard.classList.add("dash-stat-card-has-alert");
    } else {
      cta.style.display = "none";
      none.style.display = "inline";
      if (pendingCard) pendingCard.classList.remove("dash-stat-card-has-alert");
    }
  }

  updateDashboardGreeting();
  renderUpcomingMeetingsPreview();

  // Update notification badge for current user
  const cu = getCurrentUser();
  if (cu) updateNotificationBadge(cu.id || cu.username);

  if (typeof window.renderDashboardCharts === "function") window.renderDashboardCharts();
  if (typeof window.renderUserDashboardCharts === "function") window.renderUserDashboardCharts();
}

// ---------------------------------------------------------------------------
// Duration options
// ---------------------------------------------------------------------------

function populateDurationOptions() {
  const sel = $("#meeting-duration");
  if (!sel) return;
  sel.innerHTML = "";
  [1,2,3,4,5,6,7,8].forEach(h => {
    const opt = document.createElement("option");
    opt.value = String(h);
    opt.textContent = h === 1 ? "1 hour" : `${h} hours`;
    sel.appendChild(opt);
  });
  sel.value = String(SLOT_DURATION_HOURS);
}

function updateTimeSlotAvailabilityHint(options, isoDate) {
  const hint = $("#time-slot-availability-hint");
  if (!hint) return;
  const blocked = options.filter(o => o.disabled && o.conflict).length;
  const available = options.filter(o => !o.disabled).length;
  if (!isoDate) { hint.innerHTML = ""; return; }
  if (blocked === 0) {
    hint.innerHTML = `<span style="color:#16a34a;font-size:0.72rem;display:inline-flex;align-items:center;gap:4px"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 17 4 12"/></svg>All time slots available for this date</span>`;
  } else if (available === 0) {
    hint.innerHTML = `<span style="color:#dc2626;font-size:0.72rem;font-weight:600;display:inline-flex;align-items:center;gap:4px"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>No available time slots — this day is fully booked</span>`;
  } else {
    hint.innerHTML = `<span style="color:#f59e0b;font-size:0.72rem;display:inline-flex;align-items:center;gap:4px"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>${blocked} slot(s) blocked by approved meetings — grayed options are unavailable</span>`;
  }
}

function recalcDurationOptionsBasedOnStart(isoDate) {
  const timeSel = $("#meeting-time");
  const durSel = $("#meeting-duration");
  const hint = $("#meeting-duration-hint");
  if (!timeSel || !durSel) return;
  const val = timeSel.value;
  if (!val) return;
  const hour = parseInt(val.split(":")[0], 10);
  const startMin = hour * 60;

  // Calculate max duration considering both work hours AND approved meetings
  const date = isoDate || $("#meeting-date")?.value || null;
  const approvedOnDate = date
    ? meetings.filter(m => m.date === date && m.status === "Approved")
    : [];

  // Find the next approved meeting that starts after our start time
  const nextConflict = approvedOnDate
    .map(m => minutesFromTimeStr(m.timeStart))
    .filter(s => s > startMin)
    .sort((a, b) => a - b)[0];

  const workMax = WORK_END_HOUR * 60 - startMin;
  const conflictMax = nextConflict ? nextConflict - startMin : Infinity;
  const maxMinutes = Math.min(workMax, conflictMax);
  const maxHours = Math.max(1, Math.min(8, Math.floor(maxMinutes / 60)));

  const current = parseInt(durSel.value || "1", 10);
  durSel.innerHTML = "";
  for (let h = 1; h <= maxHours; h++) {
    const opt = document.createElement("option");
    opt.value = String(h);
    opt.textContent = h === 1 ? "1 hour" : `${h} hours`;
    durSel.appendChild(opt);
  }
  durSel.value = String(Math.min(current, maxHours));

  if (hint) {
    if (nextConflict && conflictMax < workMax) {
      const blockerName = approvedOnDate.find(m => minutesFromTimeStr(m.timeStart) === nextConflict)?.eventName || "another meeting";
      hint.innerHTML = `<span style="color:#f59e0b">Max ${maxHours}h — limited by approved meeting: "${blockerName}"</span>`;
    } else {
      hint.textContent = `Max duration from ${val}: ${maxHours} hour(s)`;
    }
  }

  populateTimeOptions(date);
}

function updateEndTimePreview() {
  const timeSel = $("#meeting-time");
  const durSel = $("#meeting-duration");
  const preview = $("#meeting-end-preview");
  if (!timeSel || !durSel || !preview) return;
  const startStr = timeSel.value;
  const dur = parseInt(durSel.value || "1", 10);
  if (!startStr || !dur) { preview.textContent = ""; return; }
  preview.textContent = `End Time: ${formatTime12h(minutesFromTimeStr(startStr) + dur * 60)}`;
}

// ---------------------------------------------------------------------------
// Admin page init
// ---------------------------------------------------------------------------

async function initAdminPage() {
  await initDataLayer();
  const user = requireAuth({ allowAdmin: true, allowCouncilor: false, allowResearcher: false });
  if (!user) return;

  initSessionTimeout();
  attachCommonHeader(user);
  populateDurationOptions();
  populateTimeOptions(getTodayISOManila());

  const dateInput = $("#meeting-date");
  if (dateInput) dateInput.min = getTodayISOManila();

  $("#meeting-duration")?.addEventListener("change", () => {
    const d = $("#meeting-date")?.value;
    populateTimeOptions(d);
    updateEndTimePreview();
  });
  $("#meeting-time")?.addEventListener("change", () => {
    const d = $("#meeting-date")?.value;
    recalcDurationOptionsBasedOnStart(d);
    updateEndTimePreview();
  });

  const typeSelect = $("#meeting-type");
  const typeOtherInput = $("#meeting-type-other");
  if (typeSelect && typeOtherInput) {
    typeSelect.addEventListener("change", () => {
      const show = typeSelect.value === "Others";
      typeOtherInput.style.display = show ? "block" : "none";
      if (!show) typeOtherInput.value = "";
    });
  }
  const venueSelect = $("#meeting-venue");
  const venueOtherInput = $("#meeting-venue-other");
  if (venueSelect && venueOtherInput) {
    venueSelect.addEventListener("change", () => {
      const show = venueSelect.value === "Others";
      venueOtherInput.style.display = show ? "block" : "none";
      if (!show) venueOtherInput.value = "";
    });
  }

  setupCleanupBanner();
  wireArchiveModal();

  $("#user-form")?.addEventListener("submit", handleUserFormSubmit);
  $("#special-account-form")?.addEventListener("submit", handleSpecialAccountFormSubmit);
  $("#user-table-body")?.addEventListener("click", handleUserTableClick);
  $("#special-accounts-table-body")?.addEventListener("click", handleUserTableClick);
  $("#password-form")?.addEventListener("submit", handlePasswordSubmit);
  $("#password-cancel-btn")?.addEventListener("click", closePasswordModal);
  $("#password-modal-close")?.addEventListener("click", closePasswordModal);

  // Search inputs
  document.getElementById("search-users")?.addEventListener("input", e => {
    usersSearch = e.target.value; usersPage = 1; renderUsersTable();
  });
  document.getElementById("search-admin-meetings")?.addEventListener("input", e => {
    adminMeetingsSearch = e.target.value; adminMeetingsPage = 1; renderAdminMeetingsTable();
  });

  $("#filter-type-admin")?.addEventListener("change", () => { adminMeetingsPage = 1; renderAdminMeetingsTable(); });
  $("#filter-status-admin")?.addEventListener("change", () => { adminMeetingsPage = 1; renderAdminMeetingsTable(); });

  $("#btn-export-csv")?.addEventListener("click", exportMeetingsCSV);
  $("#btn-print-table")?.addEventListener("click", printMeetingsTable);

  $("#admin-meetings-body")?.addEventListener("click", handleAdminMeetingsClick);
  $("#meeting-form")?.addEventListener("submit", handleMeetingSubmit);
  $("#meeting-cancel-btn")?.addEventListener("click", closeMeetingModal);
  $("#meeting-modal-close")?.addEventListener("click", closeMeetingModal);
  $("#policy-modal-back")?.addEventListener("click", () => { closePolicyModal(); const b = $("#meeting-modal"); if (b) b.classList.add("modal-open"); });
  $("#policy-modal-confirm")?.addEventListener("click", submitMeetingFromPolicy);
  $("#calendar-prev")?.addEventListener("click", () => changeCalendarMonth(-1));
  $("#calendar-next")?.addEventListener("click", () => changeCalendarMonth(1));
  $("#calendar-today")?.addEventListener("click", jumpToToday);
  $("#add-admin-btn")?.addEventListener("click", openAdminMgmtModal);
  $("#admin-mgmt-close")?.addEventListener("click", closeAdminMgmtModal);
  $("#admin-mgmt-cancel")?.addEventListener("click", closeAdminMgmtModal);
  $("#admin-mgmt-form")?.addEventListener("submit", handleAddAdminSubmit);

  initCalendarDate();
  renderUsersTable();
  renderAdminMeetingsTable();
  updateStatistics();
  initAdminAnnouncements();
  initSystemSettings();

  // Password strength meters
  initPwdStrength("user-password",    "user-pwd-strength",    "user-pwd-fill",    "user-pwd-label");
  initPwdStrength("special-password", "special-pwd-strength", "special-pwd-fill", "special-pwd-label");
}

// ---------------------------------------------------------------------------
// User page init
// ---------------------------------------------------------------------------

async function initUserPage() {
  await initDataLayer();
  const user = requireAuth({ allowAdmin: false, allowCouncilor: true, allowResearcher: true });
  if (!user) return;

  initSessionTimeout();
  attachCommonHeader(user);
  populateDurationOptions();
  populateTimeOptions(getTodayISOManila());

  const dateInput = $("#meeting-date");
  if (dateInput) dateInput.min = getTodayISOManila();

  $("#meeting-type")?.addEventListener("change", function() {
    const show = this.value === "Others";
    const other = $("#meeting-type-other");
    if (other) { other.style.display = show ? "block" : "none"; if (!show) other.value = ""; }
  });
  $("#meeting-venue")?.addEventListener("change", function() {
    const show = this.value === "Others";
    const other = $("#meeting-venue-other");
    if (other) { other.style.display = show ? "block" : "none"; if (!show) other.value = ""; }
  });
  $("#meeting-duration")?.addEventListener("change", () => {
    const d = $("#meeting-date")?.value;
    populateTimeOptions(d);
    updateEndTimePreview();
  });
  $("#meeting-time")?.addEventListener("change", () => {
    const d = $("#meeting-date")?.value;
    recalcDurationOptionsBasedOnStart(d);
    updateEndTimePreview();
  });

  $("#meeting-form")?.addEventListener("submit", handleMeetingSubmit);
  $("#meeting-cancel-btn")?.addEventListener("click", closeMeetingModal);
  $("#meeting-modal-close")?.addEventListener("click", closeMeetingModal);
  $("#policy-modal-back")?.addEventListener("click", () => { closePolicyModal(); const b = $("#meeting-modal"); if (b) b.classList.add("modal-open"); });
  $("#policy-modal-confirm")?.addEventListener("click", submitMeetingFromPolicy);
  $("#my-meetings-body")?.addEventListener("click", handleMyMeetingsClick);
  $("#calendar-prev")?.addEventListener("click", () => changeCalendarMonth(-1));
  $("#calendar-next")?.addEventListener("click", () => changeCalendarMonth(1));
  // "Today" button
  $("#calendar-today")?.addEventListener("click", jumpToToday);
  // Quick actions row
  $("#user-quick-schedule")?.addEventListener("click", () => openMeetingModal(null));

  document.getElementById("search-my-meetings")?.addEventListener("input", e => {
    myMeetingsSearch = e.target.value; myMeetingsPage = 1; renderMyMeetingsTable(user);
  });

  initCalendarDate();
  renderMyMeetingsTable(user);
  updateStatistics();
  initUserAnnouncements();
}

// ---------------------------------------------------------------------------
// Archive / Cleanup
// ---------------------------------------------------------------------------

function prevMonthRange() {
  const now = new Date();
  const firstOfThis = new Date(now.getFullYear(), now.getMonth(), 1);
  const lastOfPrev = new Date(firstOfThis.getTime() - 24*60*60*1000);
  const startOfPrev = new Date(lastOfPrev.getFullYear(), lastOfPrev.getMonth(), 1);
  return {
    startISO: startOfPrev.toISOString().slice(0,10),
    endISO: lastOfPrev.toISOString().slice(0,10),
    month: lastOfPrev.getMonth() + 1,
    year: lastOfPrev.getFullYear(),
  };
}

function setupCleanupBanner() {
  const card = $("#cleanup-card");
  const btn = $("#export-archive-btn");
  if (!card || !btn) return;
  const range = prevMonthRange();
  const hasPrevMonthData = (meetings || []).some(m => m.date >= range.startISO && m.date <= range.endISO);
  card.style.display = hasPrevMonthData ? "block" : "none";
  btn.addEventListener("click", openArchiveModal);
}

function openArchiveModal() {
  const modal = $("#archive-modal");
  const summary = $("#archive-summary");
  const range = prevMonthRange();
  const list = (meetings || []).filter(m => m.date >= range.startISO && m.date <= range.endISO);
  if (summary) summary.textContent = `Found ${list.length} meeting(s) from ${range.startISO} to ${range.endISO}.`;
  if (modal) modal.classList.add("modal-open");
}

function wireArchiveModal() {
  const modal = $("#archive-modal");
  const check = $("#archive-confirm-check");
  const runBtn = $("#archive-run-btn");
  const close = () => { modal?.classList.remove("modal-open"); if (check) check.checked = false; if (runBtn) runBtn.disabled = true; };
  $("#archive-modal-close")?.addEventListener("click", close);
  $("#archive-cancel-btn")?.addEventListener("click", close);
  if (check && runBtn) check.addEventListener("change", () => { runBtn.disabled = !check.checked; });

  $("#archive-download-btn")?.addEventListener("click", () => {
    try {
      const { jsPDF } = window.jspdf || {};
      if (!jsPDF) { alert("PDF library not loaded."); return; }
      const doc = new jsPDF();
      const range = prevMonthRange();
      const list = (meetings || []).filter(m => m.date >= range.startISO && m.date <= range.endISO);
      let y = 10;
      doc.setFontSize(14);
      doc.text(`Meetings Report: ${range.startISO} to ${range.endISO}`, 10, y);
      y += 8;
      doc.setFontSize(10);
      list.forEach((m, idx) => {
        const line = `${idx+1}. ${m.date} ${m.timeStart} (${m.durationHours}h) - ${m.eventName} [${m.status}] by ${m.createdBy}`;
        doc.text(line, 10, y); y += 6;
        if (y > 280) { doc.addPage(); y = 10; }
      });
      doc.save(`meetings-${range.year}-${String(range.month).padStart(2,"0")}.pdf`);
    } catch { alert("Unable to generate PDF."); }
  });

  runBtn?.addEventListener("click", async () => {
    const range = prevMonthRange();
    try {
      const res = await window.api.exportAndArchivePreviousMonth({ startISO: range.startISO, endISO: range.endISO });
      showToast(`Archived ${res.archived || 0} meeting(s).`, "success");
      meetings = await window.api.getMeetings();
      renderAdminMeetingsTable(); renderCalendar(); updateStatistics();
    } catch { showToast("Archive failed.", "error"); }
    setupCleanupBanner(); close();
  });
}

// ---------------------------------------------------------------------------
// FEATURE: Password Strength Meter
// ---------------------------------------------------------------------------

function scorePassword(pw) {
  if (!pw) return { score: 0, label: "", level: "" };
  let score = 0;
  if (pw.length >= 6)  score++;
  if (pw.length >= 10) score++;
  if (/[A-Z]/.test(pw)) score++;
  if (/[0-9]/.test(pw)) score++;
  if (/[^A-Za-z0-9]/.test(pw)) score++;
  if (score <= 1) return { score: 1, label: "Weak",   level: "weak" };
  if (score <= 3) return { score: 3, label: "Medium", level: "medium" };
  return              { score: 5, label: "Strong", level: "strong" };
}

function initPwdStrength(inputId, wrapId, fillId, labelId) {
  const inp  = document.getElementById(inputId);
  const wrap = document.getElementById(wrapId);
  const fill = document.getElementById(fillId);
  const lbl  = document.getElementById(labelId);
  if (!inp || !wrap || !fill || !lbl) return;
  inp.addEventListener("input", () => {
    const val = inp.value;
    if (!val) { wrap.style.display = "none"; return; }
    wrap.style.display = "flex";
    const { score, label, level } = scorePassword(val);
    fill.style.width = `${(score / 5) * 100}%`;
    fill.className = `pwd-strength-fill pwd-strength-${level}`;
    lbl.textContent = label;
    lbl.className = `pwd-strength-label pwd-strength-label-${level}`;
  });
}

// ---------------------------------------------------------------------------
// FEATURE: Export Meetings to CSV
// ---------------------------------------------------------------------------

function getFilteredMeetingsList() {
  const filterType   = $("#filter-type-admin")?.value   || "all";
  const filterStatus = $("#filter-status-admin")?.value || "all";
  let list = [...meetings];
  if (filterType   !== "all") list = list.filter(m => (m.type || m.meetingType) === filterType);
  if (filterStatus !== "all") list = list.filter(m => m.status === filterStatus);
  if (adminMeetingsSearch) {
    const q = adminMeetingsSearch.toLowerCase();
    list = list.filter(m =>
      (m.eventName  || "").toLowerCase().includes(q) ||
      (m.createdBy  || "").toLowerCase().includes(q) ||
      (m.councilor  || "").toLowerCase().includes(q) ||
      (m.venue      || "").toLowerCase().includes(q)
    );
  }
  list.sort((a, b) => (a.date + a.timeStart).localeCompare(b.date + b.timeStart));
  return list;
}

function csvEscape(val) {
  const s = String(val ?? "").replace(/"/g, '""');
  return /[",\n]/.test(s) ? `"${s}"` : s;
}

function exportMeetingsCSV() {
  const list = getFilteredMeetingsList();
  const headers = ["Event Name","Date","Time","Type","Status","Requested By","Venue","Committee","Councilor","Researcher","Notes"];
  const rows = list.map(m => [
    m.eventName   || "",
    formatDateDisplay(m.date),
    formatTimeRange(m.timeStart, m.durationHours || SLOT_DURATION_HOURS),
    m.type || m.meetingType || "",
    m.status      || "",
    m.createdBy   || "",
    m.venue       || "",
    m.committee   || "",
    m.councilor   || "",
    m.researcher  || "",
    m.notes       || "",
  ].map(csvEscape).join(","));

  const csv  = [headers.join(","), ...rows].join("\r\n");
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement("a");
  const now  = new Date();
  a.href     = url;
  a.download = `sbp_meetings_${now.getFullYear()}${String(now.getMonth()+1).padStart(2,"0")}${String(now.getDate()).padStart(2,"0")}.csv`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  showToast(`Exported ${list.length} meeting${list.length !== 1 ? "s" : ""} to CSV.`, "success");
}

// ---------------------------------------------------------------------------
// FEATURE: Print Meetings Table
// ---------------------------------------------------------------------------

function printMeetingsTable() {
  const list = getFilteredMeetingsList();
  const filterType   = $("#filter-type-admin")?.value   || "all";
  const filterStatus = $("#filter-status-admin")?.value || "all";

  const filterLabel = [
    filterType   !== "all" ? `Type: ${filterType}`     : "",
    filterStatus !== "all" ? `Status: ${filterStatus}` : "",
    adminMeetingsSearch    ? `Search: "${adminMeetingsSearch}"` : "",
  ].filter(Boolean).join("  ·  ") || "All Records";

  const rows = list.map(m => `
    <tr>
      <td>${h(m.eventName)}</td>
      <td>${formatDateDisplay(m.date)}</td>
      <td>${formatTimeRange(m.timeStart, m.durationHours || SLOT_DURATION_HOURS)}</td>
      <td>${h(m.type || m.meetingType || "—")}</td>
      <td class="status-${(m.status||"").toLowerCase().replace(/\s+/g,"-")}">${h(m.status)}</td>
      <td>${h(m.createdBy)}</td>
      <td>${h(m.venue || "—")}</td>
    </tr>`).join("");

  const win = window.open("", "_blank", "width=960,height=700");
  win.document.write(`<!DOCTYPE html><html><head><meta charset="utf-8">
  <title>SB Polangui — Meeting Requests</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:'Segoe UI',Arial,sans-serif;font-size:12px;color:#1e293b;padding:24px}
    .print-header{display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:20px;padding-bottom:14px;border-bottom:2px solid #1b4b8a}
    .print-logo{font-size:17px;font-weight:800;color:#1b4b8a;letter-spacing:-0.3px}
    .print-logo span{display:block;font-size:11px;font-weight:500;color:#64748b;margin-top:2px}
    .print-meta{text-align:right;font-size:10.5px;color:#64748b}
    .print-meta strong{display:block;font-size:12px;color:#1e293b;margin-bottom:2px}
    h2{font-size:14px;font-weight:700;margin-bottom:4px;color:#1e293b}
    .filter-label{font-size:10.5px;color:#64748b;margin-bottom:14px}
    table{width:100%;border-collapse:collapse;font-size:11px}
    thead tr{background:#1b4b8a;color:#fff}
    th{padding:8px 10px;text-align:left;font-weight:600;font-size:10.5px;letter-spacing:0.03em;text-transform:uppercase}
    td{padding:7px 10px;border-bottom:1px solid #e2e8f0;vertical-align:top}
    tr:nth-child(even) td{background:#f8fafc}
    .status-pending{color:#d97706;font-weight:600}
    .status-approved{color:#16a34a;font-weight:600}
    .status-rejected,.status-cancelled{color:#dc2626;font-weight:600}
    .status-done{color:#1b4b8a;font-weight:600}
    .status-cancellation-requested{color:#ea580c;font-weight:600}
    .print-footer{margin-top:16px;font-size:10px;color:#94a3b8;text-align:center;padding-top:8px;border-top:1px solid #e2e8f0}
    .count-badge{display:inline-block;background:#dbeafe;color:#1e40af;font-weight:700;padding:2px 8px;border-radius:999px;font-size:10px;margin-left:8px}
    @media print{body{padding:12px}button{display:none}}
  </style>
  </head><body>
  <div class="print-header">
    <div>
      <div class="print-logo">SB Polangui Legislative System<span>Sangguniang Bayan ng Polangui</span></div>
    </div>
    <div class="print-meta">
      <strong>All Meeting Requests</strong>
      Printed: ${new Date().toLocaleString("en-PH",{dateStyle:"medium",timeStyle:"short"})}
    </div>
  </div>
  <h2>Meeting Requests <span class="count-badge">${list.length} record${list.length !== 1 ? "s" : ""}</span></h2>
  <div class="filter-label">Filter: ${filterLabel}</div>
  <table>
    <thead><tr>
      <th>Event Name</th><th>Date</th><th>Time</th><th>Type</th><th>Status</th><th>Requested By</th><th>Venue</th>
    </tr></thead>
    <tbody>${rows || '<tr><td colspan="7" style="text-align:center;padding:20px;color:#94a3b8">No records found.</td></tr>'}</tbody>
  </table>
  <div class="print-footer">SB Polangui Legislative Scheduling &amp; Monitoring System · Confidential</div>
  <script>window.onload=()=>{window.print();}<\/script>
  </body></html>`);
  win.document.close();
}

// ---------------------------------------------------------------------------
// FEATURE: User Detail Drawer
// ---------------------------------------------------------------------------

function openUserDrawer(userId) {
  const user = users.find(u => u.id === userId);
  if (!user) return;

  const old = document.getElementById("user-detail-drawer");
  if (old) old.remove();
  const oldBd = document.getElementById("user-drawer-backdrop");
  if (oldBd) oldBd.remove();

  const userMeetings = (typeof meetings !== "undefined" && Array.isArray(meetings))
    ? meetings.filter(m => m.createdBy === user.username || m.createdBy === user.id)
               .sort((a, b) => b.date.localeCompare(a.date))
    : [];

  const stats = {
    total:     userMeetings.length,
    approved:  userMeetings.filter(m => m.status === "Approved").length,
    pending:   userMeetings.filter(m => m.status === "Pending").length,
    done:      userMeetings.filter(m => m.status === "Done").length,
    cancelled: userMeetings.filter(m => ["Cancelled","Rejected"].includes(m.status)).length,
  };

  const meetingRows = userMeetings.length
    ? userMeetings.slice(0, 50).map(m => `
      <div class="udr-meeting-row">
        <div class="udr-meeting-main">
          <div class="udr-meeting-name">${h(m.eventName)}</div>
          <div class="udr-meeting-meta">${formatDateDisplay(m.date)} &nbsp;·&nbsp; ${formatTimeRange(m.timeStart, m.durationHours || SLOT_DURATION_HOURS)} &nbsp;·&nbsp; ${h(m.type || m.meetingType || "—")}</div>
        </div>
        <span class="udr-status-badge udr-status-${(m.status||"").toLowerCase().replace(/\s+/g,"-")}">${h(m.status)}</span>
      </div>`).join("")
    : `<div style="text-align:center;padding:32px 0;color:var(--color-text-muted);font-size:0.85rem">No meetings submitted yet.</div>`;

  const initials = (user.name || user.username).split(" ").map(w=>w[0]).slice(0,2).join("").toUpperCase();

  // Backdrop
  const backdrop = document.createElement("div");
  backdrop.id = "user-drawer-backdrop";
  backdrop.style.cssText = "position:fixed;inset:0;z-index:3999;background:rgba(7,15,34,0.45);backdrop-filter:blur(2px);animation:fadeInBg 0.2s ease both";
  backdrop.addEventListener("click", closeUserDrawer);

  // Drawer
  const drawer = document.createElement("div");
  drawer.id = "user-detail-drawer";
  drawer.innerHTML = `
    <style>
      @keyframes slideInDrawer { from{transform:translateX(100%);opacity:0} to{transform:translateX(0);opacity:1} }
      #user-detail-drawer {
        position:fixed;top:0;right:0;bottom:0;z-index:4000;
        width:min(420px,100vw);
        background:var(--color-surface);
        border-left:1px solid var(--color-border);
        box-shadow:-16px 0 48px rgba(0,0,0,0.18);
        display:flex;flex-direction:column;
        animation:slideInDrawer 0.28s cubic-bezier(0.22,1,0.36,1) both;
        overflow:hidden;
      }
      .udr-header { padding:20px 20px 0;border-bottom:1px solid var(--color-border-soft); }
      .udr-close-row { display:flex;align-items:center;justify-content:space-between;margin-bottom:16px; }
      .udr-close-btn { width:30px;height:30px;border-radius:8px;border:1px solid var(--color-border);background:var(--color-bg);cursor:pointer;display:flex;align-items:center;justify-content:center;color:var(--color-text-muted);transition:background 0.15s; }
      .udr-close-btn:hover { background:var(--color-border-soft); }
      .udr-profile { display:flex;align-items:center;gap:14px;padding-bottom:18px; }
      .udr-avatar { width:52px;height:52px;border-radius:50%;background:linear-gradient(135deg,var(--brand-blue-mid),var(--brand-blue));color:#fff;font-family:var(--font-display);font-size:1.1rem;font-weight:800;display:flex;align-items:center;justify-content:center;flex-shrink:0; }
      .udr-name { font-family:var(--font-display);font-size:1rem;font-weight:800;color:var(--color-text); }
      .udr-username { font-size:0.78rem;color:var(--color-text-muted);margin-top:2px; }
      .udr-stats-row { display:grid;grid-template-columns:repeat(4,1fr);gap:0;border-top:1px solid var(--color-border-soft);border-bottom:1px solid var(--color-border-soft); }
      .udr-stat { padding:12px 8px;text-align:center;border-right:1px solid var(--color-border-soft); }
      .udr-stat:last-child { border-right:none; }
      .udr-stat-val { font-family:var(--font-display);font-size:1.2rem;font-weight:800;color:var(--color-text); }
      .udr-stat-lbl { font-size:0.62rem;font-weight:600;text-transform:uppercase;letter-spacing:0.07em;color:var(--color-text-muted);margin-top:2px; }
      .udr-body { flex:1;overflow-y:auto;padding:0 0 16px; }
      .udr-section-title { font-family:var(--font-display);font-size:0.72rem;font-weight:700;text-transform:uppercase;letter-spacing:0.08em;color:var(--color-text-muted);padding:14px 20px 8px; }
      .udr-meeting-row { display:flex;align-items:center;justify-content:space-between;gap:10px;padding:10px 20px;border-bottom:1px solid var(--color-border-soft);transition:background 0.12s; }
      .udr-meeting-row:hover { background:var(--color-bg); }
      .udr-meeting-row:last-child { border-bottom:none; }
      .udr-meeting-name { font-size:0.84rem;font-weight:600;color:var(--color-text); }
      .udr-meeting-meta { font-size:0.72rem;color:var(--color-text-muted);margin-top:2px; }
      .udr-status-badge { font-size:0.67rem;font-weight:700;padding:3px 8px;border-radius:999px;white-space:nowrap;flex-shrink:0; }
      .udr-status-pending { background:#fef3c7;color:#92400e; }
      .udr-status-approved { background:#dcfce7;color:#166534; }
      .udr-status-done { background:#dbeafe;color:#1e40af; }
      .udr-status-cancelled,.udr-status-rejected { background:#fee2e2;color:#991b1b; }
      .udr-status-cancellation-requested { background:#fff7ed;color:#c2410c; }
    </style>
    <div class="udr-header">
      <div class="udr-close-row">
        <span style="font-size:0.72rem;font-weight:700;text-transform:uppercase;letter-spacing:0.08em;color:var(--color-text-muted)">User Details</span>
        <button class="udr-close-btn" id="udr-close-btn" title="Close">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
        </button>
      </div>
      <div class="udr-profile">
        <div class="udr-avatar">${h(initials)}</div>
        <div>
          <div class="udr-name">${h(user.name || user.username)}</div>
          <div class="udr-username">@${h(user.username)} &nbsp;·&nbsp; <span class="${roleChipClass(user.role)}">${h(user.role)}</span></div>
        </div>
      </div>
    </div>
    <div class="udr-stats-row">
      <div class="udr-stat"><div class="udr-stat-val">${stats.total}</div><div class="udr-stat-lbl">Total</div></div>
      <div class="udr-stat"><div class="udr-stat-val" style="color:#16a34a">${stats.approved}</div><div class="udr-stat-lbl">Approved</div></div>
      <div class="udr-stat"><div class="udr-stat-val" style="color:#1b4b8a">${stats.done}</div><div class="udr-stat-lbl">Done</div></div>
      <div class="udr-stat"><div class="udr-stat-val" style="color:#dc2626">${stats.cancelled}</div><div class="udr-stat-lbl">Cancelled</div></div>
    </div>
    <div class="udr-body">
      <div class="udr-section-title">Meeting History</div>
      <div id="udr-meetings-list">${meetingRows}</div>
    </div>
  `;

  document.body.appendChild(backdrop);
  document.body.appendChild(drawer);

  document.getElementById("udr-close-btn")?.addEventListener("click", closeUserDrawer);

  // Close on Escape
  const escHandler = (e) => { if (e.key === "Escape") { closeUserDrawer(); document.removeEventListener("keydown", escHandler); } };
  document.addEventListener("keydown", escHandler);
}

function closeUserDrawer() {
  const drawer  = document.getElementById("user-detail-drawer");
  const backdrop = document.getElementById("user-drawer-backdrop");
  if (drawer) {
    drawer.style.transition = "transform 0.22s ease, opacity 0.22s ease";
    drawer.style.transform  = "translateX(100%)";
    drawer.style.opacity    = "0";
    setTimeout(() => drawer.remove(), 230);
  }
  if (backdrop) {
    backdrop.style.transition = "opacity 0.22s ease";
    backdrop.style.opacity    = "0";
    setTimeout(() => backdrop.remove(), 230);
  }
}

// ---------------------------------------------------------------------------
// Admin Management
// ---------------------------------------------------------------------------

function openAdminMgmtModal() { document.getElementById("admin-mgmt-modal")?.classList.add("modal-open"); }
function closeAdminMgmtModal() { document.getElementById("admin-mgmt-modal")?.classList.remove("modal-open"); }

async function handleAddAdminSubmit(e) {
  e.preventDefault();
  const email = document.getElementById("admin-mgmt-email")?.value.trim() || "";
  const reason = document.getElementById("admin-mgmt-reason")?.value.trim() || "";
  const pwd = document.getElementById("admin-mgmt-password")?.value || "";
  if (!email || !reason || !pwd) { showToast("All fields are required.", "error"); return; }
  if (!(window.firebase && firebase.auth && firebase.functions)) { showToast("Requires Firebase Auth & Functions.", "error"); return; }
  try {
    const current = firebase.auth().currentUser;
    if (!current?.email) { showToast("Sign in with Firebase Auth to continue.", "error"); return; }
    const cred = firebase.auth.EmailAuthProvider.credential(current.email, pwd);
    await current.reauthenticateWithCredential(cred);
    const callable = firebase.functions().httpsCallable("secureAddAdmin");
    await callable({ email, reason });
    showToast("Admin privileges granted.", "success");
    closeAdminMgmtModal();
  } catch { showToast("Unable to add admin.", "error"); }
}

// ---------------------------------------------------------------------------
// SYSTEM SETTINGS — Data Overview, Edit User, Force Reset, Bulk Tools
// ---------------------------------------------------------------------------

function renderSysDataStats() {
  const el = document.getElementById("sysdata-stats");
  if (!el) return;
  const safeMeetings = (typeof meetings !== "undefined" && Array.isArray(meetings)) ? meetings : [];
  const safeUsers    = (typeof users    !== "undefined" && Array.isArray(users))    ? users    : [];

  const statItems = [
    { label: "Total Users",      val: safeUsers.filter(u => u.role !== ROLES.ADMIN).length, icon: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="9" cy="7" r="4"/></svg>`, color: "#3b82f6" },
    { label: "Total Meetings",   val: safeMeetings.length,                                 icon: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4" width="18" height="18" rx="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/></svg>`, color: "#6366f1" },
    { label: "Pending",          val: safeMeetings.filter(m => m.status === "Pending").length, icon: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>`, color: "#f59e0b" },
    { label: "Approved",         val: safeMeetings.filter(m => m.status === "Approved").length, icon: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>`, color: "#16a34a" },
    { label: "Done",             val: safeMeetings.filter(m => m.status === "Done").length, icon: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 11-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>`, color: "#1b4b8a" },
    { label: "Cancelled",        val: safeMeetings.filter(m => ["Cancelled","Rejected"].includes(m.status)).length, icon: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>`, color: "#dc2626" },
    { label: "Councilors",       val: safeUsers.filter(u => u.role === ROLES.COUNCILOR).length, icon: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="8" r="4"/><path d="M6 20v-2a4 4 0 014-4h4a4 4 0 014 4v2"/></svg>`, color: "#8b5cf6" },
    { label: "Researchers",      val: safeUsers.filter(u => u.role === ROLES.RESEARCHER).length, icon: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>`, color: "#0891b2" },
  ];

  el.innerHTML = statItems.map(s => `
    <div style="padding:18px 16px;border-right:1px solid var(--color-border-soft);display:flex;flex-direction:column;gap:6px">
      <div style="color:${s.color};opacity:0.8">${s.icon}</div>
      <div style="font-family:var(--font-display);font-size:1.5rem;font-weight:800;color:var(--color-text);line-height:1">${s.val}</div>
      <div style="font-size:0.72rem;font-weight:600;text-transform:uppercase;letter-spacing:0.07em;color:var(--color-text-muted)">${s.label}</div>
    </div>
  `).join("");
}

function populateEditUserSelect() {
  const sel = document.getElementById("edit-user-select");
  const forcesel = document.getElementById("force-reset-select");
  if (!sel) return;
  const safeUsers = (typeof users !== "undefined" && Array.isArray(users)) ? users : [];
  const nonAdmin = safeUsers.filter(u => u.role !== ROLES.ADMIN);
  const opts = nonAdmin.map(u => `<option value="${u.id}">${h(u.name || u.username)} — ${h(u.role)}</option>`).join("");
  sel.innerHTML = `<option value="">— choose a user —</option>` + opts;
  if (forcesel) forcesel.innerHTML = `<option value="">— choose a user —</option>` + opts;
}

function initSystemSettings() {
  renderSysDataStats();
  populateEditUserSelect();

  // Refresh data stats
  document.getElementById("sysdata-refresh-btn")?.addEventListener("click", () => {
    renderSysDataStats();
    populateEditUserSelect();
    showToast("Data refreshed.", "success");
  });

  // Edit user — populate fields when user is selected
  document.getElementById("edit-user-select")?.addEventListener("change", function () {
    const uid = this.value;
    const saveBtn = document.getElementById("edit-user-save-btn");
    const msgEl   = document.getElementById("edit-user-msg");
    if (msgEl) msgEl.textContent = "";
    if (!uid) {
      document.getElementById("edit-user-name").value = "";
      document.getElementById("edit-user-username").value = "";
      if (saveBtn) saveBtn.disabled = true;
      return;
    }
    const safeUsers = (typeof users !== "undefined" && Array.isArray(users)) ? users : [];
    const u = safeUsers.find(x => x.id === uid);
    if (!u) return;
    document.getElementById("edit-user-name").value     = u.name     || "";
    document.getElementById("edit-user-username").value = u.username || "";
    const roleEl = document.getElementById("edit-user-role");
    if (roleEl) roleEl.value = u.role || "Councilor";
    if (saveBtn) saveBtn.disabled = false;
  });

  // Save edit
  document.getElementById("edit-user-save-btn")?.addEventListener("click", async () => {
    const uid      = document.getElementById("edit-user-select")?.value;
    const newName  = (document.getElementById("edit-user-name")?.value || "").trim();
    const newUname = (document.getElementById("edit-user-username")?.value || "").trim();
    const newRole  = document.getElementById("edit-user-role")?.value;
    const msgEl    = document.getElementById("edit-user-msg");
    const saveBtn  = document.getElementById("edit-user-save-btn");

    if (!uid) { if (msgEl) msgEl.textContent = "No user selected."; return; }
    if (!newName)  { if (msgEl) msgEl.textContent = "Name cannot be empty."; return; }
    if (!newUname) { if (msgEl) msgEl.textContent = "Username cannot be empty."; return; }

    // Check username uniqueness (excluding self)
    const safeUsers = (typeof users !== "undefined" && Array.isArray(users)) ? users : [];
    if (safeUsers.some(u => u.username === newUname && u.id !== uid)) {
      if (msgEl) msgEl.textContent = `Username "${newUname}" is already taken.`;
      return;
    }

    if (saveBtn) { saveBtn.disabled = true; saveBtn.textContent = "Saving…"; }
    try {
      const fields = { name: newName, username: newUname, role: newRole };
      if (window.api && window.api.updateUser) {
        await window.api.updateUser(uid, fields);
        users = await window.api.getUsers();
      } else {
        const u = safeUsers.find(x => x.id === uid);
        if (u) { Object.assign(u, fields); persistUsers(); }
      }
      renderUsersTable();
      populateEditUserSelect();
      updateStatistics();
      if (msgEl) { msgEl.textContent = "Saved!"; msgEl.style.color = "#16a34a"; setTimeout(() => { if (msgEl) { msgEl.textContent = ""; msgEl.style.color = ""; } }, 2500); }
      showToast("User profile updated.", "success");
    } catch {
      if (msgEl) msgEl.textContent = "Failed to save.";
      showToast("Update failed.", "error");
    } finally {
      if (saveBtn) { saveBtn.disabled = false; saveBtn.innerHTML = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M19 21H5a2 2 0 01-2-2V5a2 2 0 012-2h11l5 5v11a2 2 0 01-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg> Save Changes`; }
    }
  });

  // Force password reset
  document.getElementById("force-reset-select")?.addEventListener("change", function () {
    const btn = document.getElementById("force-reset-btn");
    if (btn) btn.disabled = !this.value;
  });
  document.getElementById("force-reset-btn")?.addEventListener("click", async () => {
    const uid = document.getElementById("force-reset-select")?.value;
    if (!uid) return;
    const safeUsers = (typeof users !== "undefined" && Array.isArray(users)) ? users : [];
    const u = safeUsers.find(x => x.id === uid);
    if (!u) return;
    openConfirmModal(
      "Force Password Reset",
      `<strong>${h(u.name || u.username)}</strong> will be required to change their password on next login.`,
      async () => {
        try {
          const fields = { mustChangePassword: true };
          if (window.api && window.api.updateUser) {
            await window.api.updateUser(uid, fields);
            users = await window.api.getUsers();
          } else {
            Object.assign(u, fields); persistUsers();
          }
          showToast(`Password reset flagged for ${u.name || u.username}.`, "success");
          document.getElementById("force-reset-select").value = "";
          document.getElementById("force-reset-btn").disabled = true;
        } catch { showToast("Failed to flag for reset.", "error"); }
      }
    );
  });

  // Export ALL meetings (ignores filters)
  document.getElementById("sysdata-export-all-btn")?.addEventListener("click", () => {
    const safeMeetings = (typeof meetings !== "undefined" && Array.isArray(meetings)) ? meetings : [];
    const headers = ["Event Name","Date","Time","Type","Status","Requested By","Venue","Committee","Councilor","Researcher","Notes"];
    const rows = safeMeetings.map(m => [
      m.eventName || "", formatDateDisplay(m.date),
      formatTimeRange(m.timeStart, m.durationHours || SLOT_DURATION_HOURS),
      m.type || m.meetingType || "", m.status || "", m.createdBy || "",
      m.venue || "", m.committee || "", m.councilor || "", m.researcher || "", m.notes || "",
    ].map(csvEscape).join(","));
    const csv  = [headers.join(","), ...rows].join("\r\n");
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
    const url  = URL.createObjectURL(blob);
    const a    = Object.assign(document.createElement("a"), { href: url, download: `sbp_all_meetings_${new Date().toISOString().slice(0,10)}.csv` });
    document.body.appendChild(a); a.click(); document.body.removeChild(a); URL.revokeObjectURL(url);
    showToast(`Exported ${safeMeetings.length} meetings.`, "success");
  });

  // Export users list
  document.getElementById("sysdata-export-users-btn")?.addEventListener("click", () => {
    const safeUsers = (typeof users !== "undefined" && Array.isArray(users)) ? users.filter(u => u.role !== ROLES.ADMIN) : [];
    const headers = ["Username","Full Name","Role"];
    const rows = safeUsers.map(u => [u.username || "", u.name || "", u.role || ""].map(csvEscape).join(","));
    const csv  = [headers.join(","), ...rows].join("\r\n");
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
    const url  = URL.createObjectURL(blob);
    const a    = Object.assign(document.createElement("a"), { href: url, download: `sbp_users_${new Date().toISOString().slice(0,10)}.csv` });
    document.body.appendChild(a); a.click(); document.body.removeChild(a); URL.revokeObjectURL(url);
    showToast(`Exported ${safeUsers.length} users.`, "success");
  });

  // Mark past approved → done
  document.getElementById("sysdata-mark-done-btn")?.addEventListener("click", () => {
    const safeMeetings = (typeof meetings !== "undefined" && Array.isArray(meetings)) ? meetings : [];
    const todayISO = getTodayISOManila();
    const eligible = safeMeetings.filter(m => m.status === "Approved" && m.date < todayISO);
    if (!eligible.length) { showToast("No past approved meetings to mark done.", "info"); return; }
    openConfirmModal(
      "Mark Past Meetings as Done",
      `This will mark <strong>${eligible.length}</strong> approved meeting${eligible.length !== 1 ? "s" : ""} with dates before today as <strong>Done</strong>. This cannot be undone.`,
      async () => {
        let count = 0;
        for (const m of eligible) {
          try {
            if (window.api && window.api.updateMeetingStatus) {
              await window.api.updateMeetingStatus(m.id, "Done", "Auto-marked Done by admin.");
            } else {
              m.status = "Done"; m.adminNote = "Auto-marked Done by admin."; count++;
            }
            count++;
          } catch {}
        }
        if (!window.api?.updateMeetingStatus) persistMeetings();
        renderAdminMeetingsTable(); renderCalendar(); updateStatistics();
        showToast(`${count} meeting${count !== 1 ? "s" : ""} marked as Done.`, "success");
      }
    );
  });
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

document.addEventListener("DOMContentLoaded", () => {
  const page = document.body.dataset.page;
  if (page === "login") initLoginPage();
  else if (page === "admin") initAdminPage();
  else if (page === "user") initUserPage();
});

// ===========================================================================
// ANNOUNCEMENTS SYSTEM
// Admin: post + delete; Users: read-only view; Dashboard: preview widget
// ===========================================================================

const ANN_TYPE_META = {
  general:   { label: "General Info",     icon: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M3 11l19-9-9 19-2-8-8-2z"/></svg>`, color: "#3b82f6", bg: "rgba(59,130,246,0.08)"  },
  important: { label: "Important Notice", icon: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`, color: "#dc2626", bg: "rgba(220,38,38,0.08)"   },
  reminder:  { label: "Reminder",         icon: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M18 8A6 6 0 006 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 01-3.46 0"/></svg>`, color: "#f59e0b", bg: "rgba(245,158,11,0.08)"  },
  event:     { label: "Upcoming Event",   icon: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><rect x="3" y="4" width="18" height="18" rx="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/></svg>`, color: "#8b5cf6", bg: "rgba(139,92,246,0.08)"  },
};

function _annMeta(type) {
  return ANN_TYPE_META[type] || ANN_TYPE_META.general;
}

function _annTimeAgo(isoStr) {
  if (!isoStr) return "";
  const diff = Date.now() - new Date(isoStr).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return mins + "m ago";
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return hrs + "h ago";
  const days = Math.floor(hrs / 24);
  if (days < 7) return days + "d ago";
  return new Date(isoStr).toLocaleDateString("en-PH", { month: "short", day: "numeric", year: "numeric" });
}

// Render announcement card HTML — shared between admin and user views
function _renderAnnCard(ann, isAdmin) {
  const meta = _annMeta(ann.type);
  const pinHtml = ann.pinned ? `<span style="font-size:0.7rem;font-weight:700;letter-spacing:0.04em;color:#d97706;background:rgba(217,119,6,0.12);padding:2px 8px;border-radius:999px;display:inline-flex;align-items:center;gap:4px"><svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0118 0z"/><circle cx="12" cy="10" r="3"/></svg> PINNED</span>` : "";
  const deleteHtml = isAdmin ? `<button class="btn btn-ghost btn-sm ann-delete-btn" data-id="${ann.id}" title="Delete announcement" style="color:var(--color-text-muted);padding:4px 8px;flex-shrink:0">
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6"/><path d="M10 11v6M14 11v6"/><path d="M9 6V4h6v2"/></svg>
  </button>` : "";

  return `<div class="ann-card" data-id="${ann.id}" style="
    border:1px solid var(--color-border-soft);
    border-left: 4px solid ${meta.color};
    border-radius:12px;
    padding:16px 18px;
    background:var(--color-surface);
    display:flex;flex-direction:column;gap:8px;
    transition:box-shadow 0.15s;
  ">
    <div style="display:flex;align-items:flex-start;gap:10px">
      <div style="width:36px;height:36px;border-radius:10px;background:${meta.bg};display:flex;align-items:center;justify-content:center;flex-shrink:0;color:${meta.color}">${meta.icon}</div>
      <div style="flex:1;min-width:0">
        <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:2px">
          ${pinHtml}
          <span style="font-size:0.7rem;font-weight:600;letter-spacing:0.05em;color:${meta.color};text-transform:uppercase">${meta.label}</span>
        </div>
        <div style="font-weight:700;font-size:0.95rem;color:var(--color-text);line-height:1.3;word-break:break-word">${_escHtml(ann.title)}</div>
      </div>
      ${deleteHtml}
    </div>
    <div style="font-size:0.875rem;color:var(--color-text-muted);line-height:1.6;white-space:pre-wrap;word-break:break-word;padding-left:46px">${_escHtml(ann.body)}</div>
    <div style="font-size:0.75rem;color:var(--color-text-muted);padding-left:46px;display:flex;align-items:center;gap:6px">
      <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
      ${_annTimeAgo(ann.createdAt)}
      ${ann.postedBy ? `· Posted by <strong>${_escHtml(ann.postedBy)}</strong>` : ""}
    </div>
  </div>`;
}

function _escHtml(str) {
  if (!str) return "";
  return String(str).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}

// ── Admin: render full announcements list ──────────────────────────────────
function renderAdminAnnouncements(list) {
  const el = document.getElementById("admin-announce-list");
  if (!el) return;
  const badge = document.getElementById("ann-total-badge");
  if (badge) badge.textContent = list.length ? list.length + " posted" : "";

  // Sort: pinned first, then by date desc
  const sorted = list.slice().sort((a, b) => {
    if (a.pinned && !b.pinned) return -1;
    if (!a.pinned && b.pinned) return 1;
    return (b.createdAt || "").localeCompare(a.createdAt || "");
  });

  if (!sorted.length) {
    el.innerHTML = `<div class="empty-state" style="padding:48px 20px">
      <svg class="empty-state-icon" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M3 11l19-9-9 19-2-8-8-2z"/></svg>
      <p>No announcements posted yet.</p></div>`;
    return;
  }
  el.innerHTML = `<div style="display:flex;flex-direction:column;gap:10px;padding:16px">${sorted.map(a => _renderAnnCard(a, true)).join("")}</div>`;
}

// ── User: render announcements page + dashboard preview ────────────────────
function renderUserAnnouncements(list) {
  const el = document.getElementById("user-announce-list");
  if (!el) return;
  const sorted = list.slice().sort((a, b) => {
    if (a.pinned && !b.pinned) return -1;
    if (!a.pinned && b.pinned) return 1;
    return (b.createdAt || "").localeCompare(a.createdAt || "");
  });

  if (!sorted.length) {
    el.innerHTML = `<div class="empty-state" style="padding:64px 20px">
      <svg class="empty-state-icon" width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.4"><path d="M3 11l19-9-9 19-2-8-8-2z"/></svg>
      <p>No announcements yet.</p></div>`;
    return;
  }
  el.innerHTML = sorted.map(a => _renderAnnCard(a, false)).join("");

  // Check for new (unseen) announcements
  try {
    const lastSeen = parseInt(localStorage.getItem("sbp_ann_seen") || "0", 10);
    const hasNew = sorted.some(a => a.createdAt && new Date(a.createdAt).getTime() > lastSeen);
    const badge = document.getElementById("new-ann-badge");
    if (badge) badge.style.display = hasNew ? "inline-flex" : "none";
  } catch(e) {}
}

// ── Dashboard announcement preview (user) ─────────────────────────────────
function renderUserDashAnnouncements(list) {
  const el = document.getElementById("dash-announce-preview");
  if (!el) return;
  const sorted = list.slice().sort((a, b) => {
    if (a.pinned && !b.pinned) return -1;
    if (!a.pinned && b.pinned) return 1;
    return (b.createdAt || "").localeCompare(a.createdAt || "");
  }).slice(0, 3);

  if (!sorted.length) {
    el.innerHTML = `<div style="font-size:0.83rem;color:var(--color-text-muted);padding:16px 0;text-align:center">No announcements yet.</div>`;
    return;
  }
  el.innerHTML = sorted.map(a => {
    const meta = _annMeta(a.type);
    const pin = a.pinned ? `<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="#d97706" stroke-width="2.5" style="flex-shrink:0"><path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0118 0z"/><circle cx="12" cy="10" r="3"/></svg> ` : "";
    return `<div style="display:flex;align-items:flex-start;gap:10px;padding:10px 0;border-bottom:1px solid var(--color-border-soft)">
      <div style="width:30px;height:30px;border-radius:8px;background:${meta.bg};display:flex;align-items:center;justify-content:center;flex-shrink:0;color:${meta.color}">${meta.icon}</div>
      <div style="flex:1;min-width:0">
        <div style="font-weight:600;font-size:0.86rem;color:var(--color-text);white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${pin}${_escHtml(a.title)}</div>
        <div style="font-size:0.77rem;color:var(--color-text-muted);margin-top:2px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${_escHtml(a.body)}</div>
        <div style="font-size:0.72rem;color:var(--color-text-muted);margin-top:3px">${_annTimeAgo(a.createdAt)}</div>
      </div>
    </div>`;
  }).join("") + `<div style="padding-top:8px;text-align:right">
    <a href="#" class="dash-see-all" onclick="if(typeof switchSection==='function'){event.preventDefault();switchSection('announcements');}">See all →</a>
  </div>`;
}

// ── Admin dashboard announcement preview ──────────────────────────────────
function renderAdminDashAnnouncements(list) {
  const el = document.getElementById("dash-admin-announce-preview");
  if (!el) return;
  const recent = list.slice().sort((a, b) => (b.createdAt || "").localeCompare(a.createdAt || "")).slice(0, 2);
  if (!recent.length) {
    el.innerHTML = `<div style="font-size:0.83rem;color:var(--color-text-muted);padding:12px 0">No announcements posted yet.</div>`;
    return;
  }
  el.innerHTML = recent.map(a => {
    const meta = _annMeta(a.type);
    return `<div style="display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid var(--color-border-soft)">
      <div style="width:26px;height:26px;border-radius:7px;background:${meta.bg};display:flex;align-items:center;justify-content:center;flex-shrink:0;color:${meta.color}">${meta.icon}</div>
      <div style="flex:1;min-width:0">
        <div style="font-weight:600;font-size:0.85rem;color:var(--color-text);white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${_escHtml(a.title)}</div>
        <div style="font-size:0.73rem;color:var(--color-text-muted)">${_annTimeAgo(a.createdAt)}</div>
      </div>
    </div>`;
  }).join("") + `<div style="padding-top:8px;text-align:right">
    <a href="#" class="dash-see-all" onclick="if(typeof switchSection==='function'){event.preventDefault();switchSection('announcements');}">Manage →</a>
  </div>`;
}

// ── Wire admin announcements form ──────────────────────────────────────────
function initAdminAnnouncements() {
  const form = document.getElementById("announce-form");
  if (!form) return;

  // Subscribe to live updates
  if (window.api && window.api.subscribeAnnouncements) {
    window.api.subscribeAnnouncements(list => {
      window.announcements = list;
      renderAdminAnnouncements(list);
      renderAdminDashAnnouncements(list);
      const badge = document.getElementById("announce-count-badge");
      if (badge) {
        badge.textContent = list.length;
        badge.style.display = list.length ? "inline-flex" : "none";
      }
    });
  }

  form.addEventListener("submit", async e => {
    e.preventDefault();
    const titleEl = document.getElementById("ann-title");
    const bodyEl  = document.getElementById("ann-body");
    const typeEl  = document.getElementById("ann-type");
    const pinEl   = document.getElementById("ann-pinned");
    const msgEl   = document.getElementById("ann-msg");
    const btn     = document.getElementById("ann-submit-btn");

    const title = (titleEl?.value || "").trim();
    const body  = (bodyEl?.value  || "").trim();
    if (!title) { if (msgEl) msgEl.textContent = "Title is required."; titleEl?.focus(); return; }
    if (!body)  { if (msgEl) msgEl.textContent = "Message is required."; bodyEl?.focus(); return; }
    if (msgEl) msgEl.textContent = "";

    const currentUser = getCurrentUser();
    const ann = {
      title, body,
      type:      typeEl?.value || "general",
      pinned:    pinEl?.checked || false,
      postedBy:  currentUser?.name || currentUser?.username || "Admin",
      createdAt: new Date().toISOString(),
    };

    if (btn) { btn.disabled = true; btn.textContent = "Posting…"; }
    try {
      await window.api.addAnnouncement(ann);
      // Notify all non-admin users
      if (window.users) {
        window.users.filter(u => u.role !== ROLES.ADMIN).forEach(u => {
          addNotification(u.id || u.username,
            `New announcement: <strong>${title}</strong>`,
            "info", "announcements");
        });
      }
      showToast("Announcement posted successfully!", "success");
      form.reset();
      // Refresh list
      const list = await window.api.getAnnouncements();
      renderAdminAnnouncements(list);
      renderAdminDashAnnouncements(list);
    } catch(err) {
      showToast("Failed to post announcement.", "error");
    } finally {
      if (btn) { btn.disabled = false; btn.innerHTML = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg> Post Announcement`; }
    }
  });

  // Delete delegation
  document.getElementById("admin-announce-list")?.addEventListener("click", async e => {
    const btn = e.target.closest(".ann-delete-btn");
    if (!btn) return;
    const id = btn.dataset.id;
    if (!id) return;
    openConfirmModal("Delete Announcement",
      "Are you sure you want to delete this announcement? This cannot be undone.",
      async () => {
        try {
          await window.api.deleteAnnouncement(id);
          showToast("Announcement deleted.", "success");
          const list = await window.api.getAnnouncements();
          renderAdminAnnouncements(list);
          renderAdminDashAnnouncements(list);
        } catch(err) {
          showToast("Failed to delete.", "error");
        }
      }
    );
  });
}

// ── Wire user announcements (read-only) ───────────────────────────────────
function initUserAnnouncements() {
  if (!window.api?.subscribeAnnouncements) return;

  let _prevCount = null; // track previous count to detect new arrivals

  window.api.subscribeAnnouncements(list => {
    window.announcements = list;
    renderUserAnnouncements(list);
    renderUserDashAnnouncements(list);

    // ── Update sidebar "New" badge ──────────────────────────────────────────
    const badge = document.getElementById("new-ann-badge");
    if (badge && list.length > 0) {
      badge.style.display = "inline-flex";
      badge.textContent   = list.length > 9 ? "9+" : String(list.length);
    } else if (badge) {
      badge.style.display = "none";
    }

    // ── Push bell notification when a new announcement arrives in real-time ──
    // Only fire after initial load (when _prevCount is already set)
    if (_prevCount !== null && list.length > _prevCount) {
      const newest = list[0]; // list is ordered newest first
      if (newest) {
        const currentUser = getCurrentUser();
        if (currentUser) {
          addNotification(
            currentUser.id || currentUser.username,
            `New announcement: <strong>${h(newest.title || "Untitled")}</strong>`,
            "info",
            "announcements"
          );
          updateNotificationBadge(currentUser.id || currentUser.username);
        }
      }
    }
    _prevCount = list.length;
  });
}


// BOTTOM DRAWER — mobile replacement for modals (≤768px)
// Completely independent from the .modal system — no inline style conflicts.
// ===========================================================================

(function () {

  // ── Shared drawer infrastructure ──────────────────────────────────────────

  let _overlay = null;
  let _activeDrawer = null;

  function _getOverlay() {
    if (!_overlay) {
      _overlay = document.createElement("div");
      _overlay.className = "drawer-overlay";
      document.body.appendChild(_overlay);
      _overlay.addEventListener("click", _closeActive);
    }
    return _overlay;
  }

  function _openDrawer(drawer) {
    const overlay = _getOverlay();
    if (_activeDrawer && _activeDrawer !== drawer) _destroyDrawer(_activeDrawer);
    _activeDrawer = drawer;
    document.body.appendChild(drawer);
    document.body.style.overflow = "hidden";
    overlay.classList.add("drawer-visible");
    // Force reflow so CSS transition fires
    drawer.offsetHeight;
    drawer.classList.add("drawer-open");
  }

  function _closeActive() {
    if (_activeDrawer) _destroyDrawer(_activeDrawer);
  }

  function _destroyDrawer(drawer) {
    drawer.classList.remove("drawer-open");
    if (_overlay) _overlay.classList.remove("drawer-visible");
    document.body.style.overflow = "";
    setTimeout(() => {
      if (drawer.parentNode) drawer.parentNode.removeChild(drawer);
    }, 380);
    _activeDrawer = null;
  }

  function _makeDrawer(id, titleHTML, subtitleHTML, bodyHTML, footerHTML) {
    // Remove stale instance
    const old = document.getElementById(id);
    if (old) old.parentNode && old.parentNode.removeChild(old);

    const d = document.createElement("div");
    d.id = id;
    d.className = "bottom-drawer";
    d.innerHTML = `
      <div class="drawer-handle"></div>
      <div class="drawer-header">
        <div class="drawer-title-wrap">
          <div class="drawer-title">${titleHTML}</div>
          ${subtitleHTML ? `<div class="drawer-subtitle">${subtitleHTML}</div>` : ""}
        </div>
        <button class="drawer-close" aria-label="Close">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
            <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
          </svg>
        </button>
      </div>
      <div class="drawer-body">${bodyHTML}</div>
      <div class="drawer-footer">${footerHTML}</div>`;

    d.querySelector(".drawer-close").addEventListener("click", _closeActive);
    return d;
  }

  // ── Day Schedule Drawer ───────────────────────────────────────────────────

  window.openDayDrawer = function (isoDate, canBook) {
    const d = new Date(isoDate + "T00:00:00");
    const dateDisplay = d.toLocaleDateString("en-PH", {
      weekday: "long", year: "numeric", month: "long", day: "numeric"
    });

    const holidayInfo = getHolidayInfo(isoDate);
    const dayMeetings = meetings
      .filter(m => m.date === isoDate)
      .sort((a, b) => (a.timeStart || "").localeCompare(b.timeStart || ""));
    const approvedMeetings = dayMeetings.filter(m => m.status === "Approved");
    const approvedMins = approvedMeetings.reduce(
      (s, m) => s + (m.durationHours || SLOT_DURATION_HOURS) * 60, 0
    );
    const isFullyBooked = approvedMins >= (WORK_END_HOUR - WORK_START_HOUR) * 60;

    // Title
    const titleHTML = `
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2">
        <rect x="3" y="4" width="18" height="18" rx="2"/>
        <line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/>
        <line x1="3" y1="10" x2="21" y2="10"/>
      </svg>
      ${dateDisplay}`;

    // Subtitle (holiday)
    const subtitleHTML = holidayInfo
      ? `<span class="holiday-tag">
           <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
             <circle cx="12" cy="12" r="10"/>
             <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
             <line x1="2" y1="12" x2="22" y2="12"/>
           </svg>
           PH Holiday: ${holidayInfo.localName}
         </span>`
      : "";

    // Body — timeline + meeting list
    const STATUS_STYLE = {
      "Approved":               { bg:"#dcfce7", border:"#16a34a", text:"#166534" },
      "Pending":                { bg:"#fef3c7", border:"#f59e0b", text:"#92400e" },
      "Cancelled":              { bg:"#f3f4f6", border:"#d1d5db", text:"#9ca3af" },
      "Rejected":               { bg:"#f3f4f6", border:"#d1d5db", text:"#9ca3af" },
      "Done":                   { bg:"#dbeafe", border:"#3b82f6", text:"#1e40af" },
      "Cancellation Requested": { bg:"#fff7ed", border:"#f97316", text:"#c2410c" },
    };

    let meetingListHtml = "";
    if (!dayMeetings.length) {
      meetingListHtml = `
        <div style="text-align:center;padding:28px 0 16px;color:var(--color-text-muted);font-size:0.86rem">
          <svg width="34" height="34" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.4"
               style="display:block;margin:0 auto 10px;opacity:.35">
            <rect x="3" y="4" width="18" height="18" rx="2"/>
            <line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/>
            <line x1="3" y1="10" x2="21" y2="10"/>
          </svg>
          No meetings scheduled for this day.
        </div>`;
    } else {
      const statusNote = isFullyBooked
        ? `<div style="background:#fee2e2;border:1px solid #fca5a5;border-radius:10px;padding:10px 14px;font-size:0.82rem;color:#991b1b;font-weight:600;margin-bottom:12px;display:flex;align-items:center;gap:7px">
             <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
               <circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/>
             </svg>
             This day is fully booked — no available slots.
           </div>`
        : approvedMeetings.length
          ? `<div style="background:#fef3c7;border:1px solid #fcd34d;border-radius:10px;padding:10px 14px;font-size:0.82rem;color:#92400e;font-weight:500;margin-bottom:12px;display:flex;align-items:center;gap:7px">
               <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                 <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
                 <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
               </svg>
               Some slots are taken — check timeline before booking.
             </div>`
          : "";

      meetingListHtml = statusNote +
        `<div style="font-size:0.71rem;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:var(--color-text-muted);margin-bottom:10px">
           Meetings (${dayMeetings.length})
         </div>
         <div style="display:flex;flex-direction:column;gap:9px">
           ${dayMeetings.map(m => {
             const c = STATUS_STYLE[m.status] || STATUS_STYLE["Cancelled"];
             const timeRange = m.timeStart
               ? formatTimeRange(m.timeStart, m.durationHours || SLOT_DURATION_HOURS) : "—";
             const belongsToMe = meetingBelongsToUser(m, currentUser);
             const canCancel = belongsToMe && currentUser.role !== ROLES.ADMIN && ["Pending", "Approved"].includes(m.status);
             const createdAt = m.createdAt ? new Date(m.createdAt) : null;
             const within24h = createdAt && (new Date() - createdAt) < 24 * 60 * 60 * 1000;
             const cancelLabel = within24h ? "Cancel (Free)" : "Request Cancel";
             return `
               <div style="background:${c.bg};border:1px solid ${c.border};border-left:4px solid ${c.border};border-radius:10px;padding:12px 14px">
                 <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:8px">
                   <div style="min-width:0">
                     <div style="font-weight:700;font-size:0.88rem;color:${c.text};overflow:hidden;text-overflow:ellipsis;white-space:nowrap">
                       ${h(m.eventName) || "Meeting"}
                     </div>
                     <div style="font-size:0.77rem;color:${c.text};opacity:.85;margin-top:4px;display:flex;flex-wrap:wrap;gap:8px">
                       <span style="display:inline-flex;align-items:center;gap:3px">
                         <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                           <circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>
                         </svg>${timeRange}
                       </span>
                       <span style="display:inline-flex;align-items:center;gap:3px">
                         <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                           <path d="M12 22s-8-4.5-8-11.8A8 8 0 0 1 12 2a8 8 0 0 1 8 8.2c0 7.3-8 11.8-8 11.8z"/>
                           <path d="M12 7v5l3 3"/>
                         </svg>${m.durationHours || SLOT_DURATION_HOURS}h
                       </span>
                       ${m.venue ? `<span style="display:inline-flex;align-items:center;gap:3px">
                         <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                           <path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"/>
                           <circle cx="12" cy="10" r="3"/>
                         </svg>${h(m.venue)}</span>` : ""}
                     </div>
                     ${m.councilor ? `<div style="font-size:0.73rem;color:${c.text};opacity:.72;margin-top:4px;display:flex;align-items:center;gap:3px">
                       <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                         <circle cx="12" cy="8" r="4"/><path d="M4 20c0-4 3.6-7 8-7s8 3 8 7"/>
                       </svg>${h(m.councilor)}</div>` : ""}
                     ${m.committee ? `<div style="font-size:0.73rem;color:${c.text};opacity:.72;display:flex;align-items:center;gap:3px">
                       <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                         <rect x="2" y="7" width="20" height="14" rx="1"/>
                         <path d="M16 7V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v2"/>
                       </svg>${h(m.committee)}</div>` : ""}
                     ${m.adminNote ? `<div style="font-size:0.71rem;color:${c.text};opacity:.65;margin-top:5px;font-style:italic;display:flex;align-items:center;gap:3px">
                       <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                         <path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"/>
                       </svg>${h(m.adminNote)}</div>` : ""}
                     ${belongsToMe ? `
                       <div style="display:flex;gap:6px;margin-top:10px;flex-wrap:wrap">
                         ${canCancel ? `<button
                           class="btn btn-sm ${within24h ? "btn-ghost cancel-btn-free" : "btn-ghost"}"
                           style="font-size:0.75rem;padding:4px 10px"
                           data-action="request-cancel"
                           data-meeting-id="${m.id}">
                           ${cancelLabel}
                         </button>` : ""}
                         <button
                           class="btn btn-sm btn-ghost"
                           style="font-size:0.75rem;padding:4px 10px"
                           data-action="export-pdf"
                           data-meeting-id="${m.id}">
                           Export PDF
                         </button>
                       </div>` : ""}
                   </div>
                   <span style="flex-shrink:0;font-size:0.69rem;font-weight:700;background:white;color:${c.text};border:1px solid ${c.border};padding:3px 9px;border-radius:999px;white-space:nowrap">
                     ${m.status}
                   </span>
                 </div>
               </div>`;
           }).join("")}
         </div>`;
    }

    const bodyHTML = buildTimelineHTML(isoDate, dayMeetings) + meetingListHtml;

    // Footer
    let footerHTML = "";
    if (canBook && !isFullyBooked && !holidayInfo) {
      footerHTML = `
        <button id="drawer-day-close" class="btn btn-ghost">Close</button>
        <button id="drawer-day-book" class="btn btn-primary">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2">
            <line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>
          </svg>
          Book a Meeting
        </button>`;
    } else {
      const reason = holidayInfo
        ? "Philippine Holiday — no bookings allowed"
        : isFullyBooked ? "No available time slots" : "";
      footerHTML = `
        ${reason ? `<span style="font-size:0.78rem;color:var(--color-text-muted);flex:1;display:flex;align-items:center">${reason}</span>` : ""}
        <button id="drawer-day-close" class="btn btn-ghost" style="min-width:100px">Close</button>`;
    }

    const drawer = _makeDrawer("drawer-day", titleHTML, subtitleHTML, bodyHTML, footerHTML);
    _openDrawer(drawer);

    requestAnimationFrame(() => {
      document.getElementById("drawer-day-close")
        ?.addEventListener("click", _closeActive);
      document.getElementById("drawer-day-book")
        ?.addEventListener("click", () => {
          _closeActive();
          // Small delay so first drawer fully closes before second opens
          setTimeout(() => openBookingDrawer(isoDate), 120);
        });

      // Delegate cancel + export-pdf button clicks inside the day drawer meeting cards
      drawer.addEventListener("click", function (e) {
        const btn = e.target.closest("button[data-action]");
        if (!btn) return;
        handleMyMeetingsClick(e);
      });
    });
  };

  // ── Booking Drawer ────────────────────────────────────────────────────────

  window.openBookingDrawer = function (isoDate) {
    const currentUser = getCurrentUser();
    if (!currentUser ||
        ![ROLES.ADMIN, ROLES.COUNCILOR, ROLES.RESEARCHER, ROLES.VICE_MAYOR, ROLES.SECRETARY]
          .includes(currentUser.role)) {
      showToast("Only authorized roles may book meetings.", "warning");
      return;
    }

    const todayISO = getTodayISOManila();
    if (isoDate && isoDate < todayISO) {
      showToast("Cannot schedule meetings on past dates.", "error");
      return;
    }
    const activeDate = isoDate || todayISO;

    const titleHTML = `
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2">
        <rect x="3" y="4" width="18" height="18" rx="2"/>
        <line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/>
        <line x1="3" y1="10" x2="21" y2="10"/>
      </svg>
      Schedule Meeting`;

    // Build councilor options
    const dbCouncilorOpts = users
      .filter(u => u.role === ROLES.COUNCILOR || u.role === ROLES.VICE_MAYOR)
      .map(u => `<option value="${h(u.name || u.username)}">${h(u.name || u.username)} (${u.role})</option>`)
      .join("");
    const dbResearcherOpts = users
      .filter(u => u.role === ROLES.RESEARCHER)
      .map(u => `<option value="${h(u.name || u.username)}">${h(u.name || u.username)} (${u.role})</option>`)
      .join("");

    const isAdminDrawer = currentUser.role === ROLES.ADMIN;
    const isCouncilorDrawer = currentUser.role === ROLES.COUNCILOR;
    const isResearcherDrawer = currentUser.role === ROLES.RESEARCHER;

    const dbCouncilorField = isResearcherDrawer
      ? `<select id="db-councilor" class="field" required>
           <option value="">— Select Councilor —</option>
           <option value="N/A">N/A (No Councilor)</option>
           ${dbCouncilorOpts}
         </select>`
      : isCouncilorDrawer
        ? `<input id="db-councilor" class="field" value="${h(currentUser.name)}" readonly />`
        : `<select id="db-councilor" class="field" required>
             <option value="">— Select Councilor —</option>
             <option value="N/A">N/A (No Councilor)</option>
             ${dbCouncilorOpts}
           </select>`;

    const dbResearcherField = isCouncilorDrawer
      ? `<select id="db-researcher" class="field" required>
           <option value="">— Select Researcher —</option>
           <option value="N/A">N/A (No Researcher)</option>
           ${dbResearcherOpts}
         </select>`
      : isResearcherDrawer
        ? `<input id="db-researcher" class="field" value="${h(currentUser.name)}" readonly />`
        : `<select id="db-researcher" class="field" required>
             <option value="">— Select Researcher —</option>
             <option value="N/A">N/A (No Researcher)</option>
             ${dbResearcherOpts}
           </select>`;

    const bodyHTML = `
      <form id="drawer-booking-form" class="section-stack" onsubmit="return false">
        <div>
          <label class="field-label" for="db-event">Event Name *</label>
          <input id="db-event" class="field" required placeholder="e.g. Committee Hearing" autocomplete="off" />
        </div>
        <div>
          <label class="field-label" for="db-committee">Committee *</label>
          <input id="db-committee" class="field" required placeholder="e.g. Ways and Means" autocomplete="off" />
        </div>
        <div>
          <label class="field-label" for="db-councilor">Councilor *</label>
          ${dbCouncilorField}
        </div>
        <div>
          <label class="field-label" for="db-researcher">Researcher *</label>
          ${dbResearcherField}
        </div>
        <div>
          <label class="field-label" for="db-date">Date *</label>
          <input id="db-date" type="date" class="field" required
                 min="${todayISO}" value="${activeDate}" />
        </div>
        <div>
          <label class="field-label" for="db-time">Start Time *</label>
          <select id="db-time" class="field" required></select>
          <div id="db-time-hint" class="helper-text" style="margin-top:4px;font-size:0.78rem"></div>
          <div class="calendar-lunch-block">Office hours: 8:00 AM – 5:00 PM</div>
          <div id="db-end-preview" class="helper-text" style="font-size:0.78rem"></div>
        </div>
        <div>
          <label class="field-label" for="db-duration">Duration *</label>
          <select id="db-duration" class="field" required></select>
          <div id="db-duration-hint" class="helper-text" style="font-size:0.78rem"></div>
        </div>
        <div>
          <label class="field-label" for="db-type">Type of Meeting *</label>
          <select id="db-type" class="field">
            <option value="Regular Session">Regular Session</option>
            <option value="Special Session">Special Session</option>
            <option value="Others">Others (Please Specify)</option>
          </select>
          <input id="db-type-other" class="field" placeholder="Please specify..."
                 style="display:none;margin-top:8px" />
        </div>
        <div>
          <label class="field-label" for="db-venue">Venue *</label>
          <select id="db-venue" class="field">
            <option value="SB Hall">SB Hall</option>
            <option value="Old SB Hall">Old SB Hall</option>
            <option value="ABC Hall">ABC Hall</option>
            <option value="Others">Others (Please Specify)</option>
          </select>
          <input id="db-venue-other" class="field" placeholder="Please specify..."
                 style="display:none;margin-top:8px" />
        </div>
        <div>
          <label class="field-label" for="db-stakeholders">Stakeholders / External Participants</label>
          <input id="db-stakeholders" class="field" placeholder="e.g. DILG, DSWD, Barangay Representatives (comma-separated)" autocomplete="off" />
          <div class="helper-text" style="margin-top:3px;font-size:0.78rem">Optional — list organizations or individuals attending from outside.</div>
        </div>
        <div>
          <label class="field-label" for="db-notes">Notes</label>
          <textarea id="db-notes" class="field" rows="3" style="resize:vertical"
                    placeholder="Optional additional information…"></textarea>
        </div>
        <div id="db-form-msg" class="helper-text" style="color:var(--color-danger);font-size:0.82rem"></div>
      </form>`;

    const footerHTML = `
      <button id="db-cancel" class="btn btn-ghost">Cancel</button>
      <button id="db-submit" class="btn btn-primary">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2">
          <path d="M19 21H5a2 2 0 01-2-2V5a2 2 0 012-2h11l5 5v14a2 2 0 01-2 2z"/>
          <polyline points="17 21 17 13 7 13 7 21"/>
        </svg>
        Save Schedule
      </button>`;

    const drawer = _makeDrawer("drawer-booking", titleHTML, "", bodyHTML, footerHTML);
    _openDrawer(drawer);

    requestAnimationFrame(() => {
      // Populate dropdowns
      _dbPopulateTime(activeDate);
      _dbPopulateDuration();
      _dbUpdateEndPreview();

      // Event listeners
      document.getElementById("db-cancel")?.addEventListener("click", _closeActive);
      document.getElementById("db-submit")?.addEventListener("click", _dbHandleSubmit);

      document.getElementById("db-date")?.addEventListener("change", function () {
        _dbPopulateTime(this.value);
        _dbUpdateEndPreview();
      });
      document.getElementById("db-time")?.addEventListener("change", _dbUpdateEndPreview);
      document.getElementById("db-duration")?.addEventListener("change", function () {
        const d = document.getElementById("db-date")?.value;
        _dbPopulateTime(d);
        _dbUpdateEndPreview();
      });

      document.getElementById("db-type")?.addEventListener("change", function () {
        document.getElementById("db-type-other").style.display =
          this.value === "Others" ? "" : "none";
      });
      document.getElementById("db-venue")?.addEventListener("change", function () {
        document.getElementById("db-venue-other").style.display =
          this.value === "Others" ? "" : "none";
      });
    });
  };

  // ── Booking drawer helpers ─────────────────────────────────────────────────

  function _dbPopulateTime(isoDate) {
    const sel  = document.getElementById("db-time");
    const hint = document.getElementById("db-time-hint");
    const durEl = document.getElementById("db-duration");
    if (!sel) return;

    const dur = parseInt(durEl?.value) || SLOT_DURATION_HOURS;
    const approved = meetings.filter(
      m => m.date === isoDate && m.status === "Approved"
    );
    sel.innerHTML = "";
    let count = 0;

    for (let h = WORK_START_HOUR; h < WORK_END_HOUR; h++) {
      const slotStart = h * 60;
      const slotEnd   = slotStart + dur * 60;

      // Skip if duration would exceed office hours
      if (slotEnd > WORK_END_HOUR * 60) continue;

      // Skip if this slot overlaps any approved meeting
      const blocked = approved.some(m => {
        const s = minutesFromTimeStr(m.timeStart);
        const e = s + (m.durationHours || SLOT_DURATION_HOURS) * 60;
        return slotStart < e && slotEnd > s;
      });

      if (!blocked) {
        const label = h < 12
          ? `${h}:00 AM`
          : h === 12 ? "12:00 PM"
          : `${h - 12}:00 PM`;
        const opt = document.createElement("option");
        opt.value = `${String(h).padStart(2, "0")}:00`;
        opt.textContent = label;
        sel.appendChild(opt);
        count++;
      }
    }

    if (hint) {
      if (count === 0) {
        hint.style.color = "var(--color-danger)";
        hint.textContent = "✗ No time slots available for this date";
      } else if (approved.length === 0) {
        hint.style.color = "var(--color-success)";
        hint.textContent = "✓ All time slots available for this date";
      } else {
        hint.style.color = "var(--color-warning)";
        hint.textContent = "⚠ Some slots are taken";
      }
    }
  }

  function _dbPopulateDuration() {
    const sel = document.getElementById("db-duration");
    if (!sel) return;
    sel.innerHTML = "";
    for (let h = 1; h <= 8; h++) {
      const opt = document.createElement("option");
      opt.value = h;
      opt.textContent = `${h} hour${h > 1 ? "s" : ""}`;
      if (h === (SLOT_DURATION_HOURS || 3)) opt.selected = true;
      sel.appendChild(opt);
    }
  }

  function _dbUpdateEndPreview() {
    const timeEl = document.getElementById("db-time");
    const durEl  = document.getElementById("db-duration");
    const prev   = document.getElementById("db-end-preview");
    if (!timeEl || !durEl || !prev) return;
    const startMins = minutesFromTimeStr(timeEl.value);
    const dur = parseInt(durEl.value) || SLOT_DURATION_HOURS;
    const endMins = startMins + dur * 60;
    const eh = Math.floor(endMins / 60);
    const em = endMins % 60;
    const label = eh < 12
      ? `${eh}:${String(em).padStart(2, "0")} AM`
      : eh === 12 ? `12:${String(em).padStart(2, "0")} PM`
      : `${eh - 12}:${String(em).padStart(2, "0")} PM`;
    prev.style.color = endMins > WORK_END_HOUR * 60
      ? "var(--color-danger)" : "var(--color-text-muted)";
    prev.textContent = endMins > WORK_END_HOUR * 60
      ? `⚠ End time ${label} exceeds office hours`
      : `End Time: ${label}`;
  }

  function _dbHandleSubmit() {
    const msg = document.getElementById("db-form-msg");
    const currentUser = getCurrentUser();
    if (!currentUser) return;

    const get = id => document.getElementById(id)?.value.trim();

    const eventName    = get("db-event");
    const committee    = get("db-committee");
    const councilor    = get("db-councilor");
    const researcher   = get("db-researcher");
    const date         = get("db-date");
    const timeStart    = get("db-time");
    const durationHours = parseInt(get("db-duration"));
    const typeVal      = get("db-type");
    const type         = typeVal === "Others" ? get("db-type-other") : typeVal;
    const venueVal     = get("db-venue");
    const venue        = venueVal === "Others" ? get("db-venue-other") : venueVal;
    const stakeholders = get("db-stakeholders");
    const notes        = get("db-notes");

    if (!eventName || !committee || !date || !timeStart) {
      if (msg) msg.textContent = "Please fill in all required fields.";
      return;
    }
    if (!councilor) {
      if (msg) msg.textContent = "Please select a Councilor or choose N/A.";
      return;
    }
    if (!researcher) {
      if (msg) msg.textContent = "Please select a Researcher or choose N/A.";
      return;
    }
    if (councilor === "N/A" && researcher === "N/A") {
      if (msg) msg.textContent = "Councilor and Researcher cannot both be N/A.";
      return;
    }
    const todayISO = getTodayISOManila();
    if (date < todayISO) {
      if (msg) msg.textContent = "Cannot schedule meetings on past dates.";
      return;
    }
    if (msg) msg.textContent = "";

    const btn = document.getElementById("db-submit");
    if (btn) { btn.disabled = true; btn.textContent = "Saving…"; }

    window.api.addMeeting({
      id: `mtg_${Math.random().toString(36).slice(2, 9)}`,
      eventName, committee, councilor, researcher, stakeholders,
      date, timeStart, durationHours,
      type, venue, notes,
      status: currentUser.role === ROLES.ADMIN ? "Approved" : "Pending",
      createdBy: currentUser.username,
      createdByRole: currentUser.role,
      createdAt: new Date().toISOString(),
    }).then(() => {
      // Only notify admins if it's a user request (admin doesn't need to notify themselves)
      if (currentUser.role !== ROLES.ADMIN) {
        users.filter(u => u.role === ROLES.ADMIN).forEach(admin => {
          addNotification(
            admin.id || admin.username,
            `New meeting request from <strong>${currentUser.name}</strong>: <strong>"${eventName}"</strong> on ${formatDateDisplay(date)} at ${formatTimeRange(timeStart, durationHours)}. Review and take action.`,
          "info",
          "meeting-logs"
        );
      });
      } // end if non-admin notify
      // If admin scheduled on behalf of councilor/researcher, notify them
      if (currentUser.role === ROLES.ADMIN) {
        const dateStr = formatDateDisplay(date);
        const timeStr = formatTimeRange(timeStart, durationHours);
        if (councilor && councilor !== "N/A") {
          const cUser = users.find(u => u.name === councilor);
          if (cUser) addNotification(cUser.id || cUser.username,
            `The Admin has scheduled a meeting on your behalf: <strong>"${eventName}"</strong> on ${dateStr} at ${timeStr}. Venue: ${venue}. Status: <strong>Approved</strong>.`,
            "success", "my-meetings");
        }
        if (researcher && researcher !== "N/A") {
          const rUser = users.find(u => u.name === researcher);
          if (rUser) addNotification(rUser.id || rUser.username,
            `The Admin has scheduled a meeting on your behalf: <strong>"${eventName}"</strong> on ${dateStr} at ${timeStr}. Venue: ${venue}. Status: <strong>Approved</strong>.`,
            "success", "my-meetings");
        }
      }
      // Optimistic badge refresh
      updateNotificationBadge(currentUser.id || currentUser.username);

      const toastMsg = currentUser.role === ROLES.ADMIN
        ? "Meeting scheduled and automatically approved."
        : "Meeting request submitted! Awaiting admin approval.";
      showToast(toastMsg, "success");
      renderCalendar();
      renderMyMeetingsTable(currentUser);
      renderAdminMeetingsTable();
      updateStatistics();
      _closeActive();
    }).catch(() => {
      if (msg) msg.textContent = "Failed to save. Please try again.";
      if (btn) { btn.disabled = false; btn.innerHTML = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M19 21H5a2 2 0 01-2-2V5a2 2 0 012-2h11l5 5v14a2 2 0 01-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/></svg> Save Schedule`; }
    });
  }

  // ── Logout confirmation drawer (mobile) ───────────────────────────────────
  window.openLogoutDrawer = function (onConfirm) {
    const titleHTML = `
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2">
        <path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4"/>
        <polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/>
      </svg>
      Sign Out`;

    const bodyHTML = `
      <div style="text-align:center;padding:8px 0 4px">
        <div style="width:56px;height:56px;border-radius:50%;background:#fee2e2;display:flex;align-items:center;justify-content:center;margin:0 auto 14px">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#dc2626" stroke-width="2.2">
            <path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4"/>
            <polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/>
          </svg>
        </div>
        <div style="font-weight:700;font-size:1rem;color:var(--color-text);margin-bottom:6px">Sign out?</div>
        <div style="font-size:0.86rem;color:var(--color-text-muted);line-height:1.5">Any unsaved changes will be lost.</div>
      </div>`;

    const footerHTML = `
      <button id="logout-drawer-cancel" class="btn btn-ghost" style="flex:1">Cancel</button>
      <button id="logout-drawer-confirm" class="btn btn-danger" style="flex:1">Sign Out</button>`;

    const drawer = _makeDrawer("drawer-logout", titleHTML, "", bodyHTML, footerHTML);
    _openDrawer(drawer);

    requestAnimationFrame(() => {
      document.getElementById("logout-drawer-cancel")?.addEventListener("click", _closeActive);
      document.getElementById("logout-drawer-confirm")?.addEventListener("click", () => {
        _closeActive();
        onConfirm();
      });
    });
  };

})();