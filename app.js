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
};

const ROLE_LIMITS = {
  [ROLES.COUNCILOR]: 10,
  [ROLES.RESEARCHER]: 10,
  [ROLES.VICE_MAYOR]: 1,
};

const WORK_START_HOUR = 8;
const WORK_END_HOUR = 17;
let SLOT_DURATION_HOURS = 3;

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
// ---------------------------------------------------------------------------

function refreshSession() {
  save(STORAGE_KEYS.SESSION_EXPIRY, Date.now() + SESSION_TIMEOUT_MS);
}

function checkSessionExpiry() {
  const expiry = load(STORAGE_KEYS.SESSION_EXPIRY, null);
  if (expiry && Date.now() > expiry) {
    setCurrentUser(null);
    localStorage.removeItem(STORAGE_KEYS.SESSION_EXPIRY);
    window.location.href = "./index.html?timeout=1";
    return false;
  }
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
    const pendingCount = (meetings || []).filter(m => m.status === "Pending" || m.status === "Cancellation Requested").length;
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

function statusColorForCalendar(status) {
  const map = {
    "Approved": "calendar-badge calendar-badge-approved",
    "Pending": "calendar-badge calendar-badge-pending",
    "Cancelled": "calendar-badge calendar-badge-cancelled",
    "Rejected": "calendar-badge calendar-badge-cancelled",
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
              (role === ROLES.VICE_MAYOR && allowCouncilor);
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
      openConfirmModal(
        "Sign Out",
        "Are you sure you want to sign out? Any unsaved changes will be lost.",
        () => {
          setCurrentUser(null);
          window.location.href = "./index.html";
        }
      );
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

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
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
      setError("Invalid username or password.");
      return;
    }

    // Fix 14: Check mustChangePassword flag — force password change before proceeding
    if (account.mustChangePassword) {
      if (loginBtn) { loginBtn.classList.remove("loading"); loginBtn.disabled = false; }
      // Store minimal session so the password modal can save
      const tempUser = { id: account.id, username: account.username, role: account.role, name: account.name || account.username };
      setCurrentUser(tempUser);
      openForcePasswordChangeModal(account);
      return;
    }

    const current = { id: account.id, username: account.username, role: account.role, name: account.name || account.username };
    setCurrentUser(current);
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
  if (!tbody) return;

  let list = [...users];
  if (usersSearch) {
    const q = usersSearch.toLowerCase();
    list = list.filter(u =>
      (u.username || "").toLowerCase().includes(q) ||
      (u.name || "").toLowerCase().includes(q) ||
      (u.role || "").toLowerCase().includes(q)
    );
  }

  // Pagination
  const totalPages = Math.max(1, Math.ceil(list.length / MEETINGS_PAGE_SIZE));
  if (usersPage > totalPages) usersPage = totalPages;
  const paginated = list.slice((usersPage - 1) * MEETINGS_PAGE_SIZE, usersPage * MEETINGS_PAGE_SIZE);

  if (!paginated.length) {
    tbody.innerHTML = '<tr><td colspan="4" class="text-muted">No user accounts found.</td></tr>';
    renderPagination("users-pagination", totalPages, usersPage, (p) => { usersPage = p; renderUsersTable(); });
    return;
  }

  tbody.innerHTML = paginated.map(u => {
    const isAdmin = u.role === ROLES.ADMIN;
    return `<tr>
      <td>${u.username}</td>
      <td>${u.name || ""}</td>
      <td><span class="${roleChipClass(u.role)}">${u.role}</span></td>
      <td>
        <button class="btn btn-sm btn-ghost" data-action="change-password" data-user-id="${u.id}">Change Password</button>
        ${!isAdmin ? `<button class="btn btn-sm btn-ghost" data-action="remove-user" data-user-id="${u.id}">Remove</button>` : ""}
      </td>
    </tr>`;
  }).join("");

  renderPagination("users-pagination", totalPages, usersPage, (p) => { usersPage = p; renderUsersTable(); });
}

async function handleUserFormSubmit(e) {
  e.preventDefault();
  const username = $("#user-username").value.trim();
  const name = $("#user-name").value.trim();
  const password = $("#user-password").value;
  const confirm = $("#user-confirm").value;
  const role = $("#user-role").value;
  const msg = $("#user-form-message");

  if (!username || !name) { msg.textContent = "Username and full name are required."; showToast("Username and full name are required.", "error"); return; }
  if (password.length < 6) { msg.textContent = "Password must be at least 6 characters."; showToast("Password too short.", "error"); return; }
  if (password !== confirm) { msg.textContent = "Passwords do not match."; showToast("Passwords do not match.", "error"); return; }
  if (users.some(u => u.username === username)) { msg.textContent = "Username already exists."; showToast("Username already exists.", "error"); return; }

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

  if (window.api && window.api.createUser) {
    window.api.createUser(newUser).then(async () => {
      users = await window.api.getUsers();
      $("#user-form").reset();
      msg.textContent = "User account created successfully.";
      showToast("User account created.", "success");
      renderUsersTable();
      updateStatistics();
    });
  } else {
    users.push(newUser);
    persistUsers();
    $("#user-form").reset();
    msg.textContent = "User account created successfully.";
    showToast("User account created.", "success");
    renderUsersTable();
    updateStatistics();
  }
}

function handleUserTableClick(e) {
  const btn = e.target.closest("button[data-action]");
  if (!btn) return;
  const action = btn.dataset.action;
  const userId = btn.dataset.userId;
  const user = users.find(u => u.id === userId);
  if (!user) return;

  if (action === "remove-user") {
    openConfirmModal(
      "Remove User Account",
      `Are you sure you want to remove <strong>${user.name}</strong>? This cannot be undone.`,
      () => {
        if (window.api && window.api.deleteUser) {
          window.api.deleteUser(userId).then(async () => {
            users = await window.api.getUsers();
            renderUsersTable(); updateStatistics();
            showToast("User account removed.", "success");
          });
        } else {
          users = users.filter(u => u.id !== userId);
          persistUsers(); renderUsersTable(); updateStatistics();
          showToast("User account removed.", "success");
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
      <div class="modal" style="max-width:420px">
        <div class="modal-header">
          <div class="modal-title" id="confirm-modal-title"></div>
          <button id="confirm-modal-close" class="btn btn-ghost btn-sm">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
          </button>
        </div>
        <div class="modal-body"><div id="confirm-modal-body" style="font-size:0.9rem;color:#374151;line-height:1.6"></div></div>
        <div class="modal-footer">
          <button id="confirm-modal-cancel" class="btn btn-ghost btn-sm">Cancel</button>
          <button id="confirm-modal-ok" class="btn btn-danger btn-sm">Confirm</button>
        </div>
      </div>`;
    document.body.appendChild(modal);
  }
  document.getElementById("confirm-modal-title").textContent = title;
  document.getElementById("confirm-modal-body").innerHTML = bodyHtml;
  modal.classList.add("modal-open");
  const close = (cancelled) => {
    modal.classList.remove("modal-open");
    if (cancelled && typeof onCancel === "function") onCancel();
  };
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
      (m.type || "").toLowerCase().includes(q) ||
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
    const noteTitle = m.adminNote ? ` title="${String(m.adminNote).replace(/"/g, "&quot;")}"` : "";
    const noteHint = m.adminNote ? `<div style="font-size:0.72rem;color:#6b7280;margin-top:3px;max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${String(m.adminNote).replace(/"/g, "&quot;")}">Note: ${m.adminNote}</div>` : "";
    return `<tr>
      <td>${m.eventName}</td>
      <td>${formatDateDisplay(m.date)}</td>
      <td>${formatTimeRange(m.timeStart, m.durationHours || SLOT_DURATION_HOURS)}</td>
      <td>${m.type}</td>
      <td${noteTitle}>${meetingStatusBadge(m.status)}${noteHint}</td>
      <td>
        ${canRequestCancel
          ? `<button class="btn btn-sm btn-ghost" data-action="request-cancel" data-meeting-id="${m.id}">Request Cancellation</button>`
          : `<button class="btn btn-sm btn-ghost" data-action="export-pdf" data-meeting-id="${m.id}">Export PDF</button>`}
      </td>
    </tr>`;
  }).join("");

  renderPagination("my-meetings-pagination", totalPages, myMeetingsPage, (p) => { myMeetingsPage = p; renderMyMeetingsTable(currentUser); });
}

function renderAdminMeetingsTable() {
  const tbody = $("#admin-meetings-body");
  if (!tbody) return;

  const filterType = $("#filter-type-admin")?.value || "all";
  const filterStatus = $("#filter-status-admin")?.value || "all";
  let list = [...meetings];
  if (filterType !== "all") list = list.filter(m => m.type === filterType);
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
    const printBtn = m.status === "Approved"
      ? `<button class="btn btn-sm btn-ghost" data-action="print" data-meeting-id="${m.id}">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 6 2 18 2 18 9"/><path d="M6 18H4a2 2 0 01-2-2v-5a2 2 0 012-2h16a2 2 0 012 2v5a2 2 0 01-2 2h-2"/><rect x="6" y="14" width="12" height="8"/></svg>
          PDF</button>` : "";

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
          <button class="action-btn action-btn-approve" data-action="status" data-status="Approved" data-meeting-id="${m.id}">
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>Approve
          </button>
          <button class="action-btn action-btn-reject" data-action="status" data-status="Rejected" data-meeting-id="${m.id}">
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>Reject
          </button>
          <button class="action-btn action-btn-cancel" data-action="status" data-status="Cancelled" data-meeting-id="${m.id}">
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>Cancel
          </button>
          <button class="action-btn action-btn-done" data-action="status" data-status="Done" data-meeting-id="${m.id}">
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>Done
          </button>
          ${printBtn}
        </div>`;
    return `<tr${isCancelRequest ? ' style="background:rgba(249,115,22,0.04)"' : ''}>
      <td>${m.eventName}</td>
      <td>${formatDateDisplay(m.date)}</td>
      <td>${formatTimeRange(m.timeStart, m.durationHours || SLOT_DURATION_HOURS)}</td>
      <td>${m.type}</td>
      <td>${meetingStatusBadge(m.status)}</td>
      <td>${m.createdBy}</td>
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
        <div class="modal-body section-stack">
          <div id="note-modal-prompt" style="font-size:0.85rem;color:#374151"></div>
          <textarea id="note-modal-input" class="field" rows="3" style="resize:vertical"></textarea>
          <div id="note-modal-error" style="color:#dc2626;font-size:0.8rem"></div>
        </div>
        <div class="modal-footer">
          <button id="note-modal-cancel" class="btn btn-ghost btn-sm">Cancel</button>
          <button id="note-modal-submit" class="btn btn-primary btn-sm">Confirm</button>
        </div>
      </div>`;
    document.body.appendChild(modal);
  }
  document.getElementById("note-modal-title").textContent = title;
  document.getElementById("note-modal-prompt").textContent = prompt;
  document.getElementById("note-modal-input").value = "";
  document.getElementById("note-modal-error").textContent = "";
  modal.classList.add("modal-open");

  const close = (cancelled) => {
    modal.classList.remove("modal-open");
    if (cancelled && typeof onCancel === "function") onCancel();
  };

  document.getElementById("note-modal-close").onclick = () => close(true);
  document.getElementById("note-modal-cancel").onclick = () => close(true);
  document.getElementById("note-modal-submit").onclick = () => {
    const note = document.getElementById("note-modal-input").value.trim();
    if (required && !note) {
      document.getElementById("note-modal-error").textContent = "A reason is required.";
      return;
    }
    close(false);
    onSubmit(note);
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
      `Type: ${mtg.type}`, `Venue: ${mtg.venue || ""}`,
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
    // Disable immediately to prevent double-click
    btn.disabled = true;
    btn.dataset.processing = "1";
    const reenable = () => { btn.disabled = false; btn.dataset.processing = "0"; };

    openConfirmModal(
      "Request Cancellation",
      `Request cancellation for <strong>${mtg.eventName}</strong> on ${formatDateDisplay(mtg.date)}? The admin will review and confirm.`,
      () => {
        mtg.status = "Cancellation Requested";
        persistMeetings();
        const currentUser = getCurrentUser();
        renderMyMeetingsTable(currentUser);
        renderAdminMeetingsTable();
        renderCalendar();
        showToast("Cancellation request submitted.", "info");

        // Notify all admins
        users.filter(u => u.role === ROLES.ADMIN).forEach(admin => {
          addNotification(
            admin.id || admin.username,
            `<strong>${currentUser.name}</strong> has requested cancellation of <strong>"${mtg.eventName}"</strong> scheduled on ${formatDateDisplay(mtg.date)}. Please review and take action.`,
            "warning",
            "meeting-logs"
          );
        });

        // Confirm back to the requesting user
        addNotification(
          currentUser.id || currentUser.username,
          `Your cancellation request for <strong>"${mtg.eventName}"</strong> on ${formatDateDisplay(mtg.date)} has been submitted and is pending admin review.`,
          "info",
          "my-meetings"
        );
        updateNotificationBadge(currentUser.id || currentUser.username);
      },
      reenable   // re-enable button if user cancels the confirm dialog
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
      const badge = document.createElement("div");
      badge.className = statusColorForCalendar(m.status);
      const timeLabel = m.timeStart ? `${formatTime12h(minutesFromTimeStr(m.timeStart))} ` : "";
      badge.textContent = timeLabel + (m.eventName || "Meeting");
      badge.title = `${m.eventName} — ${formatTimeRange(m.timeStart, m.durationHours || SLOT_DURATION_HOURS)} [${m.status}]`;
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
      [ROLES.ADMIN, ROLES.COUNCILOR, ROLES.RESEARCHER, ROLES.VICE_MAYOR].includes(currentUser.role);

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
    [ROLES.ADMIN, ROLES.COUNCILOR, ROLES.RESEARCHER, ROLES.VICE_MAYOR].includes(currentUser.role);

  let modal = document.getElementById("day-schedule-modal");
  if (!modal) {
    modal = document.createElement("div");
    modal.id = "day-schedule-modal";
    modal.className = "modal-backdrop";
    modal.innerHTML = `
      <div class="modal" style="max-width:520px">
        <div class="modal-header" style="flex-direction:column;align-items:flex-start;gap:4px">
          <div style="display:flex;align-items:center;justify-content:space-between;width:100%">
            <div class="modal-title" id="day-modal-title"></div>
            <button id="day-modal-close" class="btn btn-ghost btn-sm">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
            </button>
          </div>
          <div id="day-modal-subtitle" style="font-size:0.78rem;margin-top:2px"></div>
        </div>
        <div class="modal-body" id="day-schedule-body" style="padding:16px 20px;max-height:65vh;overflow-y:auto"></div>
        <div class="modal-footer" id="day-modal-footer"></div>
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
  const body = document.getElementById("day-schedule-body");

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
      ? `<div style="background:#fee2e2;border:1px solid #fca5a5;border-radius:8px;padding:8px 12px;font-size:0.8rem;color:#991b1b;font-weight:600;margin-bottom:10px";display:flex;align-items:center;gap:6px"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg> This day is fully booked — no available time slots.</div>`
      : approvedMeetings.length
        ? `<div style="background:#fef3c7;border:1px solid #fcd34d;border-radius:8px;padding:8px 12px;font-size:0.8rem;color:#92400e;font-weight:500;margin-bottom:10px";display:flex;align-items:center;gap:6px"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg> Some slots are taken — check the timeline above before booking.</div>`
        : "";

    meetingListHtml = statusNote + `<div style="font-size:0.71rem;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:var(--color-text-muted);margin-bottom:8px">Meetings (${dayMeetings.length})</div>
      <div style="display:flex;flex-direction:column;gap:7px">
        ${dayMeetings.map(m => {
          const c = STATUS_STYLE[m.status] || STATUS_STYLE["Cancelled"];
          const timeRange = m.timeStart ? formatTimeRange(m.timeStart, m.durationHours || SLOT_DURATION_HOURS) : "—";
          return `<div style="background:${c.bg};border:1px solid ${c.border};border-left:4px solid ${c.border};border-radius:8px;padding:10px 12px">
            <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:8px">
              <div style="min-width:0">
                <div style="font-weight:600;font-size:0.85rem;color:${c.text};overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${m.eventName || "Meeting"}</div>
                <div style="font-size:0.75rem;color:${c.text};opacity:.85;margin-top:3px;display:flex;flex-wrap:wrap;gap:6px">
                  <span style="display:inline-flex;align-items:center;gap:3px"><svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>${timeRange}</span>
                  <span style="display:inline-flex;align-items:center;gap:3px"><svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>${m.durationHours || SLOT_DURATION_HOURS}h</span>
                  ${m.venue ? `<span style="display:inline-flex;align-items:center;gap:3px"><svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"/><circle cx="12" cy="10" r="3"/></svg>${m.venue}</span>` : ""}
                </div>
                ${m.councilor ? `<div style="font-size:0.72rem;color:${c.text};opacity:.7;margin-top:3px" style=\"display:flex;align-items:center;gap:3px\"><svg width=\"11\" height=\"11\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2.5\"><circle cx=\"12\" cy=\"8\" r=\"4\"/><path d=\"M4 20c0-4 3.6-7 8-7s8 3 8 7\"/></svg>${m.councilor}</div>` : ""}
                ${m.committee ? `<div style="font-size:0.72rem;color:${c.text};opacity:.7" style=\"display:flex;align-items:center;gap:3px\"><svg width=\"11\" height=\"11\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2.5\"><rect x=\"2\" y=\"7\" width=\"20\" height=\"14\" rx=\"1\"/><path d=\"M16 7V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v2\"/></svg>${m.committee}</div>` : ""}
                ${m.adminNote ? `<div style="font-size:0.7rem;color:${c.text};opacity:.65;margin-top:4px;font-style:italic" style=\"display:flex;align-items:center;gap:3px\"><svg width=\"10\" height=\"10\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2.5\"><path d=\"M12 20h9\"/><path d=\"M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z\"/></svg>${m.adminNote}</div>` : ""}
              </div>
              <span style="flex-shrink:0;font-size:0.68rem;font-weight:700;background:white;color:${c.text};border:1px solid ${c.border};padding:2px 8px;border-radius:999px;white-space:nowrap">${m.status}</span>
            </div>
          </div>`;
        }).join("")}
      </div>`;
  }

  body.innerHTML = timelineHtml + meetingListHtml;

  // Footer
  const footer = document.getElementById("day-modal-footer");
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

  // Hour ticks
  const ticks = [];
  for (let h = WORK_START_HOUR; h <= WORK_END_HOUR; h++) {
    ticks.push(`<div style="position:absolute;left:${pct(h*60)}%;top:0;bottom:0;border-left:1px dashed rgba(0,0,0,0.1);pointer-events:none"></div>
      <div style="position:absolute;left:${pct(h*60)}%;top:calc(100% + 3px);font-size:0.58rem;color:var(--color-text-muted);transform:translateX(-50%)">${h <= 12 ? h : h-12}${h < 12 ? 'a' : 'p'}</div>`);
  }

  // Approved blocks (solid red)
  const approvedBlocks = approved.map(m => {
    const s = minutesFromTimeStr(m.timeStart);
    const dur = (m.durationHours || SLOT_DURATION_HOURS) * 60;
    return `<div title="${m.eventName} (Approved)" style="position:absolute;left:${pct(s)}%;width:${wPct(dur)}%;top:4px;bottom:4px;background:#16a34a;border-radius:4px;opacity:0.85;cursor:default"></div>`;
  }).join("");

  // Pending blocks (amber)
  const pendingBlocks = pending.map(m => {
    const s = minutesFromTimeStr(m.timeStart);
    const dur = (m.durationHours || SLOT_DURATION_HOURS) * 60;
    return `<div title="${m.eventName} (Pending)" style="position:absolute;left:${pct(s)}%;width:${wPct(dur)}%;top:4px;bottom:4px;background:#f59e0b;border-radius:4px;opacity:0.75;cursor:default"></div>`;
  }).join("");

  return `
    <div style="margin-bottom:16px">
      <div style="font-size:0.71rem;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:var(--color-text-muted);margin-bottom:8px">Time Slots (8AM – 5PM)</div>
      <div style="position:relative;height:32px;background:var(--color-bg);border:1px solid var(--color-border);border-radius:8px;overflow:visible;margin-bottom:18px">
        ${ticks.join("")}
        ${approvedBlocks}
        ${pendingBlocks}
      </div>
      <div style="display:flex;gap:12px;flex-wrap:wrap">
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

function openMeetingModal(isoDate) {
  const currentUser = getCurrentUser();
  if (!currentUser || ![ROLES.ADMIN, ROLES.COUNCILOR, ROLES.RESEARCHER, ROLES.VICE_MAYOR].includes(currentUser.role)) {
    showToast("Only authorized roles may book meetings.", "warning");
    return;
  }

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

  if (currentUser.role === ROLES.COUNCILOR) {
    const c = $("#meeting-councilor");
    if (c) { c.value = currentUser.name; c.readOnly = true; }
  }
  if (currentUser.role === ROLES.RESEARCHER) {
    const r = $("#meeting-researcher");
    if (r) { r.value = currentUser.name; r.readOnly = true; }
  }

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

function handleMeetingSubmit(e) {
  e.preventDefault();
  const msg = $("#meeting-form-message");
  const currentUser = getCurrentUser();
  if (!currentUser) return;

  const eventName = $("#meeting-event").value.trim();
  const committee = $("#meeting-committee").value.trim();
  const councilor = $("#meeting-councilor").value.trim();
  const researcher = $("#meeting-researcher").value.trim();
  const notes = $("#meeting-notes").value.trim();
  const isoDate = $("#meeting-date").value;
  const timeStart = $("#meeting-time").value;
  const durationEl = $("#meeting-duration");
  const durationHours = durationEl ? parseInt(durationEl.value || "3", 10) : SLOT_DURATION_HOURS;

  const typeRaw = $("#meeting-type")?.value || "";
  const typeOther = $("#meeting-type-other")?.value.trim() || "";
  const venueRaw = $("#meeting-venue")?.value || "";
  const venueOther = $("#meeting-venue-other")?.value.trim() || "";

  let type = typeRaw || "Regular Session";
  if (typeRaw === "Others") {
    if (!typeOther) { msg.textContent = "Please specify the type of meeting."; showToast("Please specify meeting type.", "error"); return; }
    type = typeOther;
  }

  let venue = venueRaw;
  if (venueRaw === "Others") {
    if (!venueOther) { msg.textContent = "Please specify the venue."; showToast("Please specify venue.", "error"); return; }
    venue = venueOther;
  }

  if (!eventName || !committee || !venue || !councilor || !researcher) {
    msg.textContent = "Please complete all required fields (*).";
    showToast("Please complete all required fields.", "error");
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
  const endMinutes = startMinutes + durationHours * 60;
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
    const conflictTime = formatTimeRange(conflictingApproved.timeStart, conflictingApproved.durationHours || SLOT_DURATION_HOURS);
    msg.textContent = `This time overlaps with an approved meeting: "${conflictingApproved.eventName}" (${conflictTime}). Please choose a different time slot.`;
    showToast("Conflict with approved meeting — choose another slot.", "error");
    // Refresh time options to show the conflict
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
    showToast(`Note: "${conflictingPending.eventName}" is also pending for this time. If both are approved, yours may be auto-cancelled.`, "warning");
  }

  // Confirmation step before submitting
  closeMeetingModal();
  openConfirmModal(
    "Confirm Meeting Request",
    `<strong>${eventName}</strong><br>
     Date: ${formatDateDisplay(isoDate)}<br>
     Time: ${formatTimeRange(timeStart, durationHours)}<br>
     Venue: ${venue}<br>
     Type: ${type}<br><br>
     Submit this meeting request?`,
    () => {
      const meeting = {
        id: `mtg_${Math.random().toString(36).slice(2, 9)}`,
        eventName, committee, venue, councilor, researcher, notes,
        date: isoDate, timeStart, durationHours, type,
        status: "Pending",
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

      // Notify all admins of new request
      users.filter(u => u.role === ROLES.ADMIN).forEach(admin => {
        addNotification(
          admin.id || admin.username,
          `New meeting request from <strong>${currentUser.name}</strong>: <strong>"${eventName}"</strong> on ${formatDateDisplay(isoDate)} at ${formatTimeRange(timeStart, durationHours)}. Review and take action.`,
          "info",
          "meeting-logs"
        );
      });

      showToast("Meeting request submitted.", "success");
      renderCalendar();
      renderMyMeetingsTable(currentUser);
      renderAdminMeetingsTable();
      updateStatistics();
    }
  );
}

// ---------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------

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

  if (totalEl) totalEl.textContent = total;
  if (pendingEl) pendingEl.textContent = pending;
  if (activeUsersEl) activeUsersEl.textContent = activeUsers;
  if (upcomingEl) upcomingEl.textContent = upcoming;

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
    hint.innerHTML = `<span style="color:#16a34a;font-size:0.72rem";display:inline-flex;align-items:center;gap:4px"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 17 4 12"/></svg>All time slots available for this date</span>`;
  } else if (available === 0) {
    hint.innerHTML = `<span style="color:#dc2626;font-size:0.72rem;font-weight:600";display:inline-flex;align-items:center;gap:4px"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>No available time slots — this day is fully booked</span>`;
  } else {
    hint.innerHTML = `<span style="color:#f59e0b;font-size:0.72rem";display:inline-flex;align-items:center;gap:4px"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>${blocked} slot(s) blocked by approved meetings — grayed options are unavailable</span>`;
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
  $("#user-table-body")?.addEventListener("click", handleUserTableClick);
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

  $("#admin-meetings-body")?.addEventListener("click", handleAdminMeetingsClick);
  $("#meeting-form")?.addEventListener("submit", handleMeetingSubmit);
  $("#meeting-cancel-btn")?.addEventListener("click", closeMeetingModal);
  $("#meeting-modal-close")?.addEventListener("click", closeMeetingModal);
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
  $("#my-meetings-body")?.addEventListener("click", handleMyMeetingsClick);
  $("#calendar-prev")?.addEventListener("click", () => changeCalendarMonth(-1));
  $("#calendar-next")?.addEventListener("click", () => changeCalendarMonth(1));
  // "Today" button
  $("#calendar-today")?.addEventListener("click", jumpToToday);

  document.getElementById("search-my-meetings")?.addEventListener("input", e => {
    myMeetingsSearch = e.target.value; myMeetingsPage = 1; renderMyMeetingsTable(user);
  });

  initCalendarDate();
  renderMyMeetingsTable(user);
  updateStatistics();
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
// Entry point
// ---------------------------------------------------------------------------

document.addEventListener("DOMContentLoaded", () => {
  const page = document.body.dataset.page;
  if (page === "login") initLoginPage();
  else if (page === "admin") initAdminPage();
  else if (page === "user") initUserPage();
});