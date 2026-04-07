// Legislative Management System — Enhanced

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
  [ROLES.COUNCILOR]: 30,
  [ROLES.RESEARCHER]: 20,
  [ROLES.VICE_MAYOR]: 5,
  [ROLES.SECRETARY]: 5,
};

// Hard cap on total regular (non-admin, non-special) user accounts
const MAX_REGULAR_USERS = 50;

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

// Notification message sanitiser — strips all HTML except <strong> tags.
// Notification messages intentionally use <strong> for bold text (meeting names,
// status words). All other tags are escaped so a user-supplied meeting name like
// <script>alert(1)</script> can never execute inside the notification panel.
function sanitiseNotifMessage(msg) {
  if (msg == null) return "";
  const strongs = [];
  const withPlaceholders = String(msg).replace(/<strong>([\s\S]*?)<\/strong>/gi, (_, inner) => {
    strongs.push(h(inner));
    return "\x00STRONG" + (strongs.length - 1) + "\x00";
  });
  const escaped = h(withPlaceholders);
  return escaped.replace(/\x00STRONG(\d+)\x00/g, (_, i) => "<strong>" + strongs[i] + "<\/strong>");
}

// Session timeout: 30 minutes of inactivity
const SESSION_TIMEOUT_MS = 30 * 60 * 1000;

// Table pagination
const MEETINGS_PAGE_SIZE = 7;
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
    data.forEach(hol => {
      _phHolidayMap[hol.date] = { localName: hol.localName, name: hol.name, type: hol.types?.[0] || "Public" };
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

// ---------------------------------------------------------------------------
// Password hashing — PBKDF2-SHA-256 with per-password salt
// Format: "pbkdf2:<salt_hex>:<hash_hex>"
// Backwards-compatible: legacy SHA-256 hashes (64 hex chars, no prefix) are
// verified with the old method and migrated on next successful login.
// ---------------------------------------------------------------------------
async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const saltHex = Array.from(salt).map(b => b.toString(16).padStart(2,"0")).join("");
  const keyMaterial = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name:"PBKDF2", salt, iterations:200000, hash:"SHA-256" }, keyMaterial, 256
  );
  const hashHex = Array.from(new Uint8Array(bits)).map(b => b.toString(16).padStart(2,"0")).join("");
  return `pbkdf2:${saltHex}:${hashHex}`;
}

async function verifyPassword(password, storedHash) {
  if (!storedHash) return false;
  // Legacy SHA-256 format (64-char hex, no prefix) — still verify, migrate on login
  if (!storedHash.startsWith("pbkdf2:")) {
    const msgBuffer = new TextEncoder().encode(password);
    const hashBuffer = await crypto.subtle.digest("SHA-256", msgBuffer);
    const legacyHex = Array.from(new Uint8Array(hashBuffer)).map(b=>b.toString(16).padStart(2,"0")).join("");
    return legacyHex === storedHash;
  }
  // New PBKDF2 format
  const parts = storedHash.split(":");
  if (parts.length !== 3) return false;
  const saltBytes = new Uint8Array(parts[1].match(/.{2}/g).map(h => parseInt(h,16)));
  const expectedHash = parts[2];
  const keyMaterial = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name:"PBKDF2", salt:saltBytes, iterations:200000, hash:"SHA-256" }, keyMaterial, 256
  );
  const derivedHex = Array.from(new Uint8Array(bits)).map(b=>b.toString(16).padStart(2,"0")).join("");
  return derivedHex === expectedHash;
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
  // Throttle mousemove so it doesn't fire hundreds of times/sec
  let _mouseThrottle = 0;
  function _throttledRefresh() {
    const now = Date.now();
    if (now - _mouseThrottle > 30000) { _mouseThrottle = now; refreshSession(); }
  }
  ["click", "keypress", "touchstart"].forEach(evt => {
    document.addEventListener(evt, refreshSession, { passive: true });
  });
  document.addEventListener("mousemove", _throttledRefresh, { passive: true });
  setInterval(() => {
    if (!checkSessionExpiry()) return;
  }, 60 * 1000);
}

// ---------------------------------------------------------------------------
// Notifications
// ---------------------------------------------------------------------------

function getNotifications(userId) {
  // Read from localStorage cache — this is always up-to-date because
  // subscribeNotifications() keeps it in sync from Firestore in real time.
  const all = load(STORAGE_KEYS.NOTIFICATIONS, []);
  return all.filter(n => n.userId === userId);
}

function addNotification(userId, message, type = "info", section = null) {
  if (!userId) return;
  const notif = {
    id: crypto.randomUUID(),
    userId,
    message,
    type,
    section,
    read: false,
    createdAt: new Date().toISOString(),
  };
  // Primary: save to Firestore so it syncs across all devices and tabs.
  // Falls back to localStorage automatically when Firestore is unavailable.
  if (window.api && window.api.saveNotification) {
    window.api.saveNotification(notif).catch(() => {});
  } else {
    // Firestore api not ready yet — write to localStorage directly as backup
    const all = load(STORAGE_KEYS.NOTIFICATIONS, []);
    all.unshift(notif);
    const grouped = {};
    all.forEach(n => {
      if (!grouped[n.userId]) grouped[n.userId] = [];
      grouped[n.userId].push(n);
    });
    const capped = Object.values(grouped).flatMap(arr => arr.slice(0, 50));
    save(STORAGE_KEYS.NOTIFICATIONS, capped);
  }
}

function markAllNotificationsRead(userId) {
  // Mark read in Firestore (syncs across devices)
  if (window.api && window.api.markNotificationsRead) {
    window.api.markNotificationsRead(userId).catch(() => {});
  }
  // Also update localStorage cache immediately so the badge clears instantly
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

  // Update pending badge on nav link.
  // On admin page: counts all pending meetings system-wide (meeting-logs nav).
  // On user page:  counts only the current user's own pending meetings (my-meetings nav).
  const pendingBadge = document.getElementById("pending-badge");
  if (pendingBadge) {
    const safeMeetings = (typeof meetings !== "undefined" && Array.isArray(meetings)) ? meetings : [];
    const isAdminPage = document.body.dataset.page === "admin";
    const cu = getCurrentUser();
    let pendingCount = 0;

    if (isAdminPage) {
      // Admin sees all pending / cancellation-requested meetings system-wide
      pendingCount = safeMeetings.filter(m =>
        m.status === "Pending" || m.status === "Cancellation Requested"
      ).length;
    } else if (cu) {
      // Regular user: ONLY count meetings that genuinely belong to them.
      // We match by BOTH createdBy (username or id) AND by name on the
      // councilor/researcher fields — whichever the meeting was booked under.
      // This prevents stale meetings from a previous session (or meetings
      // belonging to other users) from triggering the badge on a new account.
      pendingCount = safeMeetings.filter(m => {
        if (m.status !== "Pending" && m.status !== "Cancellation Requested") return false;
        const byUsername  = m.createdBy === cu.username;
        const byId        = m.createdBy === cu.id;
        const byCouncilor = cu.role === ROLES.COUNCILOR  && m.councilor  === cu.name;
        const byResearcher= cu.role === ROLES.RESEARCHER && m.researcher === cu.name;
        return byUsername || byId || byCouncilor || byResearcher;
      }).length;
    }

    // Always keep the badge hidden when count is 0 — never show "0"
    pendingBadge.textContent = String(pendingCount);
    pendingBadge.style.display = pendingCount > 0 ? "flex" : "none";
  }

  // ── Calendar nav badge (user page only) ────────────────────────────────────
  // Show a dot on Meeting Calendar when the user has upcoming approved meetings
  // so they know there's something to see on the calendar.
  const calNavBadge = document.getElementById("calendar-nav-badge");
  if (calNavBadge && document.body.dataset.page === "user") {
    const cu = getCurrentUser();
    if (cu) {
      const todayISO = getTodayISOManila();
      const safeMeetings = (typeof meetings !== "undefined" && Array.isArray(meetings)) ? meetings : [];
      const hasUpcoming = safeMeetings.some(m => {
        if (m.status !== "Approved") return false;
        if ((m.date || "") < todayISO) return false;
        return m.createdBy === cu.username ||
               m.councilor === cu.name ||
               m.researcher === cu.name;
      });
      calNavBadge.style.display = hasUpcoming ? "inline-flex" : "none";
    }
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
          <div style="font-size:0.8rem;color:${textCol};line-height:1.5">${sanitiseNotifMessage(n.message)}</div>
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

  // Subscribe to live Firestore notifications so the badge and panel update
  // in real time. Store the unsubscribe function so we can clean up the
  // listener on logout — previously it was never stored, leaking a listener
  // on every page load.
  if (window.api && window.api.subscribeNotifications) {
    const unsubNotif = window.api.subscribeNotifications(userId, (liveNotifs) => {
      const all = load(STORAGE_KEYS.NOTIFICATIONS, []);
      const othersNotifs = all.filter(n => n.userId !== userId);
      const merged = [...liveNotifs, ...othersNotifs];
      save(STORAGE_KEYS.NOTIFICATIONS, merged);
      updateNotificationBadge(userId);
      const isOpen = notifPanel.classList.contains("notif-panel-open");
      if (isOpen) renderNotificationPanel(userId);
    });
    // Store on window so logout can call it to clean up the Firestore listener
    window._unsubNotifications = unsubNotif;
  }

  bellBtn.addEventListener("click", (e) => {
    e.stopPropagation();
    const isOpen = notifPanel.classList.toggle("notif-panel-open");
    if (isOpen) {
      renderNotificationPanel(userId);
      // Mark all as read immediately when user clicks to open — no delay
      markAllNotificationsRead(userId);
      updateNotificationBadge(userId);
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
// Offline detection — show/hide a persistent banner
// ---------------------------------------------------------------------------
(function initOfflineDetection() {
  function showOfflineBanner() {
    let banner = document.getElementById("offline-banner");
    if (banner) return;
    banner = document.createElement("div");
    banner.id = "offline-banner";
    banner.setAttribute("role", "alert");
    banner.innerHTML = `
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" style="flex-shrink:0"><line x1="1" y1="1" x2="23" y2="23"/><path d="M16.72 11.06A10.94 10.94 0 0119 12.55M5 12.55a10.94 10.94 0 015.17-2.39M10.71 5.05A16 16 0 0122.56 9M1.42 9a15.91 15.91 0 014.7-2.88M8.53 16.11a6 6 0 016.95 0M12 20h.01"/></svg>
      <span>No internet connection — some features may be unavailable.</span>`;
    banner.style.cssText = [
      "position:fixed","top:0","left:0","right:0","z-index:99999",
      "background:#dc2626","color:#fff","font-size:0.78rem","font-weight:600",
      "padding:8px 16px","display:flex","align-items:center","gap:8px",
      "justify-content:center","box-shadow:0 2px 8px rgba(0,0,0,0.25)",
      "font-family:var(--font-body,sans-serif)"
    ].join(";");
    document.body.prepend(banner);
  }
  function hideOfflineBanner() {
    const b = document.getElementById("offline-banner");
    if (b) b.remove();
  }
  if (!navigator.onLine) showOfflineBanner();
  window.addEventListener("offline", showOfflineBanner);
  window.addEventListener("online",  hideOfflineBanner);
})();

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
      // Force password change on first login — hardcoded default must be changed
      mustChangePassword: true,
    });
    save(STORAGE_KEYS.USERS, users);
  }
}

function getCurrentUser() {
  return load(STORAGE_KEYS.CURRENT_USER, null);
}

function setCurrentUser(user) {
  if (!user) {
    // BUG FIX: Read the current user BEFORE removing from localStorage.
    // The original code called localStorage.removeItem(CURRENT_USER) first,
    // then tried to load it inside pruneOwnNotifications() — always getting null,
    // so user notifications were never cleaned up on logout.
    let loggingOutUserId = null;
    try {
      const loggingOutUser = load(STORAGE_KEYS.CURRENT_USER, null);
      loggingOutUserId = loggingOutUser ? (loggingOutUser.id || loggingOutUser.username) : null;
    } catch (_) {}

    localStorage.removeItem(STORAGE_KEYS.CURRENT_USER);
    sessionStorage.removeItem(STORAGE_KEYS.SESSION_EXPIRY);   // ← correct store
    localStorage.removeItem(STORAGE_KEYS.SESSION_EXPIRY);     // ← legacy cleanup
    // BUGFIX: Only wipe the meetings cache on logout when running in Firestore
    // mode — the server is the source of truth and the cache re-hydrates on the
    // next login. In local-only mode, localStorage IS the database; clearing it
    // here permanently destroys all meeting data for every future session.
    if (window.api && window.api.mode === "firestore") {
      localStorage.removeItem(STORAGE_KEYS.MEETINGS);
    }
    // Prune only the logging-out user's notifications from localStorage cache.
    // Notifications addressed to other users (e.g. admins) are preserved.
    if (loggingOutUserId) {
      try {
        const all = load(STORAGE_KEYS.NOTIFICATIONS, []);
        const kept = all.filter(n => n.userId !== loggingOutUserId);
        save(STORAGE_KEYS.NOTIFICATIONS, kept);
      } catch (_) {}
    }
    sessionStorage.removeItem('user_section');                 // ← clear saved section
    sessionStorage.removeItem('sbp_just_logged_in');          // ← clear login flag
    // Clean up the Firestore notification listener so it doesn't keep firing
    // after logout (was previously leaking a listener on every session).
    if (typeof window._unsubNotifications === "function") {
      try { window._unsubNotifications(); } catch (_) {}
      window._unsubNotifications = null;
    }
    // Clean up announcement Firestore listeners to prevent leaks across sessions.
    if (typeof window._unsubAdminAnn === "function") {
      try { window._unsubAdminAnn(); } catch (_) {}
      window._unsubAdminAnn = null;
    }
    if (typeof window._unsubUserAnn === "function") {
      try { window._unsubUserAnn(); } catch (_) {}
      window._unsubUserAnn = null;
    }
    // Do NOT clear STORAGE_KEYS.USERS — the user list is shared/synced from
    // Firestore and is needed for login on next load.
    // Do NOT clear announcements — they are global, not per-user.
  } else {
    save(STORAGE_KEYS.CURRENT_USER, user);
    refreshSession();
  }
}

function formatDateDisplay(dateStr) {
  if (!dateStr) return dateStr;
  // Parse date-only strings (YYYY-MM-DD) as local time, not UTC.
  // new Date("2025-12-25") is treated as UTC midnight which can show
  // the wrong day in UTC+ timezones like Manila (UTC+8). Splitting
  // and passing as numbers uses the local timezone instead.
  const parts = String(dateStr).split("-");
  const d = parts.length === 3
    ? new Date(Number(parts[0]), Number(parts[1]) - 1, Number(parts[2]))
    : new Date(dateStr);
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

function hasMeetingEnded(m) {
  if (!m || !m.date || !m.timeStart) return false;
  const todayISO = getTodayISOManila();
  if (m.date < todayISO) return true;
  if (m.date > todayISO) return false;
  const now = getManilaNow();
  const nowMinutes = now.getHours() * 60 + now.getMinutes();
  const start = minutesFromTimeStr(m.timeStart);
  const dur = Number.isFinite(m.durationHours) ? m.durationHours : SLOT_DURATION_HOURS;
  const end = start + dur * 60;
  return nowMinutes >= end;
}

// Returns true if the meeting's START time is already in the past (Manila time).
// Used to block approving a meeting that has already begun or already ended.
function hasMeetingStarted(m) {
  if (!m || !m.date || !m.timeStart) return false;
  const todayISO = getTodayISOManila();
  if (m.date < todayISO) return true;
  if (m.date > todayISO) return false;
  const now = getManilaNow();
  const nowMinutes = now.getHours() * 60 + now.getMinutes();
  const start = minutesFromTimeStr(m.timeStart);
  return nowMinutes >= start;
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

  // For today: get current Manila time in minutes so we can block past slots
  const todayISO = getTodayISOManila();
  const isToday  = isoDate === todayISO;
  const nowManilaMinutes = (() => {
    if (!isToday) return 0;
    const n = getManilaNow();
    return n.getHours() * 60 + n.getMinutes();
  })();

  return [8,9,10,11,12,13,14,15,16].map(h => {
    const startMin = h * 60;
    const endMin   = startMin + dur * 60;

    // Block if goes past work hours
    if (endMin > WORK_END_HOUR * 60) {
      return { value: `${String(h).padStart(2,"0")}:00`, text: formatTime12h(startMin), hour: h, disabled: true, reason: "exceeds office hours" };
    }

    // Block if the slot's END time has already passed today
    if (isToday && endMin <= nowManilaMinutes) {
      return { value: `${String(h).padStart(2,"0")}:00`, text: formatTime12h(startMin), hour: h, disabled: true, reason: "time has passed" };
    }

    // Block if the slot START has already passed today (can't book a slot that already started)
    if (isToday && startMin <= nowManilaMinutes) {
      return { value: `${String(h).padStart(2,"0")}:00`, text: formatTime12h(startMin), hour: h, disabled: true, reason: "already started" };
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
        ? `${o.text} — ${o.reason === "time has passed" || o.reason === "already started" ? "time has passed" : o.reason || "unavailable"}`
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
  // ALL meetings: green=approved, yellow=pending, grey=rest.
  // isMine+adminCreated → purple outline via calendar-badge-is-admin-mine
  // isMine only        → yellow outline via calendar-badge-is-mine
  const map = {
    "Approved": "calendar-badge calendar-badge-approved",
    "Pending": "calendar-badge calendar-badge-pending",
    "Cancelled": "calendar-badge calendar-badge-cancelled",
    "Rejected": "calendar-badge calendar-badge-cancelled",
    "Cancellation Requested": "calendar-badge calendar-badge-pending",
    "Done": "calendar-badge calendar-badge-done",
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

// Bug Fix #1: Expose live references to window so inline chart scripts in
// admin.html / user.html can always read the current arrays via window.meetings
// and window.users without breaking when the let variable is reassigned.
Object.defineProperty(window, "meetings", {
  get: function () { return meetings; },
  set: function (v) { meetings = v; },
  configurable: true,
});
Object.defineProperty(window, "users", {
  get: function () { return users; },
  set: function (v) { users = v; },
  configurable: true,
});
let calendarYear, calendarMonth;
let unsubscribeMeetings = null;
let unsubscribeHistory = null;
let unsubscribeUsers = null;

// Search state
let adminMeetingsSearch = "";
let myMeetingsSearch = "";
let usersSearch = "";
let specialUsersSearch = "";
let regularUsersSearch = "";

// Sort direction state — "asc" (A→Z) or "desc" (Z→A); default alphabetical A→Z
let specialUsersSortDir = "asc";
let regularUsersSortDir = "asc";
let adminMeetingsSortDir = "asc";
let myMeetingsSortDir = "asc";

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
  // Security: if the stored user record still has mustChangePassword set,
  // redirect back to login so the force-change modal is shown.
  // This blocks bypassing the password change by navigating directly to admin.html / user.html.
  if (user.mustChangePassword) {
    setCurrentUser(null);
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
    const dispName = user.role === ROLES.RESEARCHER
      ? `${user.name} (Researcher)` : user.name;
    // If it's the new dash-welcome-banner style, set just the name so CSS can style it
    welcomeEl.innerHTML = `Welcome, <span>${h(dispName)}</span>`;
  }
  // Populate user dashboard greeting & date (mirrors admin updateDashboardGreeting)
  const userGreetEl = $("#user-dash-greeting");
  const userDateEl  = $("#user-dash-date-str");
  if (userGreetEl) {
    const hr = getManilaNow().getHours();
    userGreetEl.textContent = hr < 12 ? "Good morning," : hr < 17 ? "Good afternoon," : "Good evening,";
  }
  if (userDateEl) {
    userDateEl.textContent = getManilaNow().toLocaleDateString("en-PH", { weekday:"long", year:"numeric", month:"long", day:"numeric" });
  }
  if (sidebarUser) sidebarUser.textContent = user.name;
  if (sidebarRole) sidebarRole.textContent = user.role;
  const avatarEl = $("#sidebar-avatar");
  if (avatarEl) {
    const initials = (user.name || user.username || "U")
      .split(" ").filter(Boolean).map(w => w[0]).slice(0, 2).join("").toUpperCase();
    avatarEl.textContent = initials || "U";
  }
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
    // Inline local-only API used when firebase.js is absent.
    // Uses its own pub/sub so updateMeetingStatus can push live changes
    // to all active subscribers — matching the firebase.js local-mode pattern.
    const _localMtgSubs = [];
    const _notifyLocalMtgSubs = () => {
      const list = load(STORAGE_KEYS.MEETINGS, []);
      _localMtgSubs.forEach(cb => { try { cb(list); } catch (_) {} });
    };
    window.api = {
      mode: "local",
      init: () => Promise.resolve(),
      getUsers: () => Promise.resolve(load(STORAGE_KEYS.USERS, [])),
      getMeetings: () => Promise.resolve(load(STORAGE_KEYS.MEETINGS, [])),
      getCalendarHistory: () => Promise.resolve(load("sbp_calendar_history", [])),
      subscribeMeetings: (cb) => {
        _localMtgSubs.push(cb);
        cb(load(STORAGE_KEYS.MEETINGS, []));
        return () => { const i = _localMtgSubs.indexOf(cb); if (i !== -1) _localMtgSubs.splice(i, 1); };
      },
      updateMeetingStatus: (id, status, adminNote, extraFields) => {
        const list = load(STORAGE_KEYS.MEETINGS, []);
        const m = list.find(x => x.id === id);
        if (m) {
          m.status = status;
          if (typeof adminNote === "string") m.adminNote = adminNote;
          if (extraFields && typeof extraFields === "object") Object.assign(m, extraFields);
          save(STORAGE_KEYS.MEETINGS, list);
        }
        _notifyLocalMtgSubs();
        return Promise.resolve();
      },
      subscribeCalendarHistory: (cb) => { cb(load("sbp_calendar_history", [])); return () => {}; },
      exportAndArchivePreviousMonth: () => Promise.resolve({ archived: 0 }),
      _notifyMeetings: _notifyLocalMtgSubs,
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
    // Dispatch once so dashboard chart scripts render immediately on data arrival
    // instead of burning CPU on setTimeout polling loops.
    try { document.dispatchEvent(new CustomEvent('sbp:dataready')); } catch(e) {}
    const currentUser = getCurrentUser();
    renderCalendar();
    // Guard: these functions only exist on admin.html — don't call them on user.html
    if (typeof renderAdminMeetingsTable === "function") renderAdminMeetingsTable();
    if (typeof renderMyMeetingsTable === "function") renderMyMeetingsTable(currentUser);
    if (typeof renderUsersTable === "function") renderUsersTable();
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

  // Subscribe to live user updates from Firestore.
  // This is the key fix for the "deleted user reappears on refresh" bug:
  // whenever Firestore delivers a new users snapshot (including after a delete),
  // we update the in-memory array AND localStorage in one place, so the UI and
  // cache always match what Firestore actually has.
  if (unsubscribeUsers) { try { unsubscribeUsers(); } catch {} }
  if (window.api.subscribeUsers) {
    unsubscribeUsers = window.api.subscribeUsers((arr) => {
      users = arr || [];
      persistUsers();
      renderUsersTable();
      updateStatistics();
    });
  }
}

function persistUsers() { save(STORAGE_KEYS.USERS, users); }
function persistMeetings() {
  save(STORAGE_KEYS.MEETINGS, meetings);
  // Notify any active local-mode subscribers so the UI re-renders immediately.
  // In Firestore mode this is a no-op because updateMeetingStatus is used instead.
  if (window.api && typeof window.api._notifyMeetings === "function") {
    window.api._notifyMeetings();
  }
}

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

    if (newPwd.length < 8) { errEl.textContent = "Password must be at least 8 characters."; return; }
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

  // ── Brute-force lockout ───────────────────────────────────────────────────
  // 5 failures → 15-minute lockout, persisted in localStorage so closing
  // the tab or browser does NOT reset it (unlike the old sessionStorage version).
  // NOTE: This is a client-side-only lockout. A technically savvy user could
  // clear localStorage to bypass it. True protection requires a server-side
  // rate limiter (e.g. a Firebase Cloud Function). This layer still deters
  // casual brute-force attempts and is kept as a first line of defence.
  const LOCKOUT_MAX   = 5;
  const LOCKOUT_MS    = 15 * 60 * 1000; // 15 minutes
  const LS_ATTEMPTS   = "sbp_login_attempts";
  const LS_LOCKOUT_TS = "sbp_login_lockout_ts";

  function getAttempts()  { return parseInt(localStorage.getItem(LS_ATTEMPTS)  || "0", 10); }
  function getLockoutTs() { return parseInt(localStorage.getItem(LS_LOCKOUT_TS) || "0", 10); }

  function isLockedOut() {
    const ts = getLockoutTs();
    if (!ts) return false;
    if (Date.now() < ts) return true;
    localStorage.removeItem(LS_ATTEMPTS);
    localStorage.removeItem(LS_LOCKOUT_TS);
    return false;
  }

  function recordFailedAttempt() {
    const next = getAttempts() + 1;
    localStorage.setItem(LS_ATTEMPTS, String(next));
    if (next >= LOCKOUT_MAX) {
      localStorage.setItem(LS_LOCKOUT_TS, String(Date.now() + LOCKOUT_MS));
    }
    return next;
  }

  function clearAttempts() {
    localStorage.removeItem(LS_ATTEMPTS);
    localStorage.removeItem(LS_LOCKOUT_TS);
  }

  function formatLockoutTime(ms) {
    const totalSec = Math.ceil(ms / 1000);
    const mins = Math.floor(totalSec / 60);
    const secs = totalSec % 60;
    return mins > 0 ? `${mins}m ${secs}s` : `${secs}s`;
  }

  function showLockoutError() {
    const rem = getLockoutTs() - Date.now();
    if (errorEl) {
      errorEl.textContent = `Too many failed attempts. Please wait ${formatLockoutTime(rem)} before trying again.`;
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
        const r = getLockoutTs() - Date.now();
        if (errorEl) errorEl.textContent = `Too many failed attempts. Please wait ${formatLockoutTime(r)} before trying again.`;
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
        // signIn(username) fetches the user record from Firestore by username only.
        // Password verification always happens below via verifyPassword() — the
        // second signIn call with a hashed password was a bug: firebase.js ignores
        // the second argument entirely, so it was a redundant wasted Firestore read.
        const record = await window.api.signIn(username);
        if (record) {
          // Verify the supplied password against the stored hash (PBKDF2 or legacy SHA-256).
          // Plain-text password comparison removed — it is a security hole. Legacy accounts
          // are handled by verifyPassword() which supports both PBKDF2 and SHA-256 formats.
          const passwordMatch = await verifyPassword(password, record.password);
          if (passwordMatch) account = record;
        }
      } else {
        const allUsers = load(STORAGE_KEYS.USERS, []);
        // Hashed verification only — plain-text fallback removed (security fix)
        for (const u of allUsers) {
          if (u.username !== username) continue;
          if (await verifyPassword(password, u.password)) { account = u; break; }
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

    // ── Silently migrate legacy SHA-256 or plaintext password to PBKDF2 ──
    // If the stored hash doesn't start with "pbkdf2:" it is still old format.
    // Re-hash with PBKDF2 now and persist — fully transparent to the user.
    if (account.password && !account.password.startsWith("pbkdf2:")) {
      try {
        const upgraded = await hashPassword(password);
        if (window.api && window.api.updateUserPassword) {
          await window.api.updateUserPassword(account.id, upgraded);
        } else {
          const allU = load(STORAGE_KEYS.USERS, []);
          const target = allU.find(x => x.id === account.id);
          if (target) { target.password = upgraded; save(STORAGE_KEYS.USERS, allU); }
        }
        account.password = upgraded;
      } catch (_) { /* non-fatal — will retry next login */ }
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

  const specialRoles = [ROLES.VICE_MAYOR, ROLES.SECRETARY];
  const allNonAdmin = [...users].filter(u => u.role !== ROLES.ADMIN);

  // ── Special Accounts: own search + sort ───────────────────────────────────
  let specialList = allNonAdmin.filter(u => specialRoles.includes(u.role));
  if (specialUsersSearch) {
    const q = specialUsersSearch.toLowerCase();
    specialList = specialList.filter(u =>
      (u.username || "").toLowerCase().includes(q) ||
      (u.name || "").toLowerCase().includes(q) ||
      (u.role || "").toLowerCase().includes(q)
    );
  }
  specialList.sort((a, b) => {
    const nameA = (a.name || a.username || "").toLowerCase();
    const nameB = (b.name || b.username || "").toLowerCase();
    return specialUsersSortDir === "asc" ? nameA.localeCompare(nameB) : nameB.localeCompare(nameA);
  });

  if (specialTbody) {
    if (!specialList.length) {
      specialTbody.innerHTML = '<tr><td colspan="4" class="text-muted" style="text-align:center;padding:20px">No special accounts found.</td></tr>';
    } else {
      specialTbody.innerHTML = specialList.map(u => `<tr>
        <td>${h(u.username)}</td>
        <td>${h(u.name || "")}</td>
        <td><span class="${roleChipClass(u.role)}">${u.role}</span></td>
        <td>
          <button class="btn btn-sm btn-ghost" data-action="view-user" data-user-id="${u.id}">View</button>
          <button class="btn btn-sm btn-ghost" data-action="edit-user" data-user-id="${u.id}" style="color:var(--brand-blue,#2563eb)">
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" style="margin-right:3px"><path d="M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 013 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>Edit</button>
          <button class="btn btn-sm btn-ghost" data-action="change-password" data-user-id="${u.id}">Change Password</button>
          <button class="btn btn-sm btn-ghost" data-action="remove-user" data-user-id="${u.id}">Remove</button>
        </td>
      </tr>`).join("");
    }
  }

  // ── Regular Users: own search + sort + pagination ─────────────────────────
  if (!tbody) return;

  let regularList = allNonAdmin.filter(u => !specialRoles.includes(u.role));
  if (regularUsersSearch) {
    const q = regularUsersSearch.toLowerCase();
    regularList = regularList.filter(u =>
      (u.username || "").toLowerCase().includes(q) ||
      (u.name || "").toLowerCase().includes(q) ||
      (u.role || "").toLowerCase().includes(q)
    );
  }
  regularList.sort((a, b) => {
    const nameA = (a.name || a.username || "").toLowerCase();
    const nameB = (b.name || b.username || "").toLowerCase();
    return regularUsersSortDir === "asc" ? nameA.localeCompare(nameB) : nameB.localeCompare(nameA);
  });

  // Update the user count badge
  const regularRoles = [ROLES.COUNCILOR, ROLES.RESEARCHER];
  const totalRegular = users.filter(u => regularRoles.includes(u.role)).length;
  const userCountEl = document.getElementById("user-count-badge");
  if (userCountEl) {
    userCountEl.textContent = `${totalRegular} / ${MAX_REGULAR_USERS} users`;
    userCountEl.style.color = totalRegular >= MAX_REGULAR_USERS ? "var(--color-danger)" : "var(--color-text-muted)";
    userCountEl.style.fontWeight = totalRegular >= MAX_REGULAR_USERS ? "700" : "500";
  }

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
        <button class="btn btn-sm btn-ghost" data-action="edit-user" data-user-id="${u.id}" style="color:var(--brand-blue,#2563eb)">
          <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" style="margin-right:3px"><path d="M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 013 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>Edit</button>
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
  if (password.length < 8)   { msg.textContent = "Password must be at least 8 characters."; showToast("Password too short.", "error"); return; }
  if (password !== confirm)  { msg.textContent = "Passwords do not match."; showToast("Passwords do not match.", "error"); return; }
  if (users.some(u => u.username === username)) { msg.textContent = `Username "${username}" already exists.`; showToast("Username already exists.", "error"); return; }

  // Check total regular-user cap (20 max — Councilors + Researchers combined)
  const regularRoles = [ROLES.COUNCILOR, ROLES.RESEARCHER];
  if (regularRoles.includes(role)) {
    const regularCount = users.filter(u => regularRoles.includes(u.role)).length;
    if (regularCount >= MAX_REGULAR_USERS) {
      msg.textContent = `User limit reached. A maximum of ${MAX_REGULAR_USERS} regular accounts (Councilors + Researchers) are allowed.`;
      showToast(`User limit reached (max ${MAX_REGULAR_USERS}).`, "error");
      return;
    }
  }

  const limit = ROLE_LIMITS[role];
  if (limit != null && countUsersByRole(role) >= limit) {
    msg.textContent = `Role limit reached for ${role}.`;
    showToast(`Role limit reached for ${role}.`, "error");
    return;
  }

  const hashedPwd = await hashPassword(password);
  const newUser = {
    id: crypto.randomUUID(),
    username, name, password: hashedPwd, role,
  };

  const onDone = () => {
    $("#user-form").reset();
    msg.textContent = "";
    const prevU = document.getElementById("user-username-preview");
    if (prevU) prevU.innerHTML = "";
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
  if (password.length < 8)   { msg.textContent = "Password must be at least 8 characters."; showToast("Password too short.", "error"); return; }
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
    id: crypto.randomUUID(),
    username, name, password: hashedPwd, role,
  };

  const onDone = async () => {
    $("#special-account-form").reset();
    msg.textContent = "";
    const prevS = document.getElementById("special-username-preview");
    if (prevS) prevS.innerHTML = "";
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

  if (action === "edit-user") {
    openEditUserModal(userId);
    return;
  }

  if (action === "remove-user") {
    const allUserMeetings = meetings.filter(m =>
      m.createdBy === user.id || m.createdBy === user.username ||
      m.councilor === user.name || m.researcher === user.name
    );
    // Approved & Done meetings are KEPT — only their name references get scrubbed
    const approvedMeetings    = allUserMeetings.filter(m => m.status === "Approved" || m.status === "Done");
    // Pending / Cancellation Requested meetings get cancelled
    const cancellableMeetings = allUserMeetings.filter(m =>
      ["Pending", "Cancellation Requested"].includes(m.status)
    );

    const warnIcon = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="flex-shrink:0;margin-right:6px;margin-top:1px"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`;
    const infoIcon = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="flex-shrink:0;margin-right:6px;margin-top:1px"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`;

    let confirmMsg = `Are you sure you want to permanently remove <strong>${h(user.name)}</strong>? This action cannot be undone.`;
    if (cancellableMeetings.length) {
      confirmMsg += `<div style="display:flex;align-items:flex-start;margin-top:10px;padding:9px 12px;background:var(--color-danger-soft);border-radius:8px;font-size:0.84rem;color:var(--color-danger)">${warnIcon}${cancellableMeetings.length} pending meeting(s) will be <strong style="margin-left:4px">cancelled</strong>.</div>`;
    }
    if (approvedMeetings.length) {
      confirmMsg += `<div style="display:flex;align-items:flex-start;margin-top:8px;padding:9px 12px;background:var(--color-surface-2);border:1px solid var(--color-border-soft);border-radius:8px;font-size:0.84rem;color:var(--color-text-muted)">${infoIcon}${approvedMeetings.length} approved/done meeting(s) will be <strong style="margin:0 4px">kept</strong> — scheduler name shown as <em>"Deleted User"</em>.</div>`;
    }

    openConfirmModal(
      "Remove User Account",
      confirmMsg,
      async () => {
        const deleteId = user.id || userId;

        // ── Step 1: Cancel all pending/cancellation-requested meetings ────────
        const meetingUpdates = [];
        cancellableMeetings.forEach(m => {
          m.status    = "Cancelled";
          m.adminNote = `Account removed — ${user.name}`;
          if (window.api && window.api.updateMeetingStatus) {
            meetingUpdates.push(
              window.api.updateMeetingStatus(m.id, "Cancelled", m.adminNote)
            );
          }
        });

        // ── Step 2: Scrub name refs in approved/done meetings (keep the records) ──
        approvedMeetings.forEach(m => {
          const SCRUBBED = "Deleted User";
          const extraFields = {};
          if (m.councilor  === user.name) { m.councilor  = SCRUBBED; extraFields.councilor  = SCRUBBED; }
          if (m.researcher === user.name) { m.researcher = SCRUBBED; extraFields.researcher = SCRUBBED; }
          if (m.createdBy === user.id || m.createdBy === user.username) {
            m.createdByName = SCRUBBED;
            extraFields.createdByName = SCRUBBED;
          }
          if (!m.adminNote) {
            m.adminNote = `Original scheduler (${user.name}) account removed.`;
            extraFields.adminNote = m.adminNote;
          }
          if (window.api && window.api.updateMeetingStatus && Object.keys(extraFields).length) {
            meetingUpdates.push(
              window.api.updateMeetingStatus(m.id, m.status, m.adminNote, extraFields)
            );
          }
        });

        // Wait for all meeting updates to complete before touching the user record
        if (meetingUpdates.length) await Promise.all(meetingUpdates).catch(() => {});
        if (allUserMeetings.length) persistMeetings();

        // ── Step 3: Remove user from memory + localStorage immediately ────────
        // Optimistically remove from in-memory array so the UI updates instantly.
        // The subscribeUsers() listener in initDataLayer will receive the Firestore
        // delete confirmation and re-sync users + localStorage automatically —
        // so we do NOT manually re-fetch here (that was the source of the reappear bug).
        const toastMsg = [
          `User "${user.name}" removed.`,
          cancellableMeetings.length ? `${cancellableMeetings.length} pending meeting(s) cancelled.` : "",
          approvedMeetings.length    ? `${approvedMeetings.length} approved meeting(s) preserved as "Deleted User".` : "",
        ].filter(Boolean).join(" ");

        users = users.filter(u => u.id !== deleteId && u.username !== user.username);
        persistUsers();
        if (typeof renderUsersTable === "function") renderUsersTable();
        if (typeof renderAdminMeetingsTable === "function") renderAdminMeetingsTable();
        renderCalendar();
        updateStatistics();
        showToast(toastMsg, "success");

        // ── Step 4: Delete from Firestore ────────────────────────────────────
        // firebase.js deleteUser handles BOTH new-style (doc.id === user.id) and
        // old-style (Firestore auto-generated doc.id) users via a batch that does:
        //   - Direct delete by doc ID
        //   - Query-based delete by the "id" field
        // IMPORTANT: firestore.rules must have "allow delete: if true" on /users.
        // The rule was previously "allow delete: if false" which caused the silent
        // failure + 400/404 WebChannel errors you saw in the console.
        if (window.api && window.api.deleteUser) {
          window.api.deleteUser(deleteId).catch(err => {
            console.error("Firestore deleteUser failed:", err);
            // The user is gone from the UI but NOT from Firestore.
            // The subscribeUsers listener will re-deliver them on next snapshot.
            showToast(
              "Could not delete account from the database. Check Firestore rules (allow delete: if true on /users) and try again.",
              "error"
            );
            // Restore the user in memory so the UI matches Firestore reality
            window.api.getUsers && window.api.getUsers().then(fresh => {
              users = fresh;
              persistUsers();
              renderUsersTable();
              updateStatistics();
            }).catch(() => {});
          });
        }
      }
    );
  } else if (action === "change-password") {
    openPasswordModal(userId);
  }
}

// ---------------------------------------------------------------------------
// Edit User Modal — opens from the Accounts table Edit button
// ---------------------------------------------------------------------------
function openEditUserModal(userId) {
  const safeUsers = (typeof users !== "undefined" && Array.isArray(users)) ? users : [];
  const user = safeUsers.find(u => u.id === userId);
  if (!user) return;

  // Remove any old modal
  const old = document.getElementById("edit-user-modal");
  if (old) old.remove();

  const isSpecial = [ROLES.VICE_MAYOR, ROLES.SECRETARY].includes(user.role);
  const roleOptions = isSpecial
    ? [ROLES.VICE_MAYOR, ROLES.SECRETARY]
    : [ROLES.COUNCILOR, ROLES.RESEARCHER];

  const roleOptionsHtml = roleOptions.map(r =>
    `<option value="${r}"${user.role === r ? " selected" : ""}>${r}</option>`
  ).join("");

  const modal = document.createElement("div");
  modal.id = "edit-user-modal";
  modal.className = "modal-backdrop";
  modal.style.cssText = "z-index:8000;";
  modal.innerHTML = `
    <div class="modal" style="max-width:480px;width:100%">
      <div class="modal-header">
        <div style="display:flex;align-items:center;gap:10px">
          <div style="width:34px;height:34px;border-radius:10px;background:rgba(37,99,235,0.1);color:#2563eb;display:flex;align-items:center;justify-content:center;flex-shrink:0">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 013 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
          </div>
          <div>
            <div class="modal-title">Edit Account</div>
            <div style="font-size:0.75rem;color:var(--color-text-muted);margin-top:1px">Update profile information for this user</div>
          </div>
        </div>
        <button id="edit-user-modal-close" class="btn btn-ghost btn-sm">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
        </button>
      </div>
      <div class="modal-body" style="padding:20px 24px;display:flex;flex-direction:column;gap:14px">
        <div>
          <label class="field-label">Full Name <span style="color:var(--color-danger)">*</span></label>
          <input id="eum-name" class="field" value="${h(user.name || "")}" placeholder="e.g. Juan dela Cruz" autocomplete="off" />
        </div>
        <div>
          <label class="field-label">Username <span style="color:var(--color-danger)">*</span></label>
          <input id="eum-username" class="field" value="${h(user.username || "")}" placeholder="Login username" autocomplete="off" />
          <div id="eum-username-hint" class="helper-text" style="margin-top:4px;min-height:16px"></div>
        </div>
        <div>
          <label class="field-label">Role</label>
          <select id="eum-role" class="field">${roleOptionsHtml}</select>
          <div class="helper-text" style="margin-top:4px">Role type is locked to the account category (${isSpecial ? "Special" : "Regular"}).</div>
        </div>
        <div id="eum-msg" class="helper-text" style="min-height:16px"></div>
      </div>
      <div class="modal-footer" style="display:flex;justify-content:flex-end;gap:10px;padding:14px 24px;border-top:1px solid var(--color-border-soft)">
        <button id="eum-cancel-btn" class="btn btn-ghost">Cancel</button>
        <button id="eum-save-btn" class="btn btn-primary">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M19 21H5a2 2 0 01-2-2V5a2 2 0 012-2h11l5 5v11a2 2 0 01-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg>
          Save Changes
        </button>
      </div>
    </div>
  `;

  document.body.appendChild(modal);

  // Focus full name field
  setTimeout(() => document.getElementById("eum-name")?.focus(), 60);

  // Close handlers
  const closeModal = () => modal.remove();
  document.getElementById("edit-user-modal-close").addEventListener("click", closeModal);
  document.getElementById("eum-cancel-btn").addEventListener("click", closeModal);
  modal.addEventListener("click", e => { if (e.target === modal) closeModal(); });

  // Username uniqueness hint
  document.getElementById("eum-username").addEventListener("input", function () {
    const val = this.value.trim();
    const hint = document.getElementById("eum-username-hint");
    if (!hint) return;
    if (!val) { hint.textContent = ""; return; }
    const taken = safeUsers.some(u => u.username === val && u.id !== userId);
    hint.textContent = taken ? `⚠ Username "${h(val)}" is already taken.` : "";
    hint.style.color = taken ? "var(--color-danger)" : "#16a34a";
  });

  // Save
  document.getElementById("eum-save-btn").addEventListener("click", async () => {
    const newName  = (document.getElementById("eum-name")?.value || "").trim();
    const newUname = (document.getElementById("eum-username")?.value || "").trim();
    const newRole  = document.getElementById("eum-role")?.value;
    const msgEl    = document.getElementById("eum-msg");
    const saveBtn  = document.getElementById("eum-save-btn");

    if (!newName)  { if (msgEl) { msgEl.textContent = "Full name cannot be empty."; msgEl.style.color = "var(--color-danger)"; } return; }
    if (!newUname) { if (msgEl) { msgEl.textContent = "Username cannot be empty."; msgEl.style.color = "var(--color-danger)"; } return; }

    const currentUsers = (typeof users !== "undefined" && Array.isArray(users)) ? users : [];
    if (currentUsers.some(u => u.username === newUname && u.id !== userId)) {
      if (msgEl) { msgEl.textContent = `Username "${newUname}" is already taken.`; msgEl.style.color = "var(--color-danger)"; }
      return;
    }

    saveBtn.disabled = true;
    saveBtn.innerHTML = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="animation:spin 0.8s linear infinite"><path d="M21 12a9 9 0 11-6.22-8.56"/></svg> Saving…`;

    try {
      const fields = { name: newName, username: newUname, role: newRole };
      if (window.api && window.api.updateUser) {
        await window.api.updateUser(userId, fields);
        users = await window.api.getUsers();
      } else {
        const u = currentUsers.find(x => x.id === userId);
        if (u) { Object.assign(u, fields); persistUsers(); }
      }
      renderUsersTable();
      populateEditUserSelect();
      updateStatistics();
      showToast(`Profile updated for ${newName}.`, "success");
      closeModal();
    } catch {
      if (msgEl) { msgEl.textContent = "Failed to save changes. Please try again."; msgEl.style.color = "var(--color-danger)"; }
      saveBtn.disabled = false;
      saveBtn.innerHTML = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M19 21H5a2 2 0 01-2-2V5a2 2 0 012-2h11l5 5v11a2 2 0 01-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg> Save Changes`;
    }
  });

  // Keyboard shortcut — Enter to save, Escape to close
  modal.addEventListener("keydown", e => {
    if (e.key === "Escape") closeModal();
    if (e.key === "Enter" && e.target.tagName !== "SELECT") {
      e.preventDefault();
      document.getElementById("eum-save-btn")?.click();
    }
  });
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
        <div class="modal-body" id="confirm-modal-body-wrap">
          <div id="confirm-modal-body" class="confirm-modal-body-inner"></div>
        </div>
        <div class="modal-footer">
          <button id="confirm-modal-cancel" class="btn btn-ghost btn-sm">Cancel</button>
          <button id="confirm-modal-ok" class="btn btn-danger btn-sm">Confirm</button>
        </div>
      </div>`;
    document.body.appendChild(modal);
  }

  document.getElementById("confirm-modal-title").textContent = title;
  document.getElementById("confirm-modal-body").innerHTML = bodyHtml;

  const bodyWrap = document.getElementById("confirm-modal-body-wrap");
  if (bodyWrap) bodyWrap.scrollTop = 0;

  const modalInner = modal.querySelector(".modal");
  if (modalInner) { modalInner.style.animation = "none"; requestAnimationFrame(() => { modalInner.style.animation = ""; }); }

  modal.classList.add("modal-open");

  const close = (cancelled) => {
    modal.classList.remove("modal-open");
    if (cancelled && typeof onCancel === "function") onCancel();
  };

  modal.onclick = (e) => { if (e.target === modal) close(true); };
  document.getElementById("confirm-modal-close").onclick  = () => close(true);
  document.getElementById("confirm-modal-cancel").onclick = () => close(true);
  document.getElementById("confirm-modal-ok").onclick     = () => { close(false); onConfirm(); };
}

// ---------------------------------------------------------------------------
// Change Password Modal
// ---------------------------------------------------------------------------

function openPasswordModal(userId) {
  $("#password-user-id").value = userId;
  $("#password-new").value = "";
  $("#password-confirm").value = "";
  // Reset strength bar
  const strength = $("#chpwd-strength");
  if (strength) strength.style.display = "none";
  // Reset show/hide eyes
  const showNew  = $("#pw-new-eye-show");  const hideNew  = $("#pw-new-eye-hide");
  const showConf = $("#pw-confirm-eye-show"); const hideConf = $("#pw-confirm-eye-hide");
  const inpNew   = $("#password-new");     const inpConf  = $("#password-confirm");
  if (inpNew)   inpNew.type   = "password";
  if (inpConf)  inpConf.type  = "password";
  if (showNew)  showNew.style.display  = "";  if (hideNew)  hideNew.style.display  = "none";
  if (showConf) showConf.style.display = "";  if (hideConf) hideConf.style.display = "none";
  // Clear any previous error message
  const msg = $("#password-form-message");
  if (msg) msg.textContent = "";
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

  if (pwd.length < 8) { if(msg) msg.textContent = "Password must be at least 8 characters."; return; }
  if (pwd !== confirmPwd) { if(msg) msg.textContent = "Passwords do not match."; showToast("Passwords do not match.", "error"); return; }

  const user = users.find(u => u.id === userId);
  if (!user) { if(msg) msg.textContent = "User not found."; return; }

  const hashedPwd = await hashPassword(pwd);

  if (window.api && window.api.updateUserPassword) {
    window.api.updateUserPassword(user.id, hashedPwd).then(async () => {
      users = await window.api.getUsers();
      showToast("Password updated.", "success");
      setTimeout(closePasswordModal, 700);
    });
  } else {
    user.password = hashedPwd;
    persistUsers();
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
  mine.sort((a, b) => {
    const nameA = (a.eventName || "").toLowerCase();
    const nameB = (b.eventName || "").toLowerCase();
    return myMeetingsSortDir === "asc" ? nameA.localeCompare(nameB) : nameB.localeCompare(nameA);
  });

  const totalPages = Math.max(1, Math.ceil(mine.length / MEETINGS_PAGE_SIZE));
  if (myMeetingsPage > totalPages) myMeetingsPage = totalPages;
  const paginated = mine.slice((myMeetingsPage - 1) * MEETINGS_PAGE_SIZE, myMeetingsPage * MEETINGS_PAGE_SIZE);

  if (!paginated.length) {
    tbody.innerHTML = `<tr><td colspan="6" style="padding:0;border:none"><div class="empty-state" style="padding:48px 20px;text-align:center">
      <svg class="empty-state-icon" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="margin:0 auto 10px;display:block;opacity:0.35"><rect x="3" y="4" width="18" height="18" rx="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/></svg>
      <p style="margin:0;font-size:0.85rem;color:var(--color-text-muted)">No meetings found.</p>
    </div></td></tr>`;
    renderPagination("my-meetings-pagination", totalPages, myMeetingsPage, (p) => { myMeetingsPage = p; renderMyMeetingsTable(currentUser); });
    return;
  }

  tbody.innerHTML = paginated.map(m => {
    const canRequestCancel = currentUser.role !== ROLES.ADMIN && ["Pending", "Approved"].includes(m.status);
    const noteTitle = m.adminNote ? ` title="${h(m.adminNote)}"` : "";
    const noteHint = m.adminNote ? `<div style="font-size:0.72rem;color:#6b7280;margin-top:3px;max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${h(m.adminNote)}">Note: ${h(m.adminNote)}</div>` : "";
    const createdAt = m.createdAt ? new Date(m.createdAt) : null;
    const nowManila = getManilaNow();
    const msElapsed = createdAt ? Math.max(0, nowManila - createdAt) : Infinity;
    const within24h = msElapsed < 24 * 60 * 60 * 1000;
    const msLeft = within24h ? (24 * 60 * 60 * 1000 - msElapsed) : 0;
    const hoursLeft = Math.floor(msLeft / (60 * 60 * 1000));
    const minsLeft  = Math.floor((msLeft % (60 * 60 * 1000)) / 60000);
    const countdownStr = hoursLeft > 0 ? `${hoursLeft}h ${minsLeft}m` : `${minsLeft}m`;

    // ── Edit button: only within 24h and only for Pending meetings ──
    const canEdit = within24h && m.status === "Pending" && currentUser.role !== ROLES.ADMIN;
    const editBtn = canEdit
      ? `<button class="btn btn-sm btn-ghost" data-action="edit-meeting" data-meeting-id="${m.id}"
           style="display:flex;align-items:center;gap:5px;color:var(--brand-blue,#2563eb)">
           <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 013 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
           Edit
         </button>`
      : "";

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
        ${editBtn}
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
      const nowManila = getManilaNow();
      const msLeft = Math.max(0, 24 * 60 * 60 * 1000 - (nowManila - created));
      if (msLeft <= 0) {
        // Window expired — re-render to switch button to "Request Cancel"
        clearInterval(_cancelCountdownInterval);
        renderMyMeetingsTable(currentUser);
        return;
      }
      anyLeft = true;
      const hrs = Math.floor(msLeft / (60 * 60 * 1000));
      const m = Math.floor((msLeft % (60 * 60 * 1000)) / 60000);
      span.lastChild.textContent = ` ${hrs > 0 ? hrs + "h " : ""}${m}m left`;
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
  list.sort((a, b) => {
    const nameA = (a.eventName || "").toLowerCase();
    const nameB = (b.eventName || "").toLowerCase();
    return adminMeetingsSortDir === "asc" ? nameA.localeCompare(nameB) : nameB.localeCompare(nameA);
  });

  const totalPages = Math.max(1, Math.ceil(list.length / MEETINGS_PAGE_SIZE));
  if (adminMeetingsPage > totalPages) adminMeetingsPage = totalPages;
  const paginated = list.slice((adminMeetingsPage - 1) * MEETINGS_PAGE_SIZE, adminMeetingsPage * MEETINGS_PAGE_SIZE);

  if (!paginated.length) {
    tbody.innerHTML = '<tr><td colspan="8" class="text-muted">No meetings found.</td></tr>';
    renderPagination("admin-meetings-pagination", totalPages, adminMeetingsPage, (p) => { adminMeetingsPage = p; renderAdminMeetingsTable(); });
    return;
  }

  tbody.innerHTML = paginated.map(m => {
    const isCancelRequest = m.status === "Cancellation Requested";
    const isAdminCreated = m.createdByRole === ROLES.ADMIN;
  const printBtns = `<button class="btn btn-sm btn-ghost" data-action="print" data-meeting-id="${m.id}">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 6 2 18 2 18 9"/><path d="M6 18H4a2 2 0 01-2 2v-5a2 2 0 012-2h16a2 2 0 012 2v5a2 2 0 01-2 2h-2"/><rect x="6" y="14" width="12" height="8"/></svg>
          PDF</button>`;

    // Admin-created meetings: show "Referred" badge instead of Approve button
    const referredBadge = `<span style="font-size:0.72rem;color:#1e40af;font-weight:600;display:inline-flex;align-items:center;gap:4px;background:#dbeafe;border:1px solid #93c5fd;border-radius:6px;padding:3px 8px;">
      <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
      Referred
    </span>`;

    // isPendingExpired: Pending meeting whose start time has passed — lock all actions except Delete
    const isPendingExpired = m.status === "Pending" && hasMeetingStarted(m);

    const delBtn = `<button class="action-btn action-btn-cancel" data-action="delete" data-meeting-id="${m.id}">
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 01-2 2H8a2 2 0 01-2-2L5 6"/><path d="M10 11v6M14 11v6"/></svg>Delete
          </button>`;

    // Expired badge for past-start-time pending meetings
    const expiredBadge = `<span style="display:inline-flex;align-items:center;gap:4px;font-size:0.68rem;font-weight:700;color:#92400E;background:#FEF3C7;border:1px solid rgba(217,119,6,0.45);border-radius:6px;padding:3px 8px;">
      <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
      Expired
    </span>`;

    let actionButtons;
    if (isCancelRequest) {
      actionButtons = `<div style="display:flex;flex-wrap:wrap;gap:4px;align-items:center;">
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
          ${delBtn}
          ${printBtns}
        </div>`;
    } else if (isPendingExpired) {
      // Past start time — lock Approve/Reject/Cancel, only Delete allowed
      actionButtons = `<div style="display:flex;flex-wrap:wrap;gap:4px;align-items:center;">
          ${expiredBadge}
          <button class="action-btn action-btn-approve" disabled title="Start time has passed">
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>Approve
          </button>
          <button class="action-btn action-btn-reject" disabled title="Start time has passed">
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>Reject
          </button>
          <button class="action-btn action-btn-cancel" disabled title="Start time has passed">
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>Cancel
          </button>
          ${delBtn}
          ${printBtns}
        </div>`;
    } else if (m.status === "Pending") {
      actionButtons = `<div style="display:flex;flex-wrap:wrap;gap:4px;align-items:center;">
          ${isAdminCreated ? referredBadge : `<button class="action-btn action-btn-approve" data-action="status" data-status="Approved" data-meeting-id="${m.id}">
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>Approve
          </button>`}
          ${!isAdminCreated ? `<button class="action-btn action-btn-reject" data-action="status" data-status="Rejected" data-meeting-id="${m.id}">
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>Reject
          </button>` : ""}
          <button class="action-btn action-btn-cancel" data-action="status" data-status="Cancelled" data-meeting-id="${m.id}">
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>Cancel
          </button>
          ${delBtn}
          ${printBtns}
        </div>`;
    } else if (m.status === "Approved") {
      // Already approved — disable Approve, show Cancel + Delete + PDF only
      actionButtons = `<div style="display:flex;flex-wrap:wrap;gap:4px;align-items:center;">
          <button class="action-btn action-btn-approve" disabled title="Already approved">
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>Approved
          </button>
          <button class="action-btn action-btn-cancel" data-action="status" data-status="Cancelled" data-meeting-id="${m.id}">
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>Cancel
          </button>
          ${delBtn}
          ${printBtns}
        </div>`;
    } else {
      // Done, Rejected, Cancelled — Delete + PDF only
      actionButtons = `<div style="display:flex;flex-wrap:wrap;gap:4px;align-items:center;">
          ${delBtn}
          ${printBtns}
        </div>`;
    }
    const cancelReasonCell = m.cancelReason ? `<div style="font-size:0.7rem;color:#9ca3af;margin-top:2px;font-style:italic" title="${h(m.cancelReason)}">Reason: ${h(m.cancelReason)}</div>` : "";
    const submittedAt = m.createdAt ? new Date(m.createdAt) : null;
    const submittedTag = submittedAt
      ? `<div style="font-size:0.68rem;color:var(--color-text-muted);margin-top:2px">
           Submitted ${_annTimeAgo(m.createdAt)} · ${submittedAt.toLocaleString('en-PH',{ hour:'2-digit', minute:'2-digit', hour12:true, timeZone:'Asia/Manila' })}
         </div>` : "";
    const createdAt = m.createdAt ? new Date(m.createdAt) : null;
    const nowManila2 = getManilaNow();
    const msElapsedAdmin = createdAt ? Math.max(0, nowManila2 - createdAt) : Infinity;
    const within24hAdmin = msElapsedAdmin < 24 * 60 * 60 * 1000;
    const msLeftAdmin = within24hAdmin ? (24 * 60 * 60 * 1000 - msElapsedAdmin) : 0;
    const hoursLeftAdmin = Math.floor(msLeftAdmin / (60 * 60 * 1000));
    const minsLeftAdmin  = Math.floor((msLeftAdmin % (60 * 60 * 1000)) / 60000);
    const adminWindowTag = (["Pending","Approved"].includes(m.status) && within24hAdmin)
      ? `<div style="margin-top:3px;display:inline-flex;align-items:center;gap:3px;font-size:0.65rem;font-weight:700;color:#16a34a;background:rgba(22,163,74,0.1);border:1px solid rgba(22,163,74,0.2);border-radius:999px;padding:1px 7px">
           <svg width="8" height="8" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
           Cancel window: ${hoursLeftAdmin > 0 ? hoursLeftAdmin + "h " : ""}${minsLeftAdmin}m left
         </div>` : "";
    const notesCell = m.adminNote
      ? `<button class="admin-note-tap" data-action="show-note" data-note="${h(m.adminNote)}" title="${h(m.adminNote)}"
           style="font-size:0.71rem;color:var(--color-text-muted);background:var(--color-surface-2);border:1px solid var(--color-border);border-radius:6px;padding:3px 8px;cursor:pointer;max-width:120px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:block;text-align:left"
         >${h(m.adminNote)}</button>`
      : `<span style="color:var(--color-text-faint);font-size:0.78rem">—</span>`;
    return `<tr${isCancelRequest ? ' style="background:rgba(249,115,22,0.04)"' : ''}${isPendingExpired ? ' class="row-expired"' : ''}>
      <td>${h(m.eventName)}</td>
      <td>${formatDateDisplay(m.date)}</td>
      <td>${formatTimeRange(m.timeStart, m.durationHours || SLOT_DURATION_HOURS)}</td>
      <td>${h(m.type || m.meetingType || "—")}</td>
      <td>${(() => {
            const parts = [meetingStatusBadge(m.status)];
            if (isPendingExpired) parts.push('<div style="margin-top:3px;display:inline-flex;align-items:center;gap:3px;font-size:0.65rem;font-weight:700;color:#b45309;background:rgba(217,119,6,0.1);border:1px solid rgba(217,119,6,0.25);border-radius:999px;padding:1px 7px"><svg width="8" height="8" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>Start time passed</div>');
            if (cancelReasonCell) parts.push(cancelReasonCell);
            if (adminWindowTag) parts.push(adminWindowTag);
            if (submittedTag) parts.push(submittedTag);
            if (isAdminCreated) {
              const refRaw = (m.councilor && m.councilor !== "N/A") ? m.councilor
                           : (m.researcher && m.researcher !== "N/A") ? m.researcher
                           : null;
              if (refRaw) {
                const refUser = Array.isArray(users) ? users.find(u => u.name === refRaw || u.username === refRaw) : null;
                const refName = refUser ? (refUser.name || refUser.username || refRaw) : refRaw;
                parts.push(`<div style="margin-top:3px;display:inline-flex;align-items:center;gap:4px;font-size:0.7rem;color:#1e40af;background:#eef2ff;border:1px solid #c7d2fe;border-radius:999px;padding:1px 7px;"><svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d='M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z'/></svg>Referred to: ${h(refName)}</div>`);
              }
            }
            return parts.join("");
          })()}</td>
      <td>${h(m.createdBy)}</td>
      <td>${notesCell}</td>
      <td>${actionButtons}</td>
    </tr>`;
  }).join("");

  renderPagination("admin-meetings-pagination", totalPages, adminMeetingsPage, (p) => { adminMeetingsPage = p; renderAdminMeetingsTable(); });

  // ── Mobile card view ─────────────────────────────────────────────────────
  // Renders the same paginated list as cards into #admin-meetings-cards,
  // which is shown on ≤768 px and hidden on desktop (controlled by CSS).
  const cardsWrap = document.getElementById("admin-meetings-cards");
  if (cardsWrap) {
    if (!paginated.length) {
      cardsWrap.innerHTML = '<div class="admin-mtg-cards-empty">No meetings found.</div>';
    } else {
      cardsWrap.innerHTML = paginated.map(m => {
        const isCancelRequest = m.status === "Cancellation Requested";
        const isAdminCreated  = m.createdByRole === ROLES.ADMIN;
        const isPendingExpired = m.status === "Pending" && hasMeetingStarted(m);

        // ── Status tags ──
        let statusTags = meetingStatusBadge(m.status);
        if (isPendingExpired) {
          statusTags += `<span class="card-tag card-tag-expired">
            <svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
            Start time passed
          </span>`;
        }
        if (m.cancelReason) {
          statusTags += `<div class="card-cancel-reason">Reason: ${h(m.cancelReason)}</div>`;
        }
        // Cancel window tag
        const createdAt2 = m.createdAt ? new Date(m.createdAt) : null;
        if (createdAt2 && ["Pending","Approved"].includes(m.status)) {
          const now2 = getManilaNow();
          const elapsed2 = Math.max(0, now2 - createdAt2);
          if (elapsed2 < 24 * 60 * 60 * 1000) {
            const msLeft2 = 24 * 60 * 60 * 1000 - elapsed2;
            const hLeft2  = Math.floor(msLeft2 / 3600000);
            const mLeft2  = Math.floor((msLeft2 % 3600000) / 60000);
            statusTags += `<span class="card-tag card-tag-window">
              <svg width="8" height="8" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
              Cancel window: ${hLeft2 > 0 ? hLeft2 + "h " : ""}${mLeft2}m left
            </span>`;
          }
        }
        // Referred-to tag for admin-created meetings
        if (isAdminCreated) {
          const refRaw2 = (m.councilor && m.councilor !== "N/A") ? m.councilor
                        : (m.researcher && m.researcher !== "N/A") ? m.researcher : null;
          if (refRaw2) {
            const refUser2 = Array.isArray(users) ? users.find(u => u.name === refRaw2 || u.username === refRaw2) : null;
            const refName2 = refUser2 ? (refUser2.name || refUser2.username || refRaw2) : refRaw2;
            statusTags += `<span class="card-tag card-tag-referred">
              <svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
              Referred to: ${h(refName2)}
            </span>`;
          }
        }
        // Submitted time
        if (m.createdAt) {
          const subAt = new Date(m.createdAt);
          statusTags += `<div class="card-submitted">Submitted ${_annTimeAgo(m.createdAt)} · ${subAt.toLocaleString('en-PH',{ hour:'2-digit', minute:'2-digit', hour12:true, timeZone:'Asia/Manila' })}</div>`;
        }

        // ── Action buttons (same logic as table) ──
        const delBtnC = `<button class="action-btn action-btn-cancel" data-action="delete" data-meeting-id="${m.id}">
          <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 01-2 2H8a2 2 0 01-2-2L5 6"/><path d="M10 11v6M14 11v6"/></svg>Delete
        </button>`;
        const pdfBtnC = `<button class="btn btn-sm btn-ghost" data-action="print" data-meeting-id="${m.id}">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 6 2 18 2 18 9"/><path d="M6 18H4a2 2 0 01-2-2v-5a2 2 0 012-2h16a2 2 0 012 2v5a2 2 0 01-2 2h-2"/><rect x="6" y="14" width="12" height="8"/></svg>PDF
        </button>`;
        const referredBadgeC = `<span class="card-tag card-tag-referred" style="padding:5px 10px;font-size:0.72rem">
          <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>Referred
        </span>`;

        let cardActions;
        if (isCancelRequest) {
          cardActions = `
            <span style="font-size:0.72rem;color:#c2410c;font-weight:600;display:inline-flex;align-items:center;gap:4px;background:#fff7ed;border:1px solid #fed7aa;border-radius:6px;padding:4px 10px;">Cancellation Requested</span>
            <button class="action-btn action-btn-cancel" data-action="status" data-status="Cancelled" data-meeting-id="${m.id}" style="font-weight:700;">
              <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>Confirm Cancel
            </button>
            <button class="action-btn action-btn-approve" data-action="status" data-status="Approved" data-meeting-id="${m.id}">
              <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>Deny Request
            </button>
            ${delBtnC}${pdfBtnC}`;
        } else if (isPendingExpired) {
          cardActions = `
            <button class="action-btn action-btn-approve" disabled>
              <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>Approve
            </button>
            <button class="action-btn action-btn-reject" disabled>
              <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>Reject
            </button>
            <button class="action-btn action-btn-cancel" disabled>
              <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>Cancel
            </button>
            ${delBtnC}${pdfBtnC}`;
        } else if (m.status === "Pending") {
          cardActions = `
            ${isAdminCreated ? referredBadgeC : `<button class="action-btn action-btn-approve" data-action="status" data-status="Approved" data-meeting-id="${m.id}">
              <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>Approve
            </button>`}
            ${!isAdminCreated ? `<button class="action-btn action-btn-reject" data-action="status" data-status="Rejected" data-meeting-id="${m.id}">
              <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>Reject
            </button>` : ""}
            <button class="action-btn action-btn-cancel" data-action="status" data-status="Cancelled" data-meeting-id="${m.id}">
              <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>Cancel
            </button>
            ${delBtnC}${pdfBtnC}`;
        } else if (m.status === "Approved") {
          cardActions = `
            <button class="action-btn action-btn-approve" disabled>
              <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>Approved
            </button>
            <button class="action-btn action-btn-cancel" data-action="status" data-status="Cancelled" data-meeting-id="${m.id}">
              <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>Cancel
            </button>
            ${delBtnC}${pdfBtnC}`;
        } else {
          // Done, Rejected, Cancelled
          cardActions = `${delBtnC}${pdfBtnC}`;
        }

        // ── Note row ──
        const noteRow = m.adminNote
          ? `<div class="admin-mtg-card-note">
               <span class="card-note-label">Note</span>
               <span class="card-note-text">${h(m.adminNote)}</span>
             </div>` : "";

        return `
          <div class="admin-mtg-card${isCancelRequest ? " card-cancel-req" : ""}${isPendingExpired ? " row-expired" : ""}">
            <div class="admin-mtg-card-head">
              <div class="admin-mtg-card-title">${h(m.eventName)}</div>
              <div class="admin-mtg-card-status">${statusTags}</div>
            </div>
            <div class="admin-mtg-card-meta">
              <div class="card-meta-item">
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4" width="18" height="18" rx="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/></svg>
                ${formatDateDisplay(m.date)}
              </div>
              <div class="card-meta-item">
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
                ${formatTimeRange(m.timeStart, m.durationHours || SLOT_DURATION_HOURS)}
              </div>
              <div class="card-meta-item">
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 6h16M4 12h16M4 18h7"/></svg>
                ${h(m.type || m.meetingType || "—")}
              </div>
              <div class="card-meta-item">
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
                ${h(m.createdBy)}
              </div>
            </div>
            ${noteRow}
            <div class="admin-mtg-card-actions">${cardActions}</div>
          </div>`;
      }).join("");
    }
    // Wire up action buttons via event delegation.
    // Re-attach by cloning the node to prevent stacking duplicate listeners
    // on every re-render call.
    const freshWrap = cardsWrap.cloneNode(false);
    freshWrap.innerHTML = cardsWrap.innerHTML;
    cardsWrap.parentNode.replaceChild(freshWrap, cardsWrap);
    freshWrap.addEventListener("click", handleAdminMeetingsClick);
  }
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

  if (action === "print") {
    const _dt = mtg.status === "Cancelled"            ? "cancellation"
              : mtg.status === "Rejected"             ? "rejection"
              : mtg.status === "Pending"              ? "request"
              : mtg.status === "Cancellation Requested" ? "cancellation"
              : "approval";
    generateMeetingPdf(mtg, _dt);
    return;
  }

  // ── Admin note popover — safe event delegation (replaces inline onclick) ──
  if (action === "show-note") {
    const noteText = btn.dataset.note || "";
    let popover = document.getElementById("admin-note-popover");
    if (popover) popover.remove();
    popover = document.createElement("div");
    popover.id = "admin-note-popover";
    popover.style.cssText = "position:fixed;z-index:9999;max-width:300px;background:var(--color-surface);border:1px solid var(--color-border);border-radius:10px;padding:14px 16px;box-shadow:0 8px 32px rgba(0,0,0,0.18);font-size:0.82rem;color:var(--color-text);line-height:1.5;white-space:pre-wrap;word-break:break-word";
    const closeBtn = document.createElement("button");
    closeBtn.style.cssText = "float:right;background:none;border:none;cursor:pointer;font-size:0.9rem;color:var(--color-text-muted);margin:-4px -4px 6px 8px";
    closeBtn.textContent = "✕";
    closeBtn.addEventListener("click", () => popover.remove());
    const noteContent = document.createElement("span");
    noteContent.textContent = noteText; // safe — textContent never executes HTML
    popover.appendChild(closeBtn);
    popover.appendChild(noteContent);
    document.body.appendChild(popover);
    const rect = btn.getBoundingClientRect();
    popover.style.top  = (rect.bottom + 6) + "px";
    popover.style.left = Math.min(rect.left, window.innerWidth - 316) + "px";
    setTimeout(() => {
      document.addEventListener("click", function dismissNote(ev) {
        if (!popover.contains(ev.target) && ev.target !== btn) {
          popover.remove();
          document.removeEventListener("click", dismissNote);
        }
      });
    }, 0);
    return;
  }
  if (action === "delete") {
    openConfirmModal(
      "Delete Meeting",
      "Delete this meeting permanently? This cannot be undone.",
      async () => {
        try {
          if (window.api && window.api.deleteMeeting) {
            await window.api.deleteMeeting(mtg.id);
          } else {
            const idx = meetings.findIndex(x => x.id === mtg.id);
            if (idx > -1) meetings.splice(idx, 1);
          }
          renderAdminMeetingsTable();
          renderCalendar();
          updateStatistics();
          showToast("Meeting deleted.", "success");
        } catch (err) {
          showToast("Failed to delete meeting.", "error");
        }
      }
    );
    return;
  }

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

  // Block Approve if the meeting's start time has already passed
  if (status === "Approved" && hasMeetingStarted(mtg)) {
    showToast("This meeting's start time has already passed and can no longer be approved.", "warning");
    reenable();
    return;
  }
  // Block all status actions (except Delete) on expired pending meetings
  if (action === "status" && mtg.status === "Pending" && hasMeetingStarted(mtg) && status !== "Done") {
    showToast("This meeting has already passed its start time. Only Delete is allowed.", "warning");
    reenable();
    return;
  }
  if (status === "Done" && !hasMeetingEnded(mtg)) {
    showToast("This meeting has not ended yet.", "warning");
    reenable();
    return;
  }

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
    window.api.updateMeetingStatus(mtg.id, status, note).then(() => {}).catch(err => {
      console.error("updateMeetingStatus failed:", err);
      showToast("Status update may not have saved. Please refresh.", "error");
    });
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
    const noteText = note ? ` — Admin note: "${h(note)}"` : "";

    let message = "";
    let notifType = "info";
    // section the user should navigate to when clicking this notification
    const targetSection = "my-meetings";

    if (status === "Approved") {
      message = `Your meeting "<strong>${h(mtg.eventName)}</strong>" on ${dateStr} at ${timeStr} has been <strong>approved</strong>.${noteText}`;
      notifType = "success";
    } else if (status === "Rejected") {
      message = `Your meeting "<strong>${h(mtg.eventName)}</strong>" on ${dateStr} has been <strong>rejected</strong>.${noteText}`;
      notifType = "error";
    } else if (status === "Cancelled") {
      message = `Your meeting "<strong>${h(mtg.eventName)}</strong>" on ${dateStr} has been <strong>cancelled</strong>.${noteText}`;
      notifType = "error";
    }

    if (message) {
      addNotification(ownerId, message, notifType, targetSection);
      // Refresh the user's bell badge right away so they see it immediately
      updateNotificationBadge(ownerId);
    }
  }

  // --- Also notify admins when a cancellation request is approved/actioned ---
  // (admin cancelling a meeting on behalf — make sure pending badge re-counts)
  if (status === "Cancelled" || status === "Approved" || status === "Rejected") {
    updateStatistics(); // refreshes the meeting-logs pending badge for admin
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
        window.api.updateMeetingStatus(m.id, "Cancelled", m.adminNote).then(() => {}).catch(err => {
          console.error("Auto-cancel conflict update failed:", err);
        });
      }
      const conflictOwner = users.find(u => u.username === m.createdBy) ||
                            users.find(u => u.name === m.councilor);
      if (conflictOwner) {
        addNotification(
          conflictOwner.id || conflictOwner.username,
          `Your meeting "<strong>${h(m.eventName)}</strong>" on ${formatDateDisplay(m.date)} was automatically <strong>cancelled</strong> due to a scheduling conflict with another approved meeting.`,
          "warning",
          "my-meetings"
        );
      }
    });
    if (!window.api || !window.api.updateMeetingStatus) persistMeetings();
    generateMeetingPdf(mtg, "approval");
  }

  renderAdminMeetingsTable();
  renderCalendar();
  updateStatistics();
  // Refresh the admin's own badge after any status change
  const currentAdmin = getCurrentUser();
  if (currentAdmin) updateNotificationBadge(currentAdmin.id || currentAdmin.username);
  showToast(`Meeting marked as ${status}.`, "success");
}
const _SBP_HEADER_B64 = "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";
const _SBP_FOOTER_B64 = "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";

function generateMeetingPdf(mtg, docType, autoPrint) {
  // Wrap entire PDF generation in try/catch so a jsPDF failure never
  // crashes the page silently — show a user-facing toast instead.
  try {
    _generateMeetingPdfInner(mtg, docType, autoPrint);
  } catch (err) {
    console.error("PDF generation failed:", err);
    showToast("Could not generate PDF. Please try again.", "error");
  }
}
function _generateMeetingPdfInner(mtg, docType, autoPrint) {
  // docType controls the document title and filename:
  //   'approval'      → Meeting Approval Slip  (default)
  //   'cancellation'  → Cancellation Letter
  //   'rejection'     → Rejection Notice
  //   'request'       → Meeting Request Form
  try {
    const { jsPDF } = window.jspdf || {};
    if (!jsPDF) { showToast("PDF library not loaded.", "error"); return; }

    // ── Letterhead images (base64 JPEG extracted from official SBP letterhead) ──
    const HEADER_B64 = "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";
    const FOOTER_B64 = "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";

    // ── Document type config ──────────────────────────────────────────────────
    const DOC_TYPES = {
      approval:     { title: "MEETING APPROVAL SLIP",   file: "Meeting-Approval-Slip" },
      cancellation: { title: "CANCELLATION LETTER",     file: "Cancellation-Letter" },
      rejection:    { title: "REJECTION NOTICE",        file: "Rejection-Notice" },
      request:      { title: "MEETING REQUEST FORM",    file: "Meeting-Request-Form" },
    };
    const dtype = DOC_TYPES[docType] || DOC_TYPES.approval;

    // ── Page setup (custom letterhead size: 215.9 x 355.6 mm) ────────────────
    const PW = 215.9, PH = 355.6;
    const ML = 20, MR = 20;
    const CW = PW - ML - MR;
    const doc = new jsPDF({ unit: "mm", format: [PW, PH] });

    // ── Letterhead header image ───────────────────────────────────────────────
    // Header image occupies ~53mm at top (proportional to 200px out of 1482px total)
    const HEADER_H_MM = (200 / 1482) * PH;
    const FOOTER_H_MM = (100 / 1482) * PH;
    doc.addImage("data:image/jpeg;base64," + HEADER_B64, "JPEG", 0, 0, PW, HEADER_H_MM);
    doc.addImage("data:image/jpeg;base64," + FOOTER_B64, "JPEG", 0, PH - FOOTER_H_MM, PW, FOOTER_H_MM);

    // ── Letter content ────────────────────────────────────────────────────────
    let y = HEADER_H_MM + 10;
    const LINE_H = 6;   // line height for body text
    const INDENT = ML;

    // ── Document title heading ────────────────────────────────────────────────
    doc.setFontSize(12);
    doc.setFont("times", "bold");
    doc.setTextColor(20, 20, 20);
    doc.text(dtype.title, PW / 2, y, { align: "center" });
    y += LINE_H * 2;

    // ── Date ──────────────────────────────────────────────────────────────────
    // The date at the top of the letter is always today — the date it was issued/printed.
    // The meeting's scheduled date appears separately inside the details block below.
    const refDate = new Date().toLocaleDateString("en-PH", { year:"numeric", month:"long", day:"numeric" });
    doc.setFontSize(10);
    doc.setFont("times", "normal");
    doc.setTextColor(20, 20, 20);
    doc.text(`Date: ${refDate}`, INDENT, y);
    y += LINE_H * 1.8;

    // ── Addressee ─────────────────────────────────────────────────────────────
    doc.setFont("times", "bold");
    doc.text("HON. CHERILIE MELLA-SAMPAL", INDENT, y); y += LINE_H;
    doc.setFont("times", "normal");
    doc.text("Vice Mayor", INDENT, y); y += LINE_H;
    doc.text("Municipality of Polangui", INDENT, y); y += LINE_H * 1.8;

    // ── Subject ───────────────────────────────────────────────────────────────
    const subjText = dtype === DOC_TYPES.cancellation
      ? "Request to Cancel Meeting"
      : dtype === DOC_TYPES.rejection
      ? "Notice of Meeting Rejection"
      : "Request to Conduct Meeting";
    doc.setFont("times", "normal");
    doc.text("Subject: ", INDENT, y);
    doc.setFont("times", "bold");
    doc.text(subjText, INDENT + doc.getTextWidth("Subject: "), y);
    doc.setFont("times", "normal");
    y += LINE_H * 2;

    // ── Opening paragraph ─────────────────────────────────────────────────────
    const meetingType = mtg.type || mtg.meetingType || "[Type of Meeting]";
    const committee   = mtg.committee || "[Name of Committee]";
    const openPara = docType === "cancellation"
      ? `We respectfully inform your office of the cancellation of the ${meetingType} of the ${committee}, previously scheduled on ${formatDateDisplay(mtg.date)}, at ${formatTimeRange(mtg.timeStart, mtg.durationHours ?? SLOT_DURATION_HOURS)}, at ${mtg.venue || "[Venue]"}. We apologize for any inconvenience this may cause.`
      : docType === "rejection"
      ? `We regret to inform you that the ${meetingType} of the ${committee}, scheduled on ${formatDateDisplay(mtg.date)}, has been declined. We encourage you to re-submit a new request should the need arise.`
      : `We respectfully request your approval to conduct a ${meetingType} of the ${committee}, which will be held to discuss matters within the committee's jurisdiction and to address relevant concerns, with the following details for your kind consideration:`;

    doc.setFontSize(10.5);
    doc.setFont("times", "normal");
    doc.setTextColor(20, 20, 20);
    const openLines = doc.splitTextToSize(openPara, CW);
    doc.text(openLines, INDENT, y);
    y += openLines.length * LINE_H + LINE_H;

    // ── Meeting details block ─────────────────────────────────────────────────
    const detailRows = [
      ["Event/Title:",       mtg.eventName       || "—"],
      ["Meeting Type:",      meetingType],
      ["Committee:",         committee],
      ["Date:",              formatDateDisplay(mtg.date)],
      ["Time:",              formatTimeRange(mtg.timeStart, mtg.durationHours ?? SLOT_DURATION_HOURS)],
      ["Venue:",             mtg.venue           || "—"],
      ["Presiding Officer:", mtg.councilor       || "—"],
    ];

    const LABEL_W = 44;
    detailRows.forEach(([lbl, val]) => {
      doc.setFont("times", "bold");
      doc.text(lbl, INDENT + 8, y);
      doc.setFont("times", "normal");
      const valLines = doc.splitTextToSize(String(val), CW - LABEL_W - 8);
      doc.text(valLines, INDENT + 8 + LABEL_W, y);
      y += Math.max(1, valLines.length) * LINE_H;
    });
    y += LINE_H;

    // ── Admin note / reason (if any) ──────────────────────────────────────────
    if (mtg.adminNote || mtg.cancelReason) {
      const noteText = mtg.adminNote || mtg.cancelReason;
      const noteLabel = docType === "cancellation" ? "Reason:" : "Remarks:";
      doc.setFont("times", "bold");
      doc.text(noteLabel, INDENT, y);
      doc.setFont("times", "italic");
      const nLines = doc.splitTextToSize(noteText, CW - doc.getTextWidth(noteLabel) - 4);
      doc.text(nLines, INDENT + doc.getTextWidth(noteLabel) + 3, y);
      y += Math.max(1, nLines.length) * LINE_H + LINE_H;
    }

    // ── Closing paragraph — unique per document type ────────────────────────
    let closePara;
    if (docType === "cancellation") {
      closePara = "We regret any inconvenience this cancellation may have caused. Should it be necessary to reschedule, we will coordinate with your office at the earliest opportunity.\n\nThank you for your understanding and continued support.";
    } else if (docType === "rejection") {
      closePara = "We appreciate your effort in submitting this request. We encourage you to re-submit a revised request at a more appropriate time, ensuring that all requirements and schedules are properly observed.\n\nThank you for your understanding.";
    } else {
      closePara = "We will conduct the said hearing under the leadership of the above-named Chairperson to discuss matters within the jurisdiction of the committee.\n\nIn this regard, we respectfully seek your approval for the conduct of the said meeting. Thank you.";
    }

    doc.setFont("times", "normal");
    doc.setFontSize(10.5);
    const closeLines = doc.splitTextToSize(closePara, CW);
    doc.text(closeLines, INDENT, y);
    y += closeLines.length * LINE_H + LINE_H * 2;

    // ── Signature block ───────────────────────────────────────────────────────
    doc.setFont("times", "normal");
    doc.text("Respectfully yours,", INDENT, y);
    y += LINE_H * 3.5;

    // Signature line
    doc.setDrawColor(20, 20, 20);
    doc.setLineWidth(0.4);
    doc.line(INDENT, y, INDENT + 65, y);
    y += LINE_H * 0.8;
    doc.setFont("times", "normal");
    doc.text("Municipal Councilor", INDENT, y);
    y += LINE_H * 2.5;

    // Noted by block
    doc.setFont("times", "normal");
    doc.text("NOTED:", INDENT, y);
    y += LINE_H * 3;

    doc.line(INDENT, y, INDENT + 75, y);
    y += LINE_H * 0.8;
    doc.setFont("times", "bold");
    doc.text("HON. CHERILIE MELLA-SAMPAL", INDENT, y);
    y += LINE_H;
    doc.setFont("times", "normal");
    doc.text("Vice Mayor", INDENT, y);

    // ── Official note above footer ────────────────────────────────────────────
    doc.setFontSize(7);
    doc.setFont("times", "italic");
    doc.setTextColor(150, 160, 180);
    doc.text("This is an official document of the Sangguniang Bayan ng Polangui, Albay.",
      PW / 2, PH - FOOTER_H_MM - 5, { align: "center" });

    // ── Smart filename ────────────────────────────────────────────────────────
    const safeEvent = (mtg.eventName || "Meeting").replace(/[^a-zA-Z0-9 ]/g, "").trim().replace(/\s+/g, "-").slice(0, 30);
    const dateStr = (mtg.date || "").replace(/-/g, "");
    if (autoPrint) {
      doc.autoPrint();
      const url = doc.output("bloburl");
      window.open(url, "_blank");
    } else {
      doc.save(`SBP-${dtype.file}-${safeEvent}-${dateStr}.pdf`);
    }

  } catch(err) {
    console.error("PDF error:", err);
    showToast("Failed to generate PDF. Please try again.", "error");
  }
}

function handleMyMeetingsClick(e) {
  const btn = e.target.closest("button[data-action]");
  if (!btn) return;
  if (btn.disabled || btn.dataset.processing === "1") return;

  const id = btn.dataset.meetingId;
  const action = btn.dataset.action;
  const mtg = meetings.find(m => m.id === id);
  if (!mtg) return;

  if (action === "edit-meeting") {
    const createdAt = mtg.createdAt ? new Date(mtg.createdAt) : null;
    const within24h = createdAt && (getManilaNow() - createdAt) < 24 * 60 * 60 * 1000;
    if (!within24h || mtg.status !== "Pending") {
      showToast("Editing is only allowed within 24 hours of submission for Pending meetings.", "warning");
      return;
    }
    openEditMeetingModal(mtg);
    return;
  }

  if (action === "export-pdf") {
    const _dt = mtg.status === "Cancelled" || mtg.status === "Cancellation Requested"
                  ? "cancellation"
                  : mtg.status === "Rejected"
                    ? "rejection"
                    : mtg.status === "Pending"
                      ? "request"
                      : "approval";
    generateMeetingPdf(mtg, _dt);
    return;
  }

  if (action === "request-cancel") {
    btn.disabled = true;
    btn.dataset.processing = "1";
    const reenable = () => { btn.disabled = false; btn.dataset.processing = "0"; };

    const currentUser = getCurrentUser();
    const createdAt = mtg.createdAt ? new Date(mtg.createdAt) : null;
    const now = getManilaNow();
    const within24h = !!(createdAt && Math.max(0, now - createdAt) < 24 * 60 * 60 * 1000);

    // Use openNoteModal to collect a cancellation reason
    const promptHtml = within24h
      ? `<div style="margin-bottom:10px">
           <span style="display:inline-flex;align-items:center;gap:6px;background:#dcfce7;color:#166534;font-size:0.75rem;font-weight:700;padding:4px 10px;border-radius:999px;margin-bottom:8px">
             <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
             Within 24-hour allowed cancellation window
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
      true, // required: cancellation reason is mandatory
      (reason) => {
        if (!reason || !reason.trim()) return "Please provide a reason for cancellation.";

        if (within24h) {
          // Direct cancel — no admin needed
          mtg.status = "Cancelled";
          mtg.cancelReason = reason.trim();
          mtg.cancelledAt = new Date().toISOString();

          const extraFields = { cancelReason: mtg.cancelReason, cancelledAt: mtg.cancelledAt };
          if (window.api && window.api.updateMeetingStatus) {
            window.api.updateMeetingStatus(mtg.id, "Cancelled", "", extraFields).then(() => {}).catch(err => {
              console.error("Cancel update failed:", err);
              showToast("Cancellation may not have saved. Please refresh.", "error");
            });
          } else {
            persistMeetings();
          }

          renderMyMeetingsTable(currentUser);
          renderAdminMeetingsTable();
          renderCalendar();
          updateStatistics();
          showToast("Meeting cancelled successfully.", "success");
          if (window.innerWidth <= 768 && typeof _closeActive === "function") _closeActive();

          // Notify ALL admins of the self-cancellation and refresh their badge immediately
          const adminList = (Array.isArray(users) ? users : []).filter(u => u.role === ROLES.ADMIN);
          adminList.forEach(admin => {
            const adminUserId = admin.id || admin.username;
            addNotification(
              adminUserId,
              `<strong>${h(currentUser.name)}</strong> cancelled their meeting <strong>"${h(mtg.eventName)}"</strong> on ${formatDateDisplay(mtg.date)} (within 24h free window). Reason: <em>${h(reason.trim())}</em>`,
              "info",
              "meeting-logs"
            );
            // Refresh the admin's bell badge right away so they see it immediately
            updateNotificationBadge(adminUserId);
          });

          // Also refresh the current user's own badge
          updateNotificationBadge(currentUser.id || currentUser.username);

        } else {
          // ── Admin-review path (past 24h window) ──────────────────────────
          mtg.status = "Cancellation Requested";
          mtg.cancelReason = reason.trim();

          const extraFields = { cancelReason: mtg.cancelReason };
          if (window.api && window.api.updateMeetingStatus) {
            window.api.updateMeetingStatus(mtg.id, "Cancellation Requested", "", extraFields).then(() => {}).catch(err => {
              console.error("Cancellation request failed:", err);
              showToast("Cancellation request may not have saved. Please refresh.", "error");
            });
          } else {
            persistMeetings();
          }

          renderMyMeetingsTable(currentUser);
          renderAdminMeetingsTable();
          renderCalendar();
          // Update statistics so the pending-badge on meeting-logs nav refreshes
          updateStatistics();
          showToast("Cancellation request submitted to admin.", "info");
          if (window.innerWidth <= 768 && typeof _closeActive === "function") _closeActive();

          // Notify ALL admins and refresh their badge immediately
          const adminList2 = (Array.isArray(users) ? users : []).filter(u => u.role === ROLES.ADMIN);
          adminList2.forEach(admin => {
            const adminUserId = admin.id || admin.username;
            addNotification(
              adminUserId,
              `<strong>${h(currentUser.name)}</strong> requested cancellation of <strong>"${h(mtg.eventName)}"</strong> scheduled on ${formatDateDisplay(mtg.date)}. Reason: <em>${h(reason.trim())}</em> — Please review in Meeting Logs.`,
              "warning",
              "meeting-logs"
            );
            updateNotificationBadge(adminUserId);
          });

          // Confirm to the user that their request was submitted
          addNotification(
            currentUser.id || currentUser.username,
            `Your cancellation request for <strong>"${h(mtg.eventName)}"</strong> on ${formatDateDisplay(mtg.date)} has been submitted and is <strong>pending admin review</strong>.`,
            "info",
            "my-meetings"
          );
          updateNotificationBadge(currentUser.id || currentUser.username);
        }
        return null; // no error — close the modal
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

let _calendarDebounceTimer = null;
function renderCalendar() {
  // Debounce: coalesce rapid successive calls (e.g. from subscribeMeetings +
  // updateStatistics firing back-to-back) into a single redraw after 80ms.
  clearTimeout(_calendarDebounceTimer);
  _calendarDebounceTimer = setTimeout(_renderCalendarNow, 80);
}
function _renderCalendarNow() {
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
      .filter(m => ["Approved","Pending","Cancellation Requested","Done"].includes(m.status))
      .sort((a, b) => (a.timeStart || "").localeCompare(b.timeStart || ""));

    const MAX_BADGES = 2;

    const _manilaMinutes = (() => {
      const n = getManilaNow();
      return n.getHours() * 60 + n.getMinutes();
    })();

    const isAdminPage = document.body.dataset.page === "admin";

    // ── Helpers ───────────────────────────────────────────────────────────────
    function _isMine(m) {
      return !!(currentUser && (
        m.createdBy === currentUser.username ||
        m.councilor === currentUser.name ||
        m.researcher === currentUser.name
      ));
    }
    function _isOngoing(m) {
      if (!isToday || m.status !== "Approved" || !m.timeStart) return false;
      const s = minutesFromTimeStr(m.timeStart);
      return _manilaMinutes >= s && _manilaMinutes < s + (m.durationHours || SLOT_DURATION_HOURS) * 60;
    }

    // ── DESKTOP: Text badges ──────────────────────────────────────────────────
    activeMeetings.slice(0, MAX_BADGES).forEach(m => {
      const isAdminCreated = m.createdByRole === ROLES.ADMIN;
      const mine    = _isMine(m);
      const ongoing = _isOngoing(m);
      const timeLabel = m.timeStart ? `${formatTime12h(minutesFromTimeStr(m.timeStart))} ` : "";

      const badge = document.createElement("div");

      if (ongoing) {
        // Blue gradient — always stands out
        badge.className = "calendar-badge calendar-badge-ongoing";
        badge.appendChild(document.createTextNode(timeLabel + (m.eventName || "Meeting")));

      } else if (isAdminPage) {
        // ── ADMIN PAGE: pure status colors, no ownership indicator ───────────
        // Admin sees all meetings equally — Approved=green, Pending=yellow, Done=blue
        badge.className = statusColorForCalendar(m.status, isAdminCreated, false);
        badge.appendChild(document.createTextNode(timeLabel + (m.eventName || "Meeting")));

      } else if (mine) {
        // ── USER PAGE — MINE: status color + highlight outline ────────────────
        // Approved → green badge + gold outline (clearly approved, clearly mine)
        // Pending  → gold badge (awaiting approval)
        // Admin-scheduled → purple badge (admin booked on your behalf)
        // Other statuses (Cancelled, Rejected, Done) → normal status color + outline
        if (m.status === "Approved") {
          badge.className = "calendar-badge calendar-badge-approved calendar-badge-mine-highlight";
        } else if (isAdminCreated) {
          badge.className = "calendar-badge calendar-badge-is-admin-mine";
        } else if (m.status === "Pending" || m.status === "Cancellation Requested") {
          badge.className = "calendar-badge calendar-badge-is-mine";
        } else {
          badge.className = statusColorForCalendar(m.status, isAdminCreated, true) + " calendar-badge-mine-highlight";
        }
        badge.appendChild(document.createTextNode(timeLabel + (m.eventName || "Meeting")));
        const pip = document.createElement("span");
        pip.className = "calendar-badge-dot " + (isAdminCreated ? "calendar-badge-dot-admin" : "calendar-badge-dot-mine");
        badge.appendChild(pip);

      } else {
        // ── USER PAGE — OTHERS: status-colored but dimmed so user can tell "not mine" ─
        badge.className = statusColorForCalendar(m.status, isAdminCreated, false) + " calendar-badge-others";
        badge.appendChild(document.createTextNode(timeLabel + (m.eventName || "Meeting")));
      }

      badge.title = `${h(m.eventName)} — ${formatTimeRange(m.timeStart, m.durationHours || SLOT_DURATION_HOURS)} [${m.status}]${ongoing ? " · NOW ONGOING" : ""}${!isAdminPage && mine ? " · Your meeting" : ""}`;
      cell.appendChild(badge);
    });

    if (activeMeetings.length > MAX_BADGES) {
      const more = document.createElement("div");
      more.className = "calendar-badge calendar-badge-more";
      more.textContent = `+${activeMeetings.length - MAX_BADGES} more`;
      cell.appendChild(more);
    }

    if (dayHistory.length && activeMeetings.length === 0) {
      const block = document.createElement("div");
      block.className = "calendar-badge";
      block.style.background = dayHistory[0].color || "#9ca3af";
      block.style.color = "#fff";
      block.textContent = "Archived";
      block.title = "Archived — read-only";
      cell.appendChild(block);
    }

    // ── MOBILE: Dot row (hidden on desktop via CSS display:none) ─────────────
    // Admin: status-colored dot per meeting (full visibility)
    // User:  own meetings = colored dot | others = small grey dot (slot taken)
    if (activeMeetings.length > 0 || (isAdminPage && dayHistory.length > 0)) {
      const dotsRow = document.createElement("div");
      dotsRow.className = "calendar-cell-dots";

      const MAX_DOTS = 4;
      let dotCount = 0;

      activeMeetings.forEach(m => {
        if (dotCount >= MAX_DOTS) return;
        const mine    = _isMine(m);
        const ongoing = _isOngoing(m);
        const dot     = document.createElement("div");

        if (isAdminPage) {
          // Admin: full status color — no ownership tint
          if (ongoing)             dot.className = "calendar-dot calendar-dot-ongoing";
          else if (m.status === "Approved") dot.className = "calendar-dot calendar-dot-approved";
          else if (m.status === "Pending" ||
                   m.status === "Cancellation Requested") dot.className = "calendar-dot calendar-dot-pending";
          else if (m.status === "Done")    dot.className = "calendar-dot calendar-dot-done";
          else                     dot.className = "calendar-dot calendar-dot-other";
        } else {
          // User: mine = full color, others = status-colored but slightly dimmed
          if (ongoing && mine)                                          dot.className = "calendar-dot calendar-dot-ongoing";
          else if (mine && m.status === "Approved")                     dot.className = "calendar-dot calendar-dot-approved";
          else if (mine && m.createdByRole === ROLES.ADMIN)             dot.className = "calendar-dot calendar-dot-admin-own";
          else if (mine)                                                 dot.className = "calendar-dot calendar-dot-mine";
          else if (m.status === "Approved")                 dot.className = "calendar-dot calendar-dot-others-approved";
          else if (m.status === "Pending" || m.status === "Cancellation Requested") dot.className = "calendar-dot calendar-dot-pending calendar-dot-others-dim";
          else if (m.status === "Done")                     dot.className = "calendar-dot calendar-dot-done calendar-dot-others-dim";
          else                                              dot.className = "calendar-dot calendar-dot-occupied";
        }

        dot.title = !isAdminPage && mine
          ? `${m.eventName || "Meeting"} [${m.status}] · Your meeting`
          : `${m.eventName || "Meeting"} [${m.status}]`;
        dotsRow.appendChild(dot);
        dotCount++;
      });

      if (activeMeetings.length > MAX_DOTS) {
        const overflow = document.createElement("div");
        overflow.className = "calendar-dot calendar-dot-overflow";
        overflow.title = `+${activeMeetings.length - MAX_DOTS} more`;
        dotsRow.appendChild(overflow);
      }

      if (isAdminPage && dayHistory.length > 0 && activeMeetings.length === 0) {
        const archDot = document.createElement("div");
        archDot.className = "calendar-dot calendar-dot-other";
        archDot.title = "Archived";
        dotsRow.appendChild(archDot);
      }

      cell.appendChild(dotsRow);
    }

    // ── Fully booked indicator ────────────────────────────────────────────────
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
      // Always allow clicking past days/holidays to VIEW schedule if there's anything to show
      if (dayMeetings.length || dayHistory.length || isHoliday) {
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
      <div class="modal" style="max-width:600px;max-height:90vh;display:flex;flex-direction:column;overflow:hidden">
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
    subtitle.innerHTML = `<span style="display:inline-flex;align-items:center;gap:6px;background:#fef3c7;color:#92400e;border-radius:6px;padding:3px 10px;font-size:0.78rem;font-weight:600;"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="flex-shrink:0"><circle cx="12" cy="12" r="10"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/><line x1="2" y1="12" x2="22" y2="12"/></svg> PH Holiday: ${h(holidayInfo.localName)}${holidayInfo.name !== holidayInfo.localName ? ` — ${h(holidayInfo.name)}` : ""}</span>`;
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
          const _isMine = currentUser && (
            m.createdBy === currentUser.username ||
            m.councilor === currentUser.name ||
            m.researcher === currentUser.name
          );
          const _mineOutline = _isMine ? ";outline:2px solid #F5A31A;outline-offset:1px" : "";
          return `<div style="background:${c.bg};border:1px solid ${c.border};border-left:4px solid ${isAdminCreated ? "#1d4ed8" : c.border};border-radius:8px;padding:10px 12px${_mineOutline}">
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

  const tickLines = [];
  const tickLabels = [];
  for (let hr = WORK_START_HOUR; hr <= WORK_END_HOUR; hr++) {
    tickLines.push(`<div style="position:absolute;left:${pct(hr*60)}%;top:0;bottom:0;border-left:1px dashed rgba(0,0,0,0.1);pointer-events:none"></div>`);
    const label = hr < 12 ? hr + 'a' : hr === 12 ? '12p' : (hr - 12) + 'p';
    let pos;
    if (hr === WORK_START_HOUR)    pos = `left:0`;
    else if (hr === WORK_END_HOUR) pos = `right:0`;
    else                           pos = `left:${pct(hr*60)}%;transform:translateX(-50%)`;
    tickLabels.push(`<div style="position:absolute;${pos};font-size:0.58rem;color:var(--color-text-muted);white-space:nowrap">${label}</div>`);
  }

  const approvedBlocks = approved.map(m => {
    const s = minutesFromTimeStr(m.timeStart);
    const dur = (m.durationHours || SLOT_DURATION_HOURS) * 60;
    return `<div title="${h(m.eventName)} (Approved)" style="position:absolute;left:${pct(s)}%;width:${wPct(dur)}%;top:4px;bottom:4px;background:#16a34a;border-radius:4px;opacity:0.85;cursor:default"></div>`;
  }).join("");

  const pendingBlocks = pending.map(m => {
    const s = minutesFromTimeStr(m.timeStart);
    const dur = (m.durationHours || SLOT_DURATION_HOURS) * 60;
    return `<div title="${h(m.eventName)} (Pending)" style="position:absolute;left:${pct(s)}%;width:${wPct(dur)}%;top:4px;bottom:4px;background:#f59e0b;border-radius:4px;opacity:0.75;cursor:default"></div>`;
  }).join("");

  return `
    <div style="margin-bottom:16px">
      <div style="font-size:0.71rem;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:var(--color-text-muted);margin-bottom:8px">TIME SLOTS (8AM – 5PM)</div>
      <div style="position:relative;height:32px;background:var(--color-bg);border:1px solid var(--color-border);border-radius:8px;overflow:hidden;margin-bottom:4px">
        ${tickLines.join("")}
        ${approvedBlocks}
        ${pendingBlocks}
      </div>
      <div style="position:relative;height:16px;margin-bottom:10px">${tickLabels.join("")}</div>
      <div style="display:flex;gap:12px;flex-wrap:wrap">
        <div style="display:flex;align-items:center;gap:5px;font-size:0.72rem;color:var(--color-text-muted)">
          <span style="width:12px;height:10px;border-radius:3px;background:#16a34a;display:inline-block;flex-shrink:0"></span> Approved
        </div>
        <div style="display:flex;align-items:center;gap:5px;font-size:0.72rem;color:var(--color-text-muted)">
          <span style="width:12px;height:10px;border-radius:3px;background:#f59e0b;display:inline-block;flex-shrink:0"></span> Pending
        </div>
        <div style="display:flex;align-items:center;gap:5px;font-size:0.72rem;color:var(--color-text-muted)">
          <span style="width:12px;height:10px;border-radius:3px;background:var(--color-bg);border:1px solid var(--color-border);display:inline-block;flex-shrink:0"></span> Available
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
// Admin / Vice Mayor / Secretary → both show as styled dropdowns
// Councilor → own name locked (styled readonly input), researcher is dropdown
// Researcher → own name locked (styled readonly input), councilor is dropdown
// ---------------------------------------------------------------------------
function _setupCouncilorResearcherFields(currentUser) {
  const cSelect = $("#meeting-councilor-select");
  const rSelect = $("#meeting-researcher-select");
  const cInput  = $("#meeting-councilor");
  const rInput  = $("#meeting-researcher");
  if (!cSelect || !rSelect || !cInput || !rInput) return;

  const isCouncilor  = currentUser.role === ROLES.COUNCILOR;
  const isResearcher = currentUser.role === ROLES.RESEARCHER;

  // Gather registered users
  const councilors  = users.filter(u => u.role === ROLES.COUNCILOR || u.role === ROLES.VICE_MAYOR);
  const researchers = users.filter(u => u.role === ROLES.RESEARCHER);

  // Helper: rebuild a <select> with given user list + N/A
  function fillSelect(sel, userList) {
    while (sel.options.length > 2) sel.remove(2);
    userList.forEach(u => {
      const opt = document.createElement("option");
      opt.value = u.name || u.username;
      opt.textContent = `${u.name || u.username} (${u.role})`;
      sel.appendChild(opt);
    });
  }

  fillSelect(cSelect, councilors);
  fillSelect(rSelect, researchers);

  // Reset everything hidden first
  cSelect.style.display = "none"; cInput.style.display = "none";
  rSelect.style.display = "none"; rInput.style.display = "none";
  cInput.readOnly = false; rInput.readOnly = false;
  cInput.required = false; rInput.required = false;
  cSelect.required = false; rSelect.required = false;
  cInput.value = ""; rInput.value = "";
  cSelect.value = ""; rSelect.value = "";
  // Reset locked styling
  cInput.classList.remove("field-locked"); rInput.classList.remove("field-locked");

  if (isCouncilor) {
    // Own name locked in a styled readonly input; researcher shows as dropdown
    cInput.value    = currentUser.name;
    cInput.readOnly = true;
    cInput.classList.add("field-locked");
    cInput.style.display = "";
    rSelect.style.display = "";
    rSelect.required = true;
  } else if (isResearcher) {
    // Own name locked in a styled readonly input; councilor shows as dropdown
    rInput.value    = currentUser.name;
    rInput.readOnly = true;
    rInput.classList.add("field-locked");
    rInput.style.display = "";
    cSelect.style.display = "";
    cSelect.required = true;
  } else {
    // Admin / Vice Mayor / Secretary: both as dropdowns
    cSelect.style.display = ""; cSelect.required = true;
    rSelect.style.display = ""; rSelect.required = true;
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
  _editingMeetingId = null;
  // Reset modal title back to default
  const titleEl = $("#meeting-modal-title");
  if (titleEl) titleEl.textContent = "Schedule Meeting";
}

// ---------------------------------------------------------------------------
// Edit Meeting Modal — pre-fills the booking form with existing meeting data
// Only available within 24h of submission for Pending meetings
// ---------------------------------------------------------------------------
let _editingMeetingId = null;

function openEditMeetingModal(mtg) {
  const currentUser = getCurrentUser();
  if (!currentUser) return;

  _editingMeetingId = mtg.id;

  const form = $("#meeting-form");
  if (!form) return;
  form.reset();
  $("#meeting-form-message").textContent = "";

  // Change modal title to indicate editing
  const titleEl = $("#meeting-modal-title");
  if (titleEl) titleEl.textContent = "Edit Meeting Request";

  // Pre-fill all fields
  const setVal = (id, val) => { const el = $(id); if (el) el.value = val || ""; };

  setVal("#meeting-event", mtg.eventName);
  setVal("#meeting-committee", mtg.committee);
  setVal("#meeting-date", mtg.date);
  setVal("#meeting-time", mtg.timeStart);
  setVal("#meeting-notes", mtg.notes);
  setVal("#meeting-stakeholders", mtg.stakeholders);

  // Meeting type — handle "Others"
  const typeEl = $("#meeting-type");
  const typeOtherEl = $("#meeting-type-other");
  const knownTypes = ["Regular Session", "Special Session", "Committee Meeting", "Others"];
  if (typeEl) {
    if (knownTypes.includes(mtg.type)) {
      typeEl.value = mtg.type;
      if (typeOtherEl) typeOtherEl.style.display = "none";
    } else {
      typeEl.value = "Others";
      if (typeOtherEl) { typeOtherEl.style.display = "block"; typeOtherEl.value = mtg.type || ""; }
    }
  }

  // Venue — handle "Others"
  const venueEl = $("#meeting-venue");
  const venueOtherEl = $("#meeting-venue-other");
  const knownVenues = ["SB Hall", "Old SB Hall", "ABC Hall", "Others"];
  if (venueEl) {
    if (knownVenues.includes(mtg.venue)) {
      venueEl.value = mtg.venue;
      if (venueOtherEl) venueOtherEl.style.display = "none";
    } else {
      venueEl.value = "Others";
      if (venueOtherEl) { venueOtherEl.style.display = "block"; venueOtherEl.value = mtg.venue || ""; }
    }
  }

  // Set up councilor/researcher fields then fill them
  _setupCouncilorResearcherFields(currentUser);
  setVal("#meeting-councilor", mtg.councilor);
  setVal("#meeting-researcher", mtg.researcher);

  // Populate time/duration options for the meeting's date then restore values
  populateDurationOptions();
  populateTimeOptions(mtg.date);
  recalcDurationOptionsBasedOnStart(mtg.date);
  setVal("#meeting-time", mtg.timeStart);
  setVal("#meeting-duration", String(mtg.durationHours || SLOT_DURATION_HOURS));
  updateEndTimePreview();

  // Date min
  const dateInput = $("#meeting-date");
  if (dateInput) {
    dateInput.min = getTodayISOManila();
    dateInput.onchange = () => {
      const d = dateInput.value;
      populateTimeOptions(d);
      recalcDurationOptionsBasedOnStart(d);
      updateEndTimePreview();
    };
  }

  const backdrop = $("#meeting-modal");
  if (backdrop) backdrop.classList.add("modal-open");
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

  // ── EDIT PATH: update existing meeting instead of creating a new one ──────
  if (_editingMeetingId) {
    const editId = _editingMeetingId;
    _editingMeetingId = null;
    const existing = meetings.find(m => m.id === editId);
    if (!existing) { showToast("Meeting not found. Please refresh.", "error"); return; }

    // Guard: still within 24h and still Pending
    const createdAt = existing.createdAt ? new Date(existing.createdAt) : null;
    const within24h = createdAt && (getManilaNow() - createdAt) < 24 * 60 * 60 * 1000;
    if (!within24h || existing.status !== "Pending") {
      showToast("This meeting can no longer be edited.", "warning");
      return;
    }

    // Apply changes in-place
    existing.eventName    = d.eventName;
    existing.committee    = d.committee;
    existing.venue        = d.venue;
    existing.councilor    = d.councilor;
    existing.researcher   = d.researcher;
    existing.stakeholders = d.stakeholders;
    existing.notes        = d.notes;
    existing.date         = d.date;
    existing.timeStart    = d.timeStart;
    existing.durationHours = d.durationHours;
    existing.type         = d.type;
    existing.editedAt     = new Date().toISOString();
    // Reset createdAt to the edit time so the 24-hour cancel/edit countdown
    // restarts from when the user last edited (not original submission time).
    existing.createdAt    = existing.editedAt;

    if (window.api && window.api.updateMeeting) {
      window.api.updateMeeting(editId, existing).then(() => {}).catch(err => {
        console.error("updateMeeting failed:", err);
        showToast("Failed to save changes. Please try again.", "error");
      });
    } else {
      persistMeetings();
    }

    // Notify admins of the edit
    users.filter(u => u.role === ROLES.ADMIN).forEach(admin => {
      addNotification(
        admin.id || admin.username,
        `<strong>${h(currentUser.name)}</strong> edited their meeting request <strong>"${h(d.eventName)}"</strong> (within 24h window). Please review the updated details.`,
        "info",
        "meeting-logs"
      );
      updateNotificationBadge(admin.id || admin.username);
    });

    showToast("Meeting updated successfully.", "success");
    closeMeetingModal();
    renderMyMeetingsTable(currentUser);
    renderAdminMeetingsTable();
    renderCalendar();
    updateStatistics();
    return;
  }

  // ── CREATE PATH (original logic) ──────────────────────────────────────────
  const meeting = {
    id: crypto.randomUUID(),
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
    window.api.addMeeting(meeting).then(() => {}).catch(err => {
      console.error("addMeeting failed:", err);
      showToast("Failed to save meeting. Please try again.", "error");
    });
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
        `New meeting request from <strong>${h(currentUser.name)}</strong>: <strong>"${h(d.eventName)}"</strong> on ${formatDateDisplay(d.date)} at ${formatTimeRange(d.timeStart, d.durationHours)}. Review and take action.`,
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
          `The Admin has scheduled a meeting on your behalf: <strong>"${h(d.eventName)}"</strong> on ${dateStr} at ${timeStr}. Venue: ${h(d.venue)}. Status: <strong>Approved</strong>.`,
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
          `The Admin has scheduled a meeting on your behalf: <strong>"${h(d.eventName)}"</strong> on ${dateStr} at ${timeStr}. Venue: ${h(d.venue)}. Status: <strong>Approved</strong>.`,
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
  if (!stakeholders) {
    msg.textContent = "Stakeholders / External Participants is required.";
    showToast("Please fill in the Stakeholders field.", "error");
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

  // All validation passed — preserve editing ID before closeMeetingModal() clears it,
  // then pass it into the policy modal payload so the edit path works correctly.
  msg.textContent = "";
  const _editIdSnapshot = _editingMeetingId;
  closeMeetingModal();
  _editingMeetingId = _editIdSnapshot; // restore after closeMeetingModal() nulled it
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
    const hr = getManilaNow().getHours();
    greetEl.textContent = hr < 12 ? "Good morning," : hr < 17 ? "Good afternoon," : "Good evening,";
  }
  if (dateEl) {
    dateEl.textContent = getManilaNow().toLocaleDateString("en-PH", { weekday:"long", year:"numeric", month:"long", day:"numeric" });
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
  const activeUsers = users.filter(u => u.role !== ROLES.ADMIN && !u.deleted && !u._deleted).length;
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

  // User page — pulse the pending card based on that user's own pending meetings
  const userPendingCard = $("#user-stat-pending-card");
  if (userPendingCard) {
    const cu2 = getCurrentUser();
    let userPending = 0;
    if (cu2) {
      userPending = meetings.filter(m => {
        if (m.status !== "Pending") return false;
        if (cu2.role === ROLES.COUNCILOR)  return m.councilor === cu2.name  || m.createdBy === cu2.username;
        if (cu2.role === ROLES.RESEARCHER) return m.researcher === cu2.name || m.createdBy === cu2.username;
        return m.createdBy === cu2.username;
      }).length;
    }
    if (userPending > 0) {
      userPendingCard.classList.add("dash-stat-card-has-alert");
    } else {
      userPendingCard.classList.remove("dash-stat-card-has-alert");
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
      hint.innerHTML = `<span style="color:#f59e0b">Max ${maxHours}h — limited by approved meeting: "${h(blockerName)}"</span>`;
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

  // Search inputs — separate for Special Accounts and Regular Users
  document.getElementById("search-special-users")?.addEventListener("input", e => {
    specialUsersSearch = e.target.value; renderUsersTable();
  });
  document.getElementById("search-regular-users")?.addEventListener("input", e => {
    regularUsersSearch = e.target.value; usersPage = 1; renderUsersTable();
  });
  document.getElementById("search-admin-meetings")?.addEventListener("input", e => {
    adminMeetingsSearch = e.target.value; adminMeetingsPage = 1; renderAdminMeetingsTable();
  });

  // Sort dropdowns
  document.getElementById("sort-special-users")?.addEventListener("change", e => {
    specialUsersSortDir = e.target.value; renderUsersTable();
  });
  document.getElementById("sort-regular-users")?.addEventListener("change", e => {
    regularUsersSortDir = e.target.value; usersPage = 1; renderUsersTable();
  });
  document.getElementById("sort-admin-meetings")?.addEventListener("change", e => {
    adminMeetingsSortDir = e.target.value; adminMeetingsPage = 1; renderAdminMeetingsTable();
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

  initCalendarDate();
  renderUsersTable();
  renderAdminMeetingsTable();
  updateStatistics();

  // ── Auto-Done: scan every 60s, flip Approved→Done once end time passes ──
  (function startAutoDoneInterval() {
    function runAutoDone() {
      if (!Array.isArray(meetings)) return;
      let changed = false;
      meetings.forEach(function(m) {
        if (m.status === "Approved" && hasMeetingEnded(m)) {
          m.status = "Done";
          changed = true;
          if (window.api && window.api.updateMeetingStatus) {
            window.api.updateMeetingStatus(m.id, "Done", m.adminNote || "").catch(function(){});
          } else if (typeof persistMeetings === "function") {
            persistMeetings();
          }
        }
      });
      if (changed) {
        renderAdminMeetingsTable();
        renderCalendar();
        updateStatistics();
      }
    }
    runAutoDone();
    setInterval(runAutoDone, 60 * 1000);
  })();

  initAdminAnnouncements();
  initSystemSettings();

  // Password strength meters
  initPwdStrength("user-password",    "user-pwd-strength",    "user-pwd-fill",    "user-pwd-label");
  initPwdStrength("special-password", "special-pwd-strength", "special-pwd-fill", "special-pwd-label");

  // Change-password modal: strength indicator + show/hide toggles
  initPwdStrength("password-new", "chpwd-strength", "chpwd-fill", "chpwd-label");
  (function () {
    function wireToggle(btnId, inputId, showId, hideId) {
      const btn  = document.getElementById(btnId);
      const inp  = document.getElementById(inputId);
      const show = document.getElementById(showId);
      const hide = document.getElementById(hideId);
      if (!btn || !inp) return;
      btn.addEventListener("click", function () {
        const isHidden = inp.type === "password";
        inp.type = isHidden ? "text" : "password";
        if (show) show.style.display = isHidden ? "none" : "";
        if (hide) hide.style.display = isHidden ? ""     : "none";
      });
    }
    wireToggle("pw-new-toggle",     "password-new",     "pw-new-eye-show",     "pw-new-eye-hide");
    wireToggle("pw-confirm-toggle", "password-confirm", "pw-confirm-eye-show", "pw-confirm-eye-hide");
  })();
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
  document.getElementById("sort-my-meetings")?.addEventListener("change", e => {
    myMeetingsSortDir = e.target.value; myMeetingsPage = 1; renderMyMeetingsTable(user);
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
  if (!list.length) { showToast("No meetings to export.", "info"); return; }
  const XLSX = window.XLSX;
  if (!XLSX) { showToast("Export library not loaded.", "error"); return; }

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
  ]);

  const wb = XLSX.utils.book_new();
  const ws = XLSX.utils.aoa_to_sheet([headers, ...rows]);

  // Column widths
  ws["!cols"] = [
    {wch:36},{wch:14},{wch:20},{wch:22},{wch:14},
    {wch:20},{wch:22},{wch:40},{wch:24},{wch:22},{wch:30}
  ];

  // Header row styling
  headers.forEach((_, ci) => {
    const cell = ws[XLSX.utils.encode_cell({r:0,c:ci})];
    if (!cell) return;
    cell.s = {
      font: { bold: true, color: { rgb: "FFFFFF" }, name: "Arial", sz: 11 },
      fill: { fgColor: { rgb: "1B4B8A" } },
      alignment: { horizontal: "center", vertical: "center", wrapText: true },
      border: {
        bottom: { style: "medium", color: { rgb: "F5A31A" } },
        top:    { style: "thin",   color: { rgb: "FFFFFF" } },
        left:   { style: "thin",   color: { rgb: "FFFFFF" } },
        right:  { style: "thin",   color: { rgb: "FFFFFF" } },
      }
    };
  });

  // Status color map
  const STATUS_BG = {
    "Approved":  "16A34A", "Done": "2563EB", "Pending": "F59E0B",
    "Rejected":  "DC2626", "Cancelled": "6B7280", "Cancellation Requested": "F97316"
  };

  rows.forEach((row, ri) => {
    const isEven = ri % 2 === 0;
    row.forEach((_, ci) => {
      const cell = ws[XLSX.utils.encode_cell({r:ri+1,c:ci})];
      if (!cell) return;
      const isStatus = ci === 4;
      const statusVal = row[4] || "";
      const bg = isStatus ? (STATUS_BG[statusVal] || "6B7280") : (isEven ? "F0F4FF" : "FFFFFF");
      cell.s = {
        font: {
          name: "Arial", sz: 10,
          bold: isStatus,
          color: { rgb: isStatus ? "FFFFFF" : "111827" }
        },
        fill: { fgColor: { rgb: bg } },
        alignment: { vertical: "center", wrapText: ci === 7 || ci === 10 },
        border: {
          bottom: { style: "thin", color: { rgb: "D1D5DB" } },
          right:  { style: "thin", color: { rgb: "D1D5DB" } },
        }
      };
    });
  });

  // Title row at top
  XLSX.utils.sheet_add_aoa(ws, [["SANGGUNIANG BAYAN NG POLANGUI — Meeting Records"]], {origin:"A1"});
  ws["A1"].s = {
    font: { bold: true, sz: 13, color: { rgb: "1B4B8A" }, name: "Arial" },
    alignment: { horizontal: "center" }
  };
  // Merge title across all columns
  ws["!merges"] = [{ s:{r:0,c:0}, e:{r:0,c:headers.length-1} }];
  // Re-insert headers at row 2 and data at row 3+
  const wsNew = XLSX.utils.aoa_to_sheet([["SANGGUNIANG BAYAN NG POLANGUI — Meeting Records"], headers, ...rows]);
  wsNew["!cols"] = ws["!cols"];
  wsNew["!merges"] = [{ s:{r:0,c:0}, e:{r:0,c:headers.length-1} }];

  // Style title
  const titleCell = wsNew["A1"];
  if (titleCell) titleCell.s = { font:{bold:true,sz:13,color:{rgb:"1B4B8A"},name:"Arial"}, fill:{fgColor:{rgb:"E8EFFE"}}, alignment:{horizontal:"center",vertical:"center"} };

  // Style headers (row 2)
  headers.forEach((_, ci) => {
    const cell = wsNew[XLSX.utils.encode_cell({r:1,c:ci})];
    if (!cell) return;
    cell.s = { font:{bold:true,color:{rgb:"FFFFFF"},name:"Arial",sz:10}, fill:{fgColor:{rgb:"1B4B8A"}}, alignment:{horizontal:"center",vertical:"center",wrapText:true}, border:{bottom:{style:"medium",color:{rgb:"F5A31A"}}} };
  });

  // Style data rows
  rows.forEach((row, ri) => {
    const isEven = ri % 2 === 0;
    row.forEach((_, ci) => {
      const cell = wsNew[XLSX.utils.encode_cell({r:ri+2,c:ci})];
      if (!cell) return;
      const isStatus = ci === 4;
      const statusVal = row[4] || "";
      const bg = isStatus ? (STATUS_BG[statusVal] || "6B7280") : (isEven ? "F0F4FF" : "FFFFFF");
      cell.s = { font:{name:"Arial",sz:10,bold:isStatus,color:{rgb:isStatus?"FFFFFF":"111827"}}, fill:{fgColor:{rgb:bg}}, alignment:{vertical:"center",wrapText:ci===7||ci===10}, border:{bottom:{style:"thin",color:{rgb:"D1D5DB"}},right:{style:"thin",color:{rgb:"D1D5DB"}}} };
    });
  });

  wsNew["!rows"] = [{hpt:22},{hpt:18}];

  XLSX.utils.book_append_sheet(wb, wsNew, "Meetings");

  const now = new Date();
  const fname = `SBP_Meetings_${now.getFullYear()}${String(now.getMonth()+1).padStart(2,"0")}${String(now.getDate()).padStart(2,"0")}.xlsx`;
  XLSX.writeFile(wb, fname);
  showToast(`Exported ${list.length} meeting${list.length !== 1 ? "s" : ""} to Excel.`, "success");
}

// ---------------------------------------------------------------------------
// FEATURE: Print Meetings (PDF-formatted forms)
// ---------------------------------------------------------------------------

function printMeetingsTable() {
  const list = getFilteredMeetingsList();
  if (!list.length) { showToast("No records to print.", "info"); return; }

  const { jsPDF } = window.jspdf || {};
  if (!jsPDF) { showToast("PDF library not loaded.", "error"); return; }

  try {
    // ── Reuse the same letterhead images from generateMeetingPdf ─────────────
    const HEADER_B64 = _SBP_HEADER_B64;
    const FOOTER_B64 = _SBP_FOOTER_B64;

    // ── Page setup (Legal landscape for the table: 355.6 x 215.9 mm) ──────────
    const PW = 355.6, PH = 215.9;  // Legal landscape mm
    const ML = 14, MR = 14;
    const CW = PW - ML - MR;
    const doc = new jsPDF({ unit: "mm", format: [PW, PH], orientation: "landscape" });

    const HEADER_H_MM = 24;
    const FOOTER_H_MM = 13;

    const printDate = new Date().toLocaleDateString("en-PH", { year:"numeric", month:"long", day:"numeric" });

    // ── Column definitions — widths must sum to CW (327.6) ───────────────────
    const COLS = [
      { label: "EVENT / TITLE",  w: 68 },
      { label: "DATE",           w: 28 },
      { label: "TIME",           w: 34 },
      { label: "TYPE",           w: 36 },
      { label: "STATUS",         w: 26 },
      { label: "REQUESTED BY",   w: 32 },
      { label: "COMMITTEE",      w: 68 },
      { label: "VENUE",          w: 35.6 },
    ];
    const totalW = COLS.reduce((s, c) => s + c.w, 0);
    const SCALE = CW / totalW;

    const STATUS_COLORS = {
      "Approved":  [22,163,74],  "Done": [37,99,235],
      "Pending":   [217,119,6],  "Rejected": [220,38,38],
      "Cancelled": [107,114,128], "Cancellation Requested": [249,115,22],
    };

    const ROW_H    = 8;
    const HEADER_ROW_H = 9;

    let pageNum = 1;

    function drawPage(rows, isFirst) {
      if (!isFirst) doc.addPage([PW, PH], "landscape");

      // ── Letterhead header ─────────────────────────────────────────────────
      if (HEADER_B64) {
        doc.addImage("data:image/jpeg;base64," + HEADER_B64, "JPEG", 0, 0, PW, HEADER_H_MM);
      } else {
        // Fallback: plain header bar
        doc.setFillColor(27, 75, 138);
        doc.rect(0, 0, PW, HEADER_H_MM, "F");
        doc.setTextColor(255,255,255);
        doc.setFontSize(11);
        doc.setFont("helvetica", "bold");
        doc.text("SANGGUNIANG BAYAN NG POLANGUI", PW / 2, 10, { align: "center" });
        doc.setFontSize(8);
        doc.setFont("helvetica", "normal");
        doc.text("OFFICE OF THE SANGGUNIANG BAYAN", PW / 2, 16, { align: "center" });
      }

      // ── Letterhead footer ─────────────────────────────────────────────────
      if (FOOTER_B64) {
        doc.addImage("data:image/jpeg;base64," + FOOTER_B64, "JPEG", 0, PH - FOOTER_H_MM, PW, FOOTER_H_MM);
      } else {
        doc.setFillColor(200, 210, 230);
        doc.rect(0, PH - FOOTER_H_MM, PW, FOOTER_H_MM, "F");
      }

      // ── Report title ──────────────────────────────────────────────────────
      let y = HEADER_H_MM + 5;
      doc.setFontSize(11);
      doc.setFont("helvetica", "bold");
      doc.setTextColor(27, 75, 138);
      doc.text("MEETING RECORDS REPORT", ML, y);
      doc.setFontSize(7.5);
      doc.setFont("helvetica", "normal");
      doc.setTextColor(100, 116, 139);
      doc.text(`Printed: ${printDate}   ·   Total records: ${list.length}   ·   Page ${pageNum}`, PW - MR, y, { align: "right" });
      pageNum++;
      y += 3;

      // Gold divider
      doc.setDrawColor(245, 163, 26);
      doc.setLineWidth(0.6);
      doc.line(ML, y, PW - MR, y);
      y += 4;

      // ── Table header row ──────────────────────────────────────────────────
      doc.setFillColor(27, 75, 138);
      doc.rect(ML, y, CW, HEADER_ROW_H, "F");
      let x = ML;
      COLS.forEach(col => {
        const cw = col.w * SCALE;
        doc.setFontSize(7);
        doc.setFont("helvetica", "bold");
        doc.setTextColor(255, 255, 255);
        doc.text(col.label, x + cw / 2, y + 5.8, { align: "center" });
        x += cw;
      });
      y += HEADER_ROW_H;

      // Gold underline under header
      doc.setDrawColor(245, 163, 26);
      doc.setLineWidth(0.5);
      doc.line(ML, y, ML + CW, y);

      // ── Table data rows ───────────────────────────────────────────────────
      rows.forEach((m, i) => {
        const isEven = i % 2 === 0;
        doc.setFillColor(isEven ? 245 : 255, isEven ? 248 : 255, isEven ? 255 : 255);
        doc.rect(ML, y, CW, ROW_H, "F");

        // Row border
        doc.setDrawColor(220, 228, 240);
        doc.setLineWidth(0.15);
        doc.line(ML, y + ROW_H, ML + CW, y + ROW_H);

        const statusVal = m.status || "";
        const sc = STATUS_COLORS[statusVal] || [107,114,128];
        const cells = [
          m.eventName || "—",
          formatDateDisplay(m.date),
          formatTimeRange(m.timeStart, m.durationHours || SLOT_DURATION_HOURS),
          m.type || m.meetingType || "—",
          statusVal,
          m.createdBy || "—",
          m.committee || "—",
          m.venue || "—",
        ];

        let cx = ML;
        cells.forEach((val, ci) => {
          const cw = COLS[ci].w * SCALE;
          const isStatus = ci === 4;

          if (isStatus) {
            // Colored status pill
            doc.setFillColor(...sc);
            const pw2 = Math.min(cw - 4, 22), ph2 = 5;
            const px = cx + (cw - pw2) / 2;
            doc.roundedRect(px, y + 1.5, pw2, ph2, 1, 1, "F");
            doc.setTextColor(255,255,255);
            doc.setFontSize(6);
            doc.setFont("helvetica", "bold");
            const statusShort = val === "Cancellation Requested" ? "Cancel Req." : val;
            doc.text(statusShort, cx + cw / 2, y + 5.2, { align: "center" });
          } else {
            doc.setTextColor(17, 24, 39);
            doc.setFontSize(7);
            doc.setFont("helvetica", "normal");
            const clipped = doc.splitTextToSize(String(val), cw - 3);
            doc.text(clipped[0] || "", cx + 2, y + 5.2);
          }

          // Vertical separator
          doc.setDrawColor(220, 228, 240);
          doc.setLineWidth(0.15);
          doc.line(cx + cw, y, cx + cw, y + ROW_H);

          cx += cw;
        });

        y += ROW_H;
      });

      // Outer border
      doc.setDrawColor(180, 195, 220);
      doc.setLineWidth(0.3);
      doc.rect(ML, HEADER_H_MM + 20, CW, y - (HEADER_H_MM + 20));
    }

    // ── Pagination ────────────────────────────────────────────────────────────
    const AVAILABLE_H = PH - HEADER_H_MM - FOOTER_H_MM - 28; // usable body height
    const ROWS_PER_PAGE = Math.floor(AVAILABLE_H / ROW_H);
    const pages = [];
    for (let i = 0; i < list.length; i += ROWS_PER_PAGE) {
      pages.push(list.slice(i, i + ROWS_PER_PAGE));
    }
    pages.forEach((pageRows, pi) => drawPage(pageRows, pi === 0));

    // ── Auto-print ────────────────────────────────────────────────────────────
    doc.autoPrint();
    window.open(doc.output("bloburl"), "_blank");
    showToast(`Opening print preview for ${list.length} records…`, "success");

  } catch(err) {
    console.error("Print error:", err);
    showToast("Failed to generate print preview.", "error");
  }
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
    const XLSX = window.XLSX;
    if (!XLSX) { showToast("Export library not loaded.", "error"); return; }
    const headers = ["Event Name","Date","Time","Type","Status","Requested By","Venue","Committee","Councilor","Researcher","Notes"];
    const rows = safeMeetings.map(m => [
      m.eventName || "", formatDateDisplay(m.date),
      formatTimeRange(m.timeStart, m.durationHours || SLOT_DURATION_HOURS),
      m.type || m.meetingType || "", m.status || "", m.createdBy || "",
      m.venue || "", m.committee || "", m.councilor || "", m.researcher || "", m.notes || "",
    ]);
    const ws = XLSX.utils.aoa_to_sheet([["SANGGUNIANG BAYAN NG POLANGUI — All Meeting Records"], headers, ...rows]);
    ws["!cols"] = [{wch:36},{wch:14},{wch:20},{wch:22},{wch:14},{wch:20},{wch:22},{wch:40},{wch:24},{wch:22},{wch:30}];
    ws["!merges"] = [{ s:{r:0,c:0}, e:{r:0,c:headers.length-1} }];
    const STATUS_BG2 = {"Approved":"16A34A","Done":"2563EB","Pending":"F59E0B","Rejected":"DC2626","Cancelled":"6B7280","Cancellation Requested":"F97316"};
    if (ws["A1"]) ws["A1"].s = {font:{bold:true,sz:13,color:{rgb:"1B4B8A"},name:"Arial"},fill:{fgColor:{rgb:"E8EFFE"}},alignment:{horizontal:"center",vertical:"center"}};
    headers.forEach((_,ci)=>{ const c=ws[XLSX.utils.encode_cell({r:1,c:ci})]; if(c) c.s={font:{bold:true,color:{rgb:"FFFFFF"},name:"Arial",sz:10},fill:{fgColor:{rgb:"1B4B8A"}},alignment:{horizontal:"center",vertical:"center",wrapText:true},border:{bottom:{style:"medium",color:{rgb:"F5A31A"}}}}; });
    rows.forEach((row,ri)=>{ const even=ri%2===0; row.forEach((_,ci)=>{ const c=ws[XLSX.utils.encode_cell({r:ri+2,c:ci})]; if(!c) return; const isS=ci===4,sv=row[4]||"",bg=isS?(STATUS_BG2[sv]||"6B7280"):(even?"F0F4FF":"FFFFFF"); c.s={font:{name:"Arial",sz:10,bold:isS,color:{rgb:isS?"FFFFFF":"111827"}},fill:{fgColor:{rgb:bg}},alignment:{vertical:"center",wrapText:ci===7||ci===10},border:{bottom:{style:"thin",color:{rgb:"D1D5DB"}},right:{style:"thin",color:{rgb:"D1D5DB"}}}}; }); });
    const wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, ws, "All Meetings");
    XLSX.writeFile(wb, `SBP_AllMeetings_${new Date().toISOString().slice(0,10)}.xlsx`);
    showToast(`Exported ${safeMeetings.length} meetings.`, "success");
  });

  // Export users list
  document.getElementById("sysdata-export-users-btn")?.addEventListener("click", () => {
    const safeUsers = (typeof users !== "undefined" && Array.isArray(users)) ? users.filter(u => u.role !== ROLES.ADMIN) : [];
    const XLSX = window.XLSX;
    if (!XLSX) { showToast("Export library not loaded.", "error"); return; }
    const headers = ["Username","Full Name","Role"];
    const rows = safeUsers.map(u => [u.username || "", u.name || "", u.role || ""]);
    const ws = XLSX.utils.aoa_to_sheet([["SANGGUNIANG BAYAN NG POLANGUI — Users List"], headers, ...rows]);
    ws["!cols"] = [{wch:22},{wch:32},{wch:20}];
    ws["!merges"] = [{ s:{r:0,c:0}, e:{r:0,c:2} }];
    if (ws["A1"]) ws["A1"].s = {font:{bold:true,sz:13,color:{rgb:"1B4B8A"},name:"Arial"},fill:{fgColor:{rgb:"E8EFFE"}},alignment:{horizontal:"center",vertical:"center"}};
    headers.forEach((_,ci)=>{ const c=ws[XLSX.utils.encode_cell({r:1,c:ci})]; if(c) c.s={font:{bold:true,color:{rgb:"FFFFFF"},name:"Arial",sz:10},fill:{fgColor:{rgb:"1B4B8A"}},alignment:{horizontal:"center",vertical:"center"},border:{bottom:{style:"medium",color:{rgb:"F5A31A"}}}}; });
    rows.forEach((row,ri)=>{ const even=ri%2===0; row.forEach((_,ci)=>{ const c=ws[XLSX.utils.encode_cell({r:ri+2,c:ci})]; if(c) c.s={font:{name:"Arial",sz:10,color:{rgb:"111827"}},fill:{fgColor:{rgb:even?"F0F4FF":"FFFFFF"}},alignment:{vertical:"center"},border:{bottom:{style:"thin",color:{rgb:"D1D5DB"}},right:{style:"thin",color:{rgb:"D1D5DB"}}}}; }); });
    const wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, ws, "Users");
    XLSX.writeFile(wb, `SBP_Users_${new Date().toISOString().slice(0,10)}.xlsx`);
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
              m.status = "Done"; m.adminNote = "Auto-marked Done by admin.";
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
// Committee Combobox (shared — works on both admin & user pages)
// ---------------------------------------------------------------------------

const SBP_COMMITTEES = [
  "COMMITTEE ON LAWS, JUSTICE, OVERSIGHT, GOOD GOVERNANCE, AND ACCOUNTABILITY",
  "COMMITTEE ON EDUCATION",
  "COMMITTEE ON GENDER AND DEVELOPMENT",
  "COMMITTEE ON HUMAN RIGHTS",
  "COMMITTEE ON WOMEN",
  "COMMITTEE ON TRADE, COMMERCE AND INDUSTRY",
  "COMMITTEE ON ECONOMIC ENTERPRISE AND SLAUGHTERHOUSE",
  "COMMITTEE ON WAYS AND MEANS",
  "COMMITTEE ON COMMUNICATION",
  "COMMITTEE ON GENERAL SERVICES",
  "COMMITTEE ON ENERGY",
  "COMMITTEE ON LAND USE",
  "COMMITTEE ON PUBLIC ETHICS",
  "COMMITTEE ON TOURISM",
  "COMMITTEE ON SCIENCE AND TECHNOLOGY, SISTERHOOD",
  "COMMITTEE ON RULES",
  "COMMITTEE ON HOUSING",
  "COMMITTEE ON CULTURE AND THE ARTS",
  "COMMITTEE ON AGRICULTURE",
  "COMMITTEE ON FINANCE, BUDGET AND APPROPRIATION",
  "COMMITTEE ON INFRASTRUCTURE AND PUBLIC WORKS",
  "COMMITTEE ON ENVIRONMENTAL PROTECTION AND NATURAL RESOURCES",
  "COMMITTEE ON DISASTER RISK REDUCTION AND MANAGEMENT/CLIMATE CHANGE",
  "COMMITTEE ON FAMILY",
  "COMMITTEE ON HEALTH, SANITATION AND NUTRITION",
  "COMMITTEE ON SENIOR CITIZEN",
  "COMMITTEE ON SOLO PARENTS",
  "COMMITTEE ON PERSONS WITH DISABILITY",
  "COMMITTEE ON MARKET",
  "COMMITTEE ON PEACE AND ORDER, AND PUBLIC SAFETY",
  "COMMITTEE ON TRANSPORTATION",
  "COMMITTEE ON LABOR AND EMPLOYMENT, MIGRANT WORKERS (OFW)",
  "COMMITTEE ON GAMES AND AMUSEMENT",
  "COMMITTEE ON SOCIAL SERVICES",
  "COMMITTEE ON ACCREDITATION",
  "COMMITTEE ON COOPERATIVE",
  "COMMITTEE ON BARANGAY AFFAIRS",
  "COMMITTEE ON YOUTH AND SPORTS DEVELOPMENT",
];

// ---------------------------------------------------------------------------
// Committee combobox — desktop: custom combobox | mobile: native <select>
// ---------------------------------------------------------------------------

/**
 * _buildCommitteeSelectOptions()
 * Returns <option> HTML for all SBP_COMMITTEES entries.
 */
function _isMobile() {
  // Prefer coarse pointer detection (real phones) because `innerWidth` can be
  // affected by zoom/viewport quirks on real devices.
  try {
    if (window.matchMedia && window.matchMedia("(pointer:coarse)").matches) return true;
  } catch (e) {}
  // Also treat touch-capable devices as mobile (some browsers report `fine`
  // pointer even when it's still touch).
  try {
    if (navigator && navigator.maxTouchPoints && navigator.maxTouchPoints > 0) return true;
  } catch (e) {}
  try {
    if (window.matchMedia && window.matchMedia("(hover: none)").matches) return true;
  } catch (e) {}
  return window.innerWidth <= 768;
}

/**
 * _swapCommitteeInputToSelect(inputEl, arrowEl, inlineListEl)
 *
 * Replaces the committee <input> (and its .committee-combo-wrap, arrow, and
 * inline <ul>) with a native <select> styled identically to other dropdowns.
 * The id is preserved so all existing value-reading code stays untouched.
 */
function _swapCommitteeInputToSelect(inputEl, arrowEl, inlineListEl) {
  const wrap = inputEl.closest(".committee-combo-wrap") || inputEl.parentElement;

  const sel = document.createElement("select");
  sel.id        = inputEl.id;
  sel.name      = inputEl.name || inputEl.id;
  sel.className = "field";
  sel.required  = inputEl.required;

  const placeholder = document.createElement("option");
  placeholder.value    = "";
  placeholder.disabled = true;
  placeholder.selected = true;
  placeholder.textContent = "Select a committee…";
  sel.appendChild(placeholder);

  SBP_COMMITTEES.forEach(c => {
    const opt = document.createElement("option");
    opt.value       = c;
    opt.textContent = c;
    sel.appendChild(opt);
  });

  if (inputEl.value) sel.value = inputEl.value;

  if (wrap && wrap.classList.contains("committee-combo-wrap")) {
    wrap.parentNode.replaceChild(sel, wrap);
  } else {
    inputEl.parentNode.replaceChild(sel, inputEl);
    if (arrowEl && arrowEl.parentNode) arrowEl.remove();
    if (inlineListEl && inlineListEl.parentNode) inlineListEl.remove();
  }
}

/**
 * initCommitteeCombobox()
 * Desktop → custom combobox with filtering. Mobile → native <select>.
 */
function initCommitteeCombobox() {
  const input    = document.getElementById("meeting-committee");
  const dropdown = document.getElementById("committee-dropdown");
  const arrow    = document.querySelector("#meeting-modal .committee-combo-arrow");
  if (!input) return;

  if (_isMobile()) {
    // Already swapped to a native select (avoid repeated DOM replacements).
    if (String(input.tagName || "").toLowerCase() === "select") return;
    _swapCommitteeInputToSelect(input, arrow || null, dropdown || null);
  } else {
    _makeCommitteeCombo(input, dropdown || null, arrow || null,
                        document.getElementById("meeting-modal"));
  }
}

/**
 * initDrawerCommitteeCombo(drawerEl)
 * Desktop → custom combobox. Mobile → native <select>.
 * Called by openBookingDrawer after the drawer is in the DOM.
 */
function initDrawerCommitteeCombo(drawerEl) {
  const input = drawerEl && drawerEl.querySelector("#db-committee");
  if (!input) return;

  // Booking drawer: always prefer native <select> to avoid the heavier custom
  // combobox (portal + frequent innerHTML updates), which is what can freeze
  // real low-end phones.
  const forceNative = !!(drawerEl && drawerEl.id === "drawer-booking");
  if (forceNative || _isMobile()) {
    // Already swapped to a native select (avoid repeated DOM replacements).
    if (String(input.tagName || "").toLowerCase() === "select") return;
    _swapCommitteeInputToSelect(input, null, null);
  } else {
    _makeCommitteeCombo(input, null, null, drawerEl);
  }
}

// ---------------------------------------------------------------------------
// _makeCommitteeCombo — desktop only (unchanged)
// ---------------------------------------------------------------------------
function _makeCommitteeCombo(inputEl, staticDropdownEl, arrowEl, cleanupTriggerEl) {
  if (!inputEl) return;
  // Guard: only initialize once per input element to prevent stacking listeners
  if (inputEl.dataset.comboInit === "1") return;
  inputEl.dataset.comboInit = "1";

  // If this input hasn't been wrapped yet, wrap it now so the arrow sits inside
  let wrap = inputEl.closest(".committee-combo-wrap");
  if (!wrap) {
    wrap = document.createElement("div");
    wrap.className = "committee-combo-wrap";
    inputEl.parentNode.insertBefore(wrap, inputEl);
    wrap.appendChild(inputEl);
    inputEl.classList.add("committee-combo-input");
  }

  // Create arrow button if not already present
  if (!arrowEl) {
    arrowEl = wrap.querySelector(".committee-combo-arrow");
    if (!arrowEl) {
      arrowEl = document.createElement("button");
      arrowEl.type = "button";
      arrowEl.className = "committee-combo-arrow";
      arrowEl.tabIndex = -1;
      arrowEl.setAttribute("aria-label", "Show committees");
      arrowEl.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="6 9 12 15 18 9"/></svg>`;
      wrap.appendChild(arrowEl);
    }
  }

  // Create static inline list if none was passed (we still need one for desktop)
  let inlineList = staticDropdownEl;
  if (!inlineList) {
    inlineList = document.createElement("ul");
    inlineList.className = "committee-dropdown";
    inlineList.setAttribute("role", "listbox");
    inlineList.style.display = "none";
    wrap.appendChild(inlineList);
  }

  let activeIndex = -1;
  let _skipClose  = false;
  let _portal     = null;   // fixed-position portal used on mobile

  // ── Render ────────────────────────────────────────────────────────────────

  function renderList(filter) {
    const q = (filter || "").trim().toLowerCase();
    const matches = q
      ? SBP_COMMITTEES.filter(c => c.toLowerCase().includes(q))
      : SBP_COMMITTEES;
    const target = _portal || inlineList;
    if (!matches.length) {
      target.innerHTML = `<li class="committee-dropdown-empty">No matching committee found</li>`;
    } else {
      target.innerHTML = matches.map((c, i) => {
        const hi = q
          ? c.replace(new RegExp(`(${q.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")})`, "gi"),
              `<mark class="committee-match">$1</mark>`)
          : c;
        return `<li class="committee-dropdown-item" role="option" data-value="${c}" data-idx="${i}">${hi}</li>`;
      }).join("");
    }
    activeIndex = -1;
    syncActive();
  }

  function syncActive() {
    const target = _portal || inlineList;
    const items = target.querySelectorAll(".committee-dropdown-item");
    items.forEach((el, i) => el.classList.toggle("committee-dropdown-active", i === activeIndex));
    if (activeIndex >= 0 && items[activeIndex]) {
      items[activeIndex].scrollIntoView({ block: "nearest" });
    }
  }

  // ── Portal (mobile) ────────────────────────────────────────────────────────
  // Always portal on mobile so overflow:auto parents can't clip the list.

  function _positionPortal() {
    if (!_portal) return;
    const rect       = inputEl.getBoundingClientRect();
    const spaceBelow = window.innerHeight - rect.bottom;
    const spaceAbove = rect.top;
    const maxH       = 240;
    const showAbove  = spaceBelow < maxH + 8 && spaceAbove > spaceBelow;

    _portal.style.left  = rect.left + "px";
    _portal.style.width = rect.width + "px";

    if (showAbove) {
      _portal.style.top    = "";
      _portal.style.bottom = (window.innerHeight - rect.top + 4) + "px";
    } else {
      _portal.style.top    = (rect.bottom + 4) + "px";
      _portal.style.bottom = "";
    }
  }

  function _ensurePortal() {
    if (_portal) return;
    _portal = document.createElement("ul");
    _portal.className = "committee-dropdown committee-dropdown-portal";
    _portal.setAttribute("role", "listbox");
    _portal.style.cssText = [
      "position:fixed",
      "display:none",
      "margin:0",
      "z-index:99999",
      "max-height:240px",
      "overflow-y:auto",
      "-webkit-overflow-scrolling:touch",
      "overscroll-behavior:contain"
    ].join(";");
    document.body.appendChild(_portal);

    _portal.addEventListener("touchstart", e => {
      const item = e.target.closest(".committee-dropdown-item");
      if (item) { _skipClose = true; selectValue(item.dataset.value); }
    }, { passive: true });

    _portal.addEventListener("mousedown", e => {
      const item = e.target.closest(".committee-dropdown-item");
      if (item) { e.preventDefault(); selectValue(item.dataset.value); }
    });
  }

  function _destroyPortal() {
    if (_portal) { _portal.remove(); _portal = null; }
  }

  // ── Open / Close ──────────────────────────────────────────────────────────

  function isOpen() {
    if (_portal && _portal.style.display !== "none") return true;
    return inlineList.style.display !== "none";
  }

  function openDropdown() {
    const mobile = window.innerWidth <= 768;
    if (mobile) {
      _ensurePortal();
      renderList(inputEl.value);
      _portal.style.display = "block";
      _positionPortal();
      inlineList.style.display = "none";
    } else {
      _destroyPortal();
      renderList(inputEl.value);
      inlineList.style.display = "block";
    }
    arrowEl.classList.add("open");
  }

  function closeDropdown() {
    if (_portal) _portal.style.display = "none";
    inlineList.style.display = "none";
    arrowEl.classList.remove("open");
    activeIndex = -1;
  }

  function selectValue(val) {
    inputEl.value = val;
    inputEl.dispatchEvent(new Event("input", { bubbles: true }));
    closeDropdown();
    inputEl.focus();
  }

  // ── Events ────────────────────────────────────────────────────────────────

  inputEl.addEventListener("focus", () => { if (!isOpen()) openDropdown(); });
  inputEl.addEventListener("input", () => { if (!isOpen()) openDropdown(); else renderList(inputEl.value); });

  inputEl.addEventListener("keydown", e => {
    const target = _portal || inlineList;
    const items  = target.querySelectorAll(".committee-dropdown-item");
    if (!isOpen()) { openDropdown(); return; }
    if (e.key === "ArrowDown") {
      e.preventDefault();
      activeIndex = Math.min(activeIndex + 1, items.length - 1);
      syncActive();
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      activeIndex = Math.max(activeIndex - 1, 0);
      syncActive();
    } else if (e.key === "Enter" && activeIndex >= 0 && items[activeIndex]) {
      e.preventDefault();
      selectValue(items[activeIndex].dataset.value);
    } else if (e.key === "Escape") {
      closeDropdown();
    }
  });

  // Arrow button — mouse + touch
  function _toggleViaArrow(e) {
    // Prevent default only when available (older mobile browsers can emit
    // synthetic events that should not be blocked aggressively).
    if (e && typeof e.preventDefault === "function") e.preventDefault();
    if (isOpen()) closeDropdown();
    else { inputEl.focus(); openDropdown(); }
  }
  arrowEl.addEventListener("mousedown", _toggleViaArrow);
  arrowEl.addEventListener("touchend", _toggleViaArrow, { passive: true });

  // Desktop inline list click
  inlineList.addEventListener("mousedown", e => {
    const item = e.target.closest(".committee-dropdown-item");
    if (item) { e.preventDefault(); selectValue(item.dataset.value); }
  });

  // Outside close — use AbortController so listeners are properly removed on cleanup
  const _ac = new AbortController();
  const _sig = { signal: _ac.signal };

  document.addEventListener("touchend", e => {
    if (_skipClose) { _skipClose = false; return; }
    if (!wrap.contains(e.target) && (!_portal || !_portal.contains(e.target))) closeDropdown();
  }, { passive: true, ..._sig });

  document.addEventListener("click", e => {
    if (!wrap.contains(e.target) && (!_portal || !_portal.contains(e.target))) closeDropdown();
  }, _sig);

  // Reposition on resize / scroll
  window.addEventListener("resize",  () => { if (isOpen()) _positionPortal(); }, { passive: true, ..._sig });
  document.addEventListener("scroll", () => { if (isOpen() && _portal) _positionPortal(); }, { passive: true, capture: true, ..._sig });

  // Cleanup when container closes
  if (cleanupTriggerEl) {
    new MutationObserver(() => {
      const gone = !document.body.contains(cleanupTriggerEl) ||
                   cleanupTriggerEl.classList.contains("drawer-open") === false;
      if (gone) { closeDropdown(); _destroyPortal(); _ac.abort(); }
    }).observe(cleanupTriggerEl.parentNode || document.body, { childList: true, subtree: false, attributes: true, attributeFilter: ["class"] });
  }
}


// ---------------------------------------------------------------------------
// System Maintenance (admin-only)
// ---------------------------------------------------------------------------

function initSystemMaintenance() {
  const purgeBtn     = document.getElementById("sysdata-purge-junk-btn");
  const purgeApprovedBtn = document.getElementById("sysdata-purge-approved-btn");
  const clearNotifsBtn = document.getElementById("sysdata-clear-notifs-btn");

  if (purgeBtn) {
    purgeBtn.addEventListener("click", async () => {
      const safeMeetings = (typeof meetings !== "undefined" && Array.isArray(meetings)) ? meetings : [];
      const junk = safeMeetings.filter(m => m.status === "Rejected" || m.status === "Cancelled");
      if (!junk.length) { showToast("No rejected or cancelled records found.", "info"); return; }

      openConfirmModal(
        "Purge Rejected & Cancelled Records",
        `This will <strong>permanently delete ${junk.length} record${junk.length !== 1 ? "s" : ""}</strong> (Rejected &amp; Cancelled) from Firebase.<br><br>
        <span style="color:var(--color-success);font-weight:600">✓ Approved and Pending meetings are NOT affected.</span><br>
        This action cannot be undone.`,
        async () => {
          let count = 0, errors = 0;
          for (const m of junk) {
            try {
              if (window.api && window.api.deleteMeeting) {
                await window.api.deleteMeeting(m.id);
              } else {
                const idx = meetings.indexOf(m); if (idx > -1) meetings.splice(idx, 1);
              }
              count++;
            } catch (err) {
              console.error("Purge error for", m.id, err);
              errors++;
            }
          }
          if (typeof fetchAllData === "function") await fetchAllData();
          if (typeof renderAdminMeetingsTable === "function") renderAdminMeetingsTable();
          if (typeof renderCalendar === "function") renderCalendar();
          if (typeof updateStatistics === "function") updateStatistics();
          if (typeof renderDashboardCharts === "function") renderDashboardCharts();

          if (errors > 0) {
            showToast(`Purged ${count} record${count !== 1 ? "s" : ""}. ${errors} failed — check console.`, "warning");
          } else {
            showToast(`Purged ${count} record${count !== 1 ? "s" : ""} successfully.`, "success");
          }
        }
      );
    });
  }

  if (purgeApprovedBtn) {
    purgeApprovedBtn.addEventListener("click", async () => {
      const safeMeetings = (typeof meetings !== "undefined" && Array.isArray(meetings)) ? meetings : [];
      const targets = safeMeetings.filter(m => m.status === "Approved" || m.status === "Done");
      if (!targets.length) { showToast("No Approved or Done records found.", "info"); return; }
      openConfirmModal(
        "Purge Approved & Done Records",
        `This will <strong>permanently delete ${targets.length} record${targets.length !== 1 ? "s" : ""}</strong> (Approved &amp; Done) from Firebase.<br><br>
        <span style="color:var(--color-danger);font-weight:700">Warning:</span> This cannot be undone.`,
        async () => {
          let count = 0, errors = 0;
          for (const m of targets) {
            try {
              if (window.api && window.api.deleteMeeting) {
                await window.api.deleteMeeting(m.id);
              } else {
                const idx = meetings.indexOf(m); if (idx > -1) meetings.splice(idx, 1);
              }
              count++;
            } catch (err) {
              console.error("Purge Approved/Done error for", m.id, err);
              errors++;
            }
          }
          if (typeof fetchAllData === "function") await fetchAllData();
          if (typeof renderAdminMeetingsTable === "function") renderAdminMeetingsTable();
          if (typeof renderCalendar === "function") renderCalendar();
          if (typeof updateStatistics === "function") updateStatistics();
          if (typeof renderDashboardCharts === "function") renderDashboardCharts();
          if (errors > 0) {
            showToast(`Purged ${count} record${count !== 1 ? "s" : ""}. ${errors} failed — check console.`, "warning");
          } else {
            showToast(`Purged ${count} record${count !== 1 ? "s" : ""} successfully.`, "success");
          }
        }
      );
    });
  }

  if (clearNotifsBtn) {
    clearNotifsBtn.addEventListener("click", () => {
      openConfirmModal(
        "Clear All Notifications",
        "This will clear the local notification history for this browser. Firebase data is not affected.",
        () => {
          try {
            // Clear all sbp notification keys from localStorage
            Object.keys(localStorage).forEach(k => {
              if (k.startsWith("sbp_notif") || k.includes("NOTIFICATIONS") || k.includes("notifications")) {
                localStorage.removeItem(k);
              }
            });
            // Also try STORAGE_KEYS if defined
            if (typeof STORAGE_KEYS !== "undefined" && STORAGE_KEYS.NOTIFICATIONS) {
              localStorage.setItem(STORAGE_KEYS.NOTIFICATIONS, JSON.stringify([]));
            }
          } catch(e) {}
          showToast("Notification history cleared.", "success");
          const badge = document.getElementById("notif-badge");
          const list  = document.getElementById("notif-list");
          if (badge) badge.textContent = "";
          if (list)  list.innerHTML = `<div class="notif-empty">No notifications yet.</div>`;
        }
      );
    });
  }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

document.addEventListener("DOMContentLoaded", () => {
  const page = document.body.dataset.page;
  if (page === "login") initLoginPage();
  else if (page === "admin") { initAdminPage().then(() => initSystemMaintenance()).catch(err => { console.error("Admin page init failed:", err); }); }
  else if (page === "user") initUserPage();

  // Activate theme transitions after first paint — prevents flash-of-wrong-theme on load.
  // The CSS in styles.css gates all transitions behind body.theme-ready.
  requestAnimationFrame(() => {
    requestAnimationFrame(() => {
      document.body.classList.add("theme-ready");
    });
  });

  // Committee combobox — runs on both admin & user pages
  if (page === "admin" || page === "user") {
    // Wait for the meeting modal to exist (it's inline in HTML, so immediate)
    initCommitteeCombobox();
    // Re-init if the modal gets re-created dynamically
    const mo = document.getElementById("meeting-modal");
    if (mo) {
      // Guard: only observe once — the combo itself guards against double-init
    if (!mo.dataset.comboObserved) {
      mo.dataset.comboObserved = "1";
        const isMob = _isMobile();
        // On real phones this observer can trigger very frequently while the UI
        // updates. Keep it lightweight: no deep subtree watching + throttle.
        let lastInit = 0;
        new MutationObserver(() => {
          const now = Date.now();
          if (now - lastInit < 450) return;
          lastInit = now;
          initCommitteeCombobox();
        }).observe(mo, { childList: true, subtree: !isMob });
    }
    }
  }
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

// Human-readable "expires in X" label for announcement cards
function _annExpiresIn(isoStr) {
  if (!isoStr) return "";
  const diff = new Date(isoStr).getTime() - Date.now();
  if (diff <= 0) return "expired";
  const mins = Math.floor(diff / 60000);
  if (mins < 60) return mins + "m";
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return hrs + "h";
  const days = Math.floor(hrs / 24);
  return days + "d";
}

// ── Announcement detail modal ──────────────────────────────────────────────
function _openAnnModal(ann) {
  const meta = _annMeta(ann.type);
  let expHtml = "";
  if (ann.expiresAt) {
    const diff = new Date(ann.expiresAt).getTime() - Date.now();
    const label = diff <= 0 ? "Expired" : "Expires in " + _annExpiresIn(ann.expiresAt);
    const urgent = diff > 0 && diff < 3 * 24 * 60 * 60 * 1000;
    const expiredNow = diff <= 0;
    const bg    = expiredNow ? "rgba(220,38,38,0.10)" : urgent ? "rgba(234,88,12,0.10)" : "rgba(107,114,128,0.08)";
    const color = expiredNow ? "#dc2626" : urgent ? "#ea580c" : "var(--color-text-muted)";
    const border= expiredNow ? "rgba(220,38,38,0.25)" : urgent ? "rgba(234,88,12,0.25)" : "var(--color-border-soft)";
    expHtml = `<span style="display:inline-flex;align-items:center;gap:4px;font-size:0.72rem;font-weight:600;padding:3px 10px;border-radius:999px;background:${bg};color:${color};border:1px solid ${border}">
      <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>${label}</span>`;
  }
  const pinHtml = ann.pinned
    ? `<span style="display:inline-flex;align-items:center;gap:4px;font-size:0.72rem;font-weight:700;letter-spacing:0.05em;color:#d97706;background:rgba(217,119,6,0.12);padding:3px 10px;border-radius:999px;border:1px solid rgba(217,119,6,0.25)">
        <svg width="9" height="9" viewBox="0 0 24 24" fill="currentColor" stroke="none"><path d="M12 2l2.4 7.4H22l-6.2 4.5 2.4 7.4L12 17l-6.2 4.3 2.4-7.4L2 9.4h7.6z"/></svg> PINNED</span>` : "";
  const existing = document.getElementById("ann-view-modal");
  if (existing) existing.remove();
  const modal = document.createElement("div");
  modal.id = "ann-view-modal";
  modal.style.cssText = "position:fixed;inset:0;z-index:9999;display:flex;align-items:flex-end;justify-content:center;background:rgba(0,0,0,0);transition:background 0.25s;";
  const iconInner = (meta.icon.match(/<svg[^>]*>([\s\S]*?)<\/svg>/) || ["",""])[1];
  modal.innerHTML = `
    <div id="ann-modal-backdrop" style="position:absolute;inset:0;cursor:pointer;"></div>
    <div id="ann-modal-sheet" style="position:relative;width:100%;max-width:680px;max-height:92dvh;background:var(--color-surface);border-radius:20px 20px 0 0;display:flex;flex-direction:column;overflow:hidden;box-shadow:0 -4px 40px rgba(0,0,0,0.18);transform:translateY(100%);transition:transform 0.32s cubic-bezier(0.32,0.72,0,1);">
      <div style="height:4px;background:linear-gradient(90deg,${meta.color},${meta.color}99);flex-shrink:0;"></div>
      <div style="display:flex;justify-content:center;padding:10px 0 0;flex-shrink:0;">
        <div style="width:36px;height:4px;border-radius:2px;background:var(--color-border);"></div>
      </div>
      <div style="padding:14px 20px 14px;display:flex;align-items:flex-start;gap:14px;flex-shrink:0;border-bottom:1px solid var(--color-border-soft);">
        <div style="width:44px;height:44px;border-radius:12px;background:${meta.bg};border:1px solid ${meta.color}22;display:flex;align-items:center;justify-content:center;flex-shrink:0;color:${meta.color};">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">${iconInner}</svg>
        </div>
        <div style="flex:1;min-width:0;">
          <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;margin-bottom:6px;">
            <span style="font-size:0.68rem;font-weight:700;letter-spacing:0.07em;color:${meta.color};text-transform:uppercase;background:${meta.bg};padding:2px 9px;border-radius:999px;border:1px solid ${meta.color}22;">${meta.label}</span>
            ${pinHtml}${expHtml}
          </div>
          <div style="font-weight:700;font-size:1.05rem;color:var(--color-text);line-height:1.4;word-break:break-word;">${h(ann.title)}</div>
        </div>
        <button onclick="_closeAnnModal()" style="flex-shrink:0;width:34px;height:34px;border-radius:8px;background:var(--color-bg-subtle,rgba(0,0,0,0.05));border:1px solid var(--color-border-soft);cursor:pointer;display:flex;align-items:center;justify-content:center;color:var(--color-text-muted);">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
        </button>
      </div>
      <div style="flex:1;overflow-y:auto;padding:22px;-webkit-overflow-scrolling:touch;">
        <div style="font-size:0.9rem;color:var(--color-text);line-height:1.9;white-space:pre-wrap;word-break:break-word;">${h(ann.body || "")}</div>
      </div>
      <div style="padding:12px 20px;border-top:1px solid var(--color-border-soft);display:flex;align-items:center;gap:8px;flex-wrap:wrap;flex-shrink:0;background:var(--color-surface);">
        <div style="display:flex;align-items:center;gap:5px;font-size:0.73rem;color:var(--color-text-muted);">
          <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
          <span>${_annTimeAgo(ann.createdAt)}</span>
        </div>
        ${ann.postedBy ? `<span style="color:var(--color-border);font-size:0.7rem;">·</span>
        <div style="display:flex;align-items:center;gap:5px;font-size:0.73rem;color:var(--color-text-muted);">
          <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
          <span>Posted by <strong style="color:var(--color-text);font-weight:600;">${h(ann.postedBy)}</strong></span>
        </div>` : ""}
        <div style="margin-left:auto;">
          <button onclick="_closeAnnModal()" style="display:inline-flex;align-items:center;gap:6px;font-size:0.8rem;font-weight:600;padding:7px 20px;border-radius:8px;cursor:pointer;background:var(--color-bg-subtle,rgba(0,0,0,0.05));color:var(--color-text-muted);border:1px solid var(--color-border-soft);">Close</button>
        </div>
      </div>
    </div>`;
  document.body.appendChild(modal);
  requestAnimationFrame(() => {
    modal.style.background = "rgba(0,0,0,0.45)";
    const sheet = document.getElementById("ann-modal-sheet");
    if (sheet) sheet.style.transform = "translateY(0)";
  });
  function _applyLayout() {
    const sheet = document.getElementById("ann-modal-sheet");
    if (!sheet) return;
    if (window.innerWidth >= 640) {
      modal.style.alignItems = "center";
      sheet.style.borderRadius = "16px";
      sheet.style.margin = "0 16px";
    } else {
      modal.style.alignItems = "flex-end";
      sheet.style.borderRadius = "20px 20px 0 0";
      sheet.style.margin = "0";
    }
  }
  _applyLayout();
  window.addEventListener("resize", _applyLayout);
  document.getElementById("ann-modal-backdrop").addEventListener("click", _closeAnnModal);
  function _escKey(e) { if (e.key === "Escape") _closeAnnModal(); }
  document.addEventListener("keydown", _escKey);
  modal._escKey = _escKey;
  modal._resizeFn = _applyLayout;
}
function _closeAnnModal() {
  const modal = document.getElementById("ann-view-modal");
  if (!modal) return;
  modal.style.background = "rgba(0,0,0,0)";
  const sheet = document.getElementById("ann-modal-sheet");
  if (sheet) sheet.style.transform = "translateY(100%)";
  if (modal._escKey) document.removeEventListener("keydown", modal._escKey);
  if (modal._resizeFn) window.removeEventListener("resize", modal._resizeFn);
  setTimeout(() => { if (modal.parentNode) modal.remove(); }, 320);
}
window._openAnnModal  = _openAnnModal;
window._closeAnnModal = _closeAnnModal;

// ── Render announcement card (compact preview — full content opens in modal) ──
function _renderAnnCard(ann, isAdmin) {
  const meta = _annMeta(ann.type);
  const pinHtml = ann.pinned
    ? `<span style="font-size:0.68rem;font-weight:700;letter-spacing:0.05em;color:#d97706;background:rgba(217,119,6,0.12);padding:2px 9px;border-radius:999px;display:inline-flex;align-items:center;gap:4px;border:1px solid rgba(217,119,6,0.2)">
        <svg width="9" height="9" viewBox="0 0 24 24" fill="currentColor" stroke="none"><path d="M12 2l2.4 7.4H22l-6.2 4.5 2.4 7.4L12 17l-6.2 4.3 2.4-7.4L2 9.4h7.6z"/></svg> PINNED</span>` : "";
  const editHtml = isAdmin
    ? `<button class="btn btn-ghost btn-sm ann-edit-btn" data-id="${ann.id}" title="Edit" style="color:var(--color-text-muted);padding:5px 7px;border-radius:7px;flex-shrink:0;">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 013 3L7 19l-4 1 1-4L16.5 3.5z"/></svg></button>` : "";
  const deleteHtml = isAdmin
    ? `<button class="btn btn-ghost btn-sm ann-delete-btn" data-id="${ann.id}" title="Delete" style="color:var(--color-text-muted);padding:5px 7px;border-radius:7px;flex-shrink:0;">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6"/><path d="M10 11v6M14 11v6"/><path d="M9 6V4h6v2"/></svg></button>` : "";
  const expBadge = ann.expiresAt ? (() => {
    const diff = new Date(ann.expiresAt).getTime() - Date.now();
    const label = diff <= 0 ? "Expired" : "in " + _annExpiresIn(ann.expiresAt);
    const urgent = diff > 0 && diff < 3 * 24 * 60 * 60 * 1000;
    const expiredNow = diff <= 0;
    const bg    = expiredNow ? "rgba(220,38,38,0.10)" : urgent ? "rgba(234,88,12,0.10)" : "rgba(107,114,128,0.08)";
    const color = expiredNow ? "#dc2626" : urgent ? "#ea580c" : "var(--color-text-muted)";
    const border= expiredNow ? "rgba(220,38,38,0.2)" : urgent ? "rgba(234,88,12,0.2)" : "transparent";
    return `<span style="display:inline-flex;align-items:center;gap:3px;font-size:0.66rem;font-weight:600;padding:2px 7px;border-radius:999px;background:${bg};color:${color};border:1px solid ${border}">
      <svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>expires ${label}</span>`;
  })() : "";
  const bodyText = ann.body || "";
  const isLong   = bodyText.length > 180;
  const preview  = isLong ? bodyText.slice(0, 180).trimEnd() + "…" : bodyText;
  if (!window.__annStore) window.__annStore = {};
  window.__annStore[ann.id] = ann;
  return `<div class="ann-card" data-id="${ann.id}" style="border:1px solid var(--color-border-soft);border-radius:14px;background:var(--color-surface);overflow:hidden;transition:box-shadow 0.2s,transform 0.2s;box-shadow:0 1px 4px rgba(0,0,0,0.05);"
    onmouseover="this.style.boxShadow='0 6px 20px rgba(0,0,0,0.09)';this.style.transform='translateY(-1px)'"
    onmouseout="this.style.boxShadow='0 1px 4px rgba(0,0,0,0.05)';this.style.transform='translateY(0)'">
    <div style="height:4px;background:linear-gradient(90deg,${meta.color},${meta.color}77);"></div>
    <div style="padding:16px 18px;display:flex;flex-direction:column;gap:10px;">
      <div style="display:flex;align-items:flex-start;gap:12px;">
        <div style="width:38px;height:38px;border-radius:10px;background:${meta.bg};border:1px solid ${meta.color}22;display:flex;align-items:center;justify-content:center;flex-shrink:0;color:${meta.color};">${meta.icon}</div>
        <div style="flex:1;min-width:0;">
          <div style="display:flex;align-items:center;gap:5px;flex-wrap:wrap;margin-bottom:5px;">
            <span style="font-size:0.66rem;font-weight:700;letter-spacing:0.07em;color:${meta.color};text-transform:uppercase;background:${meta.bg};padding:2px 8px;border-radius:999px;border:1px solid ${meta.color}22;">${meta.label}</span>
            ${pinHtml}${expBadge}
          </div>
          <div style="font-weight:700;font-size:0.96rem;color:var(--color-text);line-height:1.35;word-break:break-word;">${h(ann.title)}</div>
        </div>
        ${isAdmin ? `<div style="display:flex;gap:2px;flex-shrink:0;">${editHtml}${deleteHtml}</div>` : ""}
      </div>
      <div style="height:1px;background:var(--color-border-soft);"></div>
      <div style="font-size:0.855rem;color:var(--color-text-muted);line-height:1.7;word-break:break-word;">${h(preview)}</div>
      <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;">
        <div style="display:flex;align-items:center;gap:4px;font-size:0.72rem;color:var(--color-text-muted);">
          <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
          ${_annTimeAgo(ann.createdAt)}${ann.postedBy ? ` · <strong style="color:var(--color-text-muted);font-weight:600;">${h(ann.postedBy)}</strong>` : ""}
        </div>
        ${isLong ? `<button onclick="event.stopPropagation();_openAnnModal(window.__annStore&&window.__annStore['${ann.id}']||{})" style="margin-left:auto;display:inline-flex;align-items:center;gap:5px;font-size:0.75rem;font-weight:600;color:${meta.color};background:${meta.bg};border:1px solid ${meta.color}33;padding:5px 13px;border-radius:999px;cursor:pointer;transition:opacity 0.15s;" onmouseover="this.style.opacity='0.8'" onmouseout="this.style.opacity='1'">
          <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>Read full</button>` : ""}
      </div>
    </div>
  </div>`;
}
function h(str) {
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

  // Show "New" badge if any announcement arrived after last time user visited Announcements section.
  // Uses sbp_ann_seen which is stamped to Date.now() when user navigates to the announcements section.
  try {
    const lastSeen = parseInt(localStorage.getItem("sbp_ann_seen") || "0", 10);
    const hasNew = sorted.some(a => a.createdAt && new Date(a.createdAt).getTime() > lastSeen);
    const badge = document.getElementById("new-ann-badge");
    if (badge) {
      badge.textContent = "New";
      // Only show if currently NOT in the announcements section
      const inAnnSection = document.getElementById("section-announcements")?.classList.contains("active");
      badge.style.display = (hasNew && !inAnnSection) ? "inline-flex" : "none";
      // If user is already viewing announcements, stamp seen immediately
      if (inAnnSection) {
        try { localStorage.setItem("sbp_ann_seen", String(Date.now())); } catch(_) {}
      }
    }
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
        <div style="font-weight:600;font-size:0.86rem;color:var(--color-text);white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${pin}${h(a.title)}</div>
        <div style="font-size:0.77rem;color:var(--color-text-muted);margin-top:2px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${h(a.body)}</div>
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
        <div style="font-weight:600;font-size:0.85rem;color:var(--color-text);white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${h(a.title)}</div>
        <div style="font-size:0.73rem;color:var(--color-text-muted)">${_annTimeAgo(a.createdAt)}</div>
      </div>
    </div>`;
  }).join("");
}

function openAnnEditModal(ann) {
  let modal = document.getElementById("ann-edit-modal");
  if (!modal) {
    modal = document.createElement("div");
    modal.id = "ann-edit-modal";
    modal.className = "modal-backdrop";
    modal.innerHTML = `
      <div class="modal" style="max-width:560px">
        <div class="modal-header">
          <div class="modal-title">Edit Announcement</div>
          <button id="ann-edit-close" class="btn btn-ghost btn-sm">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
          </button>
        </div>
        <div class="modal-body section-stack" id="ann-edit-body-wrap">
          <div>
            <label class="field-label" for="ann-edit-title">Title *</label>
            <input id="ann-edit-title" class="field" maxlength="120" />
          </div>
          <div>
            <label class="field-label" for="ann-edit-type">Category</label>
            <select id="ann-edit-type" class="field">
              <option value="general">General Info</option>
              <option value="important">Important Notice</option>
              <option value="reminder">Reminder</option>
              <option value="event">Upcoming Event</option>
            </select>
          </div>
          <div>
            <label class="field-label" for="ann-edit-body">Message *</label>
            <textarea id="ann-edit-body" class="field" rows="4" style="resize:vertical;min-height:96px"></textarea>
          </div>
          <label style="display:flex;align-items:center;gap:8px;cursor:pointer;font-size:0.85rem;color:var(--color-text);user-select:none">
            <input type="checkbox" id="ann-edit-pinned" style="width:15px;height:15px;accent-color:#d97706;cursor:pointer" />
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" style="color:#d97706;flex-shrink:0"><path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0118 0z"/><circle cx="12" cy="10" r="3"/></svg>
            <span>Pin to top of announcements</span>
          </label>
          <div id="ann-edit-error" class="helper-text" style="color:var(--color-danger)"></div>
        </div>
        <div class="modal-footer">
          <button id="ann-edit-cancel" class="btn btn-ghost btn-sm">Cancel</button>
          <button id="ann-edit-save" class="btn btn-primary btn-sm">Save Changes</button>
        </div>
      </div>`;
    document.body.appendChild(modal);
  }
  document.getElementById("ann-edit-title").value = ann.title || "";
  document.getElementById("ann-edit-type").value = ann.type || "general";
  document.getElementById("ann-edit-body").value  = ann.body || "";
  const pinEl = document.getElementById("ann-edit-pinned");
  if (pinEl) pinEl.checked = !!ann.pinned;
  const errEl = document.getElementById("ann-edit-error");
  if (errEl) errEl.textContent = "";

  const modalInner = modal.querySelector(".modal");
  if (modalInner) { modalInner.style.animation = "none"; requestAnimationFrame(() => { modalInner.style.animation = ""; }); }
  modal.classList.add("modal-open");

  const close = () => { modal.classList.remove("modal-open"); };
  document.getElementById("ann-edit-close").onclick = close;
  document.getElementById("ann-edit-cancel").onclick = close;
  modal.onclick = (e) => { if (e.target === modal) close(); };

  document.getElementById("ann-edit-save").onclick = async () => {
    const title = (document.getElementById("ann-edit-title").value || "").trim();
    const body  = (document.getElementById("ann-edit-body").value  || "").trim();
    const type  = document.getElementById("ann-edit-type").value || "general";
    const pinned= !!document.getElementById("ann-edit-pinned").checked;
    if (!title) { if (errEl) errEl.textContent = "Title is required."; return; }
    if (!body)  { if (errEl) errEl.textContent = "Message is required."; return; }
    if (errEl) errEl.textContent = "";
    try {
      await window.api.updateAnnouncement(ann.id, { title, body, type, pinned });
      showToast("Announcement updated.", "success");
      // If no live subscription, refresh manually
      if (!window.api.subscribeAnnouncements) {
        const list = await window.api.getAnnouncements();
        window.announcements = list;
        renderAdminAnnouncements(list);
        renderAdminDashAnnouncements(list);
      }
      close();
    } catch (err) {
      showToast("Failed to update announcement.", "error");
    }
  };
}

// ── Wire admin announcements form ──────────────────────────────────────────
function initAdminAnnouncements() {
  const form = document.getElementById("announce-form");
  if (!form) return;

  // Subscribe to live updates
  if (window.api && window.api.subscribeAnnouncements) {
    window._unsubAdminAnn = window.api.subscribeAnnouncements(list => {
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
            `New announcement: <strong>${h(title)}</strong>`,
            "info", "announcements");
        });
      }
      showToast("Announcement posted successfully!", "success");
      form.reset();
      // The subscribeAnnouncements callback fires automatically (local & Firestore).
      // Only fetch manually if subscribe is not available (fallback).
      if (!window.api.subscribeAnnouncements) {
        const list = await window.api.getAnnouncements();
        renderAdminAnnouncements(list);
        renderAdminDashAnnouncements(list);
      }
    } catch(err) {
      showToast("Failed to post announcement.", "error");
    } finally {
      if (btn) { btn.disabled = false; btn.innerHTML = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg> Post Announcement`; }
    }
  });

  // Edit/Delete delegation
  document.getElementById("admin-announce-list")?.addEventListener("click", async e => {
    const editBtn = e.target.closest(".ann-edit-btn");
    const delBtn  = e.target.closest(".ann-delete-btn");
    if (!editBtn && !delBtn) return;
    const id = (editBtn || delBtn).dataset.id;
    if (!id) return;
    if (delBtn) {
      openConfirmModal("Delete Announcement",
        "Are you sure you want to delete this announcement? This cannot be undone.",
        async () => {
          try {
            await window.api.deleteAnnouncement(id);
            showToast("Announcement deleted.", "success");
            if (!window.api.subscribeAnnouncements) {
              const list = await window.api.getAnnouncements();
              renderAdminAnnouncements(list);
              renderAdminDashAnnouncements(list);
            }
          } catch(err) {
            showToast("Failed to delete.", "error");
          }
        }
      );
    } else if (editBtn) {
      const ann = (window.announcements || []).find(a => a.id === id);
      if (ann) openAnnEditModal(ann);
    }
  });
}

// ── Wire user announcements (read-only) ───────────────────────────────────
function initUserAnnouncements() {
  if (!window.api?.subscribeAnnouncements) return;

  // Key stored per-user: timestamp of the newest announcement we have already
  // pushed a bell notification for. Persisted in localStorage so it survives
  // page refreshes and new logins on the same device.
  const currentUser = getCurrentUser();
  const notifKey = currentUser ? `sbp_ann_notif_ts_${currentUser.id || currentUser.username}` : null;

  function getLastNotifiedTs() {
    try { return parseInt(localStorage.getItem(notifKey) || "0", 10); } catch { return 0; }
  }
  function setLastNotifiedTs(ts) {
    try { if (notifKey) localStorage.setItem(notifKey, String(ts)); } catch {}
  }

  // Wire search + filter inputs — re-render live
  function getFilteredAnnouncements() {
    const q = (document.getElementById("ann-search")?.value || "").trim().toLowerCase();
    const t = (document.getElementById("ann-filter-type")?.value || "");
    let list = window.announcements || [];
    if (q) list = list.filter(a => (a.title || "").toLowerCase().includes(q) || (a.body || "").toLowerCase().includes(q));
    if (t) list = list.filter(a => (a.type || "general") === t);
    return list;
  }
  ["ann-search", "ann-filter-type"].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.addEventListener("input", () => renderUserAnnouncements(getFilteredAnnouncements()));
  });

  // In-memory set of announcement IDs we've already pushed a notification for
  // in this session. Prevents duplicate bell notifications when the Firestore
  // subscriber fires multiple times rapidly on initial page load.
  const _notifiedAnnIds = new Set();

  window._unsubUserAnn = window.api.subscribeAnnouncements(list => {
    window.announcements = list;
    renderUserAnnouncements(getFilteredAnnouncements());
    renderUserDashAnnouncements(list);

    // ── Push bell notifications for every announcement newer than last notified ──
    // This fires on initial page load AND on real-time updates, so users always
    // get notified even if they were offline when the admin posted.
    if (!currentUser) return;
    const lastTs = getLastNotifiedTs();
    // Sort ascending so we fire oldest-new first and update the watermark correctly
    const newAnns = list
      .filter(a => {
        if (!a.createdAt) return false;
        if (new Date(a.createdAt).getTime() <= lastTs) return false;
        // Skip if we already notified for this announcement in this session
        if (_notifiedAnnIds.has(a.id)) return false;
        return true;
      })
      .sort((a, b) => new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime());

    if (newAnns.length > 0) {
      const uid = currentUser.id || currentUser.username;
      newAnns.forEach(a => {
        _notifiedAnnIds.add(a.id); // mark as notified in-memory before async addNotification
        addNotification(
          uid,
          `New announcement: <strong>${h(a.title || "Untitled")}</strong>`,
          "info",
          "announcements"
        );
      });
      // Advance the watermark to the newest announcement we just notified
      const newMaxTs = Math.max(...newAnns.map(a => new Date(a.createdAt).getTime()));
      setLastNotifiedTs(newMaxTs);
      updateNotificationBadge(uid);
    }
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
    // Lock scroll on the scrollable content area, NOT body
    // Setting overflow:hidden on body clips position:fixed elements on iOS Safari
    const mainScroll = document.querySelector(".main-scroll");
    if (mainScroll) mainScroll.style.overflow = "hidden";
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
    // Restore scroll on main-scroll (not body — body overflow clips fixed elements on iOS)
    const mainScroll = document.querySelector(".main-scroll");
    if (mainScroll) mainScroll.style.overflow = "";
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
    const currentUser = (typeof getCurrentUser === "function") ? getCurrentUser() : null;
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
           PH Holiday: ${h(holidayInfo.localName)}
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
            const nowM = getManilaNow();
            const within24h = !!(createdAt && Math.max(0, nowM - createdAt) < 24 * 60 * 60 * 1000);
             const cancelLabel = within24h ? "Cancel (Free)" : "Request Cancel";
             return `
               <div style="background:${c.bg};border:1px solid ${c.border};border-left:4px solid ${c.border};border-radius:10px;padding:12px 14px${belongsToMe ? ';outline:2px solid #F5A31A;outline-offset:1px' : ''}">
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
            <option value="Committee Meeting">Committee Meeting</option>
            <option value="Committee Hearing">Committee Hearing</option>
            <option value="Committee Deliberation">Committee Deliberation</option>
            <option value="Public Meeting">Public Meeting</option>
            <option value="Consultative Meeting">Consultative Meeting</option>
            <option value="Others">Others (Please Specify)</option>
          </select>
          <input id="db-type-other" class="field" placeholder="Please specify type…"
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
          <input id="db-venue-other" class="field" placeholder="Please specify venue…"
                 style="display:none;margin-top:8px" />
        </div>
        <div>
          <label class="field-label" for="db-stakeholders">Stakeholders / External Participants *</label>
          <input id="db-stakeholders" class="field" required placeholder="e.g. DILG, DSWD, Barangay Representatives (comma-separated)" autocomplete="off" />
          <div class="helper-text" style="margin-top:3px;font-size:0.78rem">Required — list organizations or individuals attending from outside.</div>
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
      // Wire up committee combobox for this drawer instance
      initDrawerCommitteeCombo(drawer);

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

    // For today: block slots that have already started or passed
    const todayISO = getTodayISOManila();
    const isToday  = isoDate === todayISO;
    const nowMins  = isToday ? (() => { const n = getManilaNow(); return n.getHours() * 60 + n.getMinutes(); })() : 0;

    sel.innerHTML = "";
    let count = 0;

    for (let h = WORK_START_HOUR; h < WORK_END_HOUR; h++) {
      const slotStart = h * 60;
      const slotEnd   = slotStart + dur * 60;

      // Skip if duration would exceed office hours
      if (slotEnd > WORK_END_HOUR * 60) continue;

      // Skip if slot has already started or passed today
      if (isToday && slotStart <= nowMins) continue;

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

    const ICON_X    = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="display:inline-block;vertical-align:-1px;flex-shrink:0"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>`;
    const ICON_OK   = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="display:inline-block;vertical-align:-1px;flex-shrink:0"><circle cx="12" cy="12" r="10"/><polyline points="9 12 11 14 15 10"/></svg>`;
    const ICON_WARN = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="display:inline-block;vertical-align:-1px;flex-shrink:0"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`;
    const ICON_CLK  = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="display:inline-block;vertical-align:-1px;flex-shrink:0"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>`;
    if (hint) {
      hint.style.display = "flex";
      hint.style.alignItems = "center";
      hint.style.gap = "5px";
      if (count === 0) {
        hint.style.color = "var(--color-danger)";
        hint.innerHTML = isToday
          ? `${ICON_CLK} No remaining slots for today — all times have passed or are booked`
          : `${ICON_X} No time slots available for this date`;
      } else if (isToday) {
        hint.style.color = "var(--color-warning)";
        hint.innerHTML = `${ICON_CLK} ${count} slot${count > 1 ? "s" : ""} remaining today (past times hidden)`;
      } else if (approved.length === 0) {
        hint.style.color = "var(--color-success)";
        hint.innerHTML = `${ICON_OK} All time slots available for this date`;
      } else {
        hint.style.color = "var(--color-warning)";
        hint.innerHTML = `${ICON_WARN} Some slots are taken — check availability above`;
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
      ? `End time ${label} exceeds office hours`
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
    if (!stakeholders) {
      if (msg) msg.textContent = "Stakeholders / External Participants is required.";
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
      id: crypto.randomUUID(),
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
            `New meeting request from <strong>${h(currentUser.name)}</strong>: <strong>"${h(eventName)}"</strong> on ${formatDateDisplay(date)} at ${formatTimeRange(timeStart, durationHours)}. Review and take action.`,
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
            `The Admin has scheduled a meeting on your behalf: <strong>"${h(eventName)}"</strong> on ${dateStr} at ${timeStr}. Venue: ${h(venue)}. Status: <strong>Approved</strong>.`,
            "success", "my-meetings");
        }
        if (researcher && researcher !== "N/A") {
          const rUser = users.find(u => u.name === researcher);
          if (rUser) addNotification(rUser.id || rUser.username,
            `The Admin has scheduled a meeting on your behalf: <strong>"${h(eventName)}"</strong> on ${dateStr} at ${timeStr}. Venue: ${h(venue)}. Status: <strong>Approved</strong>.`,
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

  window.switchSection = function(sectionId) {
  // 1. Update the topbar title — explicit map so labels match sidebar exactly
  const _TITLES = {
    'dashboard':        'Dashboard',
    'meeting-logs':     'Meeting Logs',
    'user-management':  'Accounts',
    'admin-management': 'System Settings',
    'announcements':    'Announcements',
    'calendar':         'Meeting Calendar',
    'my-meetings':      'My Meetings',
  };
  const topbarTitle = document.getElementById('topbar-section-title');
  if (topbarTitle) {
    topbarTitle.textContent = _TITLES[sectionId] || sectionId.split('-').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ');
  }

  // 2. Toggle active class on sidebar links
  document.querySelectorAll('.nav-link').forEach(link => {
    link.classList.toggle('nav-link-active', link.getAttribute('data-section') === sectionId);
  });

  // 3. Toggle visibility of sections — handles both admin.html (.admin-section)
  //    and user.html (.user-section) so nav works correctly on both pages.
  document.querySelectorAll('.admin-section, .user-section').forEach(section => {
    section.classList.toggle('active', section.id === 'section-' + sectionId);
  });

  // 4. Persist the active section so a page refresh restores the same view
  try { sessionStorage.setItem('user_section', sectionId); } catch(_) {}

  // 5. Clear nav badges when the user visits the relevant section ─────────────
  // Announcements: hide "New" badge and stamp seen timestamp so it won't
  // reappear until the admin posts something newer.
  if (sectionId === 'announcements') {
    try { localStorage.setItem('sbp_ann_seen', String(Date.now())); } catch(_) {}
    const annBadge = document.getElementById('new-ann-badge');
    if (annBadge) annBadge.style.display = 'none';
  }
  // My Meetings: hide the pending badge once user has seen the section.
  // The count is already visible in the table — the nav dot is just a nudge.
  if (sectionId === 'my-meetings') {
    const pendingBadge = document.getElementById('pending-badge');
    if (pendingBadge) pendingBadge.style.display = 'none';
  }
  // Meeting Calendar: hide the calendar badge once visited
  if (sectionId === 'calendar') {
    const calBadge = document.getElementById('calendar-nav-badge');
    if (calBadge) calBadge.style.display = 'none';
  }
};

document.querySelectorAll('.nav-link').forEach(link => {
  link.addEventListener('click', (e) => {
    e.preventDefault();
    const section = link.getAttribute('data-section');
    if (section) switchSection(section);
  });
});

})();