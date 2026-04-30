;(function () {
  // ─────────────────────────────────────────────────────────────────────────
  // Firebase configuration — inlined here so no separate config file is
  // needed (and exposed) in the project. The values below are client-side
  // identifiers, NOT secret keys. Security is enforced by Firestore rules.
  // Restrict usage further in the Firebase console:
  //   Authentication → Settings → Authorized domains (add your domain only)
  //   API key restrictions in Google Cloud Console → Credentials
  // ─────────────────────────────────────────────────────────────────────────
  var FIREBASE_CONFIG = {
      apiKey: "AIzaSyDEUVl2fQST8BFoL_kxiCyLOR4EB4VMvlE",
      authDomain: "testingcalendar-41b86.firebaseapp.com",
      projectId: "testingcalendar-41b86",
      storageBucket: "testingcalendar-41b86.firebasestorage.app",
      messagingSenderId: "873072574942",
      appId: "1:873072574942:web:80061a178d951f5e441d4f",
      measurementId: "G-CCP2GW0G3B"
  };

  function hasFirebase() {
    return typeof firebase !== "undefined" && !!firebase.initializeApp
  }
  function getConfig() {
    // Prefer any externally injected config, fall back to the inlined one above.
    return (typeof window.__FIREBASE_CONFIG__ === "object" && window.__FIREBASE_CONFIG__)
      ? window.__FIREBASE_CONFIG__
      : FIREBASE_CONFIG;
  }
  var mode = "local"
  var db = null
  var fellBack = false
  if (hasFirebase() && getConfig()) {
    try {
      var app = firebase.initializeApp(getConfig())
      db = firebase.firestore(app)
      try {
        if (typeof firebase.storage === "function") {
          firebase.storage(app)
        }
      } catch (storageInitErr) {
        console.warn("Firebase Storage init:", storageInitErr && storageInitErr.message)
      }
      mode = "firestore"
      // ── Anonymous Auth ────────────────────────────────────────────────────
      // Sign in anonymously so request.auth is always populated in Firestore
      // rules. This is completely transparent to the user — no email/password
      // required. It just gives each browser session a valid auth token so
      // our security rules (require request.auth != null) work correctly.
      if (typeof firebase.auth === "function") {
        // Expose a promise that resolves once anon auth + firebaseUid write are done.
        // user.html waits on window._firebaseUidReady before running Firestore queries
        // so there's no race between the UID update and recipient-based reads.
        window._firebaseUidReady = firebase.auth(app).signInAnonymously().then(function(cred) {
          // After anon sign-in, write the Firebase UID back to the user's
          // Firestore doc so Firestore rules can match recipients by Firebase UID.
          // Also mirror role into user_roles/{firebaseUid} so isAdmin() rule works.
          try {
            var raw = localStorage.getItem("sbp_current_user");
            if (raw) {
              var appUser = JSON.parse(raw);
              if (appUser && appUser.id && cred && cred.user) {
                var firebaseUid = cred.user.uid;
                db.collection("users").doc(appUser.id)
                  .update({ firebaseUid: firebaseUid })
                  .catch(function() {});
                if (appUser.role) {
                  return db.collection("user_roles").doc(firebaseUid)
                    .set({ role: appUser.role, appUserId: appUser.id })
                    .catch(function() {});
                }
              }
            }
          } catch(e) {}
        }).catch(function(err) {
          console.warn("Anonymous auth failed — Firestore rules may block reads/writes.", err.message);
        });
      }
    } catch (e) {
      mode = "local"
    }
  }
  function fallbackToLocal() {
    if (fellBack) return
    mode = "local"
    fellBack = true
  }
  function lsGet(key, fallback) {
    try {
      var raw = localStorage.getItem(key)
      return raw ? JSON.parse(raw) : fallback
    } catch (e) {
      return fallback
    }
  }
  function lsSet(key, value) {
    localStorage.setItem(key, JSON.stringify(value))
  }
  var LS = {
    USERS: "sbp_users",
    MEETINGS: "sbp_meetings",
    HISTORY: "sbp_calendar_history",
    ANNOUNCEMENTS: "sbp_announcements",
  }
  function statusToColor(status) {
    if (status === "Approved") return "#16a34a"
    if (status === "Pending") return "#f59e0b"
    if (status === "Cancelled" || status === "Rejected") return "#dc2626"
    return "#3b82f6"
  }
  function ensureDefaultAdminIfNeeded() {
    // CRITICAL FIX: The old code had a hardcoded SHA-256 hash of 'admin123'
    // in the source file — visible to anyone who reads the JS. Replaced with
    // a locked placeholder token that can never match any real password input.
    // The mustChangePassword flag forces a new password to be set on first login
    // before any access is granted, so the placeholder is never actually used
    // to authenticate — it just ensures the account record exists in Firestore.
    var DEFAULT_ADMIN = {
      username: "sb_adminpolangui",
      password: "LOCKED_MUST_CHANGE_ON_FIRST_LOGIN",
      role: "Admin",
      name: "System Administrator",
      mustChangePassword: true,
    }
    if (mode === "firestore") {
      return db
        .collection("users")
        .where("username", "==", DEFAULT_ADMIN.username)
        .limit(1)
        .get()
        .then(function (snap) {
          if (snap.empty) {
            var docId = "admin_" + Math.random().toString(36).slice(2, 9);
            return db.collection("users").doc(docId).set(Object.assign({ id: docId }, DEFAULT_ADMIN))
          }
        })
        .catch(function () {
          fallbackToLocal()
          var users = lsGet(LS.USERS, [])
          if (!users.some(function (u) { return u.username === DEFAULT_ADMIN.username })) {
            users.push(Object.assign({ id: "admin_local" }, DEFAULT_ADMIN))
            lsSet(LS.USERS, users)
          }
        })
    } else {
      var users = lsGet(LS.USERS, [])
      if (!users.some(function (u) { return u.username === DEFAULT_ADMIN.username })) {
        users.push(Object.assign({ id: "admin_local" }, DEFAULT_ADMIN))
        lsSet(LS.USERS, users)
      }
      return Promise.resolve()
    }
  }

  var _annSubscribers = []
  function _notifyAnnSubscribers() {
    var list = lsGet(LS.ANNOUNCEMENTS, []).slice().reverse()
    _annSubscribers.forEach(function (cb) { try { cb(list) } catch (e) {} })
  }

  var _meetingSubscribers = []
  function _notifyMeetingSubscribers() {
    var list = lsGet(LS.MEETINGS, [])
    _meetingSubscribers.forEach(function (cb) { try { cb(list) } catch (e) {} })
  }

  var api = {
    // BUGFIX: mode was stored as a plain value snapshot at construction time,
    // so fallbackToLocal() mutating the `mode` variable was never visible to
    // callers checking window.api.mode after a fallback. Using a getter ensures
    // api.mode always returns the live current value of the closed-over variable.
    get mode() { return mode; },
    init: function () {
      return ensureDefaultAdminIfNeeded().then(function () {})
    },
    // Updated signIn to fetch the user by username first.
    // Password verification is now handled in app.js using verifyPassword()
    signIn: function (username) {
      if (mode === "firestore") {
        return db
          .collection("users")
          .where("username", "==", username)
          .limit(1)
          .get()
          .then(function (snap) {
            if (snap.empty) return null
            var doc = snap.docs[0]
            var u = doc.data()
            u.id = doc.id
            return u
          })
          .catch(function () {
            fallbackToLocal()
            var users = lsGet(LS.USERS, [])
            return users.find(function (x) { return x.username === username }) || null
          })
      } else {
        var users = lsGet(LS.USERS, [])
        return Promise.resolve(users.find(function (x) { return x.username === username }) || null)
      }
    },
    getUsers: function () {
      if (mode === "firestore") {
        return db
          .collection("users")
          .get()
          .then(function (snap) {
            return snap.docs.map(function (d) {
              var v = d.data()
              v.id = d.id
              return v
            })
          })
          .catch(function () {
            fallbackToLocal()
            return lsGet(LS.USERS, [])
          })
      } else {
        return Promise.resolve(lsGet(LS.USERS, []))
      }
    },
    createUser: function (user) {
      if (mode === "firestore") {
        var docId = user.id || ("user_" + Math.random().toString(36).slice(2, 9))
        var userData = Object.assign({}, user, { id: docId })
        return db
          .collection("users")
          .doc(docId)
          .set(userData)
          .then(function () {
            return userData
          })
          .catch(function () {
            fallbackToLocal()
            var users = lsGet(LS.USERS, [])
            users.push(userData)
            lsSet(LS.USERS, users)
            return userData
          })
      } else {
        var users = lsGet(LS.USERS, [])
        users.push(user)
        lsSet(LS.USERS, users)
        return Promise.resolve(user)
      }
    },
    deleteUser: function (id) {
      if (mode === "firestore") {
        return db.collection("users").doc(id).delete().then(function() {
            var cached = lsGet(LS.USERS, [])
            cached = cached.filter(function (u) { return u.id !== id })
            lsSet(LS.USERS, cached)
        }).catch(function(err) {
            console.error("Delete failed", err)
            throw err
        })
      } else {
        var users = lsGet(LS.USERS, [])
        users = users.filter(function (u) { return u.id !== id })
        lsSet(LS.USERS, users)
        return Promise.resolve()
      }
    },
    updateUser: function (id, fields) {
      if (mode === "firestore") {
        return db.collection("users").doc(id).update(fields).catch(function () {
          fallbackToLocal()
          var users = lsGet(LS.USERS, [])
          var u = users.find(function (x) { return x.id === id })
          if (u) { Object.assign(u, fields); lsSet(LS.USERS, users) }
        })
      } else {
        var users = lsGet(LS.USERS, [])
        var u = users.find(function (x) { return x.id === id })
        if (u) { Object.assign(u, fields); lsSet(LS.USERS, users) }
        return Promise.resolve()
      }
    },
    updateUserPassword: function (id, password) {
      if (mode === "firestore") {
        return db.collection("users").doc(id).update({ password: password, mustChangePassword: false }).catch(function () {
          fallbackToLocal()
          var users = lsGet(LS.USERS, [])
          var u = users.find(function (x) { return x.id === id })
          if (u) {
            u.password = password
            u.mustChangePassword = false
            lsSet(LS.USERS, users)
          }
        })
      } else {
        var users = lsGet(LS.USERS, [])
        var u = users.find(function (x) { return x.id === id })
        if (u) {
          u.password = password
          u.mustChangePassword = false
          lsSet(LS.USERS, users)
        }
        return Promise.resolve()
      }
    },
    getMeetings: function () {
      if (mode === "firestore") {
        return db
          .collection("meetings")
          .get()
          .then(function (snap) {
            return snap.docs.map(function (d) {
              var v = d.data()
              v.id = d.id
              return v
            })
          })
          .catch(function () {
            fallbackToLocal()
            return lsGet(LS.MEETINGS, [])
          })
      } else {
        return Promise.resolve(lsGet(LS.MEETINGS, []))
      }
    },
    getCalendarHistory: function () {
      if (mode === "firestore") {
        return db
          .collection("calendar_history")
          .get()
          .then(function (snap) {
            return snap.docs.map(function (d) {
              var v = d.data()
              v.id = d.id
              return v
            })
          })
          .catch(function () {
            return []
          })
      } else {
        return Promise.resolve(lsGet(LS.HISTORY, []))
      }
    },
    addMeeting: function (meeting) {
      if (mode === "firestore") {
        return db
          .collection("meetings")
          .add(meeting)
          .then(function (ref) {
            return Object.assign({ id: ref.id }, meeting)
          })
          .catch(function () {
            fallbackToLocal()
            var list = lsGet(LS.MEETINGS, [])
            list.push(meeting)
            lsSet(LS.MEETINGS, list)
            return meeting
          })
      } else {
        var list = lsGet(LS.MEETINGS, [])
        list.push(meeting)
        lsSet(LS.MEETINGS, list)
        _notifyMeetingSubscribers()
        return Promise.resolve(meeting)
      }
    },
    updateMeeting: function (id, fields) {
      // Replaces all editable fields on an existing meeting document.
      // Called by the edit-meeting path in app.js after the user confirms changes.
      if (mode === "firestore") {
        // Build a clean payload — strip the Firestore doc id before writing
        var payload = Object.assign({}, fields)
        delete payload.id
        return db.collection("meetings").doc(id).update(payload)
          .then(function () {
            // Keep localStorage cache in sync so UI is consistent before the
            // onSnapshot fires with the updated document from Firestore.
            var list = lsGet(LS.MEETINGS, [])
            var idx = list.findIndex(function (m) { return m.id === id })
            if (idx >= 0) {
              list[idx] = Object.assign({}, list[idx], payload, { id: id })
              lsSet(LS.MEETINGS, list)
            }
          })
          .catch(function (err) {
            console.error("updateMeeting Firestore error:", err)
            // Fallback: write to localStorage so the change at least persists
            // on this device even if Firestore is unreachable.
            fallbackToLocal()
            var list = lsGet(LS.MEETINGS, [])
            var idx = list.findIndex(function (m) { return m.id === id })
            if (idx >= 0) {
              list[idx] = Object.assign({}, list[idx], fields, { id: id })
              lsSet(LS.MEETINGS, list)
            }
            _notifyMeetingSubscribers()
          })
      } else {
        var list = lsGet(LS.MEETINGS, [])
        var idx = list.findIndex(function (m) { return m.id === id })
        if (idx >= 0) {
          list[idx] = Object.assign({}, list[idx], fields, { id: id })
          lsSet(LS.MEETINGS, list)
        }
        _notifyMeetingSubscribers()
        return Promise.resolve()
      }
    },
    updateMeetingStatus: function (id, status, adminNote, extraFields) {
      if (mode === "firestore") {
        var payload = { status: status }
        if (typeof adminNote === "string") payload.adminNote = adminNote
        if (extraFields && typeof extraFields === "object") {
          Object.keys(extraFields).forEach(function (k) { payload[k] = extraFields[k] })
        }
        return db.collection("meetings").doc(id).update(payload).catch(function () {
          fallbackToLocal()
          var list = lsGet(LS.MEETINGS, [])
          var m = list.find(function (x) { return x.id === id })
          if (m) {
            m.status = status
            if (typeof adminNote === "string") m.adminNote = adminNote
            if (extraFields && typeof extraFields === "object") Object.assign(m, extraFields)
            lsSet(LS.MEETINGS, list)
          }
        })
      } else {
        var list = lsGet(LS.MEETINGS, [])
        var m = list.find(function (x) { return x.id === id })
        if (m) {
          m.status = status
          if (typeof adminNote === "string") m.adminNote = adminNote
          if (extraFields && typeof extraFields === "object") Object.assign(m, extraFields)
          lsSet(LS.MEETINGS, list)
        }
        _notifyMeetingSubscribers()
        return Promise.resolve()
      }
    },
    subscribeMeetings: function (cb) {
      if (mode === "firestore") {
        try {
          var unsub = db.collection("meetings").onSnapshot(
            function (snap) {
              var arr = snap.docs.map(function (d) {
                var v = d.data()
                v.id = d.id
                return v
              })
              cb(arr)
            },
            function () {
              fallbackToLocal()
              cb(lsGet(LS.MEETINGS, []))
            }
          )
          return unsub
        } catch (e) {
          fallbackToLocal()
          cb(lsGet(LS.MEETINGS, []))
          return function () {}
        }
      } else {
        _meetingSubscribers.push(cb)
        cb(lsGet(LS.MEETINGS, []))
        return function () {
          _meetingSubscribers = _meetingSubscribers.filter(function (fn) { return fn !== cb })
        }
      }
    },
    subscribeCalendarHistory: function (cb) {
      if (mode === "firestore") {
        try {
          var unsub = db.collection("calendar_history").onSnapshot(
            function (snap) {
              var arr = snap.docs.map(function (d) {
                var v = d.data()
                v.id = d.id
                return v
              })
              cb(arr)
            },
            function () {
              cb([])
            }
          )
          return unsub
        } catch (e) {
          cb([])
          return function () {}
        }
      } else {
        cb(lsGet(LS.HISTORY, []))
        return function () {}
      }
    },
    exportAndArchivePreviousMonth: function (range) {
      var startISO = range && range.startISO
      var endISO = range && range.endISO
      function inRange(dateIso) {
        return dateIso >= startISO && dateIso <= endISO
      }
      if (mode === "firestore") {
        return db
          .collection("meetings")
          .get()
          .then(function (snap) {
            var toArchive = []
            snap.forEach(function (doc) {
              var data = doc.data()
              if (data && inRange(data.date)) {
                toArchive.push({ id: doc.id, data: data })
              }
            })
            if (!toArchive.length) return { archived: 0 }
            var batch = db.batch()
            toArchive.forEach(function (item) {
              var d = item.data
              var color = d.color || statusToColor(d.status)
              var ts = firebase.firestore.Timestamp.fromDate(new Date(d.date + "T00:00:00"))
              var ref = db.collection("calendar_history").doc()
              batch.set(ref, { date: ts, color: color, archived: true })
              batch.delete(db.collection("meetings").doc(item.id))
            })
            return batch.commit().then(function () {
              return { archived: toArchive.length }
            })
          })
      } else {
        var list = lsGet(LS.MEETINGS, [])
        var history = lsGet(LS.HISTORY, [])
        var remain = []
        var count = 0
        list.forEach(function (m) {
          if (inRange(m.date)) {
            history.push({
              id: "hist_" + Math.random().toString(36).slice(2, 9),
              date: m.date,
              color: m.color || statusToColor(m.status),
              archived: true,
            })
            count++
          } else {
            remain.push(m)
          }
        })
        lsSet(LS.HISTORY, history)
        lsSet(LS.MEETINGS, remain)
        return Promise.resolve({ archived: count })
      }
    },
    _filterExpiredAnn: function (list) {
      var now = Date.now()
      return list.filter(function (a) {
        if (!a.expiresAt) return true
        return new Date(a.expiresAt).getTime() > now
      })
    },
    _purgeExpiredAnn: function () {
      if (mode !== "firestore") return
      var now = new Date().toISOString()
      db.collection("announcements").get()
        .then(function (snap) {
          var batch = db.batch()
          var count = 0
          snap.docs.forEach(function (d) {
            var data = d.data()
            if (data.expiresAt && data.expiresAt < now) {
              batch.delete(d.ref)
              count++
            }
          })
          if (count > 0) return batch.commit()
        })
        .catch(function () {})
    },
    getAnnouncements: function () {
      var self = this
      if (mode === "firestore") {
        return db.collection("announcements").orderBy("createdAt", "desc").get()
          .then(function (snap) {
            var list = snap.docs.map(function (d) { var v = d.data(); v.id = d.id; return v })
            return self._filterExpiredAnn(list)
          })
          .catch(function () {
            return self._filterExpiredAnn(lsGet(LS.ANNOUNCEMENTS, []).slice().reverse())
          })
      } else {
        return Promise.resolve(
          this._filterExpiredAnn(lsGet(LS.ANNOUNCEMENTS, []).slice().reverse())
        )
      }
    },
    addAnnouncement: function (ann) {
      var ANN_TTL_MS = 7 * 24 * 60 * 60 * 1000
      // Only apply the default 7-day TTL if the caller did not supply their own
      // expiresAt. Previously this always overwrote any custom expiry date.
      var enriched = Object.assign({}, ann, {
        expiresAt: ann.expiresAt || new Date(Date.now() + ANN_TTL_MS).toISOString()
      })
      if (mode === "firestore") {
        var docId = "ann_" + Date.now() + "_" + Math.random().toString(36).slice(2, 7)
        var withId = Object.assign({}, enriched, { id: docId })
        // Do NOT eagerly write to localStorage here — the subscribeAnnouncements
        // onSnapshot will fire and update localStorage automatically. Writing here
        // too causes the subscriber callback to fire twice (eager write triggers it
        // once, then the snapshot fires it again), which pushes 2 bell notifications
        // for the same announcement.
        return db.collection("announcements").doc(docId).set(withId)
          .then(function () {
            return withId
          })
          .catch(function (err) {
            console.error("addAnnouncement Firestore error:", err)
            var list = lsGet(LS.ANNOUNCEMENTS, [])
            var localAnn = Object.assign({}, enriched, { id: "ann_" + Date.now() })
            list.unshift(localAnn)
            lsSet(LS.ANNOUNCEMENTS, list)
            _notifyAnnSubscribers()
            return localAnn
          })
      } else {
        var list = lsGet(LS.ANNOUNCEMENTS, [])
        var localAnn = Object.assign({}, enriched, { id: "ann_" + Date.now() })
        list.unshift(localAnn)
        lsSet(LS.ANNOUNCEMENTS, list)
        _notifyAnnSubscribers()
        return Promise.resolve(localAnn)
      }
    },
    updateAnnouncement: function (id, fields) {
      if (mode === "firestore") {
        return db.collection("announcements").doc(id).update(fields).then(function () {
          // update local cache mirror
          var list = lsGet(LS.ANNOUNCEMENTS, [])
          var idx = list.findIndex(function (a) { return a.id === id })
          if (idx >= 0) {
            list[idx] = Object.assign({}, list[idx], fields)
            lsSet(LS.ANNOUNCEMENTS, list)
          }
        }).catch(function (err) {
          console.error("updateAnnouncement Firestore error:", err)
          // fallback to local
          fallbackToLocal()
          var list = lsGet(LS.ANNOUNCEMENTS, [])
          var idx = list.findIndex(function (a) { return a.id === id })
          if (idx >= 0) {
            list[idx] = Object.assign({}, list[idx], fields)
            lsSet(LS.ANNOUNCEMENTS, list)
          }
          _notifyAnnSubscribers()
        })
      } else {
        var list = lsGet(LS.ANNOUNCEMENTS, [])
        var idx = list.findIndex(function (a) { return a.id === id })
        if (idx >= 0) {
          list[idx] = Object.assign({}, list[idx], fields)
          lsSet(LS.ANNOUNCEMENTS, list)
        }
        _notifyAnnSubscribers()
        return Promise.resolve()
      }
    },
    deleteAnnouncement: function (id) {
      if (mode === "firestore") {
        return db.collection("announcements").doc(id).delete().then(function() {
            var list = lsGet(LS.ANNOUNCEMENTS, []).filter(function (a) { return a.id !== id })
            lsSet(LS.ANNOUNCEMENTS, list)
        }).catch(function(err) {
            console.error("deleteAnnouncement Error", err)
            throw err
        })
      } else {
        var list = lsGet(LS.ANNOUNCEMENTS, []).filter(function (a) { return a.id !== id })
        lsSet(LS.ANNOUNCEMENTS, list)
        _notifyAnnSubscribers()
        return Promise.resolve()
      }
    },
    deleteMeeting: function (id) {
      if (mode === "firestore") {
        return db.collection("meetings").doc(id).delete().then(function () {
          var list = lsGet(LS.MEETINGS, []).filter(function (m) { return m.id !== id })
          lsSet(LS.MEETINGS, list)
        }).catch(function (err) {
          console.error("deleteMeeting Error", err)
          // fallback to local
          fallbackToLocal()
          var list = lsGet(LS.MEETINGS, []).filter(function (m) { return m.id !== id })
          lsSet(LS.MEETINGS, list)
          _notifyMeetingSubscribers()
        })
      } else {
        var list = lsGet(LS.MEETINGS, []).filter(function (m) { return m.id !== id })
        lsSet(LS.MEETINGS, list)
        _notifyMeetingSubscribers()
        return Promise.resolve()
      }
    },
    _notifyMeetings: function () { _notifyMeetingSubscribers() },
    // ── Notifications (Firestore-backed so they sync across devices/tabs) ────
    // In local mode, falls back to localStorage exactly as before.
    saveNotification: function (notif) {
      if (mode === "firestore") {
        var docId = notif.id || ("notif_" + Date.now() + "_" + Math.random().toString(36).slice(2,7))
        var withId = Object.assign({}, notif, { id: docId })
        // Do NOT write to localStorage here — subscribeNotifications will sync
        // the Firestore doc back into localStorage automatically. Writing here
        // too causes duplicate notifications in the bell panel.
        return db.collection("notifications").doc(docId).set(withId).catch(function () {
          // Firestore write failed — fall back to localStorage so the notification isn't lost
          var all = lsGet("sbp_notifications", [])
          var alreadyExists = all.some(function(n) { return n.userId === notif.userId && n.message === notif.message })
          if (!alreadyExists) {
            all.unshift(notif)
            lsSet("sbp_notifications", all.slice(0, 200))
          }
        })
      } else {
        var all = lsGet("sbp_notifications", [])
        all.unshift(notif)
        lsSet("sbp_notifications", all.slice(0, 200))
        return Promise.resolve()
      }
    },
    getNotificationsForUser: function (userId) {
      if (mode === "firestore") {
        // No orderBy — avoids requiring a composite index. Sort in JS instead.
        return db.collection("notifications")
          .where("userId", "==", userId)
          .limit(50)
          .get()
          .then(function (snap) {
            var list = snap.docs.map(function (d) { var v = d.data(); v.id = d.id; return v })
            list.sort(function (a, b) { return (b.createdAt || "").localeCompare(a.createdAt || "") })
            return list
          })
          .catch(function () {
            return lsGet("sbp_notifications", []).filter(function (n) { return n.userId === userId })
          })
      } else {
        return Promise.resolve(lsGet("sbp_notifications", []).filter(function (n) { return n.userId === userId }))
      }
    },
    markNotificationsRead: function (userId) {
      if (mode === "firestore") {
        // Single where() only — no composite index needed.
        // Filter unread in JS after fetching.
        return db.collection("notifications")
          .where("userId", "==", userId)
          .get()
          .then(function (snap) {
            var unread = snap.docs.filter(function (d) { return d.data().read === false })
            if (!unread.length) return
            var batch = db.batch()
            unread.forEach(function (d) { batch.update(d.ref, { read: true }) })
            return batch.commit()
          })
          .catch(function () {})
      } else {
        var all = lsGet("sbp_notifications", [])
        all.forEach(function (n) { if (n.userId === userId) n.read = true })
        lsSet("sbp_notifications", all)
        return Promise.resolve()
      }
    },
    subscribeNotifications: function (userId, cb) {
      if (mode === "firestore") {
        try {
          // No orderBy — avoids requiring a composite index. Sort in JS instead.
          // A single-field where() query on "userId" works with no index at all.
          return db.collection("notifications")
            .where("userId", "==", userId)
            .limit(50)
            .onSnapshot(
              function (snap) {
                var list = snap.docs.map(function (d) { var v = d.data(); v.id = d.id; return v })
                list.sort(function (a, b) { return (b.createdAt || "").localeCompare(a.createdAt || "") })
                cb(list)
              },
              function (err) {
                console.warn("subscribeNotifications fallback to localStorage:", err.message)
                cb(lsGet("sbp_notifications", []).filter(function (n) { return n.userId === userId }))
              }
            )
        } catch (e) {
          cb(lsGet("sbp_notifications", []).filter(function (n) { return n.userId === userId }))
          return function () {}
        }
      } else {
        cb(lsGet("sbp_notifications", []).filter(function (n) { return n.userId === userId }))
        return function () {}
      }
    },
    // ── Notification last-seen timestamp ────────────────────────────────────
    // Stores { userId, lastSeenAt } in the "notif_seen" Firestore collection.
    // This ensures the "already read" state survives logout, device switches,
    // and localStorage clears — the badge never re-inflates for old notifications.
    setNotifLastSeen: function (userId, isoTimestamp) {
      if (mode === "firestore") {
        return db.collection("notif_seen").doc(userId).set({ userId: userId, lastSeenAt: isoTimestamp })
          .catch(function () {
            // Graceful fallback — localStorage is already updated by app.js
          });
      }
      return Promise.resolve();
    },
    getNotifLastSeen: function (userId) {
      if (mode === "firestore") {
        return db.collection("notif_seen").doc(userId).get()
          .then(function (doc) {
            if (doc.exists) return doc.data().lastSeenAt || null;
            return null;
          })
          .catch(function () { return null; });
      }
      return Promise.resolve(null);
    },
    subscribeUsers: function (cb) {
      if (mode === "firestore") {
        try {
          var unsub = db.collection("users").onSnapshot(
            function (snap) {
              var arr = snap.docs.map(function (d) {
                var v = d.data()
                v.id = d.id
                return v
              })
              cb(arr)
            },
            function (err) {
              console.warn("subscribeUsers snapshot error:", err)
              fallbackToLocal()
              cb(lsGet(LS.USERS, []))
            }
          )
          return unsub
        } catch (e) {
          fallbackToLocal()
          cb(lsGet(LS.USERS, []))
          return function () {}
        }
      } else {
        cb(lsGet(LS.USERS, []))
        return function () {}
      }
    },
    subscribeAnnouncements: function (cb) {
      var self = this
      if (mode === "firestore") {
        self._purgeExpiredAnn()
        try {
          return db.collection("announcements").orderBy("createdAt", "desc").onSnapshot(
            function (snap) {
              var list = snap.docs.map(function (d) { var v = d.data(); v.id = d.id; return v })
              var active = self._filterExpiredAnn(list)
              lsSet(LS.ANNOUNCEMENTS, active)
              cb(active)
            },
            function (err) {
              console.warn("subscribeAnnouncements snapshot error:", err)
              cb(self._filterExpiredAnn(lsGet(LS.ANNOUNCEMENTS, []).slice().reverse()))
            }
          )
        } catch (e) {
          cb(self._filterExpiredAnn(lsGet(LS.ANNOUNCEMENTS, []).slice().reverse()))
          return function () {}
        }
      } else {
        _annSubscribers.push(cb)
        cb(self._filterExpiredAnn(lsGet(LS.ANNOUNCEMENTS, []).slice().reverse()))
        return function () {
          _annSubscribers = _annSubscribers.filter(function (fn) { return fn !== cb })
        }
      }
    },
  }
  window.api = api
})()