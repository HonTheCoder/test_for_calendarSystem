;(function () {
  function hasFirebase() {
    return typeof firebase !== "undefined" && !!firebase.initializeApp
  }
  function getConfig() {
    return typeof window.__FIREBASE_CONFIG__ === "object"
      ? window.__FIREBASE_CONFIG__
      : null
  }
  var mode = "local"
  var db = null
  var fellBack = false
  if (hasFirebase() && getConfig()) {
    try {
      var app = firebase.initializeApp(getConfig())
      db = firebase.firestore(app)
      mode = "firestore"
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
  }
  function statusToColor(status) {
    if (status === "Approved") return "#16a34a"
    if (status === "Pending") return "#f59e0b"
    if (status === "Cancelled" || status === "Rejected") return "#dc2626"
    return "#3b82f6"
  }
  function ensureDefaultAdminIfNeeded() {
    var DEFAULT_ADMIN = {
      id: "admin",
      username: "sb_adminpolangui",
      password: "41e5653fc7aeb894026d6bb7b2db7f65902b454945fa8fd65a6327047b5277fb",
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
            return db.collection("users").add(DEFAULT_ADMIN)
          }
        })
        .catch(function () {
          fallbackToLocal()
          var users = lsGet(LS.USERS, [])
          if (!users.some(function (u) { return u.username === DEFAULT_ADMIN.username })) {
            users.push(DEFAULT_ADMIN)
            lsSet(LS.USERS, users)
          }
        })
    } else {
      var users = lsGet(LS.USERS, [])
      if (!users.some(function (u) { return u.username === DEFAULT_ADMIN.username })) {
        users.push(DEFAULT_ADMIN)
        lsSet(LS.USERS, users)
      }
      return Promise.resolve()
    }
  }
  var api = {
    mode: mode,
    init: function () {
      return ensureDefaultAdminIfNeeded().then(function () {})
    },
    signIn: function (username, hashedPassword) {
      if (mode === "firestore") {
        return db
          .collection("users")
          .where("username", "==", username)
          .where("password", "==", hashedPassword)
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
            var u = users.find(function (x) {
              return x.username === username && x.password === hashedPassword
            })
            return u || null
          })
      } else {
        var users = lsGet(LS.USERS, [])
        var u = users.find(function (x) {
          return x.username === username && x.password === hashedPassword
        })
        return Promise.resolve(u || null)
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
        return db
          .collection("users")
          .add(user)
          .then(function (ref) {
            return Object.assign({ id: ref.id }, user)
          })
          .catch(function () {
            fallbackToLocal()
            var users = lsGet(LS.USERS, [])
            users.push(user)
            lsSet(LS.USERS, users)
            return user
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
        return db.collection("users").doc(id).delete().catch(function () {
          fallbackToLocal()
          var users = lsGet(LS.USERS, [])
          users = users.filter(function (u) {
            return u.id !== id
          })
          lsSet(LS.USERS, users)
        })
      } else {
        var users = lsGet(LS.USERS, [])
        users = users.filter(function (u) {
          return u.id !== id
        })
        lsSet(LS.USERS, users)
        return Promise.resolve()
      }
    },
    updateUserPassword: function (id, password) {
      if (mode === "firestore") {
        return db.collection("users").doc(id).update({ password: password, mustChangePassword: false }).catch(function () {
          fallbackToLocal()
          var users = lsGet(LS.USERS, [])
          var u = users.find(function (x) {
            return x.id === id
          })
          if (u) {
            u.password = password
            u.mustChangePassword = false
            lsSet(LS.USERS, users)
          }
        })
      } else {
        var users = lsGet(LS.USERS, [])
        var u = users.find(function (x) {
          return x.id === id
        })
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
        return Promise.resolve(meeting)
      }
    },
    updateMeetingStatus: function (id, status, adminNote) {
      if (mode === "firestore") {
        var payload = { status: status }
        if (typeof adminNote === "string") payload.adminNote = adminNote
        return db.collection("meetings").doc(id).update(payload).catch(function () {
          fallbackToLocal()
          var list = lsGet(LS.MEETINGS, [])
          var m = list.find(function (x) {
            return x.id === id
          })
          if (m) {
            m.status = status
            if (typeof adminNote === "string") m.adminNote = adminNote
            lsSet(LS.MEETINGS, list)
          }
        })
      } else {
        var list = lsGet(LS.MEETINGS, [])
        var m = list.find(function (x) {
          return x.id === id
        })
        if (m) {
          m.status = status
          if (typeof adminNote === "string") m.adminNote = adminNote
          lsSet(LS.MEETINGS, list)
        }
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
        cb(lsGet(LS.MEETINGS, []))
        return function () {}
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
      // range: { startISO, endISO }
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
  }
  window.api = api
})()