// Cloud Functions sample for secureAddAdmin (HTTPS Callable)
// Place this inside your Firebase Functions index.js (or as a module you import).
// Requires: firebase-admin initialized, firebase-functions
const functions = require("firebase-functions");
const admin = require("firebase-admin");

if (!admin.apps.length) {
  admin.initializeApp();
}

exports.secureAddAdmin = functions.https.onCall(async (data, context) => {
  if (!context.auth || !context.auth.token || context.auth.token.admin !== true) {
    throw new functions.https.HttpsError("permission-denied", "Unauthorized");
  }
  const targetEmail = String(data.email || "").trim().toLowerCase();
  const reason = String(data.reason || "").trim();
  if (!targetEmail || !reason) {
    throw new functions.https.HttpsError("invalid-argument", "email and reason are required");
  }

  const requesterEmail = context.auth.token.email || "unknown";
  const raw = context.rawRequest;
  const ip =
    (raw && (raw.headers["x-forwarded-for"] || raw.headers["x-appengine-user-ip"])) ||
    (raw && raw.ip) ||
    "unknown";

  const userRecord = await admin.auth().getUserByEmail(targetEmail);
  await admin.auth().setCustomUserClaims(userRecord.uid, { admin: true });

  const log = {
    created_by_email: requesterEmail,
    new_admin_email: targetEmail,
    reason_for_access: reason,
    timestamp: admin.firestore.FieldValue.serverTimestamp(),
    ip_address: String(ip),
  };
  await admin.firestore().collection("admin_audit_logs").add(log);

  return { success: true, new_admin_email: targetEmail };
});
