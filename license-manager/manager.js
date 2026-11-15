const $ = id => document.getElementById(id);
const state = { api: "", admin: "", licenses: [] };
const message = text => { $("message").textContent = text; };

function validatedApi(value) {
  let url;
  try { url = new URL(value.trim()); }
  catch { throw new Error("أدخل رابط API صالحًا."); }
  if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash) {
    throw new Error("يجب أن يكون الرابط HTTPS ومن دون بيانات اعتماد أو معاملات.");
  }
  return url.origin + url.pathname.replace(/\/+$/, "");
}

function saveApiUrl() {
  state.api = validatedApi($("api").value);
  localStorage.setItem("sana-license-api-url", state.api);
}

function requireApi() {
  if (!state.api) saveApiUrl();
  return state.api;
}

function requireAdmin() {
  if (!state.admin) throw new Error("أدخل مفتاح الإدارة ثم اضغط «حفظ الرابط والاتصال».");
}

async function apiCall(path, { method = "GET", body, admin = true } = {}) {
  const root = requireApi();
  if (admin) requireAdmin();
  let response;
  try {
    response = await fetch(root + path, {
      method,
      credentials: "omit",
      cache: "no-store",
      signal: AbortSignal.timeout(15000),
      headers: { ...(body === undefined ? {} : { "Content-Type": "application/json" }), ...(admin ? { Authorization: `Bearer ${state.admin}` } : {}) },
      body: body === undefined ? undefined : JSON.stringify(body)
    });
  } catch (error) {
    if (error.name === "TimeoutError") throw new Error("انتهت مهلة الاتصال بالخادم.");
    throw new Error("تعذر الاتصال بالخادم. تحقق من الإنترنت والرابط وإعداد CORS.");
  }
  let data;
  try { data = await response.json(); }
  catch { throw new Error(`أعاد الخادم استجابة غير مفهومة (HTTP ${response.status}).`); }
  if (!response.ok) {
    if (response.status === 401) throw new Error("رفض الخادم مفتاح الإدارة. تحقق من المفتاح.");
    if (response.status === 429) throw new Error("طلبات كثيرة خلال وقت قصير. انتظر قليلًا ثم أعد المحاولة.");
    throw new Error(data.error || `فشل الطلب (HTTP ${response.status}).`);
  }
  return data;
}

function setServerStatus(online, text) {
  const el = $("server-status");
  el.textContent = text;
  el.className = `status ${online ? "online" : "offline"}`;
}

async function checkHealth() {
  try {
    const result = await apiCall("/health", { admin: false });
    setServerStatus(true, result.database === "connected" ? "متصل وقاعدة البيانات جاهزة" : "الخادم متصل");
    return true;
  } catch (error) {
    setServerStatus(false, "غير متصل");
    message(error.message);
    return false;
  }
}

function dateText(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString("ar");
}

function cell(row, text, className = "") {
  const td = document.createElement("td");
  td.textContent = text;
  if (className) td.className = className;
  row.append(td);
  return td;
}

function statusLabel(status) { return status === "revoked" ? "ملغى" : "نشط"; }

function makeActionButton(label, className, handler) {
  const button = document.createElement("button");
  button.type = "button";
  button.textContent = label;
  if (className) button.className = className;
  button.addEventListener("click", () => handler(button));
  return button;
}

async function runAction(button, action) {
  button.disabled = true;
  try { await action(); }
  catch (error) { message(error.message); }
  finally { button.disabled = false; }
}

async function revokeLicense(license) {
  if (!confirm(`هل توافق على إلغاء الترخيص ${license.id}؟`)) return;
  const result = await apiCall(`/v1/admin/licenses/${encodeURIComponent(license.id)}/revoke`, { method: "POST" });
  message(result.ok ? "تم إلغاء الترخيص." : "لم يتغير الترخيص؛ ربما أُلغي سابقًا.");
  await refreshAll();
}

async function transferLicense(license) {
  const reason = prompt("اكتب سبب نقل الترخيص. سيُسجل السبب في سجل العمليات:");
  if (reason === null) return;
  if (reason.trim().length < 3) throw new Error("اكتب سببًا من ثلاثة أحرف على الأقل.");
  if (!confirm("تأكيد موافقة المدير على فك ربط الجهاز الحالي؟")) return;
  const result = await apiCall(`/v1/admin/licenses/${encodeURIComponent(license.id)}/transfer`, {
    method: "POST", body: { approved: true, reason: reason.trim() }
  });
  message(result.ok ? "تمت الموافقة على النقل وفك ارتباط الجهاز. يمكن تفعيل الترخيص على الجهاز الجديد." : "لم يتغير الترخيص؛ تحقق من حالته.");
  await refreshAll();
}

function renderLicenses() {
  const body = $("licenses");
  body.replaceChildren();
  if (!state.licenses.length) {
    const tr = document.createElement("tr");
    const td = cell(tr, "لا توجد تراخيص تطابق البحث.", "muted");
    td.colSpan = 5;
    body.append(tr);
    return;
  }
  for (const license of state.licenses) {
    const tr = document.createElement("tr");
    const status = document.createElement("td");
    const badge = document.createElement("span"); badge.className = "badge"; badge.textContent = statusLabel(license.status); status.append(badge); tr.append(status);
    cell(tr, dateText(license.createdAt));
    cell(tr, dateText(license.activatedAt));
    cell(tr, license.deviceKeyHash || "غير مفعّل", "device");
    const actions = document.createElement("td");
    if (license.status === "active") {
      if (license.deviceKeyHash) actions.append(makeActionButton("نقل", "", button => runAction(button, () => transferLicense(license))));
      const revoke = makeActionButton("إلغاء", "danger", button => runAction(button, () => revokeLicense(license)));
      actions.append(revoke);
    } else actions.textContent = "—";
    tr.append(actions);
    body.append(tr);
  }
}

const auditLabels = {
  issue: "إصدار", activation_challenge: "طلب إثبات الجهاز", activation_proof_rejected: "رفض إثبات الجهاز",
  activation_denied: "رفض التفعيل", activate: "تفعيل", verification_challenge: "طلب تحقق الجهاز",
  revoke: "إلغاء", transfer: "نقل"
};
async function loadAudit() {
  const result = await apiCall("/v1/admin/audit?limit=100");
  const body = $("audit");
  body.replaceChildren();
  if (!result.events.length) {
    const tr = document.createElement("tr");
    const td = cell(tr, "لا توجد عمليات مسجلة.", "muted"); td.colSpan = 4; body.append(tr); return;
  }
  for (const event of result.events) {
    const tr = document.createElement("tr");
    cell(tr, auditLabels[event.action] || event.action);
    cell(tr, event.licenseId || "—", "device");
    cell(tr, dateText(event.createdAt));
    cell(tr, Object.keys(event.details || {}).length ? JSON.stringify(event.details) : "—");
    body.append(tr);
  }
}

async function refreshLicenses() {
  const query = new URLSearchParams();
  const status = $("status").value;
  const search = $("search").value.trim();
  if (status) query.set("status", status);
  if (search) query.set("q", search);
  const queryText = query.toString();
  const result = await apiCall(`/v1/admin/licenses${queryText ? `?${queryText}` : ""}`);
  state.licenses = result.licenses;
  renderLicenses();
}

async function refreshAll() {
  await refreshLicenses();
  await loadAudit();
}

$("connect").addEventListener("click", async () => {
  try {
    saveApiUrl();
    const entered = $("admin").value.trim();
    if (entered) state.admin = entered;
    $("admin").value = "";
    message("تم حفظ رابط API في هذا الجهاز. مفتاح الإدارة محفوظ في الذاكرة لهذه الجلسة فقط.");
    const online = await checkHealth();
    if (online && state.admin) await refreshAll();
  } catch (error) { message(error.message); }
});

$("health").addEventListener("click", async () => {
  try { if (!state.api) saveApiUrl(); await checkHealth(); }
  catch (error) { message(error.message); }
});

$("disconnect").addEventListener("click", () => {
  state.admin = "";
  state.licenses = [];
  $("admin").value = "";
  renderLicenses();
  $("audit").replaceChildren();
  setServerStatus(false, "انتهت جلسة الإدارة");
  message("تم مسح مفتاح الإدارة والبيانات المعروضة من الذاكرة.");
});

$("issue").addEventListener("click", async event => {
  const button = event.currentTarget;
  await runAction(button, async () => {
    const count = Number($("count").value);
    if (!Number.isInteger(count) || count < 1 || count > 50) throw new Error("اختر عددًا صحيحًا بين 1 و50.");
    const result = await apiCall("/v1/admin/licenses", { method: "POST", body: { count } });
    const output = $("issued"); output.replaceChildren();
    for (const license of result.licenses) {
      const row = document.createElement("div"); row.className = "row";
      const key = document.createElement("div"); key.className = "key"; key.textContent = license.licenseKey;
      const copy = makeActionButton("نسخ المفتاح", "", async button => {
        try { await navigator.clipboard.writeText(license.licenseKey); message("تم نسخ المفتاح."); }
        catch { message("تعذر النسخ تلقائيًا؛ انسخ المفتاح يدويًا."); }
      });
      row.append(key, copy); output.append(row);
    }
    message(`تم إصدار ${result.licenses.length} مفتاحًا. انسخها الآن؛ لن يعيد الخادم عرضها.`);
    await refreshAll();
  });
});

$("refresh").addEventListener("click", event => runAction(event.currentTarget, refreshAll));
$("status").addEventListener("change", () => runAction($("refresh"), refreshLicenses));
$("search").addEventListener("change", () => runAction($("refresh"), refreshLicenses));

const storedApi = localStorage.getItem("sana-license-api-url");
if (storedApi) {
  try { state.api = validatedApi(storedApi); $("api").value = state.api; }
  catch { localStorage.removeItem("sana-license-api-url"); }
}
window.addEventListener("beforeunload", () => { state.admin = ""; });
