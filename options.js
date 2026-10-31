const $ = selector => document.querySelector(selector);
const DEFAULTS = {
  settings: { enabled: false, whitelistHistory: {}, inheritTabs: {}, ruleNames: {}, ruleTypes: {}, ruleRegex: {}, theme: "auto", historyLimit: 100 },
  lists: { blacklist: [], whitelist: [] },
  vault: { publicKey: "", encryptedPrivateKey: "", records: [] }
};

let state = structuredClone(DEFAULTS);
let activeTab = "blacklist";
let privateKey = null;
let editingRule = null;
let decryptedHistory = null;

function encode(value) {
  return btoa(String.fromCharCode(...new Uint8Array(value)));
}

function decode(value) {
  return Uint8Array.from(atob(value), char => char.charCodeAt(0));
}

function pemToBytes(pem) {
  return decode(pem.replace(/-----[^-]+-----/g, "").replace(/\s/g, ""));
}

function bytesToPem(value, label) {
  const base64 = encode(value).match(/.{1,64}/g).join("\n");
  return `-----BEGIN ${label}-----\n${base64}\n-----END ${label}-----`;
}

async function derivePasswordKey(password, salt) {
  const material = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 250000, hash: "SHA-256" },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptPrivateKey(pem, password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await derivePasswordKey(password, salt);
  const data = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    new TextEncoder().encode(pem)
  );
  return { salt: encode(salt), iv: encode(iv), data: encode(data) };
}

async function unlockPrivateKey(password) {
  const encrypted = state.vault.encryptedPrivateKey;
  const key = await derivePasswordKey(password, decode(encrypted.salt));
  const pem = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: decode(encrypted.iv) },
    key,
    decode(encrypted.data)
  );
  return crypto.subtle.importKey(
    "pkcs8",
    pemToBytes(new TextDecoder().decode(pem)),
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["decrypt"]
  );
}

async function createVault(password) {
  const pair = await crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256"
    },
    true,
    ["encrypt", "decrypt"]
  );
  const publicKey = bytesToPem(await crypto.subtle.exportKey("spki", pair.publicKey), "PUBLIC KEY");
  const privatePem = bytesToPem(await crypto.subtle.exportKey("pkcs8", pair.privateKey), "PRIVATE KEY");
  return {
    publicKey,
    publicCryptoKey: pair.publicKey,
    encryptedPrivateKey: await encryptPrivateKey(privatePem, password),
    privateKey: pair.privateKey
  };
}

async function migrateLegacyRecord(record, oldKeyBase64, publicKey) {
  const oldKey = await crypto.subtle.importKey("raw", decode(oldKeyBase64), "AES-GCM", false, ["decrypt"]);
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: decode(record.iv) },
    oldKey,
    decode(record.data)
  );
  const rawKey = crypto.getRandomValues(new Uint8Array(32));
  const aesKey = await crypto.subtle.importKey("raw", rawKey, "AES-GCM", false, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, plaintext);
  const key = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, publicKey, rawKey);
  return { iv: encode(iv), key: encode(key), data: encode(data) };
}

async function decryptRecord(record) {
  const rawKey = await crypto.subtle.decrypt(
    { name: "RSA-OAEP" },
    privateKey,
    decode(record.key)
  );
  const key = await crypto.subtle.importKey("raw", rawKey, "AES-GCM", false, ["decrypt"]);
  const data = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: decode(record.iv) },
    key,
    decode(record.data)
  );
  return JSON.parse(new TextDecoder().decode(data));
}

function setAuthView(mode, message = "") {
  const setup = mode === "setup";
  decryptedHistory = null;
  $("#history-search").value = "";
  $("#history").replaceChildren();
  document.body.classList.add("locked");
  $("#auth").hidden = false;
  $("#auth-title").textContent = setup ? "Set a password" : "Unlock history";
  $("#auth-description").textContent = setup
    ? "Create a password to protect hidden history."
    : "Enter your password to view hidden history.";
  $("#password").value = "";
  $("#password").minLength = setup ? 8 : 1;
  $("#password").autocomplete = setup ? "new-password" : "current-password";
  $("#password-confirm").hidden = !setup;
  $("#password-confirm").required = setup;
  $("#password-confirm").value = "";
  $("#auth-submit").textContent = setup ? "Create password" : "Unlock";
  $("#auth-error").textContent = message;
}

function showApp() {
  document.body.classList.remove("locked");
  $("#auth").hidden = true;
  $("#lock").hidden = false;
  void render();
}

async function load() {
  const data = await chrome.storage.local.get(DEFAULTS);
  state = {
    settings: { ...DEFAULTS.settings, ...data.settings },
    lists: { ...DEFAULTS.lists, ...data.lists },
    vault: { ...DEFAULTS.vault, ...data.vault }
  };
  state.settings.whitelistHistory = { ...(state.settings.whitelistHistory || {}) };
  state.settings.inheritTabs = { ...(state.settings.inheritTabs || {}) };
  state.settings.ruleNames = { ...(state.settings.ruleNames || {}) };
  state.settings.ruleTypes = { ...(state.settings.ruleTypes || {}) };
  state.settings.historyLimit = normalizeHistoryLimit(state.settings.historyLimit);
  applyTheme();
  for (const [rule, isRegex] of Object.entries(state.settings.ruleRegex || {})) {
    if (isRegex && !state.settings.ruleTypes[rule]) state.settings.ruleTypes[rule] = "regex";
  }
  delete state.settings.ruleRegex;
  if (data.settings?.saveWhitelistHistory === false) {
    for (const domain of state.lists.whitelist) {
      if (!(domain in state.settings.whitelistHistory)) state.settings.whitelistHistory[domain] = false;
    }
    delete state.settings.saveWhitelistHistory;
  }
  if (!state.vault.encryptedPrivateKey) {
    $("#lock").hidden = true;
    setAuthView("setup");
  } else if (privateKey) {
    showApp();
  } else {
    $("#lock").hidden = true;
    setAuthView("unlock");
  }
}

async function render() {
  applyTheme();
  $("#enabled").checked = state.settings.enabled;
  $("#theme").value = ["auto", "light", "dark"].includes(state.settings.theme)
    ? state.settings.theme
    : "auto";
  $("#history-limit").value = state.settings.historyLimit;
  $("#mode").textContent = state.settings.enabled ? "On" : "Off";
  $("#blacklist-count").textContent = state.lists.blacklist.length;
  $("#whitelist-count").textContent = state.lists.whitelist.length;
  $("[data-tab=blacklist]").classList.toggle("active", activeTab === "blacklist");
  $("[data-tab=whitelist]").classList.toggle("active", activeTab === "whitelist");
  const domains = state.lists[activeTab];
  $("#domains").innerHTML = domains.length
    ? domains.map(rule => `<div class="domain-row"><span>${escapeHtml(state.settings.ruleNames[rule] || rule)}</span><button data-edit="${escapeHtml(rule)}">Edit</button></div>`).join("")
    : '<div class="empty">No domains in this list.</div>';

  await renderHistory();
}

async function renderHistory() {
  const history = $("#history");
  if (!state.vault.records.length) {
    decryptedHistory = [];
    history.innerHTML = '<div class="empty">No hidden visits yet.</div>';
    return;
  }
  if (decryptedHistory === null) {
    const results = await Promise.allSettled(state.vault.records.map(decryptRecord));
    decryptedHistory = results.map((result, index) => ({
      index,
      item: result.status === "fulfilled" ? result.value : null
    }));
  }
  const query = $("#history-search").value.trim().toLocaleLowerCase();
  const matches = decryptedHistory.filter(({ item }) => !query || !item ||
    `${item.title || ""}\n${item.url || ""}`.toLocaleLowerCase().includes(query));
  if (!matches.length) {
    history.innerHTML = '<div class="empty">No visits match your search.</div>';
    return;
  }
  history.innerHTML = matches.map(({ index, item }) => {
    const removeButton = `<button class="history-delete" type="button" data-remove-history="${index}" aria-label="Remove this hidden visit">Remove</button>`;
    if (!item) return `<div class="history-row"><div class="history-entry"><span>Unable to decrypt this visit.</span></div>${removeButton}</div>`;
    const title = escapeHtml(item.title || item.url);
    const link = canOpenHistoryUrl(item.url)
      ? `<a href="${escapeHtml(item.url)}" target="_blank" rel="noopener">${title}</a>`
      : `<span>${title}</span>`;
    return `<div class="history-row"><div class="history-entry">${link}<time>${new Date(item.time).toLocaleString()}</time></div>${removeButton}</div>`;
  }).join("");
}

function normalizeHistoryLimit(value) {
  const limit = Number(value);
  return Number.isInteger(limit) ? Math.min(10000, Math.max(1, limit)) : 100;
}

function applyTheme() {
  const theme = state.settings.theme || "auto";
  document.documentElement.dataset.theme = theme === "auto"
    ? window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light"
    : theme;
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, char => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  })[char]);
}

function canOpenHistoryUrl(value) {
  try {
    const url = new URL(value);
    return ["http:", "https:"].includes(url.protocol) ||
      url.protocol === "chrome-extension:" && url.host === chrome.runtime.id;
  } catch {
    return false;
  }
}

async function saveRules() {
  await chrome.storage.local.set({ settings: state.settings, lists: state.lists });
  await render();
}

$("#auth-form").addEventListener("submit", async event => {
  event.preventDefault();
  $("#auth-submit").disabled = true;
  $("#auth-error").textContent = "";
  const password = $("#password").value;
  try {
    if (!state.vault.encryptedPrivateKey) {
      if (password !== $("#password-confirm").value) throw new Error("Passwords do not match.");
      const vault = await createVault(password);
      const legacyKey = state.vault.key;
      if (legacyKey) {
        state.vault.records = await Promise.all(state.vault.records.map(record =>
          record.key ? record : migrateLegacyRecord(record, legacyKey, vault.publicCryptoKey)
        ));
        delete state.vault.key;
      }
      privateKey = vault.privateKey;
      state.vault.publicKey = vault.publicKey;
      state.vault.encryptedPrivateKey = vault.encryptedPrivateKey;
      await chrome.storage.local.set({ vault: state.vault });
    } else {
      privateKey = await unlockPrivateKey(password);
    }
    $("#password").value = "";
    showApp();
  } catch (error) {
    privateKey = null;
    const message = error instanceof Error && error.message === "Passwords do not match."
      ? error.message
      : state.vault.encryptedPrivateKey ? "Incorrect password." : "Could not create password protection.";
    setAuthView(state.vault.encryptedPrivateKey ? "unlock" : "setup", message);
  } finally {
    $("#auth-submit").disabled = false;
  }
});

$("#lock").addEventListener("click", () => {
  privateKey = null;
  setAuthView("unlock");
});
$("#enabled").addEventListener("change", () => {
  state.settings.enabled = $("#enabled").checked;
  void saveRules();
});
$("#theme").addEventListener("change", () => {
  state.settings.theme = $("#theme").value;
  applyTheme();
  void saveRules();
});
window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => {
  if ((state.settings.theme || "auto") === "auto") applyTheme();
});
$("#save").addEventListener("click", () => void saveRules());
document.querySelectorAll("[data-tab]").forEach(button => button.addEventListener("click", () => {
  activeTab = button.dataset.tab;
  void render();
}));
$("#clear-history").addEventListener("click", async () => {
  state.vault.records = [];
  decryptedHistory = [];
  await chrome.storage.local.set({ vault: state.vault });
  await render();
});
$("#history-search").addEventListener("input", () => void renderHistory());
$("#history").addEventListener("click", async event => {
  const button = event.target.closest("[data-remove-history]");
  if (!button) return;
  const index = Number(button.dataset.removeHistory);
  if (!Number.isInteger(index) || index < 0 || index >= state.vault.records.length) return;
  button.disabled = true;
  state.vault.records.splice(index, 1);
  decryptedHistory = null;
  await chrome.storage.local.set({ vault: state.vault });
  await render();
});
$("#history-limit").addEventListener("change", async () => {
  state.settings.historyLimit = normalizeHistoryLimit($("#history-limit").value);
  state.vault.records = state.vault.records.slice(0, state.settings.historyLimit);
  decryptedHistory = null;
  await chrome.storage.local.set({ settings: state.settings, vault: state.vault });
  await render();
});
$("#add").addEventListener("click", () => {
  editingRule = null;
  $("#dialog-title").textContent = "Add rule";
  $("#confirm").textContent = "Add rule";
  $("#kind").hidden = false;
  $("#edit-options").hidden = true;
  $("#domain").value = "";
  $("#rule-name").value = "";
  $("#domain").placeholder = "example.com, a keyword, or a full-URL regular expression";
  $("#kind").value = activeTab;
  $("#rule-type").value = "domain";
  $("#domain-error").textContent = "";
  $("#dialog").showModal();
});
$("#cancel").addEventListener("click", () => $("#dialog").close());
$("#rule-type").addEventListener("change", () => {
  const placeholders = {
    domain: "example.com, localhost, or a protocol URL",
    regex: "Regular expression matching the full URL",
    keyword: "Keyword contained in the full URL"
  };
  const descriptions = {
    domain: "Matches a host and its subdomains.",
    regex: "Evaluates a regular expression against the full URL.",
    keyword: "Matches a case-insensitive keyword anywhere in the full URL, including its path and query."
  };
  $("#domain").placeholder = placeholders[$("#rule-type").value];
  $("#rule-type-help").textContent = descriptions[$("#rule-type").value];
  $("#domain-error").textContent = "";
});
$("#kind").addEventListener("change", () => {
  if (editingRule !== null) $("#edit-options").hidden = $("#kind").value !== "whitelist";
});
$("#domain-form").addEventListener("submit", async event => {
  event.preventDefault();
  const input = $("#domain").value.trim();
  const type = $("#rule-type").value;
  let rule;
  if (type === "regex") {
    if (!input) {
      $("#domain-error").textContent = "Enter a regular expression.";
      return;
    }
    try {
      new RegExp(input);
      rule = input;
    } catch {
      $("#domain-error").textContent = "Enter a valid regular expression.";
      return;
    }
  } else if (type === "keyword") {
    if (!input) {
      $("#domain-error").textContent = "Enter a keyword.";
      return;
    }
    rule = input;
  } else {
    try {
      if (/^[a-z][a-z\d+.-]*:(?!\d)/i.test(input)) {
        const parsed = new URL(input);
        rule = parsed.hostname
          ? ["http:", "https:"].includes(parsed.protocol)
            ? parsed.hostname.toLowerCase()
            : `${parsed.protocol}//${parsed.hostname.toLowerCase()}`
          : parsed.href;
      } else {
        rule = new URL(`https://${input}`).hostname.toLowerCase();
      }
      if (!rule || /\s/.test(rule)) throw new Error("Invalid rule");
    } catch {
      $("#domain-error").textContent = "Enter a valid host or URL.";
      return;
    }
  }
  const kind = $("#kind").value;
  if (editingRule !== null) {
    const originalRule = editingRule;
    const originalKind = activeTab;
    const originalIndex = state.lists[originalKind].indexOf(originalRule);
    state.lists[originalKind] = state.lists[originalKind].filter(item => item !== originalRule);
    state.lists.blacklist = state.lists.blacklist.filter(item => item !== rule);
    state.lists.whitelist = state.lists.whitelist.filter(item => item !== rule);
    const insertAt = kind === originalKind
      ? Math.min(Math.max(originalIndex, 0), state.lists[kind].length)
      : state.lists[kind].length;
    state.lists[kind].splice(insertAt, 0, rule);
    for (const key of ["ruleTypes", "whitelistHistory", "inheritTabs", "ruleNames"]) {
      if (key in state.settings && originalRule !== rule) {
        if (originalRule in state.settings[key]) state.settings[key][rule] = state.settings[key][originalRule];
        delete state.settings[key][originalRule];
      }
    }
    state.settings.ruleTypes[rule] = type;
    const name = $("#rule-name").value.trim();
    if (name) state.settings.ruleNames[rule] = name;
    else delete state.settings.ruleNames[rule];
    if (kind === "whitelist") {
      state.settings.whitelistHistory[rule] = $("#edit-whitelist-history").checked;
      state.settings.inheritTabs[rule] = $("#edit-inherit-tabs").checked;
    } else {
      delete state.settings.whitelistHistory[rule];
      delete state.settings.inheritTabs[rule];
    }
    editingRule = null;
    $("#dialog").close();
    await saveRules();
    return;
  }
  state.lists.blacklist = state.lists.blacklist.filter(item => item !== rule);
  state.lists.whitelist = state.lists.whitelist.filter(item => item !== rule);
  state.settings.ruleTypes[rule] = type;
  const name = $("#rule-name").value.trim();
  if (name) state.settings.ruleNames[rule] = name;
  else delete state.settings.ruleNames[rule];
  if (kind === "whitelist" && !(rule in state.settings.whitelistHistory)) {
    state.settings.whitelistHistory[rule] = true;
  }
  state.lists[kind].push(rule);
  activeTab = kind;
  $("#dialog").close();
  await saveRules();
});

$("#domains").addEventListener("click", event => {
  const rule = event.target.dataset.edit;
  if (!rule) return;
  editingRule = rule;
  $("#dialog-title").textContent = "Edit rule";
  $("#confirm").textContent = "Save changes";
  $("#kind").hidden = false;
  $("#kind").value = activeTab;
  $("#rule-type").value = state.settings.ruleTypes[rule] || "domain";
  $("#domain").value = rule;
  $("#rule-name").value = state.settings.ruleNames[rule] || "";
  $("#domain").placeholder = "Rule value";
  $("#domain-error").textContent = "";
  $("#edit-options").hidden = activeTab !== "whitelist";
  $("#edit-whitelist-history").checked = state.settings.whitelistHistory[rule] !== false;
  $("#edit-inherit-tabs").checked = !!state.settings.inheritTabs[rule];
  $("#rule-type").dispatchEvent(new Event("change"));
  $("#dialog").showModal();
});
$("#remove-rule").addEventListener("click", async () => {
  if (editingRule === null) return;
  state.lists[activeTab] = state.lists[activeTab].filter(item => item !== editingRule);
  delete state.settings.whitelistHistory[editingRule];
  delete state.settings.ruleTypes[editingRule];
  delete state.settings.inheritTabs[editingRule];
  delete state.settings.ruleNames[editingRule];
  editingRule = null;
  $("#dialog").close();
  await saveRules();
});

chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== "local" || !["settings", "lists", "vault"].some(key => changes[key])) return;
  void load();
});
void load();
