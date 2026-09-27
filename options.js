const $ = selector => document.querySelector(selector);
const DEFAULTS = {
  settings: { enabled: false },
  lists: { blacklist: [], whitelist: [] },
  vault: { publicKey: "", encryptedPrivateKey: "", records: [] }
};

let state = structuredClone(DEFAULTS);
let activeTab = "blacklist";
let privateKey = null;

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
  $("#enabled").checked = state.settings.enabled;
  $("#mode").textContent = state.settings.enabled ? "On" : "Off";
  $("#blacklist-count").textContent = state.lists.blacklist.length;
  $("#whitelist-count").textContent = state.lists.whitelist.length;
  $("[data-tab=blacklist]").classList.toggle("active", activeTab === "blacklist");
  $("[data-tab=whitelist]").classList.toggle("active", activeTab === "whitelist");

  const domains = state.lists[activeTab];
  $("#domains").innerHTML = domains.length
    ? domains.map(domain => `<div class="domain-row"><span>${escapeHtml(domain)}</span><button data-remove="${escapeHtml(domain)}" title="Remove domain">Remove</button></div>`).join("")
    : '<div class="empty">No domains in this list.</div>';

  if (!state.vault.records.length) {
    $("#history").innerHTML = '<div class="empty">No hidden visits yet.</div>';
    return;
  }
  const results = await Promise.allSettled(state.vault.records.map(decryptRecord));
  $("#history").innerHTML = results.map(result => {
    if (result.status === "rejected") return '<div class="history-row">Unable to decrypt this visit.</div>';
    const item = result.value;
    return `<div class="history-row"><a href="${escapeHtml(item.url)}" target="_blank" rel="noopener">${escapeHtml(item.title || item.url)}</a><time>${new Date(item.time).toLocaleString()}</time></div>`;
  }).join("");
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, char => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  })[char]);
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
$("#save").addEventListener("click", () => void saveRules());
document.querySelectorAll("[data-tab]").forEach(button => button.addEventListener("click", () => {
  activeTab = button.dataset.tab;
  void render();
}));
$("#domains").addEventListener("click", async event => {
  const domain = event.target.dataset.remove;
  if (!domain) return;
  state.lists[activeTab] = state.lists[activeTab].filter(item => item !== domain);
  await saveRules();
});
$("#clear-history").addEventListener("click", async () => {
  state.vault.records = [];
  await chrome.storage.local.set({ vault: state.vault });
  await render();
});
$("#add").addEventListener("click", () => {
  $("#domain").value = "";
  $("#kind").value = activeTab;
  $("#dialog").showModal();
});
$("#cancel").addEventListener("click", () => $("#dialog").close());
$("#domain-form").addEventListener("submit", async event => {
  event.preventDefault();
  const input = $("#domain").value.trim().toLowerCase();
  let domain;
  try {
    domain = new URL(/^[a-z][a-z\d+.-]*:\/\//i.test(input) ? input : `https://${input}`).hostname;
  } catch {
    return;
  }
  if (!domain.includes(".") || !/^[a-z0-9.-]+$/.test(domain)) return;
  const kind = $("#kind").value;
  state.lists.blacklist = state.lists.blacklist.filter(item => item !== domain);
  state.lists.whitelist = state.lists.whitelist.filter(item => item !== domain);
  state.lists[kind].push(domain);
  activeTab = kind;
  $("#dialog").close();
  await saveRules();
});

chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== "local" || !["settings", "lists", "vault"].some(key => changes[key])) return;
  void load();
});
void load();
