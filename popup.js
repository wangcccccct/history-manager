const enabled = document.querySelector("#enabled");
const status = document.querySelector("#status");
const options = document.querySelector("#options");
const temporaryStatus = document.querySelector("#temporary-status");
const temporaryToggle = document.querySelector("#temporary-toggle");
const globalRow = document.querySelector("#global-row");
const temporaryRow = document.querySelector("#temporary-row");

let activeTabId = null;
let vaultReady = false;
let linkTrackingAvailable = false;

function applyTheme(theme) {
  const dark = theme === "dark" || theme === "auto" &&
    window.matchMedia("(prefers-color-scheme: dark)").matches;
  document.documentElement.dataset.theme = dark ? "dark" : "light";
}

async function updateTemporaryStatus() {
  if (activeTabId == null) {
    temporaryStatus.textContent = "No active tab available.";
    temporaryToggle.disabled = true;
    temporaryRow.classList.add("ready");
    return;
  }
  try {
    const result = await chrome.runtime.sendMessage({ type: "getTemporaryHideStatus", tabId: activeTabId });
    linkTrackingAvailable = !!result?.linkTrackingAvailable;
    if (!linkTrackingAvailable) {
      temporaryStatus.textContent = "Reload the extension to enable link tracking.";
      temporaryToggle.disabled = true;
      return;
    }
    const active = !!result.enabled;
    temporaryToggle.textContent = active ? "Stop" : "Hide";
  } catch {
    linkTrackingAvailable = false;
    temporaryStatus.textContent = "Background unavailable. Reload the extension.";
    temporaryToggle.disabled = true;
  } finally {
    temporaryRow.classList.add("ready");
  }
}

chrome.storage.local.get({
  settings: { enabled: false, theme: "auto" },
  vault: { publicKey: "", encryptedPrivateKey: "", records: [] }
}).then(async ({ settings, vault }) => {
  applyTheme(settings.theme || "auto");
  enabled.checked = !!settings.enabled;
  globalRow.classList.add("ready");
  vaultReady = !!vault.publicKey;
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  activeTabId = tab?.id ?? null;

  if (!vaultReady) {
    enabled.disabled = true;
    temporaryToggle.disabled = true;
    status.textContent = "Password needed";
  } else {
    status.textContent = enabled.checked ? "On" : "Off";
  }
  if (activeTabId == null || !vaultReady) temporaryToggle.disabled = true;
  await updateTemporaryStatus();
}).catch(() => {
  status.textContent = "Could not load history settings.";
  enabled.disabled = true;
  temporaryToggle.disabled = true;
  globalRow.classList.add("ready");
  temporaryRow.classList.add("ready");
});

enabled.addEventListener("change", async () => {
  const { settings = {} } = await chrome.storage.local.get("settings");
  await chrome.storage.local.set({ settings: { ...settings, enabled: enabled.checked } });
  status.textContent = enabled.checked ? "On" : "Off";
});

temporaryToggle.addEventListener("click", async () => {
  if (activeTabId == null || !vaultReady) return;
  temporaryToggle.disabled = true;
  try {
    const result = await chrome.runtime.sendMessage({ type: "toggleTemporaryHide", tabId: activeTabId });
    if (result?.error) throw new Error(result.error);
    await updateTemporaryStatus();
  } catch (error) {
    temporaryStatus.textContent = error instanceof Error ? error.message : "Could not update temporary hiding.";
  } finally {
    temporaryToggle.disabled = !vaultReady || activeTabId == null || !linkTrackingAvailable;
  }
});

options.addEventListener("click", () => chrome.runtime.openOptionsPage());
