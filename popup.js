const enabled = document.querySelector("#enabled");
const status = document.querySelector("#status");
const options = document.querySelector("#options");

chrome.storage.local.get({
  settings: { enabled: false },
  vault: { publicKey: "", encryptedPrivateKey: "", records: [] }
}).then(({ settings, vault }) => {
  enabled.checked = !!settings.enabled;
  if (!vault.publicKey) {
    enabled.disabled = true;
    status.textContent = "Set a password in settings to enable history hiding.";
  } else {
    status.textContent = enabled.checked ? "New visits will be hidden." : "History hiding is off.";
  }
});
enabled.addEventListener("change", async () => {
  await chrome.storage.local.set({ settings: { enabled: enabled.checked } });
  status.textContent = enabled.checked ? "New visits will be hidden." : "History hiding is off.";
});
options.addEventListener("click", () => chrome.runtime.openOptionsPage());
