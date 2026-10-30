const MENU = {
  toggle: "hm-toggle",
  blacklist: "hm-blacklist",
  whitelist: "hm-whitelist"
};

const DEFAULTS = {
  settings: { enabled: false, whitelistHistory: {}, inheritTabs: {}, ruleNames: {}, ruleTypes: {}, ruleRegex: {}, theme: "auto", historyLimit: 100 },
  lists: { blacklist: [], whitelist: [] },
  vault: { publicKey: "", encryptedPrivateKey: "", records: [] }
};

let writeQueue = Promise.resolve();

async function getState() {
  const data = await chrome.storage.local.get(DEFAULTS);
  return {
    settings: { ...DEFAULTS.settings, ...(data.settings || {}) },
    lists: { ...DEFAULTS.lists, ...(data.lists || {}) },
    vault: { ...DEFAULTS.vault, ...(data.vault || {}) }
  };
}

function save(data) {
  writeQueue = writeQueue.catch(() => {}).then(() => chrome.storage.local.set(data));
  return writeQueue;
}

function encode(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes)));
}

function decode(value) {
  return Uint8Array.from(atob(value), char => char.charCodeAt(0));
}

async function importPublicKey(pem) {
  const value = pem.replace(/-----[^-]+-----/g, "").replace(/\s/g, "");
  return crypto.subtle.importKey("spki", decode(value), {
    name: "RSA-OAEP", hash: "SHA-256"
  }, false, ["encrypt"]);
}

async function encryptRecord(state, record) {
  const publicKey = await importPublicKey(state.vault.publicKey);
  const rawKey = crypto.getRandomValues(new Uint8Array(32));
  const key = await crypto.subtle.importKey("raw", rawKey, "AES-GCM", false, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = new TextEncoder().encode(JSON.stringify(record));
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, data);
  const encryptedKey = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, publicKey, rawKey);
  return { iv: encode(iv), key: encode(encryptedKey), data: encode(encrypted) };
}

async function updateActionIcon() {
  const { settings } = await getState();
  await chrome.action.setIcon({
    path: settings.enabled ? {
      16: "icons/icon-active.png", 48: "icons/icon-active.png", 128: "icons/icon-active.png"
    } : {
      16: "icons/icon-inactive.png", 48: "icons/icon-inactive.png", 128: "icons/icon-inactive.png"
    }
  });
}

chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && changes.settings) void updateActionIcon();
});
void updateActionIcon();

function domainOf(url) {
  try {
    const parsed = new URL(url);
    if (!parsed.hostname) return parsed.href;
    return ["http:", "https:"].includes(parsed.protocol)
      ? parsed.hostname
      : `${parsed.protocol}//${parsed.hostname}`;
  } catch {
    return "";
  }
}

function hostMatches(host, ruleHost) {
  return host === ruleHost || host.endsWith(`.${ruleHost}`);
}

function hasUrlScheme(value) {
  return /^[a-z][a-z\d+.-]*:(?!\d)/i.test(value);
}

function ruleMatches(rule, url, settings) {
  const type = settings.ruleTypes?.[rule] || (settings.ruleRegex?.[rule] ? "regex" : "domain");
  if (type === "regex") {
    try {
      return new RegExp(rule).test(url);
    } catch {
      return false;
    }
  }

  if (type === "keyword") return url.toLowerCase().includes(rule.toLowerCase());

  let actual;
  try {
    actual = new URL(url);
  } catch {
    return false;
  }

  if (hasUrlScheme(rule)) {
    let target;
    try {
      target = new URL(rule);
    } catch {
      return false;
    }
    if (!target.hostname) return actual.href === target.href;
    const webRule = ["http:", "https:"].includes(target.protocol);
    return (webRule || actual.protocol === target.protocol) &&
      hostMatches(actual.hostname.toLowerCase(), target.hostname.toLowerCase());
  }

  return !!actual.hostname && hostMatches(actual.hostname.toLowerCase(), rule.toLowerCase());
}

function matchingRule(list, url, settings) {
  return list.find(rule => ruleMatches(rule, url, settings));
}

const inheritedTabs = new Map();
const inheritanceReady = chrome.storage.session.get("inheritedTabs").then(({ inheritedTabs: saved = {} }) => {
  for (const [tabId, rule] of Object.entries(saved)) inheritedTabs.set(Number(tabId), rule);
});

async function setInheritedTab(tabId, rule) {
  await inheritanceReady;
  inheritedTabs.set(tabId, rule);
  await chrome.storage.session.set({ inheritedTabs: Object.fromEntries(inheritedTabs) });
}

async function removeInheritedTab(tabId) {
  await inheritanceReady;
  inheritedTabs.delete(tabId);
  await chrome.storage.session.set({ inheritedTabs: Object.fromEntries(inheritedTabs) });
}

function tabInheritanceForUrl(url, state) {
  const rule = matchingRule(state.lists.whitelist, url, state.settings);
  return rule && state.settings.inheritTabs?.[rule] ? rule : null;
}

async function inheritFromOpener(tab) {
  await inheritanceReady;
  if (tab.openerTabId == null) return;
  let inheritedRule = inheritedTabs.get(tab.openerTabId);
  if (!inheritedRule) {
    try {
      const opener = await chrome.tabs.get(tab.openerTabId);
      const state = await getState();
      inheritedRule = tabInheritanceForUrl(opener.url || "", state);
      if (inheritedRule) await setInheritedTab(opener.id, inheritedRule);
    } catch {}
  }
  if (inheritedRule) await setInheritedTab(tab.id, inheritedRule);
}

async function refreshMenus(tab) {
  const state = await getState();
  const domain = domainOf(tab?.url || "");
  await Promise.all([
    chrome.contextMenus.update(MENU.toggle, { checked: state.settings.enabled }),
    chrome.contextMenus.update(MENU.blacklist, { checked: !!domain && !!matchingRule(state.lists.blacklist, tab?.url || "", state.settings) }),
    chrome.contextMenus.update(MENU.whitelist, { checked: !!domain && !!matchingRule(state.lists.whitelist, tab?.url || "", state.settings) })
  ]).catch(() => {});
}

let menuSetup;

async function ensureMenus() {
  if (menuSetup) return menuSetup;
  menuSetup = (async () => {
    await chrome.contextMenus.removeAll();
    const items = [
      { id: MENU.toggle, title: "Hide browser history", type: "checkbox" },
      { id: "hm-separator", type: "separator" },
      { id: MENU.blacklist, title: "Keep this domain in browser history", type: "checkbox" },
      { id: MENU.whitelist, title: "Hide this domain", type: "checkbox" }
    ];
    for (const item of items) {
      await chrome.contextMenus.create({ ...item, contexts: ["all"] });
    }
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    await refreshMenus(tab);
  })().finally(() => {
    menuSetup = null;
  });
  return menuSetup;
}

chrome.runtime.onInstalled.addListener(() => {
  void ensureMenus();
});
chrome.runtime.onStartup.addListener(() => {
  void ensureMenus();
  void trimHiddenHistory();
});
void ensureMenus();

function historyLimit(settings) {
  const limit = Number(settings.historyLimit);
  return Number.isInteger(limit) ? Math.min(10000, Math.max(1, limit)) : 100;
}

async function trimHiddenHistory() {
  try {
    const state = await getState();
    const limit = historyLimit(state.settings);
    if (state.vault.records.length > limit) {
      state.vault.records = state.vault.records.slice(0, limit);
      await save({ vault: state.vault });
    }
  } catch (error) {
    console.error("Could not limit the number of hidden history records:", error);
  }
}

chrome.tabs.onActivated.addListener(({ tabId }) => {
  chrome.tabs.get(tabId).then(refreshMenus).catch(() => {});
});
chrome.tabs.onCreated.addListener(tab => { void inheritFromOpener(tab); });
chrome.tabs.onUpdated.addListener((_, changeInfo, tab) => {
  if (changeInfo.url) void refreshMenus(tab);
  if (changeInfo.status === "complete" && tab.url) {
    void (async () => {
      const state = await getState();
      const rule = tabInheritanceForUrl(tab.url, state);
      if (rule) await setInheritedTab(tab.id, rule);
    })();
    try {
      const protocol = new URL(tab.url).protocol;
      if (!["http:", "https:"].includes(protocol)) queueSpecialUrlHistory(tab);
    } catch {}
  }
});
chrome.tabs.onRemoved.addListener(tabId => { void removeInheritedTab(tabId); });

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  const state = await getState();
  if (info.menuItemId === MENU.toggle) {
    state.settings.enabled = !!info.checked;
    await save({ settings: state.settings });
    await updateActionIcon();
    return;
  }

  const domain = domainOf(tab?.url || "");
  if (!domain) return;
  const list = info.menuItemId === MENU.blacklist ? state.lists.blacklist :
    info.menuItemId === MENU.whitelist ? state.lists.whitelist : null;
  if (!list) return;

  const other = list === state.lists.blacklist ? state.lists.whitelist : state.lists.blacklist;
  const currentRule = matchingRule(list, tab?.url || "", state.settings);
  const index = currentRule ? list.indexOf(currentRule) : list.indexOf(domain);
  if (index >= 0) {
    const [removed] = list.splice(index, 1);
    delete state.settings.ruleRegex[removed];
    delete state.settings.ruleTypes[removed];
    delete state.settings.whitelistHistory[removed];
    delete state.settings.inheritTabs[removed];
    delete state.settings.ruleNames[removed];
  }
  else {
    list.push(domain);
    delete state.settings.ruleRegex[domain];
    state.settings.ruleTypes[domain] = "domain";
    const otherIndex = other.indexOf(domain);
    if (otherIndex >= 0) other.splice(otherIndex, 1);
  }
  await save({ lists: state.lists, settings: state.settings });
  await refreshMenus(tab);
});

let visitQueue = Promise.resolve();

function visitShouldBeHidden(item, state) {
  const domain = domainOf(item.url);
  const keep = !!domain && !!matchingRule(state.lists.blacklist, item.url, state.settings);
  const whitelistDomain = matchingRule(state.lists.whitelist, item.url, state.settings);
  return {
    hide: state.settings.enabled && !keep || !!whitelistDomain,
    saveVisit: !whitelistDomain || (state.settings.whitelistHistory || {})[whitelistDomain] !== false
  };
}

async function handleVisit(item, state) {
  if (!state) state = await getState();
  await inheritanceReady;
  let inheritedRule = null;
  for (const [tabId, rule] of inheritedTabs) {
    if (!state.settings.inheritTabs?.[rule]) continue;
    try {
      if ((await chrome.tabs.get(tabId)).url === item.url) {
        inheritedRule = rule;
        break;
      }
    } catch {
      await removeInheritedTab(tabId);
    }
  }
  if (!inheritedRule) {
    const tabs = await chrome.tabs.query({});
    for (const tab of tabs) {
      if (tab.url !== item.url) continue;
      const ownRule = tabInheritanceForUrl(tab.url, state);
      if (ownRule) await setInheritedTab(tab.id, ownRule);
      else await inheritFromOpener(tab);
      if (inheritedTabs.has(tab.id) && state.settings.inheritTabs?.[inheritedTabs.get(tab.id)]) {
        inheritedRule = inheritedTabs.get(tab.id);
        break;
      }
    }
  }
  const { hide: ruleHide, saveVisit: ruleSaveVisit } = visitShouldBeHidden(item, state);
  const hide = ruleHide || !!inheritedRule;
  const saveVisit = inheritedRule
    ? state.settings.whitelistHistory?.[inheritedRule] !== false
    : ruleSaveVisit;
  if (!hide) return false;
  if (saveVisit && !state.vault.publicKey) {
    console.warn("Skipped deleting matching history because hidden-history password setup is incomplete.");
    return false;
  }
  if (saveVisit) {
    state.vault.records = [
      await encryptRecord(state, {
        url: item.url,
        title: item.title || item.url,
        time: item.lastVisitTime || Date.now()
      }),
      ...state.vault.records
    ].slice(0, historyLimit(state.settings));
    await save({ vault: state.vault });
  }
  try {
    await chrome.history.deleteUrl({ url: item.url });
    return true;
  } catch (error) {
    console.error("Could not delete browser history URL:", item.url, error);
    throw error;
  }
}

function queueSpecialUrlHistory(tab) {
  visitQueue = visitQueue.then(async () => {
    const items = await chrome.history.search({ text: tab.url, startTime: 0, maxResults: 20 });
    const item = items.find(result => result.url === tab.url);
    if (item) await handleVisit(item);
  }).catch(error => {
    console.error("Could not process special-protocol history URL:", tab.url, error);
  });
}

chrome.history.onVisited.addListener(item => {
  visitQueue = visitQueue.then(() => handleVisit(item)).catch(error => {
    console.error("Could not process visit:", error);
  });
});
