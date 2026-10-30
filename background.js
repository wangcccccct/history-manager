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
const TEMP_HIDE_RULE = "__temporary_tab_hide__";

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
const temporaryTabs = new Set();
const stoppedRuleTabs = new Map();
const hiddenTabVisitRules = new Map();
const pendingTabTracks = new Map();
const tabNavigationUrls = new Map();
const inheritanceReady = chrome.storage.session.get(["inheritedTabs", "temporaryTabs", "stoppedRuleTabs", "hiddenTabVisitRules", "tabNavigationUrls"]).then(({ inheritedTabs: savedTabs = {}, temporaryTabs: savedTemporaryTabs = [], stoppedRuleTabs: savedStoppedTabs = {}, hiddenTabVisitRules: savedVisits = {}, tabNavigationUrls: savedNavigations = {} }) => {
  for (const [tabId, rule] of Object.entries(savedTabs)) inheritedTabs.set(Number(tabId), rule);
  for (const tabId of savedTemporaryTabs) temporaryTabs.add(Number(tabId));
  for (const [tabId, rule] of Object.entries(savedStoppedTabs)) stoppedRuleTabs.set(Number(tabId), rule);
  for (const [tabId, visits] of Object.entries(savedVisits)) hiddenTabVisitRules.set(Number(tabId), visits);
  for (const [tabId, urls] of Object.entries(savedNavigations)) tabNavigationUrls.set(Number(tabId), urls);
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

async function setTemporaryTab(tabId, enabled) {
  await inheritanceReady;
  if (enabled) temporaryTabs.add(tabId);
  else temporaryTabs.delete(tabId);
  await chrome.storage.session.set({ temporaryTabs: [...temporaryTabs] });
}

async function setStoppedRuleTab(tabId, rule) {
  await inheritanceReady;
  if (rule) stoppedRuleTabs.set(tabId, rule);
  else stoppedRuleTabs.delete(tabId);
  await chrome.storage.session.set({ stoppedRuleTabs: Object.fromEntries(stoppedRuleTabs) });
}

function inheritanceEnabled(rule, settings) {
  return rule === TEMP_HIDE_RULE || !!settings.inheritTabs?.[rule];
}

function tabHideRule(tabId) {
  return temporaryTabs.has(tabId) ? TEMP_HIDE_RULE : inheritedTabs.get(tabId);
}

async function setHiddenVisitRule(tabId, url, rule) {
  if (!url || !rule) return;
  await inheritanceReady;
  const visits = hiddenTabVisitRules.get(tabId) || {};
  visits[url] = rule;
  hiddenTabVisitRules.set(tabId, visits);
  await chrome.storage.session.set({ hiddenTabVisitRules: Object.fromEntries(hiddenTabVisitRules) });
}

async function recordTabNavigation(tab) {
  if (!tab.url) return;
  await inheritanceReady;
  const urls = tabNavigationUrls.get(tab.id) || [];
  if (urls.at(-1) !== tab.url) urls.push(tab.url);
  tabNavigationUrls.set(tab.id, urls);
  await chrome.storage.session.set({ tabNavigationUrls: Object.fromEntries(tabNavigationUrls) });
}

async function clearTabNavigation(tabId) {
  await inheritanceReady;
  tabNavigationUrls.delete(tabId);
  await chrome.storage.session.set({ tabNavigationUrls: Object.fromEntries(tabNavigationUrls) });
}

async function clearTabVisitRules(tabId) {
  await inheritanceReady;
  hiddenTabVisitRules.delete(tabId);
  await chrome.storage.session.set({ hiddenTabVisitRules: Object.fromEntries(hiddenTabVisitRules) });
}

async function clearProcessedVisitUrls(urls) {
  await inheritanceReady;
  const processed = new Set(urls);
  for (const [tabId, visits] of hiddenTabVisitRules) {
    for (const url of processed) delete visits[url];
    if (!Object.keys(visits).length) hiddenTabVisitRules.delete(tabId);
  }
  for (const [tabId, visits] of tabNavigationUrls) {
    const remaining = visits.filter(url => !processed.has(url));
    if (remaining.length) tabNavigationUrls.set(tabId, remaining);
    else tabNavigationUrls.delete(tabId);
  }
  await chrome.storage.session.set({
    hiddenTabVisitRules: Object.fromEntries(hiddenTabVisitRules),
    tabNavigationUrls: Object.fromEntries(tabNavigationUrls)
  });
}

function tabInheritanceForUrl(url, state) {
  const rule = matchingRule(state.lists.whitelist, url, state.settings);
  return rule && state.settings.inheritTabs?.[rule] ? rule : null;
}

async function inheritFromNavigationSource(sourceTabId, targetTabId, url) {
  await inheritanceReady;
  const stoppedRule = stoppedRuleTabs.get(sourceTabId);
  const state = await getState();
  if (stoppedRule) {
    let sourceTab;
    try {
      sourceTab = await chrome.tabs.get(sourceTabId);
    } catch (error) {
      console.error("Could not read the source tab while checking its stopped rule:", sourceTabId, error);
      return;
    }
    const sourceRule = tabInheritanceForUrl(sourceTab?.url || "", state);
    if (sourceRule === stoppedRule) {
      if (tabInheritanceForUrl(url || "", state) === stoppedRule) {
        await setStoppedRuleTab(targetTabId, stoppedRule);
      }
      return;
    }
    await setStoppedRuleTab(sourceTabId, null);
  }
  let rule = tabHideRule(sourceTabId);
  const pendingTrack = pendingTabTracks.get(sourceTabId);
  if (!rule && pendingTrack) {
    await pendingTrack;
    rule = tabHideRule(sourceTabId);
  }
  if (!rule) {
    try {
      const sourceTab = await chrome.tabs.get(sourceTabId);
      rule = tabInheritanceForUrl(sourceTab.url || "", state);
      if (rule) await setInheritedTab(sourceTabId, rule);
    } catch {}
  }
  if (!rule) return;
  if (rule === TEMP_HIDE_RULE) await setTemporaryTab(targetTabId, true);
  else await setInheritedTab(targetTabId, rule);
  if (url) {
    await recordTabNavigation({ id: targetTabId, url });
    await setHiddenVisitRule(targetTabId, url, rule);
    try {
      const targetTab = await chrome.tabs.get(targetTabId);
      if (targetTab.status === "complete") queueCompletedTabVisit(targetTab);
    } catch (error) {
      console.error("Could not recheck an inherited target tab:", targetTabId, error);
    }
  }
}

async function trackTabVisit(tab) {
  await inheritanceReady;
  let rule = tabHideRule(tab.id);
  const state = await getState();
  const urlRule = tabInheritanceForUrl(tab.url || "", state);
  const stoppedRule = stoppedRuleTabs.get(tab.id);
  if (stoppedRule && stoppedRule !== urlRule) await setStoppedRuleTab(tab.id, null);
  if (!rule) rule = urlRule;
  if (rule && stoppedRuleTabs.get(tab.id) === rule) rule = null;
  if (rule && !tabHideRule(tab.id)) await setInheritedTab(tab.id, rule);
  if (rule) await setHiddenVisitRule(tab.id, tab.url, rule);
  return rule || null;
}

function scheduleTabTracking(tab) {
  if (!tab.url) return;
  const url = tab.url;
  const previous = pendingTabTracks.get(tab.id) || Promise.resolve();
  const tracking = previous.then(async () => {
    await recordTabNavigation(tab);
    return trackTabVisit(tab);
  }).catch(error => {
    console.error("Could not track hidden tab navigation:", url, error);
  });
  pendingTabTracks.set(tab.id, tracking);
  void tracking.then(() => {
    if (pendingTabTracks.get(tab.id) === tracking) pendingTabTracks.delete(tab.id);
  });
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
if (chrome.webNavigation?.onCreatedNavigationTarget) {
  chrome.webNavigation.onCreatedNavigationTarget.addListener(details => {
    void inheritFromNavigationSource(details.sourceTabId, details.tabId, details.url).catch(error => {
      console.error("Could not inherit status for a linked tab:", details.tabId, error);
    });
  });
} else {
  console.error("Linked-tab inheritance is unavailable: reload the extension to grant webNavigation permission.");
}
chrome.tabs.onUpdated.addListener((_, changeInfo, tab) => {
  if (changeInfo.url) {
    void refreshMenus(tab);
    scheduleTabTracking(tab);
  }
  if (changeInfo.status === "complete" && tab.url) {
    scheduleTabTracking(tab);
    queueCompletedTabVisit(tab);
  }
});
chrome.tabs.onRemoved.addListener(tabId => {
  pendingTabTracks.delete(tabId);
  void removeInheritedTab(tabId);
  void setTemporaryTab(tabId, false);
  void setStoppedRuleTab(tabId, null);
  void clearTabNavigation(tabId);
  void clearTabVisitRules(tabId);
});

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (!message || !["getTemporaryHideStatus", "toggleTemporaryHide"].includes(message.type)) return;
  void (async () => {
    await inheritanceReady;
    const tabId = Number(message.tabId);
    if (!Number.isInteger(tabId)) throw new Error("No active tab was selected.");
    const current = temporaryTabs.has(tabId);
    const linkTrackingAvailable = !!chrome.webNavigation?.onCreatedNavigationTarget;
    if (message.type === "getTemporaryHideStatus") {
      const tab = await chrome.tabs.get(tabId);
      const state = await getState();
      const detectedRule = tabInheritanceForUrl(tab.url || "", state);
      const ruleHidden = (!!inheritedTabs.get(tabId) || !!detectedRule) && stoppedRuleTabs.get(tabId) !== (inheritedTabs.get(tabId) || detectedRule);
      return { enabled: current || ruleHidden, linkTrackingAvailable };
    }
    if (!linkTrackingAvailable) throw new Error("Reload the extension to grant webNavigation permission.");

    const state = await getState();
    if (!state.vault.publicKey) throw new Error("Set a password in settings to use history hiding.");
    const tab = await chrome.tabs.get(tabId);
    const detectedRule = tabInheritanceForUrl(tab.url || "", state);
    const activeRule = inheritedTabs.get(tabId) || detectedRule;
    const stopping = current || (!!activeRule && stoppedRuleTabs.get(tabId) !== activeRule);
    if (stopping) {
      await setTemporaryTab(tabId, false);
      if (activeRule) {
        await setStoppedRuleTab(tabId, activeRule);
        await removeInheritedTab(tabId);
        await clearTabVisitRules(tabId);
      }
      return { enabled: false };
    }
    await setStoppedRuleTab(tabId, null);
    await setTemporaryTab(tabId, true);
    if (!stopping) {
      await recordTabNavigation(tab);
      await setHiddenVisitRule(tabId, tab.url, TEMP_HIDE_RULE);
      if (tab.url) {
        const items = await chrome.history.search({ text: tab.url, startTime: 0, maxResults: 20 });
        const item = items.find(result => result.url === tab.url);
        if (item) await handleVisit({ ...item, title: tab.title || item.title || tab.url }, state);
      }
    }
    return { enabled: true };
  })().then(sendResponse).catch(error => {
    sendResponse({ error: error instanceof Error ? error.message : String(error) });
  });
  return true;
});

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

async function handleVisit(item, state, sourceTabId = null) {
  if (!state) state = await getState();
  await inheritanceReady;
  const whitelistRule = matchingRule(state.lists.whitelist, item.url, state.settings);
  const stoppedRule = sourceTabId == null ? null : stoppedRuleTabs.get(sourceTabId);
  const stopRuleForVisit = !!whitelistRule && stoppedRule === whitelistRule;
  let inheritedRule = null;
  for (const [tabId, visits] of hiddenTabVisitRules) {
    const rule = visits[item.url];
    if (stoppedRuleTabs.get(tabId) === rule) continue;
    if (inheritanceEnabled(rule, state.settings)) {
      inheritedRule = rule;
      break;
    }
  }
  for (const tabId of new Set([...inheritedTabs.keys(), ...temporaryTabs])) {
    if (inheritedRule) break;
    const rule = tabHideRule(tabId);
    if (stoppedRuleTabs.get(tabId) === rule) continue;
    if (!inheritanceEnabled(rule, state.settings)) continue;
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
      await pendingTabTracks.get(tab.id);
      const rule = await trackTabVisit(tab);
      if (!rule) continue;
      if (inheritanceEnabled(tabHideRule(tab.id), state.settings)) {
        inheritedRule = tabHideRule(tab.id);
        break;
      }
    }
  }
  if (!inheritedRule && inheritedTabs.size + temporaryTabs.size) {
    await new Promise(resolve => setTimeout(resolve, 75));
    for (const visits of hiddenTabVisitRules.values()) {
      const rule = visits[item.url];
      if (inheritanceEnabled(rule, state.settings)) {
        inheritedRule = rule;
        break;
      }
    }
  }
  const { hide: ruleHide, saveVisit: ruleSaveVisit } = visitShouldBeHidden(item, state);
  const effectiveRuleHide = stopRuleForVisit ? false : ruleHide;
  const hide = effectiveRuleHide || !!inheritedRule;
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

function queueCompletedTabVisit(tab) {
  if (!tab.url) return;
  const { id, url } = tab;
  visitQueue = visitQueue.then(async () => {
    await new Promise(resolve => setTimeout(resolve, 120));
    const current = await chrome.tabs.get(id).catch(() => null);
    if (!current || current.status !== "complete" || current.url !== url) return;
    await pendingTabTracks.get(id);
    await trackTabVisit(current);
    const navigationUrls = [...(tabNavigationUrls.get(id) || [])];
    if (!navigationUrls.length || navigationUrls.at(-1) !== url) navigationUrls.push(url);
    const items = await chrome.history.search({ text: url, startTime: 0, maxResults: 20 });
    const historyItem = items.find(item => item.url === url);
    if (!historyItem) return;
    const item = {
      ...historyItem,
      title: current.title || historyItem.title || url
    };
    const hidden = await handleVisit(item, undefined, id);
    if (hidden) {
      for (const redirectUrl of new Set(navigationUrls)) {
        if (redirectUrl !== url) await chrome.history.deleteUrl({ url: redirectUrl });
      }
      await clearProcessedVisitUrls(navigationUrls);
    }
    await clearTabNavigation(id);
    await clearTabVisitRules(id);
  }).catch(error => {
    console.error("Could not process completed tab history:", url, error);
  });
}

chrome.history.onVisited.addListener(item => {
  chrome.tabs.query({}).then(tabs => {
    for (const tab of tabs) {
      if (tab.url !== item.url) continue;
      scheduleTabTracking(tab);
      if (tab.status === "complete") queueCompletedTabVisit(tab);
    }
  }).catch(error => {
    console.error("Could not find the tab for a visited URL:", item.url, error);
  });
});
