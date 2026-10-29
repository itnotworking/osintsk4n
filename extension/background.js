// SC4N for Chrome: right-click a link, highlighted text or the page to check it on sc4n.lol.
// Nothing is sent anywhere until the user picks a menu item; the report opens in a new tab.
const SITE = "https://sc4n.lol/";
const WEB_PAGES = ["http://*/*", "https://*/*"];

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({ id: "sc4n-link", title: "Check this link with SC4N", contexts: ["link"], targetUrlPatterns: WEB_PAGES });
    chrome.contextMenus.create({ id: "sc4n-selection", title: "Check “%s” with SC4N", contexts: ["selection"] });
    chrome.contextMenus.create({ id: "sc4n-page", title: "Check this site with SC4N", contexts: ["page"], documentUrlPatterns: WEB_PAGES });
  });
});

// Query strings and fragments are where links carry email addresses and tokens, so they stay behind.
function withoutQuery(u) {
  try { const x = new URL(u); return x.origin + x.pathname; } catch (e) { return ""; }
}
function hostOf(u) {
  try { return new URL(u).hostname; } catch (e) { return ""; }
}

chrome.contextMenus.onClicked.addListener((info, tab) => {
  let target = "";
  if (info.menuItemId === "sc4n-link") target = withoutQuery(info.linkUrl || "");
  else if (info.menuItemId === "sc4n-selection") target = (info.selectionText || "").trim();
  else if (info.menuItemId === "sc4n-page") target = hostOf(info.pageUrl || "");
  if (!target) return;
  chrome.tabs.create({
    url: SITE + "#q=" + encodeURIComponent(target.slice(0, 2048)),
    index: tab ? tab.index + 1 : undefined,
  });
});
