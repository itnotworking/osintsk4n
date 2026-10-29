# SC4N for Chrome: publishing

Build the upload with `python extension/build.py`. It writes `extension/sc4n-extension-<version>.zip`.
Raise `version` in `extension/manifest.json` for every update you upload.

Try it before uploading: open `chrome://extensions`, turn on **Developer mode**, click **Load unpacked**
and choose the `extension` folder.

Developer dashboard: https://chrome.google.com/webstore/devconsole (the same account as Typowatch; the
$5 registration covers every extension on it).

## Store listing

**Name:** SC4N Threat Lookup

**Summary** (132 characters at most, also in the manifest):
Check a link, domain, IP, email, phone number or file hash for threats. Right-click or paste for a plain-English verdict.

**Category:** Privacy & Security (or Tools, if that one isn't offered)

**Description:**

SC4N checks suspicious links, domains, IP addresses, email addresses, phone numbers and file hashes, and
tells you in plain English whether they're dangerous.

Two ways to check:
- Right-click a link, highlighted text or the page and choose Check with SC4N. The full report opens in
  a new tab.
- Click the SC4N icon, paste anything, or press Check this site. The verdict and its main reasons show
  right in the popup.

What SC4N looks at:
- Domains and URLs: registration age, look-alike and brand impersonation checks, email security (SPF,
  DKIM and DMARC), hosting, threat feeds and a fresh screenshot of where the page really lands.
- IP addresses: abuse reports, security vendor detections, proxy, VPN and Tor detection, public
  blocklists, open ports and known vulnerabilities.
- Email addresses: infostealer logs, data breaches, disposable address checks and fraud scoring.
- Phone numbers: consumer complaints about scam calls, robocalls and texts, call-back numbers used in
  scams, and the line type, including internet (VoIP) numbers.
- File hashes: known malware and sandbox results.

Built for SOC and help desk analysts triaging phishing reports, and for anyone who wants to check a
suspicious link, sender or caller before acting on it.

Free, with no account. The extension sends nothing until you ask it to check something, and it never
reads the pages you visit. For links and pages it removes the query string first, where links carry
email addresses and tokens.

**Screenshots** (1280x800): `extension/store/store-phone.png`, `extension/store/store-ip.png`. Both show
real results from sc4n.lol, checked October 28, 2026, and say so in a caption.

**Small promo tile** (440x280): optional.

**Homepage:** https://sc4n.lol
**Support:** https://sc4n.lol

## Privacy practices tab

**Single purpose:**
Checks a link, domain, IP address, email address, phone number or file hash the user chooses with SC4N
and shows whether it is dangerous.

**Permission justifications:**
- `contextMenus`: adds Check with SC4N to the right-click menu for links, highlighted text and pages.
- `activeTab`: when the user opens the popup, reads the current tab's address so Check this site can
  check that site. Only the site's name is used, and only when the user presses the button.
- Host permission `https://sc4n.lol/*`: sends the item the user chose to check to sc4n.lol and shows the
  verdict in the popup.

**Remote code:** No, I am not using remote code. All code is in the package.

**Data usage:** tick **Website content** (the link, text or site the user chooses to check is sent to
sc4n.lol to run the lookup). Nothing else is collected. Tick all three certifications (not sold, not used
for unrelated purposes, not used for credit decisions).

**Privacy policy:** https://sc4n.lol/privacy (section "The SC4N Chrome extension").

## Test instructions for the reviewer

No account or key is needed:

> Click the SC4N icon, type `185.220.101.34` and press Check: the popup shows a verdict and its reasons.
> Then right-click any link on a web page and choose Check this link with SC4N: the full report opens on
> sc4n.lol in a new tab.

## After approval

1. Link the listing from sc4n.lol and from Typowatch's site, next to the Typowatch extension.
2. Edge: the same zip can go to the Microsoft Edge Add-ons store (free registration).
