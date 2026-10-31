# History Manager

A lightweight Chrome extension for controlling browser history with domain, regular-expression, and keyword rules.

## Project background

This project was inspired by [Hide My History](https://github.com/monokaijs/hide-my-history). Its current implementation and feature set have since developed independently.

The eye icon is adapted from [GitLab SVGs](https://gitlab.com/gitlab-org/gitlab-svgs), licensed under MIT. Its colors are adapted for this extension.

Thanks to the [Linux.do](https://linux.do) community for its support.

## Features

- A lightweight Manifest V3 extension built with plain JavaScript, HTML, and CSS. No package installation or build step is required.
- A settings page and popup with light, dark, and system themes.
- Hide new visits globally or only for selected domains.
- Keep selected domains in normal browser history with a blacklist.
- Whitelist rules hide matching visits even when global hiding is disabled.
- Manage domain rules from the options page or the page context menu.
- Match rules by domain, full-URL regular expression, or keyword.
- For each whitelist rule, optionally hide visits in tabs opened from matching tabs; this behavior continues through tabs opened by inherited tabs.
- Temporarily hide the current tab and tabs opened from it. **Stop** pauses hiding for that tab and its descendants for the current browser session without changing saved rules. This does not launch Chrome's Incognito mode.
- Search saved hidden visits by title or URL, remove individual entries, or clear all entries.
- Review encrypted hidden visits after unlocking with your password. A password-derived key protects the private key; each saved visit is encrypted with AES-GCM and its data key is wrapped with RSA-OAEP. The password is not stored.
- Migrate records from the earlier encrypted history format.
- Store rules and encrypted visits in Chrome local storage, with configurable history retention; temporary tab state uses session storage.

## Install

Download the project ZIP from GitHub and extract it.

1. Open Chrome's Extensions page at `chrome://extensions` and turn on **Developer mode**.
2. Click **Load unpacked** and select the extracted project folder that contains `manifest.json`. The extension loads as soon as you select the folder.

## Domain rules

- **Blacklist**: matching domains remain in browser history while global hiding is enabled.
- **Whitelist**: matching visits are hidden even when global hiding is disabled. Each whitelist rule can also enable inheritance to tabs opened from matching tabs.

Domain rules match the selected host and its subdomains. Regular-expression and keyword rules match against the full URL.

## Data protection

The private key is encrypted with a key derived from your password using PBKDF2 and AES-GCM. Each hidden visit is encrypted with AES-GCM, and its data key is protected with the corresponding RSA public key.

The password is not stored. If you forget it, encrypted hidden visits cannot be recovered.

## Permissions

- `history`: find and remove visits that match the enabled hiding behavior.
- `tabs` and `webNavigation`: identify tabs and detect tabs opened from a hidden tab so the rule can be inherited.
- `storage`: save settings and encrypted hidden visits locally, and keep temporary tab state for the current browser session.
- `contextMenus`: provide controls for history hiding and domain rules in the page context menu.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).
