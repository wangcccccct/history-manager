# History Manager

A lightweight Chrome extension for controlling browser history with domain, regular-expression, and keyword rules.

## Attribution

This project is based on [Hide My History](https://github.com/monokaijs/hide-my-history) by [Edward Nguyen (@monokaijs)](https://github.com/monokaijs). See the upstream repository for the original project.

The eye icon is adapted from [GitLab SVGs](https://gitlab.com/gitlab-org/gitlab-svgs), licensed under MIT. Its colors are adapted for this extension.

## Changes from upstream

- Rebuilt the extension as a lightweight, dependency-free Manifest V3 project using plain JavaScript, HTML, and CSS. It can be loaded unpacked in Chrome without installing packages or running a build step.
- Reworked the interface into a focused settings page and popup, with light, dark, and system themes.
- Added three selectable rule types: domain matching (host and subdomains, including protocol URLs), regular expressions against the full URL, and case-insensitive keyword matching anywhere in the full URL.
- Kept the upstream blacklist/whitelist behavior and added a per-whitelist option to save or discard matching visits from the hidden-history vault.
- Reworked password protection and encryption. A password-derived key protects the private key; each saved visit is encrypted with AES-GCM and its random data key is wrapped with RSA-OAEP. The password is not stored.
- Added migration for records encrypted with the earlier shared AES key format, when setting up password protection.
- Kept saved hidden visits encrypted in Chrome local storage, added a configurable retention limit, and added a clear-all action.
- Added per-rule inheritance for tabs opened from matching tabs and temporary tab hiding with a session-only Stop control.

The upstream project also has a searchable hidden-history view and per-entry removal; those controls are not currently included here. Per-tab incognito mode is also not implemented in this project.

## Features

- Hide new visits globally or only for selected domains.
- Keep selected domains in normal browser history with a blacklist.
- Manage domain rules from the options page or the page context menu.
- Match rules by domain, full-URL regular expression, or keyword.
- For each whitelist rule, optionally hide visits in tabs opened from matching tabs; this behavior continues through tabs opened by inherited tabs.
- Temporarily hide the current tab and tabs opened from it. **Stop** pauses the current tab's hiding rule for it and tabs it opens during this browser session. Other matching rules remain active, and saved rules are unchanged.
- Review encrypted hidden visits after unlocking with your password.
- Store rules, encrypted visits, and temporary tab state in Chrome local or session storage.

## Install

1. Open `chrome://extensions` in Chrome.
2. Enable **Developer mode**.
3. Select **Load unpacked** and choose this project directory.
4. Open the extension options page and create a password.

## Domain rules

- **Blacklist**: matching domains remain in browser history while global hiding is enabled.
- **Whitelist**: matching visits are hidden even when global hiding is disabled. Each whitelist rule can also enable inheritance to tabs opened from matching tabs.

Domain rules match the selected host and its subdomains. Regular-expression and keyword rules match against the full URL.

## Data protection

The private key is encrypted with a key derived from your password using PBKDF2 and AES-GCM. Each hidden visit is encrypted with AES-GCM, and its data key is protected with the corresponding RSA public key.

The password is not stored. If you forget it, encrypted hidden visits cannot be recovered. This protects locally stored extension data; it does not replace a separate operating-system account or protect against a compromised browser profile.

See [Privacy](PRIVACY.md) for data handling details and the permissions this extension uses.

## Permissions

- `history`: find and remove visits that match the enabled hiding behavior.
- `tabs` and `webNavigation`: identify tabs and detect tabs opened from a hidden tab so the rule can be inherited.
- `storage`: save settings and encrypted hidden visits locally, and keep temporary tab state for the current browser session.
- `contextMenus`: provide controls for history hiding and domain rules in the page context menu.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the local development and review steps. The extension has no package installation or build step.

## License

This project is based on [Hide My History](https://github.com/monokaijs/hide-my-history) by Edward Nguyen. No license has been selected for this repository yet. Confirm the upstream terms and choose a compatible license before granting reuse rights or describing this as an open-source release.
