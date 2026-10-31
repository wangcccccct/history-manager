# History Manager

A lightweight Chrome extension for controlling browser history with domain, regular-expression, and keyword rules.

## Project background

This project was inspired by [Hide My History](https://github.com/monokaijs/hide-my-history). Its current implementation and feature set have since developed independently.

The eye icon is adapted from [GitLab SVGs](https://gitlab.com/gitlab-org/gitlab-svgs), licensed under MIT. Its colors are adapted for this extension.

## Overview

- Rebuilt the extension as a lightweight, dependency-free Manifest V3 project using plain JavaScript, HTML, and CSS. It can be loaded unpacked in Chrome without installing packages or running a build step.
- Reworked the interface into a focused settings page and popup, with light, dark, and system themes.
- Added three selectable rule types: domain matching (host and subdomains, including protocol URLs), regular expressions against the full URL, and case-insensitive keyword matching anywhere in the full URL.
- Supports global history hiding, blacklist exceptions, and whitelist rules that hide matching visits even when global hiding is disabled.
- Reworked password protection and encryption. A password-derived key protects the private key; each saved visit is encrypted with AES-GCM and its random data key is wrapped with RSA-OAEP. The password is not stored.
- Includes migration of records from the earlier encrypted history format.
- Stores saved hidden visits encrypted in Chrome local storage, with a configurable retention limit.
- Added per-rule inheritance for tabs opened from matching tabs and temporary tab hiding with a session-only Stop control.

Temporary hiding applies to the current tab and tabs opened from it; it does not launch Chrome's actual Incognito mode.

## Features

- Hide new visits globally or only for selected domains.
- Keep selected domains in normal browser history with a blacklist.
- Manage domain rules from the options page or the page context menu.
- Match rules by domain, full-URL regular expression, or keyword.
- For each whitelist rule, optionally hide visits in tabs opened from matching tabs; this behavior continues through tabs opened by inherited tabs.
- Temporarily hide the current tab and tabs opened from it. **Stop** pauses the current tab's hiding rule for it and tabs it opens during this browser session. Other matching rules remain active, and saved rules are unchanged.
- Search saved hidden visits by title or URL, remove individual entries, or clear all entries.
- Review encrypted hidden visits after unlocking with your password.
- Store rules, encrypted visits, and temporary tab state in Chrome local or session storage.

## Install

See the [Chrome installation guide in Chinese](INSTALL.md). After downloading and extracting the project, enable Developer mode at `chrome://extensions`, then choose the folder containing `manifest.json` with **Load unpacked**.

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

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).
