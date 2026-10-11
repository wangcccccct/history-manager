# History Manager

A lightweight Chrome extension for controlling browser history by domain.

## Attribution

This project is based on [Hide My History](https://github.com/monokaijs/hide-my-history) by [Edward Nguyen (@monokaijs)](https://github.com/monokaijs). See the upstream repository for the original project.

## Changes from upstream

- Rebuilt the extension as a lightweight, dependency-free Manifest V3 project using plain JavaScript, HTML, and CSS. It can be loaded unpacked in Chrome without installing packages or running a build step.
- Reworked the interface into a focused settings page and popup, with light, dark, and system themes.
- Expanded domain rules to match a host and its subdomains. Rules can also target protocol URLs (including non-web URLs), or use regular expressions against the full URL.
- Kept the upstream blacklist/whitelist behavior and added a per-whitelist option to save or discard matching visits from the hidden-history vault.
- Reworked password protection and encryption. A password-derived key protects the private key; each saved visit is encrypted with AES-GCM and its random data key is wrapped with RSA-OAEP. The password is not stored.
- Added migration for records encrypted with the earlier shared AES key format, when setting up password protection.
- Kept hidden visits in Chrome local storage, capped the vault at 100 records, and added a clear-all action.

The upstream project also has a searchable hidden-history view and per-entry removal; those controls are not currently included here. Per-tab incognito mode is also not implemented in this project.

## Features

- Hide new visits globally or only for selected domains.
- Keep selected domains in normal browser history with a blacklist.
- Manage domain rules from the options page or the page context menu.
- Review encrypted hidden visits after unlocking with your password.
- Store extension data locally in Chrome.

## Install

1. Open `chrome://extensions` in Chrome.
2. Enable **Developer mode**.
3. Select **Load unpacked** and choose this project directory.
4. Open the extension options page and create a password.

## Domain rules

- **Blacklist**: matching domains remain in browser history while global hiding is enabled.
- **Whitelist**: matching domains are hidden even when global hiding is disabled.

Rules match the selected domain and its subdomains.

## Data protection

The private key is encrypted with a key derived from your password using PBKDF2 and AES-GCM. Each hidden visit is encrypted with AES-GCM, and its data key is protected with the corresponding RSA public key.

The password is not stored. If you forget it, encrypted hidden visits cannot be recovered. This protects locally stored extension data; it does not replace a separate operating-system account or protect against a compromised browser profile.
