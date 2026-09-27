# History Manager

A lightweight Chrome extension for controlling browser history by domain.

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
