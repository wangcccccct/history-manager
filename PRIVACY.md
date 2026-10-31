# Privacy

Last updated: October 31, 2026

History Manager processes browsing history to remove visits covered by your settings and rules. It does not send browsing history, page titles, rules, or vault contents to a developer-controlled server. The extension has no analytics or telemetry code.

## Data stored

- Rules, theme, and other settings are stored in Chrome's extension-local storage.
- Hidden visits that you choose to save are encrypted before being stored in the extension vault. The vault is limited by the retention setting in the options page.
- Temporary tab-hiding state is stored in Chrome session storage and is cleared when the browser session ends. Closing a tab also clears its tab-specific state.
- The password is not stored. It is used to derive a key that encrypts the private key used to unlock saved visits.

If a rule is configured not to save hidden visits, matching visits are removed from Chrome history without being added to the extension vault. You can clear saved hidden visits from the options page. Removing the extension does not guarantee that Chrome has immediately erased every copy of its extension data; use Chrome's extension data controls if you need to remove it.

## Browser permissions

- **History** is used to find matching visits, save them in the encrypted vault when configured, and remove matching URLs from Chrome history.
- **Tabs** and **webNavigation** are used to identify the active tab and detect tabs opened from another tab so tab-hiding rules can be inherited.
- **Storage** is used for local settings, the encrypted vault, and browser-session tab state.
- **Context menus** is used to show history and rule controls when you right-click a page.

## Third parties

The extension does not include analytics, advertising, remote APIs, or third-party data processing. Chrome itself processes extension data according to your browser settings and Google's privacy terms.

## Changes to this policy

If data handling changes, this file and the corresponding project documentation should be updated before release.
