# Hestiaworks Home Assistant add-ons

Home Assistant add-on repository.

## Adding this repository

*Settings → Add-ons → Add-on Store → ⋮ → Repositories*, then add:

```
https://github.com/hestiaworks/addons
```

## Add-ons

### NSPanel Companion Updater

Discovers NSPanel Companion devices on a local subnet and installs or updates
them over network ADB. It verifies the release metadata, SHA-256 checksum,
application identity, ABI and pinned signing certificate before any panel is
modified, and restores the Home-app assignment afterwards.

Sources: GitHub Releases, or a locally staged release directory.
