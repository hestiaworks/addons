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

### NSPanel Companion Talkback

Low-latency two-way audio from a panel to a Reolink doorbell.

Speaking to the door through the camera's ONVIF backchannel arrives two to
three seconds late, because that path carries a large fixed buffer in the
firmware. Reolink's own app is under a second, and the difference is the
protocol: their app uses Baichuan, on TCP 9000. This add-on does the same.

It takes the 16 kHz mono PCM a panel already sends, encodes it to ADPCM, and
carries it over Baichuan. Nothing resamples, because the rate already matches.

**Video is not affected.** Whatever serves the panel's video — Scrypted, with
its prebuffered rebroadcast — goes on doing so. Only the microphone's route
changes, and a panel whose add-on stops answering falls back to the path it
used before.

Needs the camera's address and a **limited** camera user; talkback does not
require an admin account.

