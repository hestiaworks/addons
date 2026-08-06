# NSPanel Companion Updater

Optional Home Assistant app/add-on that owns network ADB discovery and signed
APK updates. Home Assistant Core never executes ADB directly.

1. Copy this folder into `/addons/nspanel_companion_updater` on Home Assistant.
2. Reload the local app/add-on store, install it, and start it.
3. Read the six-digit pairing code from its log.
4. In **NSPanel Companion**, pair `http://<home-assistant-ip>:8098`.

Only devices identified as an existing NSPanel Companion installation or a
probable NSPanel are eligible for installation. Every update requires an
explicit confirmation in the Home Assistant UI.

