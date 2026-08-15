# Android Deep-Link to WebView Bridge Exploit

The app opens verified-looking deep links into a JavaScript-enabled WebView and exposes a `Native.exec()` bridge to any page under the chosen URL. Craft `/src/deeplink.txt` that loads attacker-controlled script through the deep link and calls `Native.exec("dumpToken")`.
