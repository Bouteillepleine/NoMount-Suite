#!/system/bin/sh
# Emit one package name per line for every installed 3rd-party app that is an
# Xposed/LSPosed module (its manifest carries the xposedmodule / xposedminversion
# meta-data). The pathhide rule matches the package name, which appears in the
# APK path (/data/app/*/PKG-*/base.apk) that gets mapped into a hooked process.
pm list packages -3 -f 2>/dev/null | sed 's/^package://' | while IFS= read -r line; do
    pkg=${line##*=}
    apk=${line%=*}
    [ -f "$apk" ] || continue
    if unzip -p "$apk" AndroidManifest.xml 2>/dev/null | grep -qa "xposedmodule"; then
        echo "$pkg"
    fi
done | sort -u
