#!/usr/bin/env bash
# Full build pipeline: cross-compile Rust (debug + release), build WebUI, package module ZIPs.
# Usage: ./scripts/package.sh --build [--version v2.0.0-dev] [--clean] [--deploy] [--reboot]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
MODULE_DIR="$PROJECT_ROOT/module"
RELEASE_DIR="$PROJECT_ROOT/release"

CURRENT_VERSION="$(grep '^version' "$PROJECT_ROOT/Cargo.toml" | head -1 | sed 's/.*"\(.*\)".*/\1/')"
VERSION=""
BUILD=false
CLEAN=false
DEPLOY=false
REBOOT=false
DEPLOY_PROFILE="debug"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --version) VERSION="$2"; shift 2 ;;
        --build)   BUILD=true; shift ;;
        --clean)   CLEAN=true; shift ;;
        --deploy)  DEPLOY=true; shift ;;
        --reboot)  REBOOT=true; shift ;;
        --release) DEPLOY_PROFILE="release"; shift ;;
        --debug)   DEPLOY_PROFILE="debug"; shift ;;
        *)         echo "Unknown arg: $1"; exit 1 ;;
    esac
done

# Decide the version: auto-bump the patch level, or take the one given.
if [ -z "$VERSION" ]; then
    IFS='.-' read -r major minor patch pre <<< "$CURRENT_VERSION"
    patch=$((patch + 1))
    if [ -n "$pre" ]; then
        NEW_VERSION="${major}.${minor}.${patch}-${pre}"
    else
        NEW_VERSION="${major}.${minor}.${patch}"
    fi
    echo "==> Version bumped: v${CURRENT_VERSION} → v${NEW_VERSION}"
else
    NEW_VERSION="${VERSION#v}"
    [ "$NEW_VERSION" != "$CURRENT_VERSION" ] && \
        echo "==> Version set: v${CURRENT_VERSION} → v${NEW_VERSION}"
fi

# Stamp it EVERYWHERE, for an explicit --version just as much as an auto-bump.
# These writes used to live inside the auto-bump branch, so `--version 1.3.9`
# renamed the zip while Cargo.toml and module.prop stayed behind: the artifact
# was called 1.3.9 and the binary inside it answered `nomount 1.3.8`. A version
# that lies about itself is the one thing a release must never do.
sed -i "s/^version = \"$CURRENT_VERSION\"/version = \"$NEW_VERSION\"/" "$PROJECT_ROOT/Cargo.toml"

# major*10000 + minor*100 + patch. Plain dot-stripping regressed the code
# (1.2.0 -> "120" < 10102 for v1.1.2), which a manager reads as a downgrade.
vbase="${NEW_VERSION%%-*}"
IFS=. read -r vmaj vmin vpat <<< "$vbase"
vcode=$(( ${vmaj:-0} * 10000 + ${vmin:-0} * 100 + ${vpat:-0} ))
sed -i "s/^version=.*/version=v${NEW_VERSION}/" "$MODULE_DIR/module.prop"
sed -i "s/^versionCode=.*/versionCode=${vcode}/" "$MODULE_DIR/module.prop"

VERSION="v${NEW_VERSION}"

# --- nm: build it, or say plainly that a prebuilt is being shipped ------------
# nm is freestanding C with no libc, so it needs a cross compiler rather than
# cargo. Only CI ever built it, and packaging silently fell back to the gitignored
# prebuilt under module/bin/ -- so a local build shipped a STALE nm whenever
# userspace/src/nm.c had changed, with nothing in the output saying so. Build it
# here when zig is around, and refuse to ship a prebuilt older than its source.
# 1 = no zig (fall back to a prebuilt, which the staleness check then polices)
# 2 = zig IS here and the compile FAILED. Collapsing both into `return 1` made a
#     genuine compile error print "no zig on PATH", which sends the reader looking
#     for a toolchain they already have instead of at the error they just caused.
build_nm() {
    local zig
    zig="$(command -v zig || true)"
    if [ -z "$zig" ]; then
        return 1
    fi
    make -s -C "$PROJECT_ROOT/userspace/tools/sstrip" >/dev/null 2>&1 || true
    "$zig" cc -target aarch64-linux -Oz -static -nostdlib -ffreestanding \
        -fno-unwind-tables -fno-ident -Wno-invalid-noreturn -Wl,--entry=_start \
        "$PROJECT_ROOT/userspace/src/nm.c" -o "$PROJECT_ROOT/nm-arm64" || return 2
    "$PROJECT_ROOT/userspace/tools/sstrip/sstrip" -z "$PROJECT_ROOT/nm-arm64" >/dev/null 2>&1 || true
    local profile
    for profile in debug release; do
        install -Dm755 "$PROJECT_ROOT/nm-arm64" \
            "$PROJECT_ROOT/target/aarch64-linux-android/${profile}/nm"
    done
    rm -f "$PROJECT_ROOT/nm-arm64"
    echo "==> nm built from source ($(wc -c < "$PROJECT_ROOT/target/aarch64-linux-android/release/nm") bytes)"
    return 0
}

if $BUILD; then
    build_nm || _nmrc=$?
    case "${_nmrc:-0}" in
        0) ;;
        2) echo "FATAL: zig is on PATH but compiling userspace/src/nm.c FAILED." >&2
           echo "       Fix the compile error; shipping the previous prebuilt would" >&2
           echo "       package a binary that does not match the source in this zip." >&2
           exit 1 ;;
        *) echo "==> nm: no zig on PATH, will fall back to a prebuilt" ;;
    esac
fi

mkdir -p "$RELEASE_DIR/debug" "$RELEASE_DIR/release"

if [ "$CLEAN" = true ]; then
    echo "==> Cleaning old releases"
    rm -f "$RELEASE_DIR"/debug/00_NoMount-Module-*.zip "$RELEASE_DIR"/release/00_NoMount-Module-*.zip
fi

SCRIPTS=(
    customize.sh
    metamount.sh
    post-fs-data.sh
    service.sh
    spoof.sh
    scan.sh
    uidscan.sh
    uidwatch.sh
)

# OnePlus (and any device that can run this kernel) is arm64-v8a only — the
# module loads bin/$(getprop ro.product.cpu.abi) at runtime, which is always
# arm64-v8a, so the other ABIs are dead weight. Add entries back for wider reach.
declare -A ABI_TARGET=(
    [arm64-v8a]=aarch64-linux-android
)

setup_toolchain() {
    # Honour the environment first; the previous hardcoded /opt path made this
    # script unusable on any machine that installs the NDK anywhere else.
    local ndk="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}"
    # The prebuilt toolchain directory is named after the HOST, so linux-x86_64
    # was as unportable as the /opt path above it -- setting ANDROID_NDK_HOME on
    # a Windows/Git-Bash or macOS box still failed with "NDK not found", which
    # reads as "you did not set it" rather than "your host is not Linux".
    local hostdir=""
    for h in linux-x86_64 windows-x86_64 darwin-x86_64; do
        [ -n "$ndk" ] && [ -d "$ndk/toolchains/llvm/prebuilt/$h/bin" ] && hostdir="$h" && break
    done
    if [ -z "$ndk" ]; then
        for c in /opt/android-ndk-r25b "$HOME"/Android/Sdk/ndk/* "$HOME"/android-ndk-* \
                 "$LOCALAPPDATA"/Android/Sdk/ndk/*; do
            for h in linux-x86_64 windows-x86_64 darwin-x86_64; do
                [ -d "$c/toolchains/llvm/prebuilt/$h/bin" ] && ndk="$c" && hostdir="$h"
            done
        done
    fi
    export NDK_BIN="$ndk/toolchains/llvm/prebuilt/${hostdir:-linux-x86_64}/bin"
    if [ -z "$ndk" ] || [ ! -d "$NDK_BIN" ]; then
        echo "FATAL: Android NDK not found. Set ANDROID_NDK_HOME." >&2
        exit 1
    fi
    echo "==> NDK: $ndk"
    if [ -f "/home/president/.cargo/bin/cargo" ]; then
        export RUSTUP_HOME=/home/president/.rustup
        export CARGO_HOME=/home/president/.cargo
        CARGO="/home/president/.cargo/bin/cargo"
    else
        CARGO="cargo"
    fi
    export PATH="$NDK_BIN:$PATH"
}

# Build Rust for one profile across all ABIs
build_rust() {
    local profile="$1"
    local cargo_flag=""
    local target_subdir="debug"

    if [ "$profile" = "release" ]; then
        cargo_flag="--release"
        target_subdir="release"
    fi

    for abi in "${!ABI_TARGET[@]}"; do
        target="${ABI_TARGET[$abi]}"
        echo "==> [$profile] Building $abi ($target)"
        "$CARGO" build --manifest-path "$PROJECT_ROOT/Cargo.toml" \
            --target "$target" $cargo_flag 2>&1
    done
    echo "==> [$profile] All Rust targets built"
}


# Package one ZIP from a given Rust profile
package_zip() {
    local profile="$1"
    local target_subdir="debug"
    [ "$profile" = "release" ] && target_subdir="release"

    local suffix=""
    [ "$profile" = "debug" ] && suffix="-debug"

    local out_name="00_NoMount-Module-${VERSION}${suffix}.zip"
    local out_path="$RELEASE_DIR/$profile/$out_name"
    local staging
    staging="$(mktemp -d)"

    echo ""
    echo "==> Packaging $profile: $out_name"

    for script in "${SCRIPTS[@]}"; do
        local src="$MODULE_DIR/$script"
        if [ ! -f "$src" ]; then
            echo "FATAL: missing $script" >&2
            rm -rf "$staging"
            exit 1
        fi
        cp "$src" "$staging/$script"
    done

    if [ ! -f "$MODULE_DIR/module.prop" ]; then
        echo "FATAL: missing module.prop" >&2
        rm -rf "$staging"
        exit 1
    fi
    cp "$MODULE_DIR/module.prop" "$staging/module.prop"

    # Sync the human-readable version string to the build version, but PRESERVE
    # the committed versionCode (KSU's update key) verbatim. Deriving it from the
    # semver (v1.0.0 -> 100) silently downgrades the intended value (10000) and
    # can break update detection, so leave module.prop's versionCode untouched.
    sed -i "s/^version=.*/version=${VERSION}/" "$staging/module.prop"

    # Every ABI needs BOTH the Rust manager (nomount) and the freestanding
    # netlink client (nm) that the WebUI and metamount.sh shell out to. A zip
    # with nomount but no nm installs fine but never injects, so require both.
    local want=${#ABI_TARGET[@]}
    local found_nomount=0 found_nm=0
    for abi in "${!ABI_TARGET[@]}"; do
        local target="${ABI_TARGET[$abi]}"
        mkdir -p "$staging/bin/$abi"

        local nomount_src="$PROJECT_ROOT/target/$target/$target_subdir/nomount"
        if [ -f "$nomount_src" ]; then
            cp "$nomount_src" "$staging/bin/$abi/nomount"; found_nomount=$((found_nomount + 1))
        elif [ -f "$MODULE_DIR/bin/$abi/nomount" ]; then
            # The SAME staleness guard nm gets 20 lines below, which this arm did
            # not have. Without it, `package.sh` (no --build) with an empty or
            # partial target/ dir silently packages an arbitrarily old `nomount`
            # -- and the version stamping at the top of this script has already
            # written the NEW version into module.prop, so the zip is labelled
            # v1.3.51 while the binary inside answers whatever it was built as.
            # That is the "a version that lies about itself" failure the stamping
            # comment says a release must never produce, reached the other way.
            local _newer
            _newer="$(find "$PROJECT_ROOT/src" "$PROJECT_ROOT/Cargo.toml"                         -newer "$MODULE_DIR/bin/$abi/nomount" -print -quit 2>/dev/null)"
            if [ -n "$_newer" ]; then
                echo "FATAL: $MODULE_DIR/bin/$abi/nomount predates the Rust sources" >&2
                echo "       (newer: $_newer). Re-run with --build." >&2
                rm -rf "$staging"
                exit 1
            fi
            echo "    !! nomount/$abi: NO built binary in target/$target/$target_subdir —" >&2
            echo "       packaging the committed prebuilt from module/bin/$abi instead." >&2
            cp "$MODULE_DIR/bin/$abi/nomount" "$staging/bin/$abi/nomount"; found_nomount=$((found_nomount + 1))
        fi

        # nm is arch-shared C, built by build_nm() above (or by CI) into the target
        # dir next to nomount; a committed prebuilt is the last resort.
        local nm_src="$PROJECT_ROOT/target/$target/$target_subdir/nm"
        if [ -f "$nm_src" ]; then
            cp "$nm_src" "$staging/bin/$abi/nm"; found_nm=$((found_nm + 1))
        elif [ -f "$MODULE_DIR/bin/$abi/nm" ]; then
            # A prebuilt older than nm.c is a stale binary the zip would present as
            # current -- the failure this whole check exists to make impossible.
            if [ "$PROJECT_ROOT/userspace/src/nm.c" -nt "$MODULE_DIR/bin/$abi/nm" ] \
               || [ "$PROJECT_ROOT/userspace/src/nm.h" -nt "$MODULE_DIR/bin/$abi/nm" ]; then
                echo "FATAL: $MODULE_DIR/bin/$abi/nm predates userspace/src/nm.[ch]." >&2
                echo "       Install zig (0.14.x) and re-run, or let CI build it." >&2
                rm -rf "$staging"
                exit 1
            fi
            cp "$MODULE_DIR/bin/$abi/nm" "$staging/bin/$abi/nm"; found_nm=$((found_nm + 1))
        fi
    done

    if [ "$found_nomount" -ne "$want" ] || [ "$found_nm" -ne "$want" ]; then
        echo "FATAL: [$profile] nomount ${found_nomount}/${want}, nm ${found_nm}/${want}" >&2
        rm -rf "$staging"
        exit 1
    fi


    # WebUI
    local webroot_src=""
    if [ -d "$MODULE_DIR/webroot" ]; then
        webroot_src="$MODULE_DIR/webroot"
    elif [ -d "$PROJECT_ROOT/staging/webroot" ]; then
        webroot_src="$PROJECT_ROOT/staging/webroot"
    fi
    if [ -n "$webroot_src" ]; then
        cp -r "$webroot_src" "$staging/webroot"
        # Bake the release into the page. Stamped on the STAGING copy only: the
        # tree's webroot keeps saying "dev", which is what it is.
        if [ -f "$staging/webroot/index.html" ]; then
            sed -i "s/const SUITE_VERSION = \"[^\"]*\"/const SUITE_VERSION = \"${VERSION}\"/" \
                "$staging/webroot/index.html"
            # ASSERT. A sed that matches nothing is silent, and the failure mode
            # here is a shipped WebUI that calls itself "dev" and then reports
            # every real release as a staged update forever.
            if ! grep -q "const SUITE_VERSION = \"${VERSION}\"" "$staging/webroot/index.html"; then
                echo "FATAL: could not stamp SUITE_VERSION into webroot/index.html" >&2
                exit 1
            fi
        fi
    fi

    # META-INF
    mkdir -p "$staging/META-INF/com/google/android"
    cat > "$staging/META-INF/com/google/android/update-binary" << 'UPDATER'
#!/sbin/sh

OUTFD=/proc/self/fd/$2
ZIPFILE="$3"

ui_print() { echo -e "ui_print $1\nui_print" >> $OUTFD; }

MODPATH="${MODPATH:-/data/adb/modules/meta-nomount}"
mkdir -p "$MODPATH"
unzip -o "$ZIPFILE" -d "$MODPATH" >&2
chmod 755 "$MODPATH"/*.sh "$MODPATH"/bin/*/nomount "$MODPATH"/bin/*/nm 2>/dev/null || true
ui_print "NoMount installed via recovery"
exit 0
UPDATER
    # 0755: some recoveries EXEC update-binary rather than handing it to sh. The
    # heredoc above creates it 0644 under the build umask, and mkzip.py's
    # path-based exec heuristic (.sh / bin/) does not cover this name either, so
    # both packaging paths were shipping the recovery installer non-executable.
    chmod 0755 "$staging/META-INF/com/google/android/update-binary"
    echo "" > "$staging/META-INF/com/google/android/updater-script"

    # Verify no eliminated scripts
    local eliminated=(logging.sh susfs_integration.sh sync.sh zm-diag.sh zm-init.sh)
    for dead in "${eliminated[@]}"; do
        if [ -f "$staging/$dead" ]; then
            echo "FATAL: eliminated script $dead in staging!" >&2
            rm -rf "$staging"
            exit 1
        fi
    done

    # Integrity manifest: sha256 of every payload file, excluding META-INF
    # (the recovery installer, not staged into the module) and the manifest
    # itself. customize.sh verifies this on-device to catch a corrupted or
    # tampered download before it runs the root binary.
    (
        cd "$staging"
        find . -type f \
            ! -path './META-INF/*' \
            ! -name 'nomount.sha256sums' \
            -print0 | sort -z | xargs -0 sha256sum > nomount.sha256sums
    )
    echo "    Sums:    $(wc -l < "$staging/nomount.sha256sums") files hashed"

    rm -f "$out_path"
    if command -v zip >/dev/null 2>&1; then
        (cd "$staging" && zip -r9 "$out_path" .)
    else
        # No zip on this host (Git Bash ships none). Do NOT reach for
        # Compress-Archive as a substitute: it writes backslash-separated entry
        # names, which the installer cannot resolve, and drops the unix mode so
        # every binary lands non-executable. Build the archive explicitly.
        python3 "$SCRIPT_DIR/mkzip.py" "$staging" "$out_path" \
            || python "$SCRIPT_DIR/mkzip.py" "$staging" "$out_path"
    fi
    rm -rf "$staging"

    echo "    Output:  $out_path"
    echo "    Size:    $(du -h "$out_path" | cut -f1)"
    echo "    Bins:    nomount+nm x${want} ($(printf '%s ' "${!ABI_TARGET[@]}"))"
    echo "    WebUI:   present"
}

# -- Main --
echo "==> NoMount $VERSION build pipeline"
echo ""

if [ "$BUILD" = true ]; then
    setup_toolchain

    build_rust "debug"
    build_rust "release"
fi

package_zip "debug"
package_zip "release"

echo ""
echo "==> Build complete"
echo "    Debug:   $RELEASE_DIR/debug/00_NoMount-Module-${VERSION}-debug.zip"
echo "    Release: $RELEASE_DIR/release/00_NoMount-Module-${VERSION}.zip"

if [ "$DEPLOY" = true ]; then
    if [ "$DEPLOY_PROFILE" = "release" ]; then
        ZIP="$RELEASE_DIR/release/00_NoMount-Module-${VERSION}.zip"
    else
        ZIP="$RELEASE_DIR/debug/00_NoMount-Module-${VERSION}-debug.zip"
    fi
    if [ ! -f "$ZIP" ]; then
        echo "FATAL: ${DEPLOY_PROFILE} zip not found at $ZIP" >&2
        exit 1
    fi

    if ! adb devices 2>/dev/null | grep -q 'device$'; then
        echo "FATAL: no adb device connected" >&2
        exit 1
    fi

    REMOTE="/data/local/tmp/nomount-deploy.zip"
    echo "==> Deploying $ZIP to device"
    adb push "$ZIP" "$REMOTE"
    adb shell "/data/adb/ksu/bin/ksud module install $REMOTE" 2>/dev/null \
        || adb shell "/data/adb/ap/bin/apd module install $REMOTE" 2>/dev/null \
        || adb shell "su -c 'magisk --install-module $REMOTE'" 2>/dev/null \
        || { echo "FATAL: module install failed" >&2; exit 1; }
    adb shell "rm -f $REMOTE"
    echo "==> Module installed"

    if [ "$REBOOT" = true ]; then
        echo "==> Rebooting device"
        adb reboot
    fi
fi
