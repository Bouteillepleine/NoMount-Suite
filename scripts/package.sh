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

# Auto-bump patch version unless explicitly provided
if [ -z "$VERSION" ]; then
    IFS='.-' read -r major minor patch pre <<< "$CURRENT_VERSION"
    patch=$((patch + 1))
    if [ -n "$pre" ]; then
        NEW_VERSION="${major}.${minor}.${patch}-${pre}"
    else
        NEW_VERSION="${major}.${minor}.${patch}"
    fi

    sed -i "s/^version = \"$CURRENT_VERSION\"/version = \"$NEW_VERSION\"/" "$PROJECT_ROOT/Cargo.toml"

    vcode="${NEW_VERSION%%-*}"
    vcode="${vcode//./}"
    sed -i "s/^version=.*/version=v${NEW_VERSION}/" "$MODULE_DIR/module.prop"
    sed -i "s/^versionCode=.*/versionCode=${vcode}/" "$MODULE_DIR/module.prop"

    VERSION="v${NEW_VERSION}"
    echo "==> Version bumped: v${CURRENT_VERSION} → ${VERSION}"
else
    VERSION="${VERSION#v}"
    VERSION="v${VERSION}"
fi

mkdir -p "$RELEASE_DIR/debug" "$RELEASE_DIR/release"

if [ "$CLEAN" = true ]; then
    echo "==> Cleaning old releases"
    rm -f "$RELEASE_DIR"/debug/nomount-*.zip "$RELEASE_DIR"/release/nomount-*.zip
fi

SCRIPTS=(
    customize.sh
    metamount.sh
    post-fs-data.sh
    service.sh
    spoof.sh
)

declare -A ABI_TARGET=(
    [arm64-v8a]=aarch64-linux-android
    [armeabi-v7a]=armv7-linux-androideabi
    [x86_64]=x86_64-linux-android
    [x86]=i686-linux-android
)

setup_toolchain() {
    export NDK_BIN="/opt/android-ndk-r25b/toolchains/llvm/prebuilt/linux-x86_64/bin"
    if [ ! -d "$NDK_BIN" ]; then
        echo "FATAL: Android NDK not found at /opt/android-ndk-r25b" >&2
        exit 1
    fi
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

    local out_name="nomount-${VERSION}${suffix}.zip"
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

    sed -i "s/^version=.*/version=${VERSION}/" "$staging/module.prop"
    local vcode="${VERSION#v}"
    vcode="${vcode%%-*}"
    vcode="${vcode//.}"
    sed -i "s/^versionCode=.*/versionCode=${vcode}/" "$staging/module.prop"

    local found_bins=0
    for abi in "${!ABI_TARGET[@]}"; do
        local target="${ABI_TARGET[$abi]}"
        local bin_src="$PROJECT_ROOT/target/$target/$target_subdir/nomount"
        mkdir -p "$staging/bin/$abi"

        if [ -f "$bin_src" ]; then
            cp "$bin_src" "$staging/bin/$abi/nomount"
            found_bins=$((found_bins + 1))
        elif [ -f "$MODULE_DIR/bin/$abi/nomount" ]; then
            cp "$MODULE_DIR/bin/$abi/nomount" "$staging/bin/$abi/nomount"
            found_bins=$((found_bins + 1))
        fi
    done

    if [ "$found_bins" -ne 4 ]; then
        echo "FATAL: [$profile] found $found_bins/4 binaries" >&2
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
chmod 755 "$MODPATH"/*.sh "$MODPATH"/bin/*/nomount 2>/dev/null || true
ui_print "NoMount installed via recovery"
exit 0
UPDATER
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
    (cd "$staging" && zip -r9 "$out_path" .)
    rm -rf "$staging"

    echo "    Output:  $out_path"
    echo "    Size:    $(du -h "$out_path" | cut -f1)"
    echo "    Bins:    $found_bins/4"
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
echo "    Debug:   $RELEASE_DIR/debug/nomount-${VERSION}-debug.zip"
echo "    Release: $RELEASE_DIR/release/nomount-${VERSION}.zip"

if [ "$DEPLOY" = true ]; then
    if [ "$DEPLOY_PROFILE" = "release" ]; then
        ZIP="$RELEASE_DIR/release/nomount-${VERSION}.zip"
    else
        ZIP="$RELEASE_DIR/debug/nomount-${VERSION}-debug.zip"
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
