#!/usr/bin/env bash
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

_stamp_saved="$(mktemp -d)"
cp "$PROJECT_ROOT/Cargo.toml"   "$_stamp_saved/Cargo.toml"
cp "$MODULE_DIR/module.prop"    "$_stamp_saved/module.prop"
[ -f "$PROJECT_ROOT/Cargo.lock" ] && cp "$PROJECT_ROOT/Cargo.lock" "$_stamp_saved/Cargo.lock"
_unstamp() {
    local rc=$?
    if [ "$rc" -ne 0 ] && [ -f "$_stamp_saved/Cargo.toml" ]; then
        cp "$_stamp_saved/Cargo.toml" "$PROJECT_ROOT/Cargo.toml"
        cp "$_stamp_saved/module.prop" "$MODULE_DIR/module.prop"
        [ -f "$_stamp_saved/Cargo.lock" ] && cp "$_stamp_saved/Cargo.lock" "$PROJECT_ROOT/Cargo.lock"
        echo "       version stamp rolled back to v${CURRENT_VERSION}" >&2
    fi
    rm -rf "$_stamp_saved"
}
trap _unstamp EXIT

sed -i "s/^version = \"$CURRENT_VERSION\"/version = \"$NEW_VERSION\"/" "$PROJECT_ROOT/Cargo.toml"

vbase="${NEW_VERSION%%-*}"
IFS=. read -r vmaj vmin vpat <<< "$vbase"
vcode=$(( ${vmaj:-0} * 100000 + ${vmin:-0} * 1000 + ${vpat:-0} ))
sed -i "s/^version=.*/version=v${NEW_VERSION}/" "$MODULE_DIR/module.prop"
sed -i "s/^versionCode=.*/versionCode=${vcode}/" "$MODULE_DIR/module.prop"

VERSION="v${NEW_VERSION}"

BUILD_COMMIT="$(git -C "$PROJECT_ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
if [ -n "$(git -C "$PROJECT_ROOT" status --porcelain 2>/dev/null \
            | grep -vE ' (Cargo\.toml|Cargo\.lock|module/module\.prop)$')" ]; then
    BUILD_COMMIT="${BUILD_COMMIT}+dirty"
fi
export BUILD_COMMIT
echo "==> Build commit: ${BUILD_COMMIT}"

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
        2) echo "fatal: zig is on path but compiling userspace/src/nm.c FAILED." >&2
           echo "       Fix the compile error; shipping the previous prebuilt would" >&2
           echo "       package a binary that does not match the source in this zip." >&2
           exit 1 ;;
        *) echo "==> nm: no zig on path, will fall back to a prebuilt" ;;
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
    post-mount.sh
    service.sh
    uidscan.sh
    uidwatch.sh
    uninstall.sh
    lkm-load.sh
)

declare -A ABI_TARGET=(
    [arm64-v8a]=aarch64-linux-android
)

setup_toolchain() {
    local ndk="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}"
    local hostdir=""
    for h in linux-x86_64 windows-x86_64 darwin-x86_64; do
        [ -n "$ndk" ] && [ -d "$ndk/toolchains/llvm/prebuilt/$h/bin" ] && hostdir="$h" && break
    done
    if [ -z "$ndk" ]; then
        for c in /opt/android-ndk-r25b "$HOME"/Android/Sdk/ndk/* "$HOME"/android-ndk-* \
                 "${LOCALAPPDATA:-/nonexistent}"/Android/Sdk/ndk/*; do
            for h in linux-x86_64 windows-x86_64 darwin-x86_64; do
                [ -d "$c/toolchains/llvm/prebuilt/$h/bin" ] && ndk="$c" && hostdir="$h"
            done
        done
    fi
    export NDK_BIN="$ndk/toolchains/llvm/prebuilt/${hostdir:-linux-x86_64}/bin"
    if [ "$hostdir" = "windows-x86_64" ]; then
        export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$NDK_BIN/aarch64-linux-android26-clang.cmd"
        export CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER="$NDK_BIN/armv7a-linux-androideabi26-clang.cmd"
        export CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER="$NDK_BIN/x86_64-linux-android26-clang.cmd"
        export CARGO_TARGET_I686_LINUX_ANDROID_LINKER="$NDK_BIN/i686-linux-android26-clang.cmd"
    fi
    if [ -z "$ndk" ] || [ ! -d "$NDK_BIN" ]; then
        echo "fatal: Android NDK not found. Set ANDROID_NDK_HOME." >&2
        exit 1
    fi
    echo "==> NDK: $ndk"
    CARGO="${CARGO:-cargo}"
    export PATH="$NDK_BIN:$PATH"
}

build_rust() {
    local profile="$1"
    local cargo_flag=""

    if [ "$profile" = "release" ]; then
        cargo_flag="--release"
    fi

    for abi in "${!ABI_TARGET[@]}"; do
        target="${ABI_TARGET[$abi]}"
        echo "==> [$profile] Building $abi ($target)"
        "$CARGO" build --manifest-path "$PROJECT_ROOT/Cargo.toml" \
            --target "$target" $cargo_flag 2>&1
    done
    echo "==> [$profile] All Rust targets built"
}

verify_binary_version() {
    local bin="$1" want="$2" got=""
    if got="$("$bin" version 2>/dev/null)" && [ -n "$got" ]; then
        case "$got" in
            *"$want"*) return 0 ;;
            *) echo "       binary reports: $got" >&2; return 1 ;;
        esac
    fi
    if grep -qaF -- "$want" "$bin"; then
        return 0
    fi
    local seen
    seen="$(grep -aoE '[0-9]+\.[0-9]+\.[0-9]+' "$bin" 2>/dev/null | sort -u | tr '\n' ' ')"
    echo "       binary contains no \"$want\"; version-shaped literals: ${seen:-<none>}" >&2
    return 1
}

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
            echo "fatal: missing $script" >&2
            rm -rf "$staging"
            exit 1
        fi
        cp "$src" "$staging/$script"
    done

    if [ ! -f "$MODULE_DIR/module.prop" ]; then
        echo "fatal: missing module.prop" >&2
        rm -rf "$staging"
        exit 1
    fi
    cp "$MODULE_DIR/module.prop" "$staging/module.prop"

    sed -i "s/^version=.*/version=${VERSION}/" "$staging/module.prop"

    local want=${#ABI_TARGET[@]}
    local found_nomount=0 found_nm=0
    for abi in "${!ABI_TARGET[@]}"; do
        local target="${ABI_TARGET[$abi]}"
        mkdir -p "$staging/bin/$abi"

        local nomount_src="$PROJECT_ROOT/target/$target/$target_subdir/nomount"
        if [ -f "$nomount_src" ]; then
            cp "$nomount_src" "$staging/bin/$abi/nomount"; found_nomount=$((found_nomount + 1))
        elif [ -f "$MODULE_DIR/bin/$abi/nomount" ]; then
            echo "    !! nomount/$abi: NO built binary in target/$target/$target_subdir - " >&2
            echo "       packaging the committed prebuilt from module/bin/$abi instead." >&2
            cp "$MODULE_DIR/bin/$abi/nomount" "$staging/bin/$abi/nomount"; found_nomount=$((found_nomount + 1))
        fi
        if [ -f "$staging/bin/$abi/nomount" ]; then
            verify_binary_version "$staging/bin/$abi/nomount" "${VERSION#v}" || {
                echo "fatal: [$profile] bin/$abi/nomount does not report ${VERSION#v}." >&2
                echo "       The zip would be labelled ${VERSION} around a binary that" >&2
                echo "       answers something else. Re-run with --build." >&2
                rm -rf "$staging"
                exit 1
            }
        fi

        local nm_src="$PROJECT_ROOT/target/$target/$target_subdir/nm"
        if [ -f "$nm_src" ]; then
            cp "$nm_src" "$staging/bin/$abi/nm"; found_nm=$((found_nm + 1))
        elif [ -f "$MODULE_DIR/bin/$abi/nm" ]; then
            if [ "$PROJECT_ROOT/userspace/src/nm.c" -nt "$MODULE_DIR/bin/$abi/nm" ] \
               || [ "$PROJECT_ROOT/userspace/src/nm.h" -nt "$MODULE_DIR/bin/$abi/nm" ]; then
                echo "fatal: $MODULE_DIR/bin/$abi/nm predates userspace/src/nm.[ch]." >&2
                echo "       Install zig (0.14.x) and re-run, or let CI build it." >&2
                rm -rf "$staging"
                exit 1
            fi
            cp "$MODULE_DIR/bin/$abi/nm" "$staging/bin/$abi/nm"; found_nm=$((found_nm + 1))
        fi
    done

    if [ "$found_nomount" -ne "$want" ] || [ "$found_nm" -ne "$want" ]; then
        echo "fatal: [$profile] nomount ${found_nomount}/${want}, nm ${found_nm}/${want}" >&2
        rm -rf "$staging"
        exit 1
    fi

    local lkm_src=""
    if [ -d "$MODULE_DIR/lkm" ]; then
        lkm_src="$MODULE_DIR/lkm"
    elif [ -d "$PROJECT_ROOT/staging/lkm" ]; then
        lkm_src="$PROJECT_ROOT/staging/lkm"
    fi
    if [ -n "$lkm_src" ]; then
        local n_ko
        n_ko=$(find "$lkm_src" -name 'nomount-*.ko' | wc -l)
        if [ "$n_ko" -gt 0 ]; then
            mkdir -p "$staging/lkm"
            cp "$lkm_src"/nomount-*.ko "$staging/lkm/"
            echo "    lkm: $n_ko module(s) -> $(cd "$staging/lkm" && ls | tr '\n' ' ')"
        else
            echo "    lkm: directory present but empty - zip carries NO engine modules"
        fi
    else
        echo "    lkm: none bundled - this zip needs a kernel with CONFIG_NOMOUNT=y"
    fi

    local loader_src=""
    for _c in "$MODULE_DIR/bin/ko-loader-arm64" "$PROJECT_ROOT/staging/ko-loader-arm64"; do
        [ -f "$_c" ] && { loader_src="$_c"; break; }
    done
    if [ -n "$loader_src" ]; then
        install -m 0755 "$loader_src" "$staging/loader"
        echo "    loader: $(basename "$loader_src")"
    else
        echo "    loader: none - module loading falls back to ksud insmod / insmod"
    fi

    local webroot_src=""
    if [ -d "$MODULE_DIR/webroot" ]; then
        webroot_src="$MODULE_DIR/webroot"
    elif [ -d "$PROJECT_ROOT/staging/webroot" ]; then
        webroot_src="$PROJECT_ROOT/staging/webroot"
    fi
    if [ -n "$webroot_src" ]; then
        cp -r "$webroot_src" "$staging/webroot"
        if [ -f "$staging/webroot/index.html" ]; then
            sed -i "s/const SUITE_VERSION = \"[^\"]*\"/const SUITE_VERSION = \"${VERSION}\"/" \
                "$staging/webroot/index.html"
            sed -i "s/const SUITE_COMMIT = \"[^\"]*\"/const SUITE_COMMIT = \"${BUILD_COMMIT}\"/" \
                "$staging/webroot/index.html"
            if ! grep -q "const SUITE_VERSION = \"${VERSION}\"" "$staging/webroot/index.html"; then
                echo "fatal: could not stamp SUITE_VERSION into webroot/index.html" >&2
                exit 1
            fi
            if ! grep -q "const SUITE_COMMIT = \"${BUILD_COMMIT}\"" "$staging/webroot/index.html"; then
                echo "fatal: could not stamp SUITE_COMMIT into webroot/index.html" >&2
                exit 1
            fi
        fi
    fi

    mkdir -p "$staging/META-INF/com/google/android"
    cat > "$staging/META-INF/com/google/android/update-binary" << 'UPDATER'
#!/sbin/sh
# Recovery installer.
#
# Everything that makes an install safe lives in customize.sh: the sha256
# manifest check, the "only one metamodule" refusal (two metamodules fighting in
# post-fs-data is a bootloop vector), the $NMDIR mode + SELinux label, and the
# bootcount reset. This script used to unzip, chmod, print a success line and
# exit 0 - skipping all four, and reporting success even when the unzip failed.
# So it now builds the handful of helpers customize.sh expects and sources it.

OUTFD=/proc/self/fd/$2
ZIPFILE="$3"

# Two echoes rather than `echo -e`: recovery's /sbin/sh is usually busybox or
# toybox ash, where -e is not a flag and gets printed literally.
ui_print() { echo "ui_print $1" >> $OUTFD; echo "ui_print" >> $OUTFD; }
abort() { ui_print "$1"; rm -rf "$MODPATH"; exit 1; }
grep_prop() {
    _gp_re="s/^$1=//p"
    shift
    sed -n "$_gp_re" "$@" 2>/dev/null | head -n 1
}
# The manager's set_perm, including its fifth argument. Dropping the SELinux
# context is not cosmetic here: customize.sh labels $NMDIR adb_data_file
# explicitly because the default (system_file) is readable by every app domain.
set_perm() {
    chown "$2:$3" "$1" 2>/dev/null
    chmod "$4" "$1" 2>/dev/null
    if [ -n "$5" ]; then
        chcon "$5" "$1" 2>/dev/null
    else
        chcon u:object_r:system_file:s0 "$1" 2>/dev/null
    fi
    return 0
}

MODPATH="${MODPATH:-/data/adb/modules/meta-nomount}"
mkdir -p "$MODPATH" || { ui_print "! cannot create $MODPATH"; exit 1; }

# -x meta-INF: this installer is not module content, and unzipping it into the
# module directory left an update-binary sitting under /data/adb/modules. And the
# status is checked - the old `exit 0` reported a successful install of nothing
# when the unzip had failed.
if ! unzip -o "$ZIPFILE" -x 'META-INF/*' -d "$MODPATH" >&2; then
    ui_print "*********************************************************"
    ui_print "! Unpacking the zip FAILED - nothing was installed."
    ui_print "! The download is truncated or the storage is full."
    ui_print "*********************************************************"
    rm -rf "$MODPATH"
    exit 1
fi

chmod 755 "$MODPATH"/*.sh "$MODPATH"/bin/*/nomount "$MODPATH"/bin/*/nm 2>/dev/null

# Sourced, not exec'd, so customize.sh's abort() is this script's abort().
if [ -f "$MODPATH/customize.sh" ]; then
    . "$MODPATH/customize.sh"
else
    ui_print "! customize.sh is missing from this zip - install not verified."
fi

ui_print "- NoMount installed via recovery"
exit 0
UPDATER
    chmod 0755 "$staging/META-INF/com/google/android/update-binary"
    echo "" > "$staging/META-INF/com/google/android/updater-script"

    (
        cd "$staging"
        find . -type f \
            ! -path './META-INF/*' \
            ! -name 'nomount.sha256sums' \
            -print0 | sort -z | xargs -0 sha256sum \
            | sed 's/^\([0-9a-f]\{64\}\) \*/\1  /' > nomount.sha256sums
    )
    if grep -q '^[0-9a-f]\{64\} \*' "$staging/nomount.sha256sums"; then
        echo "fatal: nomount.sha256sums is in binary mode (<hash> *path)." >&2
        echo "       Android's toybox cannot verify that form." >&2
        rm -rf "$staging"
        exit 1
    fi
    echo "    Sums:    $(wc -l < "$staging/nomount.sha256sums") files hashed"

    rm -f "$out_path"
    if command -v zip >/dev/null 2>&1; then
        (cd "$staging" && zip -r9 "$out_path" .)
    else
        python3 "$SCRIPT_DIR/mkzip.py" "$staging" "$out_path" \
            || python "$SCRIPT_DIR/mkzip.py" "$staging" "$out_path"
    fi
    rm -rf "$staging"

    echo "    Output:  $out_path"
    echo "    Size:    $(du -h "$out_path" | cut -f1)"
    echo "    Bins:    nomount+nm x${want} ($(printf '%s ' "${!ABI_TARGET[@]}"))"
    echo "    WebUI:   present"
}

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
        echo "fatal: ${DEPLOY_PROFILE} zip not found at $ZIP" >&2
        exit 1
    fi

    if ! adb devices 2>/dev/null | grep -q 'device$'; then
        echo "fatal: no adb device connected" >&2
        exit 1
    fi

    REMOTE="/data/local/tmp/nomount-deploy.zip"
    echo "==> Deploying $ZIP to device"
    adb push "$ZIP" "$REMOTE"
    adb shell "/data/adb/ksu/bin/ksud module install $REMOTE" 2>/dev/null \
        || adb shell "/data/adb/ap/bin/apd module install $REMOTE" 2>/dev/null \
        || adb shell "su -c 'magisk --install-module $REMOTE'" 2>/dev/null \
        || { echo "fatal: module install failed" >&2; exit 1; }
    adb shell "rm -f $REMOTE"
    echo "==> Module installed"

    if [ "$REBOOT" = true ]; then
        echo "==> Rebooting device"
        adb reboot
    fi
fi
