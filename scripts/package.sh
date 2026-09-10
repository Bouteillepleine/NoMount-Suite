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

if [ -f "$PROJECT_ROOT/Cargo.lock" ] && [ "$NEW_VERSION" != "$CURRENT_VERSION" ]; then
    (cd "$PROJECT_ROOT" && "${CARGO:-cargo}" update --offline --quiet -p nomount 2>/dev/null) \
        || (cd "$PROJECT_ROOT" && "${CARGO:-cargo}" metadata --offline --format-version 1 >/dev/null 2>&1) \
        || echo "    !! could not refresh Cargo.lock for $NEW_VERSION; --locked builds may fail" >&2
fi

vbase="${NEW_VERSION%%-*}"
IFS=. read -r vmaj vmin vpat <<< "$vbase"
if [ "${vmin:-0}" -ge 100 ] || [ "${vpat:-0}" -ge 1000 ]; then
    echo "fatal: v${NEW_VERSION} does not fit the versionCode field widths." >&2
    echo "       vcode = major*100000 + minor*1000 + patch needs minor < 100 and" >&2
    echo "       patch < 1000; this version would collide with another release and" >&2
    echo "       managers, which key updates on versionCode alone, would read it as" >&2
    echo "       a downgrade. Widen the multipliers (and keep every new code above" >&2
    echo "       the largest already published) before bumping further." >&2
    exit 1
fi
case "$NEW_VERSION" in
    *-*)
        echo "fatal: v${NEW_VERSION} carries a pre-release suffix, and the versionCode formula" >&2
        echo "       drops it: v${vbase}-<suffix> and v${vbase} both map to the same code." >&2
        echo "       Managers key the update offer on versionCode alone, so everyone who took" >&2
        echo "       the pre-release would never be offered the final. Use a distinct patch" >&2
        echo "       number instead of a suffix." >&2
        exit 1
        ;;
esac
vcode=$(( ${vmaj:-0} * 100000 + ${vmin:-0} * 1000 + ${vpat:-0} ))

# ...and it must not fall below the published one, nor collide with it across a version
# change. The width guard above only bounds the fields; the error text has always promised
# "keep every new code above the largest already published" and nothing enforced it, so a
# hotfix cut on an older line (v1.3.99 after v1.3.176) would publish a LOWER code and
# silently stop every device being offered anything. Rebuilding the tree's own already-
# published version is allowed: packaging is not publishing.
_published=$(sed -n 's/.*"versionCode"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$PROJECT_ROOT/update.json" 2>/dev/null | head -1)
if [ -n "${_published:-}" ]; then
    if [ "$vcode" -lt "$_published" ]; then
        echo "fatal: versionCode ${vcode} for v${NEW_VERSION} is BELOW the published" >&2
        echo "       ${_published} (see update.json). Root managers key the update offer on" >&2
        echo "       versionCode alone, so publishing this would read as a downgrade and" >&2
        echo "       no device would ever be offered it. Cut the version forward instead." >&2
        exit 1
    elif [ "$vcode" -eq "$_published" ] && [ "$NEW_VERSION" != "$CURRENT_VERSION" ]; then
        echo "fatal: versionCode ${vcode} for v${NEW_VERSION} COLLIDES with the published" >&2
        echo "       ${_published} (see update.json), and this is a version change, not a" >&2
        echo "       rebuild. Two different versions sharing one code means the second is" >&2
        echo "       never offered. Cut the version forward instead." >&2
        exit 1
    elif [ "$vcode" -eq "$_published" ]; then
        # A plain rebuild of the tree's own, already-published version. Packaging is not
        # publishing, and blocking this would break the ordinary build-and-sideload loop.
        echo "==> note: rebuilding already-published v${NEW_VERSION} (versionCode ${vcode});"
        echo "    fine to sideload, but bump the version before cutting a release."
    fi
fi
unset _published
sed -i "s/^version=.*/version=v${NEW_VERSION}/" "$MODULE_DIR/module.prop"
sed -i "s/^versionCode=.*/versionCode=${vcode}/" "$MODULE_DIR/module.prop"

grep -q "^version=v${NEW_VERSION}\$" "$MODULE_DIR/module.prop" \
    || { echo "fatal: could not stamp version= into module.prop" >&2; exit 1; }
grep -q "^versionCode=${vcode}\$" "$MODULE_DIR/module.prop" \
    || { echo "fatal: could not stamp versionCode= into module.prop - the release would" >&2
         echo "       publish, and only release.yml's post-publish read would notice." >&2; exit 1; }

VERSION="v${NEW_VERSION}"

BUILD_COMMIT="$(git -C "$PROJECT_ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
_dirt="$(git -C "$PROJECT_ROOT" status --porcelain 2>/dev/null \
          | grep -vE ' (Cargo\.toml|Cargo\.lock|module/module\.prop)$' || true)"
if [ -n "$_dirt" ]; then
    BUILD_COMMIT="${BUILD_COMMIT}+dirty"
fi
export BUILD_COMMIT
echo "==> Build commit: ${BUILD_COMMIT}"
if [ -n "$_dirt" ]; then
    echo "    +dirty because these paths are not clean:"
    printf '%s\n' "$_dirt" | sed 's/^/      /'
fi
unset _dirt

build_nm() {
    local zig cc
    zig="$(command -v zig || true)"
    cc="${NDK_BIN:-/nonexistent}/aarch64-linux-android26-clang"
    if [ -n "$zig" ]; then
        "$zig" cc -target aarch64-linux -Oz -static -nostdlib -ffreestanding \
            -fno-unwind-tables -fno-ident -Wno-invalid-noreturn -Wl,--entry=_start \
            "$PROJECT_ROOT/userspace/src/nm.c" -o "$PROJECT_ROOT/nm-arm64" || return 2
    elif [ -x "$cc" ]; then
        echo "==> nm: no zig on path, building with the NDK's clang instead"
        "$cc" -Oz -static -nostdlib -ffreestanding \
            -fno-unwind-tables -fno-ident -Wno-invalid-noreturn -Wl,--entry=_start \
            "$PROJECT_ROOT/userspace/src/nm.c" -o "$PROJECT_ROOT/nm-arm64" || return 2
    else
        return 1
    fi
    make -s -C "$PROJECT_ROOT/userspace/tools/sstrip" >/dev/null 2>&1 || true
    # NOT `|| true`. commitchanges() rewrites the header before it can fail, so a failed
    # strip leaves a corrupt file behind - and the staleness gate below only compares mtimes,
    # which a corrupt file passes. Skip the strip if the tool is missing; fail if it errors.
    if [ -x "$PROJECT_ROOT/userspace/tools/sstrip/sstrip" ]; then
        if ! "$PROJECT_ROOT/userspace/tools/sstrip/sstrip" -z "$PROJECT_ROOT/nm-arm64" >/dev/null 2>&1; then
            echo "fatal: sstrip failed on nm-arm64; it rewrites the ELF header before it can" >&2
            echo "       fail, so the file is now suspect. Not packaging it." >&2
            rm -f "$PROJECT_ROOT/nm-arm64"
            return 2
        fi
    else
        echo "==> nm: sstrip not built; shipping the unstripped binary" >&2
    fi
    # ...and prove what came out is still a loadable ELF, which no check did before.
    if ! head -c 4 "$PROJECT_ROOT/nm-arm64" | grep -q 'ELF'; then
        echo "fatal: nm-arm64 is not an ELF after stripping." >&2
        rm -f "$PROJECT_ROOT/nm-arm64"
        return 2
    fi
    local profile
    for profile in debug release; do
        install -Dm755 "$PROJECT_ROOT/nm-arm64" \
            "$PROJECT_ROOT/target/aarch64-linux-android/${profile}/nm"
    done
    rm -f "$PROJECT_ROOT/nm-arm64"
    echo "==> nm built from source ($(wc -c < "$PROJECT_ROOT/target/aarch64-linux-android/release/nm") bytes)"
    return 0
}

mkdir -p "$RELEASE_DIR/debug" "$RELEASE_DIR/release"

if [ "$CLEAN" = true ]; then
    echo "==> Cleaning old releases"
    rm -f "$RELEASE_DIR"/debug/00_NoMount-Module-*.zip "$RELEASE_DIR"/release/00_NoMount-Module-*.zip
fi

SCRIPTS=(
    customize.sh
    lib.sh
    metamount.sh
    post-fs-data.sh
    post-mount.sh
    service.sh
    uidscan.sh
    uidwatch.sh
    uninstall.sh
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
        "$CARGO" build --locked --manifest-path "$PROJECT_ROOT/Cargo.toml" \
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
    # Anchored: the character after the version must not be another digit, or "1.3.17"
    # matches inside a binary built at "1.3.176" and repackaging an old label over a newer
    # binary passes the guard whose whole job is to stop that.
    if grep -qaE -- "nomount v${want//./\.}([^0-9]|\$)" "$bin"; then
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

        local nm_cand nm_stale=""
        for nm_cand in "$PROJECT_ROOT/target/$target/$target_subdir/nm" \
                       "$MODULE_DIR/bin/$abi/nm"; do
            [ -f "$nm_cand" ] || continue
            if [ "$PROJECT_ROOT/userspace/src/nm.c" -nt "$nm_cand" ] \
               || [ "$PROJECT_ROOT/userspace/src/nm.h" -nt "$nm_cand" ]; then
                nm_stale="${nm_stale}${nm_stale:+, }$nm_cand"
                continue
            fi
            cp "$nm_cand" "$staging/bin/$abi/nm"; found_nm=$((found_nm + 1))
            break
        done
        if [ ! -f "$staging/bin/$abi/nm" ] && [ -n "$nm_stale" ]; then
            echo "fatal: every nm candidate for $abi predates userspace/src/nm.[ch]:" >&2
            echo "         $nm_stale" >&2
            echo "       Re-run with --build (zig 0.14.x, or the NDK's clang), or take" >&2
            echo "       the binary from CI. Packaging the old one would ship an nm that" >&2
            echo "       does not match the source in this zip." >&2
            rm -rf "$staging"
            exit 1
        fi
    done

    if [ "$found_nomount" -ne "$want" ] || [ "$found_nm" -ne "$want" ]; then
        echo "fatal: [$profile] nomount ${found_nomount}/${want}, nm ${found_nm}/${want}" >&2
        rm -rf "$staging"
        exit 1
    fi

    if [ ! -f "$MODULE_DIR/webroot/index.html" ]; then
        echo "fatal: no module/webroot/index.html - the zip would ship no WebUI." >&2
        rm -rf "$staging"
        exit 1
    fi
    cp -r "$MODULE_DIR/webroot" "$staging/webroot"
    sed -i "s/const SUITE_VERSION = \"[^\"]*\"/const SUITE_VERSION = \"${VERSION}\"/" \
        "$staging/webroot/index.html"
    sed -i "s/const SUITE_COMMIT = \"[^\"]*\"/const SUITE_COMMIT = \"${BUILD_COMMIT}\"/" \
        "$staging/webroot/index.html"
    if ! grep -q "const SUITE_VERSION = \"${VERSION}\"" "$staging/webroot/index.html"; then
        echo "fatal: could not stamp SUITE_VERSION into webroot/index.html" >&2
        rm -rf "$staging"
        exit 1
    fi
    if ! grep -q "const SUITE_COMMIT = \"${BUILD_COMMIT}\"" "$staging/webroot/index.html"; then
        echo "fatal: could not stamp SUITE_COMMIT into webroot/index.html" >&2
        rm -rf "$staging"
        exit 1
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

# Stage, never the live install.
#
# `MODPATH` is set by ksud and by the Magisk app when they drive the install, and
# it points at /data/adb/modules_update/<id> -- a staging directory the manager
# promotes at the next boot. It is unset on the two paths that run this script
# directly (recovery, and the Magisk app's own zip handler), and the fallback was
# the live module directory. Two consequences, both bad:
#
#   * `abort()` above is `rm -rf "$MODPATH"`. So customize.sh's integrity refusal
#     and its metamodule-conflict refusal did not FAIL an install - they
#     uninstalled the working Suite the user already had. A corrupted download
#     took out a good install.
#   * `unzip -o` MERGES over the existing tree, so a file dropped in a later
#     version was never removed and `nomount.sha256sums` cannot see it (it only
#     checks that listed files match).
#
# Staging fixes both: abort's `rm -rf` then throws away a scratch directory, and
# the manager replaces the live tree wholesale instead of merging into it.
MODPATH="${MODPATH:-/data/adb/modules_update/meta-nomount}"
# A stale staging directory from an install that aborted must not merge into this
# one, for the same reason `unzip -o` must not merge into the live tree.
rm -rf "$MODPATH"
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

# Above the source, deliberately. customize.sh spends forty lines choosing the
# last line ON screen - the right next step for the state this install actually
# ended in, including "your kernel has no NoMount support, the module installs
# but injects NOTHING". Printing an unqualified "- NoMount installed" after that
# stapled a success line under every failure box. Only an abort() escaped it,
# because abort exits. So say the narrow true thing first, and let customize.sh
# have the last word.
ui_print "- Unpacked via recovery"

# Sourced, not exec'd, so customize.sh's abort() is this script's abort().
if [ -f "$MODPATH/customize.sh" ]; then
    . "$MODPATH/customize.sh"
else
    # Not a warning to print past. customize.sh IS this install's verification and
    # labelling: the sha256 manifest check, the "only one metamodule" refusal, and the
    # explicit adb_data_file label on $NMDIR. Without it nothing verified the payload,
    # nothing refused a second metamodule, and the state directory keeps the default
    # system_file label that every app domain can read. A zip missing it is corrupt,
    # so fail the install instead of reporting success.
    abort "! customize.sh is missing from this zip - the install cannot be verified or labelled. Re-download the zip."
fi

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
    if ! command -v python3 >/dev/null 2>&1; then
        echo "fatal: python3 is required to build the archive (scripts/mkzip.py)." >&2
        rm -rf "$staging"
        exit 1
    fi
    python3 "$SCRIPT_DIR/mkzip.py" "$staging" "$out_path"
    echo "    Archive: mkzip.py (reproducible)"
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

    build_nm || _nmrc=$?
    case "${_nmrc:-0}" in
        0) ;;
        2) echo "fatal: a cross compiler is on path but compiling userspace/src/nm.c FAILED." >&2
           echo "       Fix the compile error; shipping the previous prebuilt would" >&2
           echo "       package a binary that does not match the source in this zip." >&2
           exit 1 ;;
        *) echo "==> nm: no zig and no NDK clang; a prebuilt will be used only if it is" >&2
           echo "    newer than userspace/src/nm.[ch] -- otherwise packaging stops below." >&2 ;;
    esac

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

    # Git Bash (MSYS) rewrites any argument that looks like a unix path, so the REMOTE
    # path reached adb as "C:/Program Files/Git/data/local/tmp/nomount-deploy.zip" and the
    # push failed with secure_mkdirs(). MSYS_NO_PATHCONV=1 stops that rewrite - but it
    # stops it for the LOCAL path too, and adb.exe needs a real Windows path for the file
    # it reads. So both are needed: disable the rewrite, and hand adb an already-converted
    # local path. On a non-MSYS host neither applies and $ZIP is passed through unchanged.
    _adb_local="$ZIP"
    case "$(uname -s 2>/dev/null)" in
        MINGW*|MSYS*|CYGWIN*)
            export MSYS_NO_PATHCONV=1
            if command -v cygpath >/dev/null 2>&1; then
                _adb_local="$(cygpath -w "$ZIP")"
            fi
            ;;
    esac

    adb push "$_adb_local" "$REMOTE" || { echo "fatal: adb push failed" >&2; exit 1; }

    # Run through `su -c`, and carry the status back in the OUTPUT rather than in
    # adb's exit code. Two separate measured problems, both silent:
    #
    #   * adb does not reliably propagate the remote exit status - `adb shell
    #     'exit 7'` returns 0 on this adb/device pair. So `if adb shell '[ -x ... ]'`
    #     was ALWAYS true: every deploy took the ksud branch whatever the device was
    #     running, and every `|| { echo fatal; exit 1; }` under it was unreachable.
    #     A deploy that installed nothing still printed "Module installed".
    #   * /data/adb is 0700 root:root, so the probes only see anything at all when
    #     adbd happens to be running as root. Through `su -c` they work either way.
    #
    # The command is embedded in single quotes for su, so it must not contain any
    # itself; every caller below is a plain path + arguments.
    _dev_sh() {
        _dev_out=$(adb shell "su -c '$1'"'; echo "__nmrc=$?"' 2>&1 | tr -d "\r")
        printf '%s' "$_dev_out" | sed "/^__nmrc=/d"
        case "$_dev_out" in
            *__nmrc=0*) return 0 ;;
            *)          return 1 ;;
        esac
    }

    if _dev_sh "[ -x /data/adb/ksu/bin/ksud ]" >/dev/null 2>&1; then
        _mgr="ksud"; _cmd="/data/adb/ksu/bin/ksud module install $REMOTE"
    elif _dev_sh "[ -x /data/adb/ap/bin/apd ]" >/dev/null 2>&1; then
        _mgr="apd";  _cmd="/data/adb/ap/bin/apd module install $REMOTE"
    elif _dev_sh "command -v magisk" >/dev/null 2>&1; then
        _mgr="magisk"; _cmd="magisk --install-module $REMOTE"
    else
        echo "fatal: no root manager found on the device (no ksud, apd or magisk)." >&2
        echo "       Nothing was installed." >&2
        adb shell "rm -f $REMOTE" >/dev/null 2>&1
        exit 1
    fi

    echo "==> Installing via $_mgr"
    if ! _dev_sh "$_cmd"; then
        echo "fatal: $_mgr module install FAILED - nothing was installed." >&2
        adb shell "rm -f $REMOTE" >/dev/null 2>&1
        exit 1
    fi
    adb shell "rm -f $REMOTE" >/dev/null 2>&1
    echo "==> Module installed via $_mgr"

    if [ "$REBOOT" = true ]; then
        echo "==> Rebooting device"
        adb reboot
    fi
fi
