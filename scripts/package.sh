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

# The stamp below is written before anything that can fail -- it has to be, the
# staged module.prop is what goes in the zip. But the binary-version guard further
# down aborts DELIBERATELY and often (that is its job), and every abort used to
# leave Cargo.toml and module.prop carrying a version no artifact was ever built
# for. Re-running then bumped again from there, so two failed runs moved the
# version two patches with nothing released. Roll the stamp back on any failure.
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

# Stamp it EVERYWHERE, for an explicit --version just as much as an auto-bump.
# These writes used to live inside the auto-bump branch, so `--version 1.3.9`
# renamed the zip while Cargo.toml and module.prop stayed behind: the artifact
# was called 1.3.9 and the binary inside it answered `nomount 1.3.8`. A version
# that lies about itself is the one thing a release must never do.
sed -i "s/^version = \"$CURRENT_VERSION\"/version = \"$NEW_VERSION\"/" "$PROJECT_ROOT/Cargo.toml"

# major*100000 + minor*1000 + patch. Plain dot-stripping regressed the code
# (1.2.0 -> "120" < 10102 for v1.1.2), which a manager reads as a downgrade.
#
# The field widths matter. The previous major*10000 + minor*100 + patch gave
# each of minor and patch only two digits, so v1.3.100 and v1.4.0 both came
# out 10400 -- and v1.3.101 (10401) OUTRANKED v1.4.0. Managers key updates on
# versionCode alone, so that is a real release published as a downgrade, and
# at v1.3.88 it was twelve patches away. Widening to three digits keeps every
# code monotonic and every new code far above the largest old one (v1.3.88
# was 10388, is now 103088), so no device sees this change as a downgrade.
vbase="${NEW_VERSION%%-*}"
IFS=. read -r vmaj vmin vpat <<< "$vbase"
# ...and ENFORCE the field widths the paragraph above reasons about, rather than
# trusting them. The previous scheme was not wrong in principle, it was wrong
# because minor and patch outgrew their fields and NOTHING SAID SO -- v1.3.101
# quietly outranked v1.4.0 and shipped as a downgrade. Three digits of patch and
# two of minor is a bound, and an unasserted bound is the same bug waiting on a
# counter: at the current cadence v1.3.999 is reachable, and v1.3.1000 would
# collide with v1.4.0 exactly as v1.3.100 once did.
#
# Refuse to package rather than emit a colliding code: a release published as a
# downgrade is invisible until someone's manager silently declines the update.
if [ "${vmin:-0}" -ge 100 ] || [ "${vpat:-0}" -ge 1000 ]; then
    echo "FATAL: v${NEW_VERSION} does not fit the versionCode field widths." >&2
    echo "       vcode = major*100000 + minor*1000 + patch needs minor < 100 and" >&2
    echo "       patch < 1000; this version would collide with another release and" >&2
    echo "       managers, which key updates on versionCode alone, would read it as" >&2
    echo "       a downgrade. Widen the multipliers (and keep every new code above" >&2
    echo "       the largest already published) before bumping further." >&2
    exit 1
fi
vcode=$(( ${vmaj:-0} * 100000 + ${vmin:-0} * 1000 + ${vpat:-0} ))
sed -i "s/^version=.*/version=v${NEW_VERSION}/" "$MODULE_DIR/module.prop"
sed -i "s/^versionCode=.*/versionCode=${vcode}/" "$MODULE_DIR/module.prop"

VERSION="v${NEW_VERSION}"

# WHICH COMMIT this zip was built from.
#
# The version alone is not enough and today proved it twice: five commits landed
# on top of `release v1.3.80` without a bump, so a phone reporting v1.3.80 might
# or might not carry the fix you were looking for, and the only way to tell was
# to diff the repo by hand. The same shape bit the kernel side, where three
# engine commits shipped without moving NM_MODULE_VERSION.
#
# DIRTY is not cosmetic. package.sh edits Cargo.toml and module.prop itself a few
# lines above, so the tree is ALWAYS modified by the time we get here -- those
# three are excluded, and anything else still-modified means the zip does not
# match the commit it names. Better to say so than to stamp a SHA that lies.
BUILD_COMMIT="$(git -C "$PROJECT_ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
# NAME WHAT IS DIRTY. The suffix alone is not diagnosable, and that is how it came
# to be meaningless: every CI zip is stamped `+dirty` -- v1.3.118 shipped as
# `710cdcb+dirty` and v1.3.119 as `8fbb35d+dirty` -- so the one thing the marker
# exists to say ("this zip does not match the commit it names") has been on
# permanently and reads as noise. A suffix that is always present is a suffix
# nobody reads, which is the same defect class as a green tick over a failed pass.
#
# The cause is NOT reproducible outside Actions: a pristine clone of the tagged
# commit, plus `make -C userspace/tools/sstrip` and the workflow's own
# `zig cc -o nm-arm64`, leaves `git status --porcelain` empty (measured, zig
# 0.14.1 -- its local cache goes to ~/.cache/zig, not into the tree). `/artifacts/`
# and `/nm-arm64` are already ignored and ignored files never appear in
# --porcelain anyway. So whatever it is belongs to a step only the runner
# performs, and the way to find out is to print it rather than guess again.
#
# `|| true` is load-bearing, and its absence broke the build the first time this
# was written. This script runs under `set -euo pipefail`, and `grep -v` exits 1
# when it filters EVERYTHING out -- which is precisely the healthy case, a clean
# tree. So the assignment failed, `set -e` killed the pass, and the rollback trap
# fired: the fix for "+dirty is always on" turned into "packaging dies the moment
# it stops being on". The original survived only because the substitution sat
# inside `[ -n "$(...)" ]`, where the test consumes the status.
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
    # Sourced by all five entry points below. NOT optional: each one stops with a
    # kmsg line and a non-zero exit when it cannot read this, so a zip built
    # without it installs and then does nothing at every stage. It is listed FIRST
    # so a truncated list is a loud failure rather than a silent one.
    lib.sh
    metamount.sh
    post-fs-data.sh
    post-mount.sh
    service.sh
    uidscan.sh
    uidwatch.sh
    # Shipped, or removing the Suite leaves the bindhosts mode_override.sh
    # behind -- the exact "a file we wrote selects a mode under a metamodule
    # we do not control" case its own header warns about. It sat in module/
    # unlisted, so no zip ever carried it and no uninstall ever ran it.
    uninstall.sh
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
                 "${LOCALAPPDATA:-/nonexistent}"/Android/Sdk/ndk/*; do
            for h in linux-x86_64 windows-x86_64 darwin-x86_64; do
                [ -d "$c/toolchains/llvm/prebuilt/$h/bin" ] && ndk="$c" && hostdir="$h"
            done
        done
    fi
    export NDK_BIN="$ndk/toolchains/llvm/prebuilt/${hostdir:-linux-x86_64}/bin"
    # On a Windows NDK the driver is a .cmd wrapper; the bare name in
    # .cargo/config.toml is a Unix-only file and rustc reports it as
    # "linker not found". config.toml stays correct for CI, and the
    # per-target env var (which outranks it) points at the wrapper here --
    # so the host detection above actually produces a build on the host it
    # just detected, instead of getting as far as the link step and dying.
    if [ "$hostdir" = "windows-x86_64" ]; then
        export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$NDK_BIN/aarch64-linux-android26-clang.cmd"
        export CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER="$NDK_BIN/armv7a-linux-androideabi26-clang.cmd"
        export CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER="$NDK_BIN/x86_64-linux-android26-clang.cmd"
        export CARGO_TARGET_I686_LINUX_ANDROID_LINKER="$NDK_BIN/i686-linux-android26-clang.cmd"
    fi
    if [ -z "$ndk" ] || [ ! -d "$NDK_BIN" ]; then
        echo "FATAL: Android NDK not found. Set ANDROID_NDK_HOME." >&2
        exit 1
    fi
    echo "==> NDK: $ndk"
    # Whatever cargo is on PATH, or whatever $CARGO already names. This used to
    # hardcode one maintainer's home directory (/home/president/.cargo) and force
    # RUSTUP_HOME/CARGO_HOME to match it, so on that machine every release was
    # built by a toolchain nobody else could reproduce, and on every other machine
    # the block was dead weight. Set CARGO=... in the environment to pick one.
    CARGO="${CARGO:-cargo}"
    export PATH="$NDK_BIN:$PATH"
}

# Build Rust for one profile across all ABIs
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


# Does this `nomount` binary actually answer with the version being stamped?
#
# Two ways, because the packaging host is usually not the target. Running it is
# the direct answer and works when packaging on arm64 (or under qemu-user
# binfmt); otherwise read the literal out of the file, which is exact rather
# than heuristic: the version is `env!("CARGO_PKG_VERSION")`, a compile-time
# string constant, so a binary built at 1.3.92 contains "1.3.92" and cannot
# contain "1.3.94". Verified against a stripped aarch64 release build, where the
# expected version is the only version-shaped literal present.
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

    # Sync the human-readable version string. The versionCode is NOT touched
    # here -- it was already written into module.prop at the top of this script,
    # from the semver, as major*100000 + minor*1000 + patch. This comment used to
    # say the committed value was "preserved verbatim", which stopped being true
    # when that stamping was added 160 lines above and left the one field
    # managers key updates on described by a comment that contradicted the code.
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
            echo "    !! nomount/$abi: NO built binary in target/$target/$target_subdir —" >&2
            echo "       packaging the committed prebuilt from module/bin/$abi instead." >&2
            cp "$MODULE_DIR/bin/$abi/nomount" "$staging/bin/$abi/nomount"; found_nomount=$((found_nomount + 1))
        fi
        # Ask the binary what version it is, instead of guessing from mtimes.
        #
        # Both arms above used to be policed by `find "$PROJECT_ROOT/src" -newer
        # <binary>`, which deliberately excluded Cargo.toml -- and the version
        # string is `env!("CARGO_PKG_VERSION")`, so it comes FROM Cargo.toml. A
        # release commit touches only Cargo.toml, Cargo.lock and module.prop, so
        # a version-bump-only release could never trip that guard. It did not:
        # the shipped v1.3.94 zip carries a binary that reports 1.3.92, confirmed
        # by hash on-device. A timestamp cannot answer this question; the binary
        # can, and that also makes the -newer logic redundant.
        if [ -f "$staging/bin/$abi/nomount" ]; then
            verify_binary_version "$staging/bin/$abi/nomount" "${VERSION#v}" || {
                echo "FATAL: [$profile] bin/$abi/nomount does not report ${VERSION#v}." >&2
                echo "       The zip would be labelled ${VERSION} around a binary that" >&2
                echo "       answers something else. Re-run with --build." >&2
                rm -rf "$staging"
                exit 1
            }
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
            sed -i "s/const SUITE_COMMIT = \"[^\"]*\"/const SUITE_COMMIT = \"${BUILD_COMMIT}\"/" \
                "$staging/webroot/index.html"
            # ASSERT. A sed that matches nothing is silent, and the failure mode
            # here is a shipped WebUI that calls itself "dev" and then reports
            # every real release as a staged update forever.
            if ! grep -q "const SUITE_VERSION = \"${VERSION}\"" "$staging/webroot/index.html"; then
                echo "FATAL: could not stamp SUITE_VERSION into webroot/index.html" >&2
                exit 1
            fi
            if ! grep -q "const SUITE_COMMIT = \"${BUILD_COMMIT}\"" "$staging/webroot/index.html"; then
                echo "FATAL: could not stamp SUITE_COMMIT into webroot/index.html" >&2
                exit 1
            fi
        fi
    fi

    # META-INF
    mkdir -p "$staging/META-INF/com/google/android"
    cat > "$staging/META-INF/com/google/android/update-binary" << 'UPDATER'
#!/sbin/sh
# Recovery installer.
#
# Everything that makes an install SAFE lives in customize.sh: the sha256
# manifest check, the "only one metamodule" refusal (two metamodules fighting in
# post-fs-data is a bootloop vector), the $NMDIR mode + SELinux label, and the
# bootcount reset. This script used to unzip, chmod, print a success line and
# exit 0 -- skipping all four, and reporting success even when the unzip failed.
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
# The manager's set_perm, including its FIFTH argument. Dropping the SELinux
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

# -x META-INF: this installer is not module content, and unzipping it into the
# module directory left an update-binary sitting under /data/adb/modules. And the
# status is CHECKED -- the old `exit 0` reported a successful install of nothing
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
    ui_print "! customize.sh is missing from this zip - install NOT verified."
fi

ui_print "- NoMount installed via recovery"
exit 0
UPDATER
    # 0755: some recoveries EXEC update-binary rather than handing it to sh. The
    # heredoc above creates it 0644 under the build umask, and mkzip.py's
    # path-based exec heuristic (.sh / bin/) does not cover this name either, so
    # both packaging paths were shipping the recovery installer non-executable.
    chmod 0755 "$staging/META-INF/com/google/android/update-binary"
    echo "" > "$staging/META-INF/com/google/android/updater-script"

    # Integrity manifest: sha256 of every payload file, excluding META-INF
    # (the recovery installer, not staged into the module) and the manifest
    # itself. customize.sh verifies this on-device to catch a corrupted or
    # tampered download before it runs the root binary.
    #
    # TEXT MODE, forced. On a Windows/Git-Bash host `sha256sum` defaults to
    # BINARY mode and writes "<hash> *./path" -- one space and an asterisk.
    # busybox and coreutils both accept that marker; Android's toybox does not,
    # and reads the `*` as the first character of the filename, so EVERY entry
    # fails to open and customize.sh aborts the install. Demonstrated on-device.
    # The sed normalises whichever form the host produced into the two-space text
    # form toybox reads, so this no longer depends on the packaging host.
    (
        cd "$staging"
        find . -type f \
            ! -path './META-INF/*' \
            ! -name 'nomount.sha256sums' \
            -print0 | sort -z | xargs -0 sha256sum \
            | sed 's/^\([0-9a-f]\{64\}\) \*/\1  /' > nomount.sha256sums
    )
    # ASSERT it, the same way the WebUI stamping above is asserted: a manifest
    # that still carries a binary-mode marker is one every Android install will
    # reject, and the only place that shows up is on someone's phone.
    if grep -q '^[0-9a-f]\{64\} \*' "$staging/nomount.sha256sums"; then
        echo "FATAL: nomount.sha256sums is in binary mode (<hash> *path)." >&2
        echo "       Android's toybox cannot verify that form." >&2
        rm -rf "$staging"
        exit 1
    fi
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
