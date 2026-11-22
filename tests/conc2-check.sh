#!/system/bin/sh
# Drives conc2-probe across a single `nomount vfs add` to measure engine-conc-2.
#
# The add targets a vpath whose INTERMEDIATE component does not exist on disk,
# e.g. /product/overlay/NmConc2/x.apk -- that is the branch that mints a rule for
# /product/overlay/NmConc2 and publishes it at nomount.c:4746 before computing its
# metadata at 4802-4842. The probe stats that intermediate dir in a tight loop
# across the add, keeps the first successes, then re-reads it afterwards for the
# cached residue.
#
# Order matters and is the point:
#   control -> establishes the stock ino band and mtime for the real parent, with
#              the same binary in the same run, so the ceiling is measured not
#              assumed (Gate 0).
#   watch   -> races the add.
#   read    -> residue, same process lineage.
#   read    -> again from a fresh process, which distinguishes "cached in my
#              dcache" from "cached kernel-wide" (Gate 4, re-entry).
#
# A COLD nm_dev_ino_tab slot widens the window by a subtree walk of up to 8192
# dirs. The widest run is the FIRST add touching that device after a reboot, so:
#   adb reboot; <wait>; then run this once, before anything else adds a rule.
# A warm-slot run that sees nothing has NOT refuted the finding -- the script says
# which it was.
#
# Nothing here calls `vfs clear`. One rule is added and deleted; the rule count is
# printed before and after so a leak is visible.
#
#   adb push tests/conc2-check.sh /data/local/tmp/
#   adb push conc2-probe /data/local/tmp/
#   adb shell su -c 'sh /data/local/tmp/conc2-check.sh'

PROBE=${PROBE:-/data/local/tmp/conc2-probe}
BIN=${BIN:-/data/adb/modules/meta-nomount/bin/arm64-v8a/nomount}
PARENT=${PARENT:-/product/overlay}
MID=${MID:-NmConc2}
LEAF=${LEAF:-x.apk}
PAYLOAD=${PAYLOAD:-/data/adb/nomount/conc2-payload}
MS=${MS:-4000}
ADD_DELAY=${ADD_DELAY:-0.2}

IPATH="$PARENT/$MID"
VPATH="$IPATH/$LEAF"
OUT=/data/local/tmp/conc2-watch.out

[ "$(id -u)" = 0 ] || { echo "fatal: needs root (adbd is uid 0 on this device)"; exit 1; }
[ -x "$PROBE" ] || { echo "fatal: no probe at $PROBE"; exit 1; }
[ -x "$BIN" ] || { echo "fatal: no nomount binary at $BIN"; exit 1; }
[ -d "$PARENT" ] || { echo "fatal: $PARENT is not a directory on this ROM"; exit 1; }
if [ -e "$IPATH" ]; then
	echo "fatal: $IPATH already exists -- pick an unused MID, this run would"
	echo "       take the existing-ancestor branch (4643) with real metadata."
	exit 1
fi

cleanup() {
	echo
	echo "== cleanup =="
	"$BIN" vfs del "$VPATH" 2>&1 | sed 's/^/  /'
	rm -f "$PAYLOAD"
	echo "  rules after:  $("$BIN" vfs list 2>/dev/null | grep -c .)"
}
trap cleanup EXIT INT TERM

echo "== engine =="
uname -r
"$BIN" --version 2>/dev/null || "$BIN" version 2>/dev/null
echo "  rules before: $("$BIN" vfs list 2>/dev/null | grep -c .)"
UP=$(cut -d. -f1 /proc/uptime)
echo "  uptime:       ${UP}s $([ "$UP" -lt 300 ] && echo '(likely COLD dev slot -- the wide window)' || echo '(likely WARM dev slot -- narrow window, a clean result proves little)')"

echo
# Gate 0: the ceiling is measured here, not assumed.
CTL=$("$PROBE" control "$PARENT")
echo "$CTL"
CEIL=$(echo "$CTL" | sed -n 's/^SIBLING_MAX=//p')
ZSTOCK=$(echo "$CTL" | sed -n 's/^ZERO_TIME_STOCK=//p')
CTXSTOCK=$(echo "$CTL" | sed -n 's/^CTX_STOCK=//p')
DENTSTOCK=$(echo "$CTL" | sed -n 's/^DENT_STOCK=//p')
BLKSTOCK=$(echo "$CTL" | sed -n 's/^BLKSIZE_STOCK=//p')
BTSTOCK=$(echo "$CTL" | sed -n 's/^BTIME_ZERO_STOCK=//p')
[ -n "$CEIL" ] || { echo "fatal: no baseline from $PARENT"; exit 1; }
if [ "${ZSTOCK:-0}" != 0 ]; then
	echo
	echo "STOP: $ZSTOCK stock subdir(s) of $PARENT already have mtime 0, so mtime==0"
	echo "      is NOT a tell on this parent. Use the ino test alone and say so."
fi
# The comparand is this MOUNT's maximum, and conc2-probe flags only a value the mount
# could not plausibly issue NEXT -- see CONC2_INO_SLACK below.
#
# Measured on an OP15 before getting this wrong twice: /product/overlay is its own mount
# (dev 27) holding exactly 26 entries, ALL directories, inodes 3..28 and nothing else.
# Its 225 "children" live on other devices (29/30/35). So widening the sample across the
# partition is meaningless here -- those are different mounts, and an inode is only
# comparable against the filesystem that issued it. The sibling maximum IS the right
# ceiling; what was wrong was treating ceiling+1 as an anomaly, when that is exactly the
# number this mount would hand out next.
NSIB=$(echo "$CTL" | sed -n 's/^  n_subdirs *//p')
SLACK=$(( ${NSIB:-0} > 16 ? ${NSIB:-0} : 16 ))
export CONC2_INO_SLACK="$SLACK"
echo "  ino ceiling:   $CEIL + $SLACK slack (this mount issued $CEIL over ${NSIB:-?} entries;"
echo "                 ceiling+1 is its next number, a name hash is not)"
export CONC2_INO_CEILING="$CEIL"
[ "${CTXSTOCK:-0}" != 0 ] && export CONC2_EXPECT_CTX=1
[ "${DENTSTOCK:-0}" = 0 ] && export CONC2_EXPECT_DENT=1
if [ -n "$CONC2_EXPECT_CTX" ]; then echo "  secctx test:   armed (stock labels $CTXSTOCK of its subdirs)"
else echo "  secctx test:   OFF (stock labels nothing here)"; fi
if [ -n "$CONC2_EXPECT_DENT" ]; then echo "  d_ino test:    armed (stock d_ino agrees with st_ino here)"
else echo "  d_ino test:    OFF -- $DENTSTOCK stock subdir(s) ALREADY disagree."
     echo "                 That is overlayfs, not the engine. Not a tell on this parent."; fi
echo "  stock blksize: $BLKSTOCK   stock btime==0: ${BTSTOCK:-?} of $(echo "$CTL" | sed -n 's/^  n_subdirs *//p')"
echo "                 (compare these against the injected dir by eye -- they are"
echo "                  reported, not auto-flagged, because the claim does not name them)"

mkdir -p "$(dirname "$PAYLOAD")"
echo conc2 > "$PAYLOAD"

echo
echo "== racing the add =="
echo "  watch $IPATH for ${MS}ms; vfs add fires ${ADD_DELAY}s in"
"$PROBE" watch "$IPATH" "$MS" > "$OUT" 2>&1 &
WPID=$!
sleep "$ADD_DELAY"
"$BIN" vfs add "$VPATH" "$PAYLOAD" 2>&1 | sed 's/^/  add: /'
wait $WPID
WRC=$?
cat "$OUT"

echo
"$PROBE" read "$IPATH"
RRC=$?

echo
echo "== fresh process, same path (is the bad inode cached kernel-wide?) =="
"$PROBE" read "$IPATH" | sed -n '/st_ino/p;/st_blksize/p;/st_size/p;/mtime/p;/anomalies/p' | sed 's/^/  /'

echo
echo "== as an app uid (Gate 7: is an unprivileged observer enough?) =="
HID=$("$BIN" uid list 2>/dev/null | sed -n 's/.*uid \([0-9]\{4,\}\).*/\1/p' | head -1)
if [ -z "$HID" ]; then
	echo "  SKIP: no app uid on hand. Any uid will do for THIS claim (the placeholder"
	echo "        metadata is not uid-scoped) but it has to be shown once to call it"
	echo "        app-reachable. Re-run with: su <appuid> -c '$PROBE read $IPATH'"
else
	chmod 755 "$PROBE"
	su "$HID" -c "CONC2_INO_CEILING=$CEIL $PROBE read $IPATH" | sed -n '/st_ino/p;/st_blksize/p;/st_size/p;/mtime/p;/anomalies/p' | sed 's/^/  /'
fi

echo
echo "== verdict =="
if [ "$WRC" = 2 ] || [ "$RRC" = 2 ]; then
	echo "  CONFIRMED: engine-conc-2 is observable."
	echo "  watch rc=$WRC read rc=$RRC -- read the values above, not this line."
else
	echo "  NO ANOMALY SEEN. This is not a refutation. Check, in order:"
	echo "   1. did watch see the path appear at all (iterations / present count)?"
	echo "   2. was the dev slot warm (uptime above)? reboot and re-run as the first add."
	echo "   3. widen MS or shorten ADD_DELAY so the loop straddles the add."
	echo "  Only a COLD-slot run whose watch saw the transition and still found"
	echo "  nothing is evidence against the finding."
fi
