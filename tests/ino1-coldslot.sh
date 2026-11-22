#!/system/bin/sh
# engine-ino-1, COLD-slot half: does the file placer's gap-fit hand an injected
# file an inode number a sibling already holds?
#
# `di->used` is keyed per DEVICE, so a slot is cold on any device no rule has ever
# touched -- no reboot needed. On this OP15 the 287 boot rules warm devs
# 35/55/62/108/65048-65051/65061; /odm is 65054 and carries none, so the FIRST add
# there takes the cold path, where the finding says placement degrades to the
# same-type `pop` sample. /odm/etc/camera is the shape the finding names: ~94 files
# interleaved with ~24 subdirs, which mkfs lays out in traversal order.
#
# The first add is the only cold sample this device can give; every later add on
# 65054 is warm. Both are measured, so a collision can be attributed to coldness
# rather than to gap-fitting in general. Add duration is the coldness witness --
# a cold slot pays for a subtree walk of up to NM_DMAX_DIRS=8192 dirs.
#
#   adb shell su -c 'sh /data/local/tmp/ino1-coldslot.sh'

NM=${NM:-/data/adb/modules/meta-nomount/bin/arm64-v8a/nomount}
P=${P:-/odm/etc/camera}
N=${N:-12}
PAY=/data/adb/nomount/ino1-payload
T=/data/local/tmp/ino1c
rm -rf $T; mkdir -p $T

[ -x "$NM" ] || { echo "fatal: no nomount at $NM"; exit 1; }
[ -d "$P" ] || { echo "fatal: $P not a directory"; exit 1; }

snap() { find "$P" -maxdepth 1 -mindepth 1 -exec stat -c '%d %i %n' {} + 2>$T/err > "$1"
	g=$(grep -c . "$1"); w=$(ls -1 "$P" | grep -c .)
	[ "$g" = "$w" ] || { echo "   !! instrument: stat $g vs ls $w"; sed 's/^/      /' $T/err; }; }

cleanup() {
	echo
	echo "== cleanup =="
	i=1; while [ $i -le $N ]; do $NM vfs del "$P/nm_ino1_$i.tmp" >/dev/null 2>&1; i=$((i+1)); done
	rm -f "$PAY"
	echo "   rules now: $($NM vfs list 2>/dev/null | grep -c .)  (expected the pre-run count)"
	rm -rf $T
}
trap cleanup EXIT INT TERM

echo "target $P   dev=$(stat -c %d "$P")   rules before: $($NM vfs list 2>/dev/null | grep -c .)"
# Warm = the device the PLACER keys on, which is pop->dev: the device of the PARENT
# directory being injected into (nomount.c:4611, 4622, 4721, and 4313 via sl->pop.dev).
# This used to stat the rule's own virtual path, which returns the INJECTED inode's
# synthesized dev instead -- a different number. Measured on this OP15, 287 rules:
#   by parent dev (right):   27 49 58 113 65048 65049 65050 65051 65061
#   by injected dev (wrong): 35 55 62 116 65048 65049 65050 65051 65061
# Four of nine disagree, so /product/overlay, /product/app, /product/priv-app and
# /my_product/* read as COLD while the placer has them warm. A run aimed at one of those
# would have measured a warm slot and reported "no collision on the cold path" -- a pass
# that proves nothing, which is the one outcome this script must not be able to produce.
# /odm (65054) is cold under both keyings, so the target below was never wrong; the
# witness for it was.
$NM vfs list 2>$T/vlerr | sed 's/ ->.*//;s/ (public)$//' | sed 's|/[^/]*$||' | sort -u \
	| while read -r d; do stat -c %d "$d" 2>/dev/null; done | sort -un > $T/warm
[ -s $T/warm ] || { echo "fatal: no warm devices resolved -- vfs list said:"; cat $T/vlerr
	echo "   (every device would read as cold, so refusing to measure)"; exit 1; }
echo "devices already carrying rules (warm, by parent dev): $(tr '\n' ' ' < $T/warm)"
case " $(tr '\n' ' ' < $T/warm) " in
	*" $(stat -c %d "$P") "*) echo "   !! $P is on a WARM device -- this run cannot measure the cold path"; exit 1;;
esac

snap $T/before
echo "baseline: $(grep -c . $T/before) children, $(awk '{print $1" "$2}' $T/before | sort | uniq -d | grep -c .) collision(s)"
echo "   file inos:  $(awk '{print $2}' $T/before | sort -n | head -1) .. $(awk '{print $2}' $T/before | sort -n | tail -1)"
echo "   subdir count: $(find "$P" -maxdepth 1 -mindepth 1 -type d | grep -c .)"

echo "x" > "$PAY"
echo
echo "== adds (#1 is the COLD one) =="
i=1
while [ $i -le $N ]; do
	V="$P/nm_ino1_$i.tmp"
	t0=$(date +%s%N)
	out=$($NM vfs add "$V" "$PAY" 2>&1)
	t1=$(date +%s%N)
	ms=$(( (t1 - t0) / 1000000 ))
	ino=$(stat -c %i "$V" 2>/dev/null); dev=$(stat -c %d "$V" 2>/dev/null)
	hit=$(awk -v D="$dev" -v I="$ino" '$1==D && $2==I {print $3}' $T/before | head -1)
	printf "   #%-3s %5s ms  dev=%-6s ino=%-10s %s" "$i" "$ms" "${dev:-?}" "${ino:-?}" \
		"$([ $i = 1 ] && echo '<- COLD' || echo '')"
	if [ -n "$hit" ]; then printf "  *** COLLIDES with %s ***" "$hit"; fi
	echo
	[ -n "$out" ] && [ "$out" != "ok" ] && echo "        add said: $out"
	i=$((i+1))
done

echo
echo "== post-add scan of the whole directory =="
snap $T/after
awk '{print $1" "$2}' $T/after | sort | uniq -d > $T/dup
dn=$(grep -c . $T/dup)
echo "   $(grep -c . $T/after) children, $dn (dev,ino) collision(s)"
while IFS= read -r DI; do
	echo "   (dev,ino) = $DI"
	awk -v D="${DI% *}" -v I="${DI#* }" '$1==D && $2==I {print "      "$3}' $T/after
done < $T/dup
