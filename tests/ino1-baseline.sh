#!/system/bin/sh
# engine-ino-1: does a duplicate (st_dev, st_ino) pair inside one directory occur
# NATURALLY on this ROM, or only where the file placer put one there?
#
# The finding's detector is `find /system -xdev -printf '%i\n' | sort | uniq -d`.
# Two things make that detector weaker than it looks, both measured on an OP15:
#   - hardlinks put duplicate inode numbers in stock directories, so a non-zero
#     natural rate removes the oracle. That rate had never been measured.
#   - every big injected parent under /product is its OWN MOUNT at major 0
#     (/product is 254:26; /product/overlay is 0:27, /product/app 0:49,
#     /product/priv-app 0:58, /product/lib64 0:67, /product/framework 0:89), so
#     `find /product -xdev` never even enters them.
#
# Instrument notes, learned the hard way on this device's toybox:
#   - `find -printf` accepts ONLY %i %p %P %f %s here. %y %d %D %h %n all error
#     with "bad -printf", and a `2>/dev/null` on that turns the error into an
#     empty result that reads as "0 collisions". Use stat via -exec, and never
#     discard stderr on the command that produces the data.
#   - every pass asserts its child count against `ls -1` before trusting it.
#
#   adb push tests/ino1-baseline.sh /data/local/tmp/
#   adb shell su -c 'sh /data/local/tmp/ino1-baseline.sh'

NM=${NM:-/data/adb/modules/meta-nomount/bin/arm64-v8a/nomount}
T=/data/local/tmp/ino1
rm -rf $T; mkdir -p $T
[ -x "$NM" ] || { echo "fatal: no nomount binary at $NM"; exit 1; }

# (dev, ino, name) for one directory's direct children. Asserts against ls -1.
kids() {
	find "$1" -maxdepth 1 -mindepth 1 -exec stat -c '%d %i %n' {} + 2>$T/err > $T/k
	got=$(grep -c . $T/k); want=$(ls -1 "$1" 2>/dev/null | grep -c .)
	if [ "$got" != "$want" ]; then
		echo "   !! INSTRUMENT MISMATCH in $1: stat gave $got, ls -1 says $want"
		[ -s $T/err ] && sed 's/^/      stderr: /' $T/err
		return 1
	fi
	return 0
}

# stderr kept, and zero rules is FATAL. With 2>/dev/null a vfs list that failed -- a
# wrong NM path, an SELinux denial on the netlink socket, an engine that is not up --
# left $T/inj empty, and empty is not neutral here: PASS 1 then iterates nothing, and
# PASS 2's "engine never touched this" filter (grep -qF "$D/" $T/inj) matches nothing,
# so EVERY directory counts as stock and the run prints a tidy table of zeros that reads
# as "no natural collisions". The measurement would not have happened.
$NM vfs list 2>$T/vlerr | sed 's/ ->.*//' | sed 's/ (public)$//' | sort -u > $T/inj
if [ ! -s $T/inj ]; then
	echo "fatal: vfs list returned no rules. It said:"
	sed 's/^/   /' $T/vlerr
	echo "   NM=$NM"
	echo "   Refusing to continue: with no rule list every directory reads as stock and"
	echo "   both passes report zeros they never measured."
	rm -rf $T; exit 1
fi
sed 's|/[^/]*$||' $T/inj | sort -u > $T/parents
echo "rules: $(grep -c . $T/inj)   distinct parents: $(grep -c . $T/parents)"
# The device the placer keys on is the PARENT's (pop->dev, nomount.c:4611/4622/4721), not
# the injected inode's. Printed so a cold-slot run has the right list to pick against.
printf "warm devices (by parent dev, what di->used is keyed on): "
while IFS= read -r d; do stat -c %d "$d" 2>/dev/null; done < $T/parents | sort -un | tr '\n' ' '
echo

echo
echo "== PASS 1: every parent holding injected rules =="
echo "   collision = two names in one dir sharing (st_dev, st_ino)"
while IFS= read -r P; do
	[ -d "$P" ] || continue
	kids "$P" || continue
	kn=$(grep -c . $T/k)
	devs=$(awk '{print $1}' $T/k | sort -u | tr '\n' ',' | sed 's/,$//')
	awk '{print $1" "$2}' $T/k | sort | uniq -d > $T/d
	dn=$(grep -c . $T/d)
	ninj=$(while read -r a b n; do grep -qxF "$n" $T/inj && echo x; done < $T/k | grep -c .)
	printf "   %-42s %4d children (%d injected) dev=%-9s %d collision(s)\n" \
		"$P" "$kn" "$ninj" "$devs" "$dn"
	[ "$dn" = 0 ] && continue
	while IFS= read -r DI; do
		echo "      (dev,ino) = $DI"
		awk -v D="${DI% *}" -v I="${DI#* }" '$1==D && $2==I {print $3}' $T/k | while IFS= read -r nm; do
			if grep -qxF "$nm" $T/inj; then echo "        [INJECTED] $nm"; else echo "        [stock   ] $nm"; fi
		done
	done < $T/d
done < $T/parents

echo
echo "== PASS 2: stock-only control on the SAME devices =="
echo "   the natural collision rate in dirs the engine never touched"
for R in /system /system_ext /product /product/overlay /product/app /product/priv-app /product/framework; do
	[ -d "$R" ] || continue
	checked=0; tot=0; coll=0; hard=0
	find "$R" -type d -mindepth 1 2>/dev/null | head -250 > $T/cand
	while IFS= read -r D; do
		grep -qF "$D/" $T/inj && continue
		kids "$D" >/dev/null 2>&1 || continue
		c=$(grep -c . $T/k); [ "$c" -lt 2 ] && continue
		checked=$((checked+1)); tot=$((tot+c))
		u=$(awk '{print $1" "$2}' $T/k | sort | uniq -d | grep -c .)
		if [ "$u" != 0 ]; then coll=$((coll+1)); hard=$((hard+u)); fi
	done < $T/cand
	printf "   %-24s %4d stock dirs, %6d children, %d dir(s) with a collision (%d pairs)\n" \
		"$R" "$checked" "$tot" "$coll" "$hard"
done
rm -rf $T
