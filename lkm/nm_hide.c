/* A loadable engine announces itself three ways a built-in one does not:
 * a /proc/modules line, a /sys/module/<name> directory, and its symbols in
 * /proc/kallsyms tagged with the module name. All three come from the
 * module list and the module kobject, so removing the module from both
 * closes all three at once, for every reader including root.
 *
 * susfs can do this via hide_modules, but that is only there if susfs is
 * loaded, and it deliberately leaves /sys/module readable by root (its
 * parameters live there). This is self-contained and removes the directory
 * outright.
 *
 * The cost is that rmmod can no longer find the module: `insmod nomount.ko
 * hide=0` keeps it listed and unloadable, which is what a dev build wants.
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/kobject.h>

#include "nm_oot.h"
#include "nm_hide.h"

static bool nm_hide = true;
module_param_named(hide, nm_hide, bool, 0);
MODULE_PARM_DESC(hide,
	"Take the module out of /proc/modules, /sys/module and /proc/kallsyms "
	"once it is up (default 1). hide=0 keeps it listed and rmmod-able.");

static bool nm_hidden;

void nm_module_hide(void)
{
	struct mutex *mod_lock;

	if (!nm_hide || nm_hidden)
		return;

	/* module_mutex is not exported. Taking it matters: the list is walked
	 * by /proc/modules readers and mutated by any concurrent insmod. */
	mod_lock = (struct mutex *)nm_oot_lookup("module_mutex");
	if (!mod_lock) {
		pr_warn("nomount: module_mutex not resolvable - staying visible in "
			"/proc/modules rather than unlinking without the lock\n");
		return;
	}

	mutex_lock(mod_lock);
	/* list_del_rcu, not list_del: the module list has RCU readers, and this
	 * leaves a reader already walking it able to finish. It is only safe
	 * because the module is never freed afterwards - which is the same
	 * reason rmmod can no longer find it. */
	list_del_rcu(&THIS_MODULE->list);
	mutex_unlock(mod_lock);
	synchronize_rcu();

#ifdef CONFIG_SYSFS
	kobject_del(&THIS_MODULE->mkobj.kobj);
#endif

	nm_hidden = true;
	/* Deliberately not logged: a kmsg line naming the module would undo
	 * the point of the exercise. */
}
