// SPDX-License-Identifier: GPL-2.0
/*
 * Samsung LSM install overlay, revised for the pinned official SUSFS r18.1
 * source 85ef920ccf27682a2a9089b4676547f691b92828 and the eight official ARM64 KMI build targets.
 * Based on rushiranpise/Root-My-Galaxy-Payloads b9a4479's lsm_hook.c.
 *
 * An insert-shaped hook may add a denial but never turn a SELinux denial into
 * an allow. On zero verdict the original function executes unchanged. On a
 * nonzero verdict the entry probe returns directly to the caller with x0 set:
 * this is the ARM64 override_function_with_return() register operation.
 * There is no post-handler trampoline and no state carried across exception
 * return. Probe registration is inactive until its exact entry address passes
 * validation. No allocations occur in our handler or recursion guard.
 *
 * IMPORTANT BUILD CONTRACT: only the thirteen pinned SUS_PATH decisions below
 * may be called here; they must remain non-sleeping, including the resolved
 * KernelSU uid gate. This file is not a generic adapter for arbitrary LSM
 * callbacks. Source/mocked tests do not constitute a kernel build or device
 * validation. Re-audit callbacks when changing the upstream source revision.
 */
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/lsm_hooks.h>
#include <linux/kprobes.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/percpu.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/version.h>
#include <linux/smp.h>

#include "lsm_hook.h"
#include "susfs_log.h"
#include "symbol_resolver.h"

#if !defined(CONFIG_ARM64)
#error "The Samsung overlay requires ARM64"
#endif
#define SUSFS_KERNEL_FAMILY (LINUX_VERSION_CODE >> 8)
#if SUSFS_KERNEL_FAMILY != (KERNEL_VERSION(5, 10, 0) >> 8) && \
    SUSFS_KERNEL_FAMILY != (KERNEL_VERSION(5, 15, 0) >> 8) && \
    SUSFS_KERNEL_FAMILY != (KERNEL_VERSION(6, 1, 0) >> 8) && \
    SUSFS_KERNEL_FAMILY != (KERNEL_VERSION(6, 6, 0) >> 8) && \
    SUSFS_KERNEL_FAMILY != (KERNEL_VERSION(6, 12, 0) >> 8) && \
    SUSFS_KERNEL_FAMILY != (KERNEL_VERSION(6, 18, 0) >> 8)
#error "The Samsung overlay targets only the eight official GKI KMI builds"
#endif
#undef SUSFS_KERNEL_FAMILY

/*
 * Diagnostics, kept from the two reboots that produced them.
 *
 * `lsm_max=N` installs at most N probes and `lsm_off=1` installs none, so the layer can be run as a
 * prefix of itself. Skipping a member reports -EOPNOTSUPP rather than success;
 * required-hook failures remain fatal in the upstream caller.
 */
static int lsm_max = -1;
module_param(lsm_max, int, 0644);
MODULE_PARM_DESC(lsm_max, "install at most this many probes (-1 installs every hook the caller declares)");

static bool lsm_off;
module_param(lsm_off, bool, 0644);
MODULE_PARM_DESC(lsm_off, "install no probes at all (diagnostic)");

static char lsm_skip[128] = "";
module_param_string(lsm_skip, lsm_skip, sizeof(lsm_skip), 0644);
MODULE_PARM_DESC(lsm_skip, "comma-separated members not to probe, e.g. inode_permission");

/* Guard lifetime is exactly the handler, never a redirected continuation.
 * Kprobe handlers cannot migrate or sleep; separate CPUs have separate state.
 * Core kprobes also suppress nested probes, so this is a defensive local guard. */
static DEFINE_PER_CPU(bool, susfs_probe_busy);

/* One member, its probe, and what it needs to answer. */
struct susfs_slot {
	const char *member;
	const char *symbol;
	struct kprobe probe;
	const struct ksu_lsm_hook *hook;
};

/* This indirect call deliberately retains the pinned callbacks' true ABI on
 * ARM64. __nocfi prevents a false type hash on the generic register bridge.
 * No callback may sleep: audit the pinned functions and external uid gate. */
static int __nocfi susfs_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
	struct susfs_slot *slot = container_of(p, struct susfs_slot, probe);
	const struct ksu_lsm_hook *hook = smp_load_acquire(&slot->hook);
	int verdict;

	if (!hook || !hook->replacement || this_cpu_read(susfs_probe_busy))
		return 0;
	this_cpu_write(susfs_probe_busy, true);
	verdict = ((int (*)(unsigned long, unsigned long, unsigned long, unsigned long,
			    unsigned long, unsigned long, unsigned long, unsigned long))(hook->replacement))(
		regs->regs[0], regs->regs[1], regs->regs[2], regs->regs[3], regs->regs[4], regs->regs[5],
		regs->regs[6], regs->regs[7]);
	this_cpu_write(susfs_probe_busy, false);
	if (!verdict)
		return 0;

	/* Entry only: no prologue or PAC instruction has executed. Keep SP/LR and
	 * all other registers intact. No module code executes after this handler.
	 * See Linux v6.6 arch/arm64/lib/error-inject.c. */
	regs_set_return_value(regs, (unsigned long)(long)verdict);
	instruction_pointer_set(regs, procedure_link_pointer(regs));
	return 1;
}
NOKPROBE_SYMBOL(susfs_pre_handler);

/* The members `sus_path.c` declares, and the SELinux implementation each one decides. The symbol is
 * resolved to an address and the probe is registered on that address first - the rule this project's
 * delta settled on, because the breakpoint page is accepted where a write is not. */
#define SUSFS_SLOT(member_)                    \
	{                                      \
		.member = #member_,            \
		.symbol = "selinux_" #member_, \
		.probe = { .pre_handler = susfs_pre_handler, }, \
	}

static struct susfs_slot susfs_slots[] = {
	SUSFS_SLOT(inode_permission),
	SUSFS_SLOT(inode_getattr),
	SUSFS_SLOT(inode_unlink),
	SUSFS_SLOT(inode_rmdir),
	SUSFS_SLOT(inode_rename),
	SUSFS_SLOT(inode_link),
	SUSFS_SLOT(sb_statfs),
	SUSFS_SLOT(inode_setattr),
	SUSFS_SLOT(inode_getxattr),
	SUSFS_SLOT(inode_listxattr),
	SUSFS_SLOT(inode_setxattr),
	SUSFS_SLOT(inode_removexattr),
	SUSFS_SLOT(path_notify),
};

static DEFINE_MUTEX(susfs_slots_lock);
static int susfs_installed;

static struct susfs_slot *susfs_slot_for(const char *member)
{
	size_t i;

	if (!member)
		return NULL;
	for (i = 0; i < ARRAY_SIZE(susfs_slots); i++) {
		if (!strcmp(susfs_slots[i].member, member))
			return &susfs_slots[i];
	}
	return NULL;
}

/* Whole names only: an entry for `getattr` must not skip `inode_getattr`, and a prefix match would. */
static bool susfs_skip_named(const char *member)
{
	const char *cursor = lsm_skip;
	size_t length;

	if (!member || !lsm_skip[0])
		return false;
	length = strlen(member);
	while (*cursor) {
		const char *end = strchrnul(cursor, ',');
		size_t span = (size_t)(end - cursor);

		while (span && (*cursor == ' ' || *cursor == '\t')) {
			cursor++;
			span--;
		}
		while (span && (cursor[span - 1] == ' ' || cursor[span - 1] == '\t'))
			span--;
		if (span == length && !strncmp(cursor, member, length))
			return true;
		cursor = *end ? end + 1 : end;
	}
	return false;
}

/* Address first, name second - `sel_hide_register_probe`'s rule, and the reason it exists: a kernel
 * that refuses a probe placed by raw address accepts the same probe named through kallsyms. */
static int susfs_register_probe(struct susfs_slot *slot)
{
	unsigned long target = find_kernel_symbol_exact(slot->symbol);
	size_t i;
	int ret;

	if (!target) {
		pr_err("lsm_hook: %s: no address for %s, so this hook cannot be reached\n", slot->member,
		       slot->symbol);
		return -ENOENT;
	}

	/* Reject a non-entry symbol before inserting any breakpoint. */
	if (!ksu_symbol_is_start(target, slot->symbol))
		return -EINVAL;

	/* The caller holds susfs_slots_lock. Do not aggregate callbacks with
	 * different LSM prototypes on one folded/aliased selected entry. */
	for (i = 0; i < ARRAY_SIZE(susfs_slots); i++) {
		if (susfs_slots[i].hook &&
		    (unsigned long)susfs_slots[i].probe.addr == target)
			return -EEXIST;
	}

	slot->probe.addr = (kprobe_opcode_t *)target;
	ret = register_kprobe(&slot->probe);
	if (ret == -EINVAL) {
		pr_warn("lsm_hook: %s: probe on %s by address refused (%d), retrying by name\n",
			slot->member, slot->symbol, ret);
		slot->probe.addr = NULL;
		slot->probe.symbol_name = slot->symbol;
		ret = register_kprobe(&slot->probe);
		slot->probe.symbol_name = NULL;
	}
	if (ret) {
		slot->probe.addr = NULL;
		return ret;
	}
	/* A shifted probe would run after a prologue/PAC instruction and direct
	 * PC=LR would no longer be a valid entry return. It remains inactive until
	 * this check passes, because slot->hook has not been published yet. */
	if ((unsigned long)slot->probe.addr != target) {
		unregister_kprobe(&slot->probe);
		slot->probe.addr = NULL;
		return -EINVAL;
	}
	return 0;
}

int ksu_register_lsm_hook(struct ksu_lsm_hook *hook)
{
	struct susfs_slot *slot;
	int ret;

	/* >=6.12 SUS_LSM_PASS_ORIG must return zero here; kprobes resumes
	 * SELinux once. A saved original would recurse or execute it twice. */
	if (!hook || !hook->replacement || hook->original) {
		pr_err("lsm_hook: nothing to install\n");
		return -EINVAL;
	}

	/* A swap needs the read-only write this file exists to avoid. Refused with the reason, because a
	 * hook that installs and does nothing is worse than one that says it cannot run here. */
	if (!hook->insert) {
		pr_err("lsm_hook: %s: replace-shaped hooks need a write into read-only kernel memory, "
		       "which this kernel refuses; declare it with KSU_LSM_HOOK_INSERT instead\n",
		       hook->head_name ?: "unknown");
		return -EOPNOTSUPP;
	}

	slot = susfs_slot_for(hook->head_name);
	if (!slot) {
		pr_err("lsm_hook: %s: no SELinux implementation is known for this member; refusing to "
		       "install it against something else\n", hook->head_name ?: "unknown");
		return -ENOENT;
	}

	/* A requested skip is not a successfully installed hook. */
	if (susfs_skip_named(hook->head_name)) {
		SUSFS_LOGI("lsm_hook: %s: skipped by lsm_skip - this hook is not armed and the features it "
			   "gates stay off\n", hook->head_name ?: "unknown");
		return -EOPNOTSUPP;
	}

	mutex_lock(&susfs_slots_lock);
	if (lsm_off || (lsm_max >= 0 && susfs_installed >= lsm_max)) {
		pr_warn("lsm_hook: %s: not installed (lsm_off=%d lsm_max=%d, %d already installed)\n",
			hook->head_name ?: "unknown", lsm_off, lsm_max, susfs_installed);
		mutex_unlock(&susfs_slots_lock);
		return -EOPNOTSUPP;
	}

	if (slot->hook) {
		mutex_unlock(&susfs_slots_lock);
		pr_err("lsm_hook: %s: already installed\n", hook->head_name ?: "unknown");
		return -EEXIST;
	}
	/* Registration starts pass-through. Publish only after exact-entry check. */
	ret = susfs_register_probe(slot);
	if (ret) {
		mutex_unlock(&susfs_slots_lock);
		pr_err("lsm_hook: %s: probe on %s refused\n", hook->head_name ?: "unknown", slot->symbol);
		return ret;
	}
	smp_store_release(&slot->hook, hook);
	/*
	 * The `entry` field, used as the flag it is everywhere outside upstream's own install path: this
	 * module's teardown runs **only** for a hook whose `entry` is non-NULL
	 * (`if (sus_path_perm_hook.entry) ... ksu_unregister_lsm_hook(...)`, sus_path.c), and
	 * `sus_path_lsm_active()` is `getattr.entry && perm.entry`. A kprobe route inserts no node, so
	 * leaving this NULL meant two faults at once: the layer read as unarmed (`lsm=0`, so `/proc/susfs_*`
	 * was never created and the supercall reported SUS_PATH unsupported), and an unload skipped our
	 * `unregister_kprobe()` - leaving thirteen probes registered into module memory the kernel was
	 * about to free, which is a reset on the next syscall through any of them.
	 *
	 * The sentinel is a flag, never a node: nothing in this build dereferences it. Upstream's own
	 * dereferences live in `lsm_hook.c`, the file this one replaces.
	 */
	hook->entry = (struct security_hook_list *)hook;
	susfs_installed++;
	mutex_unlock(&susfs_slots_lock);

	SUSFS_LOGI("lsm_hook: %s: kprobe armed on %s\n", hook->head_name ?: "unknown", slot->symbol);
	return 0;
}

void ksu_unregister_lsm_hook(struct ksu_lsm_hook *hook)
{
	struct susfs_slot *slot;

	if (!hook)
		return;

	slot = susfs_slot_for(hook->head_name);
	if (!slot)
		return;

	mutex_lock(&susfs_slots_lock);
	if (slot->hook != hook) {
		mutex_unlock(&susfs_slots_lock);
		pr_warn("lsm_hook: %s: nothing was installed under this declaration\n",
			hook->head_name ?: "unknown");
		return;
	}
	/* Stop admitting callbacks before removing the probe. All module execution
	 * stays inside the pre-handler, so unregister_kprobe() synchronization now
	 * covers it; no redirected module trampoline can survive this call. */
	smp_store_release(&slot->hook, NULL);
	unregister_kprobe(&slot->probe);
	/* Cleared with the probe, so the guards that decide whether there is anything left to unregister
	 * read the same state this file does. */
	hook->entry = NULL;
	if (susfs_installed > 0)
		susfs_installed--;
	mutex_unlock(&susfs_slots_lock);

	SUSFS_LOGI("lsm_hook: %s: kprobe removed\n", hook->head_name ?: "unknown");
}

/* The two entry points the header carries that this install path has no separate use for: an
 * insert-shaped registration *is* the hook. Kept so the API the rest of the tree links against is
 * unchanged. */
int ksu_lsm_hook(struct ksu_lsm_hook *hook)
{
	return ksu_register_lsm_hook(hook);
}

void ksu_lsm_unhook(struct ksu_lsm_hook *hook)
{
	ksu_unregister_lsm_hook(hook);
}

void ksu_lsm_hook_init(void)
{
	SUSFS_LOGI("lsm_hook: install path is kprobe-based (multi-KMI entry-return; no handler allocation)\n");
}

void ksu_lsm_hook_exit(void)
{
	SUSFS_LOGI("lsm_hook: exit (probes are owned by the hooks that registered them)\n");
}
