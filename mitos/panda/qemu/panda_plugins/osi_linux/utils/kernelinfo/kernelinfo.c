/*!
 * @file kernelinfo.c
 * @brief Retrieves offset information from the running Linux kernel and prints them in the kernel log.
 *
 * @author Manolis Stamatogiannakis <manolis.stamatogiannakis@vu.nl>
 * @copyright This work is licensed under the terms of the GNU GPL, version 2.
 * See the COPYING file in the top-level directory.
 */
#include <linux/module.h>	/* Needed by all modules */
#include <linux/kernel.h>	/* Needed for KERN_INFO */
#include <linux/utsname.h>
#include <linux/version.h>
#include <linux/syscalls.h>
#include <linux/security.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/dcache.h>
#include <linux/mount.h>

/*
 * This function is used because to print offsets of members
 * of nested structs. It basically transforms '.' to '_', so
 * that we don't have to replicate all the nesting in the
 * structs used by the introspection program.
 *
 * E.g. for:
 * struct file {
 *	...
 *	struct dentry {
 *		struct *vfsmount;
 *		struct *dentry;
 *	}
 *	...
 * };
 *
 * Caveat: Because a static buffer is returned, the function
 * can only be used once in each invocation of printk.
 */
#define MAX_MEMBER_NAME 31
static char *cp_memb(const char *s) {
	static char memb[MAX_MEMBER_NAME+1];
	int i;
	for (i = 0; i<MAX_MEMBER_NAME && s[i]!='\0'; i++) {
		memb[i] = s[i] == '.' ? '_' : s[i];
	}
	memb[i] = 0;
	return memb;
}

/*
 * The macro printing the config lines in the kernel log.
 */
#define PRINT_OFFSET(structp, memb, cfgname) printk(KERN_INFO "%s.%s_offset = %d", cfgname, cp_memb(#memb), (int)((void *)&(structp->memb) - (void *)structp))

int init_module(void)
{
	struct cred credstruct;
	struct vm_area_struct vmastruct;
	struct dentry dentrystruct;
	struct file filestruct;
	struct thread_info threadinfostruct;
	struct files_struct filesstruct; /* mind the extra 's' :-P */
	struct fdtable fdtablestruct;
	struct vfsmount vfsmountstruct;

	struct task_struct *ts_p;
	struct cred *cs_p;
	struct mm_struct *mms_p;
	struct vm_area_struct *vma_p;
	struct dentry *ds_p;
	struct file *fs_p;
	struct fdtable *fdt_p;
	struct thread_info *ti_p;
	struct files_struct *fss_p;
	struct vfsmount *vfsmnt_p;

	ts_p = &init_task;
	cs_p = &credstruct;
	mms_p = init_task.mm;
	vma_p = &vmastruct;
	ds_p = &dentrystruct;
	fs_p = &filestruct;
	ti_p = &threadinfostruct;
	fss_p = &filesstruct;
	fdt_p = &fdtablestruct;
	vfsmnt_p = &vfsmountstruct;

	printk(KERN_INFO "--KERNELINFO-BEGIN--\n");
	printk(KERN_INFO "name = %s %s\n", utsname()->version, utsname()->machine);

	printk(KERN_INFO "task.size = %zu\n", sizeof(init_task));
	printk(KERN_INFO "#task.init_addr = 0x%08lX\n", (unsigned long)ts_p);
	printk(KERN_INFO "task.init_addr = %lu\n", (unsigned long)ts_p);

	PRINT_OFFSET(ti_p,	task,			"task");
	PRINT_OFFSET(ts_p,	tasks,			"task");
	PRINT_OFFSET(ts_p,	pid,			"task");
	PRINT_OFFSET(ts_p,	tgid,			"task");
	PRINT_OFFSET(ts_p,	group_leader,	"task");
	PRINT_OFFSET(ts_p,	thread_group,	"task");
	PRINT_OFFSET(ts_p,	real_parent,	"task");
	PRINT_OFFSET(ts_p,	parent,			"task");
	PRINT_OFFSET(ts_p,	mm,				"task");
	PRINT_OFFSET(ts_p,	stack,			"task");
	PRINT_OFFSET(ts_p,	real_cred,		"task");
	PRINT_OFFSET(ts_p,	cred,			"task");
	PRINT_OFFSET(ts_p,	comm,			"task");
	printk(KERN_INFO "task.comm_size = %zu\n", sizeof(ts_p->comm));
	PRINT_OFFSET(ts_p,	files,			"task");

	PRINT_OFFSET(cs_p,	uid,			"cred");
	PRINT_OFFSET(cs_p,	gid,			"cred");
	PRINT_OFFSET(cs_p,	euid,			"cred");
	PRINT_OFFSET(cs_p,	egid,			"cred");

	PRINT_OFFSET(mms_p, mmap,			"mm");
	PRINT_OFFSET(mms_p, pgd,			"mm");
	PRINT_OFFSET(mms_p, arg_start,		"mm");
	PRINT_OFFSET(mms_p, start_brk,		"mm");
	PRINT_OFFSET(mms_p, brk,			"mm");
	PRINT_OFFSET(mms_p, start_stack,	"mm");

	PRINT_OFFSET(vma_p, vm_mm,			"vma");
	PRINT_OFFSET(vma_p, vm_start,		"vma");
	PRINT_OFFSET(vma_p, vm_end,			"vma");
	PRINT_OFFSET(vma_p, vm_next,		"vma");
	PRINT_OFFSET(vma_p, vm_flags,		"vma");

	/* used in reading OsiModules */
	PRINT_OFFSET(vma_p, vm_file,		"vma");

	PRINT_OFFSET(fs_p,		f_path.dentry,	"fs");
	PRINT_OFFSET(fs_p,		f_path.mnt,		"fs");
    PRINT_OFFSET(fs_p,      f_pos,          "fs");
	PRINT_OFFSET(vfsmnt_p,	mnt_parent,		"fs");
	PRINT_OFFSET(vfsmnt_p,	mnt_mountpoint, "fs");
	PRINT_OFFSET(vfsmnt_p,	mnt_root,		"fs");	/* XXX: We don't use this anywhere. Marked for removal. */

	/* used in reading FDs */
	PRINT_OFFSET(fss_p,	fdt,			"fs");
	PRINT_OFFSET(fss_p,	fdtab,			"fs");
	PRINT_OFFSET(fdt_p,	fd,				"fs");

	PRINT_OFFSET(ds_p,	d_name,			"fs");
	PRINT_OFFSET(ds_p,	d_iname,		"fs");
	PRINT_OFFSET(ds_p,	d_parent,		"fs");
	printk(KERN_INFO "---KERNELINFO-END---\n");

	/* Return a failure. We only want to print the info. */
	return -1;
}

void cleanup_module(void)
{
	printk(KERN_INFO "Information module removed.\n");
}

MODULE_LICENSE("GPL");

/* vim:set tabstop=4 softtabstop=4 noexpandtab */
