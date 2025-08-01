// SPDX-License-Identifier: LGPL-2.1
/*
 *
 *   vfs operations that deal with files
 *
 *   Copyright (C) International Business Machines  Corp., 2002,2010
 *   Author(s): Steve French (sfrench@us.ibm.com)
 *              Jeremy Allison (jra@samba.org)
 *
 */
#include <linux/fs.h>
#include <linux/filelock.h>
#include <linux/backing-dev.h>
#include <linux/stat.h>
#include <linux/fcntl.h>
#include <linux/pagemap.h>
#include <linux/pagevec.h>
#include <linux/writeback.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/delay.h>
#include <linux/mount.h>
#include <linux/slab.h>
#include <linux/swap.h>
#include <linux/mm.h>
#include <asm/div64.h>
#include "cifsfs.h"
#include "cifspdu.h"
#include "cifsglob.h"
#include "cifsproto.h"
#include "smb2proto.h"
#include "cifs_unicode.h"
#include "cifs_debug.h"
#include "cifs_fs_sb.h"
#include "fscache.h"
#include "smbdirect.h"
#include "fs_context.h"
#include "cifs_ioctl.h"
#include "cached_dir.h"

/*
 * Remove the dirty flags from a span of pages.
 */
static void cifs_undirty_folios(struct inode *inode, loff_t start, unsigned int len)
{
	struct address_space *mapping = inode->i_mapping;
	struct folio *folio;
	pgoff_t end;

	XA_STATE(xas, &mapping->i_pages, start / PAGE_SIZE);

	rcu_read_lock();

	end = (start + len - 1) / PAGE_SIZE;
	xas_for_each_marked(&xas, folio, end, PAGECACHE_TAG_DIRTY) {
		if (xas_retry(&xas, folio))
			continue;
		xas_pause(&xas);
		rcu_read_unlock();
		folio_lock(folio);
		folio_clear_dirty_for_io(folio);
		folio_unlock(folio);
		rcu_read_lock();
	}

	rcu_read_unlock();
}

/*
 * Completion of write to server.
 */
void cifs_pages_written_back(struct inode *inode, loff_t start, unsigned int len)
{
	struct address_space *mapping = inode->i_mapping;
	struct folio *folio;
	pgoff_t end;

	XA_STATE(xas, &mapping->i_pages, start / PAGE_SIZE);

	if (!len)
		return;

	rcu_read_lock();

	end = (start + len - 1) / PAGE_SIZE;
	xas_for_each(&xas, folio, end) {
		if (xas_retry(&xas, folio))
			continue;
		if (!folio_test_writeback(folio)) {
			WARN_ONCE(1, "bad %x @%llx page %lx %lx\n",
				  len, start, folio->index, end);
			continue;
		}

		folio_detach_private(folio);
		folio_end_writeback(folio);
	}

	rcu_read_unlock();
}

/*
 * Failure of write to server.
 */
void cifs_pages_write_failed(struct inode *inode, loff_t start, unsigned int len)
{
	struct address_space *mapping = inode->i_mapping;
	struct folio *folio;
	pgoff_t end;

	XA_STATE(xas, &mapping->i_pages, start / PAGE_SIZE);

	if (!len)
		return;

	rcu_read_lock();

	end = (start + len - 1) / PAGE_SIZE;
	xas_for_each(&xas, folio, end) {
		if (xas_retry(&xas, folio))
			continue;
		if (!folio_test_writeback(folio)) {
			WARN_ONCE(1, "bad %x @%llx page %lx %lx\n",
				  len, start, folio->index, end);
			continue;
		}

		folio_set_error(folio);
		folio_end_writeback(folio);
	}

	rcu_read_unlock();
}

/*
 * Redirty pages after a temporary failure.
 */
void cifs_pages_write_redirty(struct inode *inode, loff_t start, unsigned int len)
{
	struct address_space *mapping = inode->i_mapping;
	struct folio *folio;
	pgoff_t end;

	XA_STATE(xas, &mapping->i_pages, start / PAGE_SIZE);

	if (!len)
		return;

	rcu_read_lock();

	end = (start + len - 1) / PAGE_SIZE;
	xas_for_each(&xas, folio, end) {
		if (!folio_test_writeback(folio)) {
			WARN_ONCE(1, "bad %x @%llx page %lx %lx\n",
				  len, start, folio->index, end);
			continue;
		}

		filemap_dirty_folio(folio->mapping, folio);
		folio_end_writeback(folio);
	}

	rcu_read_unlock();
}

/*
 * Mark as invalid, all open files on tree connections since they
 * were closed when session to server was lost.
 */
void
cifs_mark_open_files_invalid(struct cifs_tcon *tcon)
{
	struct cifsFileInfo *open_file = NULL;
	struct list_head *tmp;
	struct list_head *tmp1;

	/* only send once per connect */
	spin_lock(&tcon->tc_lock);
	if (tcon->need_reconnect)
		tcon->status = TID_NEED_RECON;

	if (tcon->status != TID_NEED_RECON) {
		spin_unlock(&tcon->tc_lock);
		return;
	}
	tcon->status = TID_IN_FILES_INVALIDATE;
	spin_unlock(&tcon->tc_lock);

	/* list all files open on tree connection and mark them invalid */
	spin_lock(&tcon->open_file_lock);
	list_for_each_safe(tmp, tmp1, &tcon->openFileList) {
		open_file = list_entry(tmp, struct cifsFileInfo, tlist);
		open_file->invalidHandle = true;
		open_file->oplock_break_cancelled = true;
	}
	spin_unlock(&tcon->open_file_lock);

	invalidate_all_cached_dirs(tcon);
	spin_lock(&tcon->tc_lock);
	if (tcon->status == TID_IN_FILES_INVALIDATE)
		tcon->status = TID_NEED_TCON;
	spin_unlock(&tcon->tc_lock);

	/*
	 * BB Add call to invalidate_inodes(sb) for all superblocks mounted
	 * to this tcon.
	 */
}

static inline int cifs_convert_flags(unsigned int flags, int rdwr_for_fscache)
{
	if ((flags & O_ACCMODE) == O_RDONLY)
		return GENERIC_READ;
	else if ((flags & O_ACCMODE) == O_WRONLY)
		return rdwr_for_fscache == 1 ? (GENERIC_READ | GENERIC_WRITE) : GENERIC_WRITE;
	else if ((flags & O_ACCMODE) == O_RDWR) {
		/* GENERIC_ALL is too much permission to request
		   can cause unnecessary access denied on create */
		/* return GENERIC_ALL; */
		return (GENERIC_READ | GENERIC_WRITE);
	}

	return (READ_CONTROL | FILE_WRITE_ATTRIBUTES | FILE_READ_ATTRIBUTES |
		FILE_WRITE_EA | FILE_APPEND_DATA | FILE_WRITE_DATA |
		FILE_READ_DATA);
}

#ifdef CONFIG_CIFS_ALLOW_INSECURE_LEGACY
static u32 cifs_posix_convert_flags(unsigned int flags)
{
	u32 posix_flags = 0;

	if ((flags & O_ACCMODE) == O_RDONLY)
		posix_flags = SMB_O_RDONLY;
	else if ((flags & O_ACCMODE) == O_WRONLY)
		posix_flags = SMB_O_WRONLY;
	else if ((flags & O_ACCMODE) == O_RDWR)
		posix_flags = SMB_O_RDWR;

	if (flags & O_CREAT) {
		posix_flags |= SMB_O_CREAT;
		if (flags & O_EXCL)
			posix_flags |= SMB_O_EXCL;
	} else if (flags & O_EXCL)
		cifs_dbg(FYI, "Application %s pid %d has incorrectly set O_EXCL flag but not O_CREAT on file open. Ignoring O_EXCL\n",
			 current->comm, current->tgid);

	if (flags & O_TRUNC)
		posix_flags |= SMB_O_TRUNC;
	/* be safe and imply O_SYNC for O_DSYNC */
	if (flags & O_DSYNC)
		posix_flags |= SMB_O_SYNC;
	if (flags & O_DIRECTORY)
		posix_flags |= SMB_O_DIRECTORY;
	if (flags & O_NOFOLLOW)
		posix_flags |= SMB_O_NOFOLLOW;
	if (flags & O_DIRECT)
		posix_flags |= SMB_O_DIRECT;

	return posix_flags;
}
#endif /* CONFIG_CIFS_ALLOW_INSECURE_LEGACY */

static inline int cifs_get_disposition(unsigned int flags)
{
	if ((flags & (O_CREAT | O_EXCL)) == (O_CREAT | O_EXCL))
		return FILE_CREATE;
	else if ((flags & (O_CREAT | O_TRUNC)) == (O_CREAT | O_TRUNC))
		return FILE_OVERWRITE_IF;
	else if ((flags & O_CREAT) == O_CREAT)
		return FILE_OPEN_IF;
	else if ((flags & O_TRUNC) == O_TRUNC)
		return FILE_OVERWRITE;
	else
		return FILE_OPEN;
}

#ifdef CONFIG_CIFS_ALLOW_INSECURE_LEGACY
int cifs_posix_open(const char *full_path, struct inode **pinode,
			struct super_block *sb, int mode, unsigned int f_flags,
			__u32 *poplock, __u16 *pnetfid, unsigned int xid)
{
	int rc;
	FILE_UNIX_BASIC_INFO *presp_data;
	__u32 posix_flags = 0;
	struct cifs_sb_info *cifs_sb = CIFS_SB(sb);
	struct cifs_fattr fattr;
	struct tcon_link *tlink;
	struct cifs_tcon *tcon;

	cifs_dbg(FYI, "posix open %s\n", full_path);

	presp_data = kzalloc(sizeof(FILE_UNIX_BASIC_INFO), GFP_KERNEL);
	if (presp_data == NULL)
		return -ENOMEM;

	tlink = cifs_sb_tlink(cifs_sb);
	if (IS_ERR(tlink)) {
		rc = PTR_ERR(tlink);
		goto posix_open_ret;
	}

	tcon = tlink_tcon(tlink);
	mode &= ~current_umask();

	posix_flags = cifs_posix_convert_flags(f_flags);
	rc = CIFSPOSIXCreate(xid, tcon, posix_flags, mode, pnetfid, presp_data,
			     poplock, full_path, cifs_sb->local_nls,
			     cifs_remap(cifs_sb));
	cifs_put_tlink(tlink);

	if (rc)
		goto posix_open_ret;

	if (presp_data->Type == cpu_to_le32(-1))
		goto posix_open_ret; /* open ok, caller does qpathinfo */

	if (!pinode)
		goto posix_open_ret; /* caller does not need info */

	cifs_unix_basic_to_fattr(&fattr, presp_data, cifs_sb);

	/* get new inode and set it up */
	if (*pinode == NULL) {
		cifs_fill_uniqueid(sb, &fattr);
		*pinode = cifs_iget(sb, &fattr);
		if (!*pinode) {
			rc = -ENOMEM;
			goto posix_open_ret;
		}
	} else {
		cifs_revalidate_mapping(*pinode);
		rc = cifs_fattr_to_inode(*pinode, &fattr, false);
	}

posix_open_ret:
	kfree(presp_data);
	return rc;
}
#endif /* CONFIG_CIFS_ALLOW_INSECURE_LEGACY */

static int cifs_nt_open(const char *full_path, struct inode *inode, struct cifs_sb_info *cifs_sb,
			struct cifs_tcon *tcon, unsigned int f_flags, __u32 *oplock,
			struct cifs_fid *fid, unsigned int xid, struct cifs_open_info_data *buf)
{
	int rc;
	int desired_access;
	int disposition;
	int create_options = CREATE_NOT_DIR;
	struct TCP_Server_Info *server = tcon->ses->server;
	struct cifs_open_parms oparms;
	int rdwr_for_fscache = 0;

	if (!server->ops->open)
		return -ENOSYS;

	/* If we're caching, we need to be able to fill in around partial writes. */
	if (cifs_fscache_enabled(inode) && (f_flags & O_ACCMODE) == O_WRONLY)
		rdwr_for_fscache = 1;

	desired_access = cifs_convert_flags(f_flags, rdwr_for_fscache);

/*********************************************************************
 *  open flag mapping table:
 *
 *	POSIX Flag            CIFS Disposition
 *	----------            ----------------
 *	O_CREAT               FILE_OPEN_IF
 *	O_CREAT | O_EXCL      FILE_CREATE
 *	O_CREAT | O_TRUNC     FILE_OVERWRITE_IF
 *	O_TRUNC               FILE_OVERWRITE
 *	none of the above     FILE_OPEN
 *
 *	Note that there is not a direct match between disposition
 *	FILE_SUPERSEDE (ie create whether or not file exists although
 *	O_CREAT | O_TRUNC is similar but truncates the existing
 *	file rather than creating a new file as FILE_SUPERSEDE does
 *	(which uses the attributes / metadata passed in on open call)
 *?
 *?  O_SYNC is a reasonable match to CIFS writethrough flag
 *?  and the read write flags match reasonably.  O_LARGEFILE
 *?  is irrelevant because largefile support is always used
 *?  by this client. Flags O_APPEND, O_DIRECT, O_DIRECTORY,
 *	 O_FASYNC, O_NOFOLLOW, O_NONBLOCK need further investigation
 *********************************************************************/

	disposition = cifs_get_disposition(f_flags);

	/* BB pass O_SYNC flag through on file attributes .. BB */

	/* O_SYNC also has bit for O_DSYNC so following check picks up either */
	if (f_flags & O_SYNC)
		create_options |= CREATE_WRITE_THROUGH;

	if (f_flags & O_DIRECT)
		create_options |= CREATE_NO_BUFFER;

retry_open:
	oparms = (struct cifs_open_parms) {
		.tcon = tcon,
		.cifs_sb = cifs_sb,
		.desired_access = desired_access,
		.create_options = cifs_create_options(cifs_sb, create_options),
		.disposition = disposition,
		.path = full_path,
		.fid = fid,
	};

	rc = server->ops->open(xid, &oparms, oplock, buf);
	if (rc) {
		if (rc == -EACCES && rdwr_for_fscache == 1) {
			desired_access = cifs_convert_flags(f_flags, 0);
			rdwr_for_fscache = 2;
			goto retry_open;
		}
		return rc;
	}
	if (rdwr_for_fscache == 2)
		cifs_invalidate_cache(inode, FSCACHE_INVAL_DIO_WRITE);

	/* TODO: Add support for calling posix query info but with passing in fid */
	if (tcon->unix_ext)
		rc = cifs_get_inode_info_unix(&inode, full_path, inode->i_sb,
					      xid);
	else
		rc = cifs_get_inode_info(&inode, full_path, buf, inode->i_sb,
					 xid, fid);

	if (rc) {
		server->ops->close(xid, tcon, fid);
		if (rc == -ESTALE)
			rc = -EOPENSTALE;
	}

	return rc;
}

static bool
cifs_has_mand_locks(struct cifsInodeInfo *cinode)
{
	struct cifs_fid_locks *cur;
	bool has_locks = false;

	down_read(&cinode->lock_sem);
	list_for_each_entry(cur, &cinode->llist, llist) {
		if (!list_empty(&cur->locks)) {
			has_locks = true;
			break;
		}
	}
	up_read(&cinode->lock_sem);
	return has_locks;
}

void
cifs_down_write(struct rw_semaphore *sem)
{
	while (!down_write_trylock(sem))
		msleep(10);
}

static void cifsFileInfo_put_work(struct work_struct *work);
void serverclose_work(struct work_struct *work);

struct cifsFileInfo *cifs_new_fileinfo(struct cifs_fid *fid, struct file *file,
				       struct tcon_link *tlink, __u32 oplock,
				       const char *symlink_target)
{
	struct dentry *dentry = file_dentry(file);
	struct inode *inode = d_inode(dentry);
	struct cifsInodeInfo *cinode = CIFS_I(inode);
	struct cifsFileInfo *cfile;
	struct cifs_fid_locks *fdlocks;
	struct cifs_tcon *tcon = tlink_tcon(tlink);
	struct TCP_Server_Info *server = tcon->ses->server;

	cfile = kzalloc(sizeof(struct cifsFileInfo), GFP_KERNEL);
	if (cfile == NULL)
		return cfile;

	fdlocks = kzalloc(sizeof(struct cifs_fid_locks), GFP_KERNEL);
	if (!fdlocks) {
		kfree(cfile);
		return NULL;
	}

	if (symlink_target) {
		cfile->symlink_target = kstrdup(symlink_target, GFP_KERNEL);
		if (!cfile->symlink_target) {
			kfree(fdlocks);
			kfree(cfile);
			return NULL;
		}
	}

	INIT_LIST_HEAD(&fdlocks->locks);
	fdlocks->cfile = cfile;
	cfile->llist = fdlocks;

	cfile->count = 1;
	cfile->pid = current->tgid;
	cfile->uid = current_fsuid();
	cfile->dentry = dget(dentry);
	cfile->f_flags = file->f_flags;
	cfile->invalidHandle = false;
	cfile->deferred_close_scheduled = false;
	cfile->tlink = cifs_get_tlink(tlink);
	INIT_WORK(&cfile->oplock_break, cifs_oplock_break);
	INIT_WORK(&cfile->put, cifsFileInfo_put_work);
	INIT_WORK(&cfile->serverclose, serverclose_work);
	INIT_DELAYED_WORK(&cfile->deferred, smb2_deferred_work_close);
	mutex_init(&cfile->fh_mutex);
	spin_lock_init(&cfile->file_info_lock);

	cifs_sb_active(inode->i_sb);

	/*
	 * If the server returned a read oplock and we have mandatory brlocks,
	 * set oplock level to None.
	 */
	if (server->ops->is_read_op(oplock) && cifs_has_mand_locks(cinode)) {
		cifs_dbg(FYI, "Reset oplock val from read to None due to mand locks\n");
		oplock = 0;
	}

	cifs_down_write(&cinode->lock_sem);
	list_add(&fdlocks->llist, &cinode->llist);
	up_write(&cinode->lock_sem);

	spin_lock(&tcon->open_file_lock);
	if (fid->pending_open->oplock != CIFS_OPLOCK_NO_CHANGE && oplock)
		oplock = fid->pending_open->oplock;
	list_del(&fid->pending_open->olist);

	fid->purge_cache = false;
	server->ops->set_fid(cfile, fid, oplock);

	list_add(&cfile->tlist, &tcon->openFileList);
	atomic_inc(&tcon->num_local_opens);

	/* if readable file instance put first in list*/
	spin_lock(&cinode->open_file_lock);
	if (file->f_mode & FMODE_READ)
		list_add(&cfile->flist, &cinode->openFileList);
	else
		list_add_tail(&cfile->flist, &cinode->openFileList);
	spin_unlock(&cinode->open_file_lock);
	spin_unlock(&tcon->open_file_lock);

	if (fid->purge_cache)
		cifs_zap_mapping(inode);

	file->private_data = cfile;
	return cfile;
}

struct cifsFileInfo *
cifsFileInfo_get(struct cifsFileInfo *cifs_file)
{
	spin_lock(&cifs_file->file_info_lock);
	cifsFileInfo_get_locked(cifs_file);
	spin_unlock(&cifs_file->file_info_lock);
	return cifs_file;
}

static void cifsFileInfo_put_final(struct cifsFileInfo *cifs_file)
{
	struct inode *inode = d_inode(cifs_file->dentry);
	struct cifsInodeInfo *cifsi = CIFS_I(inode);
	struct cifsLockInfo *li, *tmp;
	struct super_block *sb = inode->i_sb;

	/*
	 * Delete any outstanding lock records. We'll lose them when the file
	 * is closed anyway.
	 */
	cifs_down_write(&cifsi->lock_sem);
	list_for_each_entry_safe(li, tmp, &cifs_file->llist->locks, llist) {
		list_del(&li->llist);
		cifs_del_lock_waiters(li);
		kfree(li);
	}
	list_del(&cifs_file->llist->llist);
	kfree(cifs_file->llist);
	up_write(&cifsi->lock_sem);

	cifs_put_tlink(cifs_file->tlink);
	dput(cifs_file->dentry);
	cifs_sb_deactive(sb);
	kfree(cifs_file->symlink_target);
	kfree(cifs_file);
}

static void cifsFileInfo_put_work(struct work_struct *work)
{
	struct cifsFileInfo *cifs_file = container_of(work,
			struct cifsFileInfo, put);

	cifsFileInfo_put_final(cifs_file);
}

void serverclose_work(struct work_struct *work)
{
	struct cifsFileInfo *cifs_file = container_of(work,
			struct cifsFileInfo, serverclose);

	struct cifs_tcon *tcon = tlink_tcon(cifs_file->tlink);

	struct TCP_Server_Info *server = tcon->ses->server;
	int rc = 0;
	int retries = 0;
	int MAX_RETRIES = 4;

	do {
		if (server->ops->close_getattr)
			rc = server->ops->close_getattr(0, tcon, cifs_file);
		else if (server->ops->close)
			rc = server->ops->close(0, tcon, &cifs_file->fid);

		if (rc == -EBUSY || rc == -EAGAIN) {
			retries++;
			msleep(250);
		}
	} while ((rc == -EBUSY || rc == -EAGAIN) && (retries < MAX_RETRIES)
	);

	if (retries == MAX_RETRIES)
		pr_warn("Serverclose failed %d times, giving up\n", MAX_RETRIES);

	if (cifs_file->offload)
		queue_work(fileinfo_put_wq, &cifs_file->put);
	else
		cifsFileInfo_put_final(cifs_file);
}

/**
 * cifsFileInfo_put - release a reference of file priv data
 *
 * Always potentially wait for oplock handler. See _cifsFileInfo_put().
 *
 * @cifs_file:	cifs/smb3 specific info (eg refcounts) for an open file
 */
void cifsFileInfo_put(struct cifsFileInfo *cifs_file)
{
	_cifsFileInfo_put(cifs_file, true, true);
}

/**
 * _cifsFileInfo_put - release a reference of file priv data
 *
 * This may involve closing the filehandle @cifs_file out on the
 * server. Must be called without holding tcon->open_file_lock,
 * cinode->open_file_lock and cifs_file->file_info_lock.
 *
 * If @wait_for_oplock_handler is true and we are releasing the last
 * reference, wait for any running oplock break handler of the file
 * and cancel any pending one.
 *
 * @cifs_file:	cifs/smb3 specific info (eg refcounts) for an open file
 * @wait_oplock_handler: must be false if called from oplock_break_handler
 * @offload:	not offloaded on close and oplock breaks
 *
 */
void _cifsFileInfo_put(struct cifsFileInfo *cifs_file,
		       bool wait_oplock_handler, bool offload)
{
	struct inode *inode = d_inode(cifs_file->dentry);
	struct cifs_tcon *tcon = tlink_tcon(cifs_file->tlink);
	struct TCP_Server_Info *server = tcon->ses->server;
	struct cifsInodeInfo *cifsi = CIFS_I(inode);
	struct super_block *sb = inode->i_sb;
	struct cifs_sb_info *cifs_sb = CIFS_SB(sb);
	struct cifs_fid fid = {};
	struct cifs_pending_open open;
	bool oplock_break_cancelled;
	bool serverclose_offloaded = false;

	spin_lock(&tcon->open_file_lock);
	spin_lock(&cifsi->open_file_lock);
	spin_lock(&cifs_file->file_info_lock);

	cifs_file->offload = offload;
	if (--cifs_file->count > 0) {
		spin_unlock(&cifs_file->file_info_lock);
		spin_unlock(&cifsi->open_file_lock);
		spin_unlock(&tcon->open_file_lock);
		return;
	}
	spin_unlock(&cifs_file->file_info_lock);

	if (server->ops->get_lease_key)
		server->ops->get_lease_key(inode, &fid);

	/* store open in pending opens to make sure we don't miss lease break */
	cifs_add_pending_open_locked(&fid, cifs_file->tlink, &open);

	/* remove it from the lists */
	list_del(&cifs_file->flist);
	list_del(&cifs_file->tlist);
	atomic_dec(&tcon->num_local_opens);

	if (list_empty(&cifsi->openFileList)) {
		cifs_dbg(FYI, "closing last open instance for inode %p\n",
			 d_inode(cifs_file->dentry));
		/*
		 * In strict cache mode we need invalidate mapping on the last
		 * close  because it may cause a error when we open this file
		 * again and get at least level II oplock.
		 */
		if (cifs_sb->mnt_cifs_flags & CIFS_MOUNT_STRICT_IO)
			set_bit(CIFS_INO_INVALID_MAPPING, &cifsi->flags);
		cifs_set_oplock_level(cifsi, 0);
	}

	spin_unlock(&cifsi->open_file_lock);
	spin_unlock(&tcon->open_file_lock);

	oplock_break_cancelled = wait_oplock_handler ?
		cancel_work_sync(&cifs_file->oplock_break) : false;

	if (!tcon->need_reconnect && !cifs_file->invalidHandle) {
		struct TCP_Server_Info *server = tcon->ses->server;
		unsigned int xid;
		int rc = 0;

		xid = get_xid();
		if (server->ops->close_getattr)
			rc = server->ops->close_getattr(xid, tcon, cifs_file);
		else if (server->ops->close)
			rc = server->ops->close(xid, tcon, &cifs_file->fid);
		_free_xid(xid);

		if (rc == -EBUSY || rc == -EAGAIN) {
			// Server close failed, hence offloading it as an async op
			queue_work(serverclose_wq, &cifs_file->serverclose);
			serverclose_offloaded = true;
		}
	}

	if (oplock_break_cancelled)
		cifs_done_oplock_break(cifsi);

	cifs_del_pending_open(&open);

	// if serverclose has been offloaded to wq (on failure), it will
	// handle offloading put as well. If serverclose not offloaded,
	// we need to handle offloading put here.
	if (!serverclose_offloaded) {
		if (offload)
			queue_work(fileinfo_put_wq, &cifs_file->put);
		else
			cifsFileInfo_put_final(cifs_file);
	}
}

int cifs_open(struct inode *inode, struct file *file)

{
	int rc = -EACCES;
	unsigned int xid;
	__u32 oplock;
	struct cifs_sb_info *cifs_sb;
	struct TCP_Server_Info *server;
	struct cifs_tcon *tcon;
	struct tcon_link *tlink;
	struct cifsFileInfo *cfile = NULL;
	void *page;
	const char *full_path;
	bool posix_open_ok = false;
	struct cifs_fid fid = {};
	struct cifs_pending_open open;
	struct cifs_open_info_data data = {};

	xid = get_xid();

	cifs_sb = CIFS_SB(inode->i_sb);
	if (unlikely(cifs_forced_shutdown(cifs_sb))) {
		free_xid(xid);
		return -EIO;
	}

	tlink = cifs_sb_tlink(cifs_sb);
	if (IS_ERR(tlink)) {
		free_xid(xid);
		return PTR_ERR(tlink);
	}
	tcon = tlink_tcon(tlink);
	server = tcon->ses->server;

	page = alloc_dentry_path();
	full_path = build_path_from_dentry(file_dentry(file), page);
	if (IS_ERR(full_path)) {
		rc = PTR_ERR(full_path);
		goto out;
	}

	cifs_dbg(FYI, "inode = 0x%p file flags are 0x%x for %s\n",
		 inode, file->f_flags, full_path);

	if (file->f_flags & O_DIRECT &&
	    cifs_sb->mnt_cifs_flags & CIFS_MOUNT_STRICT_IO) {
		if (cifs_sb->mnt_cifs_flags & CIFS_MOUNT_NO_BRL)
			file->f_op = &cifs_file_direct_nobrl_ops;
		else
			file->f_op = &cifs_file_direct_ops;
	}

	/* Get the cached handle as SMB2 close is deferred */
	rc = cifs_get_readable_path(tcon, full_path, &cfile);
	if (rc == 0) {
		if (file->f_flags == cfile->f_flags) {
			file->private_data = cfile;
			spin_lock(&CIFS_I(inode)->deferred_lock);
			cifs_del_deferred_close(cfile);
			spin_unlock(&CIFS_I(inode)->deferred_lock);
			goto use_cache;
		} else {
			_cifsFileInfo_put(cfile, true, false);
		}
	} else {
		/* hard link on the defeered close file */
		rc = cifs_get_hardlink_path(tcon, inode, file);
		if (rc)
			cifs_close_deferred_file(CIFS_I(inode));
	}

	if (server->oplocks)
		oplock = REQ_OPLOCK;
	else
		oplock = 0;

#ifdef CONFIG_CIFS_ALLOW_INSECURE_LEGACY
	if (!tcon->broken_posix_open && tcon->unix_ext &&
	    cap_unix(tcon->ses) && (CIFS_UNIX_POSIX_PATH_OPS_CAP &
				le64_to_cpu(tcon->fsUnixInfo.Capability))) {
		/* can not refresh inode info since size could be stale */
		rc = cifs_posix_open(full_path, &inode, inode->i_sb,
				cifs_sb->ctx->file_mode /* ignored */,
				file->f_flags, &oplock, &fid.netfid, xid);
		if (rc == 0) {
			cifs_dbg(FYI, "posix open succeeded\n");
			posix_open_ok = true;
		} else if ((rc == -EINVAL) || (rc == -EOPNOTSUPP)) {
			if (tcon->ses->serverNOS)
				cifs_dbg(VFS, "server %s of type %s returned unexpected error on SMB posix open, disabling posix open support. Check if server update available.\n",
					 tcon->ses->ip_addr,
					 tcon->ses->serverNOS);
			tcon->broken_posix_open = true;
		} else if ((rc != -EIO) && (rc != -EREMOTE) &&
			 (rc != -EOPNOTSUPP)) /* path not found or net err */
			goto out;
		/*
		 * Else fallthrough to retry open the old way on network i/o
		 * or DFS errors.
		 */
	}
#endif /* CONFIG_CIFS_ALLOW_INSECURE_LEGACY */

	if (server->ops->get_lease_key)
		server->ops->get_lease_key(inode, &fid);

	cifs_add_pending_open(&fid, tlink, &open);

	if (!posix_open_ok) {
		if (server->ops->get_lease_key)
			server->ops->get_lease_key(inode, &fid);

		rc = cifs_nt_open(full_path, inode, cifs_sb, tcon, file->f_flags, &oplock, &fid,
				  xid, &data);
		if (rc) {
			cifs_del_pending_open(&open);
			goto out;
		}
	}

	cfile = cifs_new_fileinfo(&fid, file, tlink, oplock, data.symlink_target);
	if (cfile == NULL) {
		if (server->ops->close)
			server->ops->close(xid, tcon, &fid);
		cifs_del_pending_open(&open);
		rc = -ENOMEM;
		goto out;
	}

#ifdef CONFIG_CIFS_ALLOW_INSECURE_LEGACY
	if ((oplock & CIFS_CREATE_ACTION) && !posix_open_ok && tcon->unix_ext) {
		/*
		 * Time to set mode which we can not set earlier due to
		 * problems creating new read-only files.
		 */
		struct cifs_unix_set_info_args args = {
			.mode	= inode->i_mode,
			.uid	= INVALID_UID, /* no change */
			.gid	= INVALID_GID, /* no change */
			.ctime	= NO_CHANGE_64,
			.atime	= NO_CHANGE_64,
			.mtime	= NO_CHANGE_64,
			.device	= 0,
		};
		CIFSSMBUnixSetFileInfo(xid, tcon, &args, fid.netfid,
				       cfile->pid);
	}
#endif /* CONFIG_CIFS_ALLOW_INSECURE_LEGACY */

use_cache:
	fscache_use_cookie(cifs_inode_cookie(file_inode(file)),
			   file->f_mode & FMODE_WRITE);
	if (!(file->f_flags & O_DIRECT))
		goto out;
	if ((file->f_flags & (O_ACCMODE | O_APPEND)) == O_RDONLY)
		goto out;
	cifs_invalidate_cache(file_inode(file), FSCACHE_INVAL_DIO_WRITE);

out:
	free_dentry_path(page);
	free_xid(xid);
	cifs_put_tlink(tlink);
	cifs_free_open_info(&data);
	return rc;
}

#ifdef CONFIG_CIFS_ALLOW_INSECURE_LEGACY
static int cifs_push_posix_locks(struct cifsFileInfo *cfile);
#endif /* CONFIG_CIFS_ALLOW_INSECURE_LEGACY */

/*
 * Try to reacquire byte range locks that were released when session
 * to server was lost.
 */
static int
cifs_relock_file(struct cifsFileInfo *cfile)
{
	struct cifsInodeInfo *cinode = CIFS_I(d_inode(cfile->dentry));
	struct cifs_tcon *tcon = tlink_tcon(cfile->tlink);
	int rc = 0;
#ifdef CONFIG_CIFS_ALLOW_INSECURE_LEGACY
	struct cifs_sb_info *cifs_sb = CIFS_SB(cfile->dentry->d_sb);
#endif /* CONFIG_CIFS_ALLOW_INSECURE_LEGACY */

	down_read_nested(&cinode->lock_sem, SINGLE_DEPTH_NESTING);
	if (cinode->can_cache_brlcks) {
		/* can cache locks - no need to relock */
		up_read(&cinode->lock_sem);
		return rc;
	}

#ifdef CONFIG_CIFS_ALLOW_INSECURE_LEGACY
	if (cap_unix(tcon->ses) &&
	    (CIFS_UNIX_FCNTL_CAP & le64_to_cpu(tcon->fsUnixInfo.Capability)) &&
	    ((cifs_sb->mnt_cifs_flags & CIFS_MOUNT_NOPOSIXBRL) == 0))
		rc = cifs_push_posix_locks(cfile);
	else
#endif /* CONFIG_CIFS_ALLOW_INSECURE_LEGACY */
		rc = tcon->ses->server->ops->push_mand_locks(cfile);

	up_read(&cinode->lock_sem);
	return rc;
}

static int
cifs_reopen_file(struct cifsFileInfo *cfile, bool can_flush)
{
	int rc = -EACCES;
	unsigned int xid;
	__u32 oplock;
	struct cifs_sb_info *cifs_sb;
	struct cifs_tcon *tcon;
	struct TCP_Server_Info *server;
	struct cifsInodeInfo *cinode;
	struct inode *inode;
	void *page;
	const char *full_path;
	int desired_access;
	int disposition = FILE_OPEN;
	int create_options = CREATE_NOT_DIR;
	struct cifs_open_parms oparms;
	int rdwr_for_fscache = 0;

	xid = get_xid();
	mutex_lock(&cfile->fh_mutex);
	if (!cfile->invalidHandle) {
		mutex_unlock(&cfile->fh_mutex);
		free_xid(xid);
		return 0;
	}

	inode = d_inode(cfile->dentry);
	cifs_sb = CIFS_SB(inode->i_sb);
	tcon = tlink_tcon(cfile->tlink);
	server = tcon->ses->server;

	/*
	 * Can not grab rename sem here because various ops, including those
	 * that already have the rename sem can end up causing writepage to get
	 * called and if the server was down that means we end up here, and we
	 * can never tell if the caller already has the rename_sem.
	 */
	page = alloc_dentry_path();
	full_path = build_path_from_dentry(cfile->dentry, page);
	if (IS_ERR(full_path)) {
		mutex_unlock(&cfile->fh_mutex);
		free_dentry_path(page);
		free_xid(xid);
		return PTR_ERR(full_path);
	}

	cifs_dbg(FYI, "inode = 0x%p file flags 0x%x for %s\n",
		 inode, cfile->f_flags, full_path);

	if (tcon->ses->server->oplocks)
		oplock = REQ_OPLOCK;
	else
		oplock = 0;

#ifdef CONFIG_CIFS_ALLOW_INSECURE_LEGACY
	if (tcon->unix_ext && cap_unix(tcon->ses) &&
	    (CIFS_UNIX_POSIX_PATH_OPS_CAP &
				le64_to_cpu(tcon->fsUnixInfo.Capability))) {
		/*
		 * O_CREAT, O_EXCL and O_TRUNC already had their effect on the
		 * original open. Must mask them off for a reopen.
		 */
		unsigned int oflags = cfile->f_flags &
						~(O_CREAT | O_EXCL | O_TRUNC);

		rc = cifs_posix_open(full_path, NULL, inode->i_sb,
				     cifs_sb->ctx->file_mode /* ignored */,
				     oflags, &oplock, &cfile->fid.netfid, xid);
		if (rc == 0) {
			cifs_dbg(FYI, "posix reopen succeeded\n");
			oparms.reconnect = true;
			goto reopen_success;
		}
		/*
		 * fallthrough to retry open the old way on errors, especially
		 * in the reconnect path it is important to retry hard
		 */
	}
#endif /* CONFIG_CIFS_ALLOW_INSECURE_LEGACY */

	/* If we're caching, we need to be able to fill in around partial writes. */
	if (cifs_fscache_enabled(inode) && (cfile->f_flags & O_ACCMODE) == O_WRONLY)
		rdwr_for_fscache = 1;

	desired_access = cifs_convert_flags(cfile->f_flags, rdwr_for_fscache);

	/* O_SYNC also has bit for O_DSYNC so following check picks up either */
	if (cfile->f_flags & O_SYNC)
		create_options |= CREATE_WRITE_THROUGH;

	if (cfile->f_flags & O_DIRECT)
		create_options |= CREATE_NO_BUFFER;

	if (server->ops->get_lease_key)
		server->ops->get_lease_key(inode, &cfile->fid);

retry_open:
	oparms = (struct cifs_open_parms) {
		.tcon = tcon,
		.cifs_sb = cifs_sb,
		.desired_access = desired_access,
		.create_options = cifs_create_options(cifs_sb, create_options),
		.disposition = disposition,
		.path = full_path,
		.fid = &cfile->fid,
		.reconnect = true,
	};

	/*
	 * Can not refresh inode by passing in file_info buf to be returned by
	 * ops->open and then calling get_inode_info with returned buf since
	 * file might have write behind data that needs to be flushed and server
	 * version of file size can be stale. If we knew for sure that inode was
	 * not dirty locally we could do this.
	 */
	rc = server->ops->open(xid, &oparms, &oplock, NULL);
	if (rc == -ENOENT && oparms.reconnect == false) {
		/* durable handle timeout is expired - open the file again */
		rc = server->ops->open(xid, &oparms, &oplock, NULL);
		/* indicate that we need to relock the file */
		oparms.reconnect = true;
	}
	if (rc == -EACCES && rdwr_for_fscache == 1) {
		desired_access = cifs_convert_flags(cfile->f_flags, 0);
		rdwr_for_fscache = 2;
		goto retry_open;
	}

	if (rc) {
		mutex_unlock(&cfile->fh_mutex);
		cifs_dbg(FYI, "cifs_reopen returned 0x%x\n", rc);
		cifs_dbg(FYI, "oplock: %d\n", oplock);
		goto reopen_error_exit;
	}

	if (rdwr_for_fscache == 2)
		cifs_invalidate_cache(inode, FSCACHE_INVAL_DIO_WRITE);

#ifdef CONFIG_CIFS_ALLOW_INSECURE_LEGACY
reopen_success:
#endif /* CONFIG_CIFS_ALLOW_INSECURE_LEGACY */
	cfile->invalidHandle = false;
	mutex_unlock(&cfile->fh_mutex);
	cinode = CIFS_I(inode);

	if (can_flush) {
		rc = filemap_write_and_wait(inode->i_mapping);
		if (!is_interrupt_error(rc))
			mapping_set_error(inode->i_mapping, rc);

		if (tcon->posix_extensions) {
			rc = smb311_posix_get_inode_info(&inode, full_path,
							 NULL, inode->i_sb, xid);
		} else if (tcon->unix_ext) {
			rc = cifs_get_inode_info_unix(&inode, full_path,
						      inode->i_sb, xid);
		} else {
			rc = cifs_get_inode_info(&inode, full_path, NULL,
						 inode->i_sb, xid, NULL);
		}
	}
	/*
	 * Else we are writing out data to server already and could deadlock if
	 * we tried to flush data, and since we do not know if we have data that
	 * would invalidate the current end of file on the server we can not go
	 * to the server to get the new inode info.
	 */

	/*
	 * If the server returned a read oplock and we have mandatory brlocks,
	 * set oplock level to None.
	 */
	if (server->ops->is_read_op(oplock) && cifs_has_mand_locks(cinode)) {
		cifs_dbg(FYI, "Reset oplock val from read to None due to mand locks\n");
		oplock = 0;
	}

	server->ops->set_fid(cfile, &cfile->fid, oplock);
	if (oparms.reconnect)
		cifs_relock_file(cfile);

reopen_error_exit:
	free_dentry_path(page);
	free_xid(xid);
	return rc;
}

void smb2_deferred_work_close(struct work_struct *work)
{
	struct cifsFileInfo *cfile = container_of(work,
			struct cifsFileInfo, deferred.work);

	spin_lock(&CIFS_I(d_inode(cfile->dentry))->deferred_lock);
	cifs_del_deferred_close(cfile);
	cfile->deferred_close_scheduled = false;
	spin_unlock(&CIFS_I(d_inode(cfile->dentry))->deferred_lock);
	_cifsFileInfo_put(cfile, true, false);
}

static bool
smb2_can_defer_close(struct inode *inode, struct cifs_deferred_close *dclose)
{
	struct cifs_sb_info *cifs_sb = CIFS_SB(inode->i_sb);
	struct cifsInodeInfo *cinode = CIFS_I(inode);

	return (cifs_sb->ctx->closetimeo && cinode->lease_granted && dclose &&
			(cinode->oplock == CIFS_CACHE_RHW_FLG ||
			 cinode->oplock == CIFS_CACHE_RH_FLG) &&
			!test_bit(CIFS_INO_CLOSE_ON_LOCK, &cinode->flags));

}

int cifs_close(struct inode *inode, struct file *file)
{
	struct cifsFileInfo *cfile;
	struct cifsInodeInfo *cinode = CIFS_I(inode);
	struct cifs_sb_info *cifs_sb = CIFS_SB(inode->i_sb);
	struct cifs_deferred_close *dclose;

	cifs_fscache_unuse_inode_cookie(inode, file->f_mode & FMODE_WRITE);

	if (file->private_data != NULL) {
		cfile = file->private_data;
		file->private_data = NULL;
		dclose = kmalloc(sizeof(struct cifs_deferred_close), GFP_KERNEL);
		if ((cfile->status_file_deleted == false) &&
		    (smb2_can_defer_close(inode, dclose))) {
			if (test_and_clear_bit(CIFS_INO_MODIFIED_ATTR, &cinode->flags)) {
				inode_set_mtime_to_ts(inode,
						      inode_set_ctime_current(inode));
			}
			spin_lock(&cinode->deferred_lock);
			cifs_add_deferred_close(cfile, dclose);
			if (cfile->deferred_close_scheduled &&
			    delayed_work_pending(&cfile->deferred)) {
				/*
				 * If there is no pending work, mod_delayed_work queues new work.
				 * So, Increase the ref count to avoid use-after-free.
				 */
				if (!mod_delayed_work(deferredclose_wq,
						&cfile->deferred, cifs_sb->ctx->closetimeo))
					cifsFileInfo_get(cfile);
			} else {
				/* Deferred close for files */
				queue_delayed_work(deferredclose_wq,
						&cfile->deferred, cifs_sb->ctx->closetimeo);
				cfile->deferred_close_scheduled = true;
				spin_unlock(&cinode->deferred_lock);
				return 0;
			}
			spin_unlock(&cinode->deferred_lock);
			_cifsFileInfo_put(cfile, true, false);
		} else {
			_cifsFileInfo_put(cfile, true, false);
			kfree(dclose);
		}
	}

	/* return code from the ->release op is always ignored */
	return 0;
}

void
cifs_reopen_persistent_handles(struct cifs_tcon *tcon)
{
	struct cifsFileInfo *open_file, *tmp;
	struct list_head tmp_list;

	if (!tcon->use_persistent || !tcon->need_reopen_files)
		return;

	tcon->need_reopen_files = false;

	cifs_dbg(FYI, "Reopen persistent handles\n");
	INIT_LIST_HEAD(&tmp_list);

	/* list all files open on tree connection, reopen resilient handles  */
	spin_lock(&tcon->open_file_lock);
	list_for_each_entry(open_file, &tcon->openFileList, tlist) {
		if (!open_file->invalidHandle)
			continue;
		cifsFileInfo_get(open_file);
		list_add_tail(&open_file->rlist, &tmp_list);
	}
	spin_unlock(&tcon->open_file_lock);

	list_for_each_entry_safe(open_file, tmp, &tmp_list, rlist) {
		if (cifs_reopen_file(open_file, false /* do not flush */))
			tcon->need_reopen_files = true;
		list_del_init(&open_file->rlist);
		cifsFileInfo_put(open_file);
	}
}

int cifs_closedir(struct inode *inode, struct file *file)
{
	int rc = 0;
	unsigned int xid;
	struct cifsFileInfo *cfile = file->private_data;
	struct cifs_tcon *tcon;
	struct TCP_Server_Info *server;
	char *buf;

	cifs_dbg(FYI, "Closedir inode = 0x%p\n", inode);

	if (cfile == NULL)
		return rc;

	xid = get_xid();
	tcon = tlink_tcon(cfile->tlink);
	server = tcon->ses->server;

	cifs_dbg(FYI, "Freeing private data in close dir\n");
	spin_lock(&cfile->file_info_lock);
	if (server->ops->dir_needs_close(cfile)) {
		cfile->invalidHandle = true;
		spin_unlock(&cfile->file_info_lock);
		if (server->ops->close_dir)
			rc = server->ops->close_dir(xid, tcon, &cfile->fid);
		else
			rc = -ENOSYS;
		cifs_dbg(FYI, "Closing uncompleted readdir with rc %d\n", rc);
		/* not much we can do if it fails anyway, ignore rc */
		rc = 0;
	} else
		spin_unlock(&cfile->file_info_lock);

	buf = cfile->srch_inf.ntwrk_buf_start;
	if (buf) {
		cifs_dbg(FYI, "closedir free smb buf in srch struct\n");
		cfile->srch_inf.ntwrk_buf_start = NULL;
		if (cfile->srch_inf.smallBuf)
			cifs_small_buf_release(buf);
		else
			cifs_buf_release(buf);
	}

	cifs_put_tlink(cfile->tlink);
	kfree(file->private_data);
	file->private_data = NULL;
	/* BB can we lock the filestruct while this is going on? */
	free_xid(xid);
	return rc;
}

static struct cifsLockInfo *
cifs_lock_init(__u64 offset, __u64 length, __u8 type, __u16 flags)
{
	struct cifsLockInfo *lock =
		kmalloc(sizeof(struct cifsLockInfo), GFP_KERNEL);
	if (!lock)
		return lock;
	lock->offset = offset;
	lock->length = length;
	lock->type = type;
	lock->pid = current->tgid;
	lock->flags = flags;
	INIT_LIST_HEAD(&lock->blist);
	init_waitqueue_head(&lock->block_q);
	return lock;
}

void
cifs_del_lock_waiters(struct cifsLockInfo *lock)
{
	struct cifsLockInfo *li, *tmp;
	list_for_each_entry_safe(li, tmp, &lock->blist, blist) {
		list_del_init(&li->blist);
		wake_up(&li->block_q);
	}
}

#define CIFS_LOCK_OP	0
#define CIFS_READ_OP	1
#define CIFS_WRITE_OP	2

/* @rw_check : 0 - no op, 1 - read, 2 - write */
static bool
cifs_find_fid_lock_conflict(struct cifs_fid_locks *fdlocks, __u64 offset,
			    __u64 length, __u8 type, __u16 flags,
			    struct cifsFileInfo *cfile,
			    struct cifsLockInfo **conf_lock, int rw_check)
{
	struct cifsLockInfo *li;
	struct cifsFileInfo *cur_cfile = fdlocks->cfile;
	struct TCP_Server_Info *server = tlink_tcon(cfile->tlink)->ses->server;

	list_for_each_entry(li, &fdlocks->locks, llist) {
		if (offset + length <= li->offset ||
		    offset >= li->offset + li->length)
			continue;
		if (rw_check != CIFS_LOCK_OP && current->tgid == li->pid &&
		    server->ops->compare_fids(cfile, cur_cfile)) {
			/* shared lock prevents write op through the same fid */
			if (!(li->type & server->vals->shared_lock_type) ||
			    rw_check != CIFS_WRITE_OP)
				continue;
		}
		if ((type & server->vals->shared_lock_type) &&
		    ((server->ops->compare_fids(cfile, cur_cfile) &&
		     current->tgid == li->pid) || type == li->type))
			continue;
		if (rw_check == CIFS_LOCK_OP &&
		    (flags & FL_OFDLCK) && (li->flags & FL_OFDLCK) &&
		    server->ops->compare_fids(cfile, cur_cfile))
			continue;
		if (conf_lock)
			*conf_lock = li;
		return true;
	}
	return false;
}

bool
cifs_find_lock_conflict(struct cifsFileInfo *cfile, __u64 offset, __u64 length,
			__u8 type, __u16 flags,
			struct cifsLockInfo **conf_lock, int rw_check)
{
	bool rc = false;
	struct cifs_fid_locks *cur;
	struct cifsInodeInfo *cinode = CIFS_I(d_inode(cfile->dentry));

	list_for_each_entry(cur, &cinode->llist, llist) {
		rc = cifs_find_fid_lock_conflict(cur, offset, length, type,
						 flags, cfile, conf_lock,
						 rw_check);
		if (rc)
			break;
	}

	return rc;
}

/*
 * Check if there is another lock that prevents us to set the lock (mandatory
 * style). If such a lock exists, update the flock structure with its
 * properties. Otherwise, set the flock type to F_UNLCK if we can cache brlocks
 * or leave it the same if we can't. Returns 0 if we don't need to request to
 * the server or 1 otherwise.
 */
static int
cifs_lock_test(struct cifsFileInfo *cfile, __u64 offset, __u64 length,
	       __u8 type, struct file_lock *flock)
{
	int rc = 0;
	struct cifsLockInfo *conf_lock;
	struct cifsInodeInfo *cinode = CIFS_I(d_inode(cfile->dentry));
	struct TCP_Server_Info *server = tlink_tcon(cfile->tlink)->ses->server;
	bool exist;

	down_read(&cinode->lock_sem);

	exist = cifs_find_lock_conflict(cfile, offset, length, type,
					flock->fl_flags, &conf_lock,
					CIFS_LOCK_OP);
	if (exist) {
		flock->fl_start = conf_lock->offset;
		flock->fl_end = conf_lock->offset + conf_lock->length - 1;
		flock->fl_pid = conf_lock->pid;
		if (conf_lock->type & server->vals->shared_lock_type)
			flock->fl_type = F_RDLCK;
		else
			flock->fl_type = F_WRLCK;
	} else if (!cinode->can_cache_brlcks)
		rc = 1;
	else
		flock->fl_type = F_UNLCK;

	up_read(&cinode->lock_sem);
	return rc;
}

static void
cifs_lock_add(struct cifsFileInfo *cfile, struct cifsLockInfo *lock)
{
	struct cifsInodeInfo *cinode = CIFS_I(d_inode(cfile->dentry));
	cifs_down_write(&cinode->lock_sem);
	list_add_tail(&lock->llist, &cfile->llist->locks);
	up_write(&cinode->lock_sem);
}

/*
 * Set the byte-range lock (mandatory style). Returns:
 * 1) 0, if we set the lock and don't need to request to the server;
 * 2) 1, if no locks prevent us but we need to request to the server;
 * 3) -EACCES, if there is a lock that prevents us and wait is false.
 */
static int
cifs_lock_add_if(struct cifsFileInfo *cfile, struct cifsLockInfo *lock,
		 bool wait)
{
	struct cifsLockInfo *conf_lock;
	struct cifsInodeInfo *cinode = CIFS_I(d_inode(cfile->dentry));
	bool exist;
	int rc = 0;

try_again:
	exist = false;
	cifs_down_write(&cinode->lock_sem);

	exist = cifs_find_lock_conflict(cfile, lock->offset, lock->length,
					lock->type, lock->flags, &conf_lock,
					CIFS_LOCK_OP);
	if (!exist && cinode->can_cache_brlcks) {
		list_add_tail(&lock->llist, &cfile->llist->locks);
		up_write(&cinode->lock_sem);
		return rc;
	}

	if (!exist)
		rc = 1;
	else if (!wait)
		rc = -EACCES;
	else {
		list_add_tail(&lock->blist, &conf_lock->blist);
		up_write(&cinode->lock_sem);
		rc = wait_event_interruptible(lock->block_q,
					(lock->blist.prev == &lock->blist) &&
					(lock->blist.next == &lock->blist));
		if (!rc)
			goto try_again;
		cifs_down_write(&cinode->lock_sem);
		list_del_init(&lock->blist);
	}

	up_write(&cinode->lock_sem);
	return rc;
}

#ifdef CONFIG_CIFS_ALLOW_INSECURE_LEGACY
/*
 * Check if there is another lock that prevents us to set the lock (posix
 * style). If such a lock exists, update the flock structure with its
 * properties. Otherwise, set the flock type to F_UNLCK if we can cache brlocks
 * or leave it the same if we can't. Returns 0 if we don't need to request to
 * the server or 1 otherwise.
 */
static int
cifs_posix_lock_test(struct file *file, struct file_lock *flock)
{
	int rc = 0;
	struct cifsInodeInfo *cinode = CIFS_I(file_inode(file));
	unsigned char saved_type = flock->fl_type;

	if ((flock->fl_flags & FL_POSIX) == 0)
		return 1;

	down_read(&cinode->lock_sem);
	posix_test_lock(file, flock);

	if (flock->fl_type == F_UNLCK && !cinode->can_cache_brlcks) {
		flock->fl_type = saved_type;
		rc = 1;
	}

	up_read(&cinode->lock_sem);
	return rc;
}

/*
 * Set the byte-range lock (posix style). Returns:
 * 1) <0, if the error occurs while setting the lock;
 * 2) 0, if we set the lock and don't need to request to the server;
 * 3) FILE_LOCK_DEFERRED, if we will wait for some other file_lock;
 * 4) FILE_LOCK_DEFERRED + 1, if we need to request to the server.
 */
static int
cifs_posix_lock_set(struct file *file, struct file_lock *flock)
{
	struct cifsInodeInfo *cinode = CIFS_I(file_inode(file));
	int rc = FILE_LOCK_DEFERRED + 1;

	if ((flock->fl_flags & FL_POSIX) == 0)
		return rc;

	cifs_down_write(&cinode->lock_sem);
	if (!cinode->can_cache_brlcks) {
		up_write(&cinode->lock_sem);
		return rc;
	}

	rc = posix_lock_file(file, flock, NULL);
	up_write(&cinode->lock_sem);
	return rc;
}

int
cifs_push_mandatory_locks(struct cifsFileInfo *cfile)
{
	unsigned int xid;
	int rc = 0, stored_rc;
	struct cifsLockInfo *li, *tmp;
	struct cifs_tcon *tcon;
	unsigned int num, max_num, max_buf;
	LOCKING_ANDX_RANGE *buf, *cur;
	static const int types[] = {
		LOCKING_ANDX_LARGE_FILES,
		LOCKING_ANDX_SHARED_LOCK | LOCKING_ANDX_LARGE_FILES
	};
	int i;

	xid = get_xid();
	tcon = tlink_tcon(cfile->tlink);

	/*
	 * Accessing maxBuf is racy with cifs_reconnect - need to store value
	 * and check it before using.
	 */
	max_buf = tcon->ses->server->maxBuf;
	if (max_buf < (sizeof(struct smb_hdr) + sizeof(LOCKING_ANDX_RANGE))) {
		free_xid(xid);
		return -EINVAL;
	}

	BUILD_BUG_ON(sizeof(struct smb_hdr) + sizeof(LOCKING_ANDX_RANGE) >
		     PAGE_SIZE);
	max_buf = min_t(unsigned int, max_buf - sizeof(struct smb_hdr),
			PAGE_SIZE);
	max_num = (max_buf - sizeof(struct smb_hdr)) /
						sizeof(LOCKING_ANDX_RANGE);
	buf = kcalloc(max_num, sizeof(LOCKING_ANDX_RANGE), GFP_KERNEL);
	if (!buf) {
		free_xid(xid);
		return -ENOMEM;
	}

	for (i = 0; i < 2; i++) {
		cur = buf;
		num = 0;
		list_for_each_entry_safe(li, tmp, &cfile->llist->locks, llist) {
			if (li->type != types[i])
				continue;
			cur->Pid = cpu_to_le16(li->pid);
			cur->LengthLow = cpu_to_le32((u32)li->length);
			cur->LengthHigh = cpu_to_le32((u32)(li->length>>32));
			cur->OffsetLow = cpu_to_le32((u32)li->offset);
			cur->OffsetHigh = cpu_to_le32((u32)(li->offset>>32));
			if (++num == max_num) {
				stored_rc = cifs_lockv(xid, tcon,
						       cfile->fid.netfid,
						       (__u8)li->type, 0, num,
						       buf);
				if (stored_rc)
					rc = stored_rc;
				cur = buf;
				num = 0;
			} else
				cur++;
		}

		if (num) {
			stored_rc = cifs_lockv(xid, tcon, cfile->fid.netfid,
					       (__u8)types[i], 0, num, buf);
			if (stored_rc)
				rc = stored_rc;
		}
	}

	kfree(buf);
	free_xid(xid);
	return rc;
}

static __u32
hash_lockowner(fl_owner_t owner)
{
	return cifs_lock_secret ^ hash32_ptr((const void *)owner);
}
#endif /* CONFIG_CIFS_ALLOW_INSECURE_LEGACY */

struct lock_to_push {
	struct list_head llist;
	__u64 offset;
	__u64 length;
	__u32 pid;
	__u16 netfid;
	__u8 type;
};

#ifdef CONFIG_CIFS_ALLOW_INSECURE_LEGACY
static int
cifs_push_posix_locks(struct cifsFileInfo *cfile)
{
	struct inode *inode = d_inode(cfile->dentry);
	struct cifs_tcon *tcon = tlink_tcon(cfile->tlink);
	struct file_lock *flock;
	struct file_lock_context *flctx = locks_inode_context(inode);
	unsigned int count = 0, i;
	int rc = 0, xid, type;
	struct list_head locks_to_send, *el;
	struct lock_to_push *lck, *tmp;
	__u64 length;

	xid = get_xid();

	if (!flctx)
		goto out;

	spin_lock(&flctx->flc_lock);
	list_for_each(el, &flctx->flc_posix) {
		count++;
	}
	spin_unlock(&flctx->flc_lock);

	INIT_LIST_HEAD(&locks_to_send);

	/*
	 * Allocating count locks is enough because no FL_POSIX locks can be
	 * added to the list while we are holding cinode->lock_sem that
	 * protects locking operations of this inode.
	 */
	for (i = 0; i < count; i++) {
		lck = kmalloc(sizeof(struct lock_to_push), GFP_KERNEL);
		if (!lck) {
			rc = -ENOMEM;
			goto err_out;
		}
		list_add_tail(&lck->llist, &locks_to_send);
	}

	el = locks_to_send.next;
	spin_lock(&flctx->flc_lock);
	list_for_each_entry(flock, &flctx->flc_posix, fl_list) {
		if (el == &locks_to_send) {
			/*
			 * The list ended. We don't have enough allocated
			 * structures - something is really wrong.
			 */
			cifs_dbg(VFS, "Can't push all brlocks!\n");
			break;
		}
		length = cifs_flock_len(flock);
		if (flock->fl_type == F_RDLCK || flock->fl_type == F_SHLCK)
			type = CIFS_RDLCK;
		else
			type = CIFS_WRLCK;
		lck = list_entry(el, struct lock_to_push, llist);
		lck->pid = hash_lockowner(flock->fl_owner);
		lck->netfid = cfile->fid.netfid;
		lck->length = length;
		lck->type = type;
		lck->offset = flock->fl_start;
	}
	spin_unlock(&flctx->flc_lock);

	list_for_each_entry_safe(lck, tmp, &locks_to_send, llist) {
		int stored_rc;

		stored_rc = CIFSSMBPosixLock(xid, tcon, lck->netfid, lck->pid,
					     lck->offset, lck->length, NULL,
					     lck->type, 0);
		if (stored_rc)
			rc = stored_rc;
		list_del(&lck->llist);
		kfree(lck);
	}

out:
	free_xid(xid);
	return rc;
err_out:
	list_for_each_entry_safe(lck, tmp, &locks_to_send, llist) {
		list_del(&lck->llist);
		kfree(lck);
	}
	goto out;
}
#endif /* CONFIG_CIFS_ALLOW_INSECURE_LEGACY */

static int
cifs_push_locks(struct cifsFileInfo *cfile)
{
	struct cifsInodeInfo *cinode = CIFS_I(d_inode(cfile->dentry));
	struct cifs_tcon *tcon = tlink_tcon(cfile->tlink);
	int rc = 0;
#ifdef CONFIG_CIFS_ALLOW_INSECURE_LEGACY
	struct cifs_sb_info *cifs_sb = CIFS_SB(cfile->dentry->d_sb);
#endif /* CONFIG_CIFS_ALLOW_INSECURE_LEGACY */

	/* we are going to update can_cache_brlcks here - need a write access */
	cifs_down_write(&cinode->lock_sem);
	if (!cinode->can_cache_brlcks) {
		up_write(&cinode->lock_sem);
		return rc;
	}

#ifdef CONFIG_CIFS_ALLOW_INSECURE_LEGACY
	if (cap_unix(tcon->ses) &&
	    (CIFS_UNIX_FCNTL_CAP & le64_to_cpu(tcon->fsUnixInfo.Capability)) &&
	    ((cifs_sb->mnt_cifs_flags & CIFS_MOUNT_NOPOSIXBRL) == 0))
		rc = cifs_push_posix_locks(cfile);
	else
#endif /* CONFIG_CIFS_ALLOW_INSECURE_LEGACY */
		rc = tcon->ses->server->ops->push_mand_locks(cfile);

	cinode->can_cache_brlcks = false;
	up_write(&cinode->lock_sem);
	return rc;
}

static void
cifs_read_flock(struct file_lock *flock, __u32 *type, int *lock, int *unlock,
		bool *wait_flag, struct TCP_Server_Info *server)
{
	if (flock->fl_flags & FL_POSIX)
		cifs_dbg(FYI, "Posix\n");
	if (flock->fl_flags & FL_FLOCK)
		cifs_dbg(FYI, "Flock\n");
	if (flock->fl_flags & FL_SLEEP) {
		cifs_dbg(FYI, "Blocking lock\n");
		*wait_flag = true;
	}
	if (flock->fl_flags & FL_ACCESS)
		cifs_dbg(FYI, "Process suspended by mandatory locking - not implemented yet\n");
	if (flock->fl_flags & FL_LEASE)
		cifs_dbg(FYI, "Lease on file - not implemented yet\n");
	if (flock->fl_flags &
	    (~(FL_POSIX | FL_FLOCK | FL_SLEEP |
	       FL_ACCESS | FL_LEASE | FL_CLOSE | FL_OFDLCK)))
		cifs_dbg(FYI, "Unknown lock flags 0x%x\n", flock->fl_flags);

	*type = server->vals->large_lock_type;
	if (flock->fl_type == F_WRLCK) {
		cifs_dbg(FYI, "F_WRLCK\n");
		*type |= server->vals->exclusive_lock_type;
		*lock = 1;
	} else if (flock->fl_type == F_UNLCK) {
		cifs_dbg(FYI, "F_UNLCK\n");
		*type |= server->vals->unlock_lock_type;
		*unlock = 1;
		/* Check if unlock includes more than one lock range */
	} else if (flock->fl_type == F_RDLCK) {
		cifs_dbg(FYI, "F_RDLCK\n");
		*type |= server->vals->shared_lock_type;
		*lock = 1;
	} else if (flock->fl_type == F_EXLCK) {
		cifs_dbg(FYI, "F_EXLCK\n");
		*type |= server->vals->exclusive_lock_type;
		*lock = 1;
	} else if (flock->fl_type == F_SHLCK) {
		cifs_dbg(FYI, "F_SHLCK\n");
		*type |= server->vals->shared_lock_type;
		*lock = 1;
	} else
		cifs_dbg(FYI, "Unknown type of lock\n");
}

static int
cifs_getlk(struct file *file, struct file_lock *flock, __u32 type,
	   bool wait_flag, bool posix_lck, unsigned int xid)
{
	int rc = 0;
	__u64 length = cifs_flock_len(flock);
	struct cifsFileInfo *cfile = (struct cifsFileInfo *)file->private_data;
	struct cifs_tcon *tcon = tlink_tcon(cfile->tlink);
	struct TCP_Server_Info *server = tcon->ses->server;
#ifdef CONFIG_CIFS_ALLOW_INSECURE_LEGACY
	__u16 netfid = cfile->fid.netfid;

	if (posix_lck) {
		int posix_lock_type;

		rc = cifs_posix_lock_test(file, flock);
		if (!rc)
			return rc;

		if (type & server->vals->shared_lock_type)
			posix_lock_type = CIFS_RDLCK;
		else
			posix_lock_type = CIFS_WRLCK;
		rc = CIFSSMBPosixLock(xid, tcon, netfid,
				      hash_lockowner(flock->fl_owner),
				      flock->fl_start, length, flock,
				      posix_lock_type, wait_flag);
		return rc;
	}
#endif /* CONFIG_CIFS_ALLOW_INSECURE_LEGACY */

	rc = cifs_lock_test(cfile, flock->fl_start, length, type, flock);
	if (!rc)
		return rc;

	/* BB we could chain these into one lock request BB */
	rc = server->ops->mand_lock(xid, cfile, flock->fl_start, length, type,
				    1, 0, false);
	if (rc == 0) {
		rc = server->ops->mand_lock(xid, cfile, flock->fl_start, length,
					    type, 0, 1, false);
		flock->fl_type = F_UNLCK;
		if (rc != 0)
			cifs_dbg(VFS, "Error unlocking previously locked range %d during test of lock\n",
				 rc);
		return 0;
	}

	if (type & server->vals->shared_lock_type) {
		flock->fl_type = F_WRLCK;
		return 0;
	}

	type &= ~server->vals->exclusive_lock_type;

	rc = server->ops->mand_lock(xid, cfile, flock->fl_start, length,
				    type | server->vals->shared_lock_type,
				    1, 0, false);
	if (rc == 0) {
		rc = server->ops->mand_lock(xid, cfile, flock->fl_start, length,
			type | server->vals->shared_lock_type, 0, 1, false);
		flock->fl_type = F_RDLCK;
		if (rc != 0)
			cifs_dbg(VFS, "Error unlocking previously locked range %d during test of lock\n",
				 rc);
	} else
		flock->fl_type = F_WRLCK;

	return 0;
}

void
cifs_move_llist(struct list_head *source, struct list_head *dest)
{
	struct list_head *li, *tmp;
	list_for_each_safe(li, tmp, source)
		list_move(li, dest);
}

int
cifs_get_hardlink_path(struct cifs_tcon *tcon, struct inode *inode,
				struct file *file)
{
	struct cifsFileInfo *open_file = NULL;
	struct cifsInodeInfo *cinode = CIFS_I(inode);
	int rc = 0;

	spin_lock(&tcon->open_file_lock);
	spin_lock(&cinode->open_file_lock);

	list_for_each_entry(open_file, &cinode->openFileList, flist) {
		if (file->f_flags == open_file->f_flags) {
			rc = -EINVAL;
			break;
		}
	}

	spin_unlock(&cinode->open_file_lock);
	spin_unlock(&tcon->open_file_lock);
	return rc;
}

void
cifs_free_llist(struct list_head *llist)
{
	struct cifsLockInfo *li, *tmp;
	list_for_each_entry_safe(li, tmp, llist, llist) {
		cifs_del_lock_waiters(li);
		list_del(&li->llist);
		kfree(li);
	}
}

#ifdef CONFIG_CIFS_ALLOW_INSECURE_LEGACY
int
cifs_unlock_range(struct cifsFileInfo *cfile, struct file_lock *flock,
		  unsigned int xid)
{
	int rc = 0, stored_rc;
	static const int types[] = {
		LOCKING_ANDX_LARGE_FILES,
		LOCKING_ANDX_SHARED_LOCK | LOCKING_ANDX_LARGE_FILES
	};
	unsigned int i;
	unsigned int max_num, num, max_buf;
	LOCKING_ANDX_RANGE *buf, *cur;
	struct cifs_tcon *tcon = tlink_tcon(cfile->tlink);
	struct cifsInodeInfo *cinode = CIFS_I(d_inode(cfile->dentry));
	struct cifsLockInfo *li, *tmp;
	__u64 length = cifs_flock_len(flock);
	struct list_head tmp_llist;

	INIT_LIST_HEAD(&tmp_llist);

	/*
	 * Accessing maxBuf is racy with cifs_reconnect - need to store value
	 * and check it before using.
	 */
	max_buf = tcon->ses->server->maxBuf;
	if (max_buf < (sizeof(struct smb_hdr) + sizeof(LOCKING_ANDX_RANGE)))
		return -EINVAL;

	BUILD_BUG_ON(sizeof(struct smb_hdr) + sizeof(LOCKING_ANDX_RANGE) >
		     PAGE_SIZE);
	max_buf = min_t(unsigned int, max_buf - sizeof(struct smb_hdr),
			PAGE_SIZE);
	max_num = (max_buf - sizeof(struct smb_hdr)) /
						sizeof(LOCKING_ANDX_RANGE);
	buf = kcalloc(max_num, sizeof(LOCKING_ANDX_RANGE), GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	cifs_down_write(&cinode->lock_sem);
	for (i = 0; i < 2; i++) {
		cur = buf;
		num = 0;
		list_for_each_entry_safe(li, tmp, &cfile->llist->locks, llist) {
			if (flock->fl_start > li->offset ||
			    (flock->fl_start + length) <
			    (li->offset + li->length))
				continue;
			if (current->tgid != li->pid)
				continue;
			if (types[i] != li->type)
				continue;
			if (cinode->can_cache_brlcks) {
				/*
				 * We can cache brlock requests - simply remove
				 * a lock from the file's list.
				 */
				list_del(&li->llist);
				cifs_del_lock_waiters(li);
				kfree(li);
				continue;
			}
			cur->Pid = cpu_to_le16(li->pid);
			cur->LengthLow = cpu_to_le32((u32)li->length);
			cur->LengthHigh = cpu_to_le32((u32)(li->length>>32));
			cur->OffsetLow = cpu_to_le32((u32)li->offset);
			cur->OffsetHigh = cpu_to_le32((u32)(li->offset>>32));
			/*
			 * We need to save a lock here to let us add it again to
			 * the file's list if the unlock range request fails on
			 * the server.
			 */
			list_move(&li->llist, &tmp_llist);
			if (++num == max_num) {
				stored_rc = cifs_lockv(xid, tcon,
						       cfile->fid.netfid,
						       li->type, num, 0, buf);
				if (stored_rc) {
					/*
					 * We failed on the unlock range
					 * request - add all locks from the tmp
					 * list to the head of the file's list.
					 */
					cifs_move_llist(&tmp_llist,
							&cfile->llist->locks);
					rc = stored_rc;
				} else
					/*
					 * The unlock range request succeed -
					 * free the tmp list.
					 */
					cifs_free_llist(&tmp_llist);
				cur = buf;
				num = 0;
			} else
				cur++;
		}
		if (num) {
			stored_rc = cifs_lockv(xid, tcon, cfile->fid.netfid,
					       types[i], num, 0, buf);
			if (stored_rc) {
				cifs_move_llist(&tmp_llist,
						&cfile->llist->locks);
				rc = stored_rc;
			} else
				cifs_free_llist(&tmp_llist);
		}
	}

	up_write(&cinode->lock_sem);
	kfree(buf);
	return rc;
}
#endif /* CONFIG_CIFS_ALLOW_INSECURE_LEGACY */

static int
cifs_setlk(struct file *file, struct file_lock *flock, __u32 type,
	   bool wait_flag, bool posix_lck, int lock, int unlock,
	   unsigned int xid)
{
	int rc = 0;
	__u64 length = cifs_flock_len(flock);
	struct cifsFileInfo *cfile = (struct cifsFileInfo *)file->private_data;
	struct cifs_tcon *tcon = tlink_tcon(cfile->tlink);
	struct TCP_Server_Info *server = tcon->ses->server;
	struct inode *inode = d_inode(cfile->dentry);

#ifdef CONFIG_CIFS_ALLOW_INSECURE_LEGACY
	if (posix_lck) {
		int posix_lock_type;

		rc = cifs_posix_lock_set(file, flock);
		if (rc <= FILE_LOCK_DEFERRED)
			return rc;

		if (type & server->vals->shared_lock_type)
			posix_lock_type = CIFS_RDLCK;
		else
			posix_lock_type = CIFS_WRLCK;

		if (unlock == 1)
			posix_lock_type = CIFS_UNLCK;

		rc = CIFSSMBPosixLock(xid, tcon, cfile->fid.netfid,
				      hash_lockowner(flock->fl_owner),
				      flock->fl_start, length,
				      NULL, posix_lock_type, wait_flag);
		goto out;
	}
#endif /* CONFIG_CIFS_ALLOW_INSECURE_LEGACY */
	if (lock) {
		struct cifsLockInfo *lock;

		lock = cifs_lock_init(flock->fl_start, length, type,
				      flock->fl_flags);
		if (!lock)
			return -ENOMEM;

		rc = cifs_lock_add_if(cfile, lock, wait_flag);
		if (rc < 0) {
			kfree(lock);
			return rc;
		}
		if (!rc)
			goto out;

		/*
		 * Windows 7 server can delay breaking lease from read to None
		 * if we set a byte-range lock on a file - break it explicitly
		 * before sending the lock to the server to be sure the next
		 * read won't conflict with non-overlapted locks due to
		 * pagereading.
		 */
		if (!CIFS_CACHE_WRITE(CIFS_I(inode)) &&
					CIFS_CACHE_READ(CIFS_I(inode))) {
			cifs_zap_mapping(inode);
			cifs_dbg(FYI, "Set no oplock for inode=%p due to mand locks\n",
				 inode);
			CIFS_I(inode)->oplock = 0;
		}

		rc = server->ops->mand_lock(xid, cfile, flock->fl_start, length,
					    type, 1, 0, wait_flag);
		if (rc) {
			kfree(lock);
			return rc;
		}

		cifs_lock_add(cfile, lock);
	} else if (unlock)
		rc = server->ops->mand_unlock_range(cfile, flock, xid);

out:
	if ((flock->fl_flags & FL_POSIX) || (flock->fl_flags & FL_FLOCK)) {
		/*
		 * If this is a request to remove all locks because we
		 * are closing the file, it doesn't matter if the
		 * unlocking failed as both cifs.ko and the SMB server
		 * remove the lock on file close
		 */
		if (rc) {
			cifs_dbg(VFS, "%s failed rc=%d\n", __func__, rc);
			if (!(flock->fl_flags & FL_CLOSE))
				return rc;
		}
		rc = locks_lock_file_wait(file, flock);
	}
	return rc;
}

int cifs_flock(struct file *file, int cmd, struct file_lock *fl)
{
	int rc, xid;
	int lock = 0, unlock = 0;
	bool wait_flag = false;
	bool posix_lck = false;
	struct cifs_sb_info *cifs_sb;
	struct cifs_tcon *tcon;
	struct cifsFileInfo *cfile;
	__u32 type;

	xid = get_xid();

	if (!(fl->fl_flags & FL_FLOCK)) {
		rc = -ENOLCK;
		free_xid(xid);
		return rc;
	}

	cfile = (struct cifsFileInfo *)file->private_data;
	tcon = tlink_tcon(cfile->tlink);

	cifs_read_flock(fl, &type, &lock, &unlock, &wait_flag,
			tcon->ses->server);
	cifs_sb = CIFS_FILE_SB(file);

	if (cap_unix(tcon->ses) &&
	    (CIFS_UNIX_FCNTL_CAP & le64_to_cpu(tcon->fsUnixInfo.Capability)) &&
	    ((cifs_sb->mnt_cifs_flags & CIFS_MOUNT_NOPOSIXBRL) == 0))
		posix_lck = true;

	if (!lock && !unlock) {
		/*
		 * if no lock or unlock then nothing to do since we do not
		 * know what it is
		 */
		rc = -EOPNOTSUPP;
		free_xid(xid);
		return rc;
	}

	rc = cifs_setlk(file, fl, type, wait_flag, posix_lck, lock, unlock,
			xid);
	free_xid(xid);
	return rc;


}

int cifs_lock(struct file *file, int cmd, struct file_lock *flock)
{
	int rc, xid;
	int lock = 0, unlock = 0;
	bool wait_flag = false;
	bool posix_lck = false;
	struct cifs_sb_info *cifs_sb;
	struct cifs_tcon *tcon;
	struct cifsFileInfo *cfile;
	__u32 type;

	rc = -EACCES;
	xid = get_xid();

	cifs_dbg(FYI, "%s: %pD2 cmd=0x%x type=0x%x flags=0x%x r=%lld:%lld\n", __func__, file, cmd,
		 flock->fl_flags, flock->fl_type, (long long)flock->fl_start,
		 (long long)flock->fl_end);

	cfile = (struct cifsFileInfo *)file->private_data;
	tcon = tlink_tcon(cfile->tlink);

	cifs_read_flock(flock, &type, &lock, &unlock, &wait_flag,
			tcon->ses->server);
	cifs_sb = CIFS_FILE_SB(file);
	set_bit(CIFS_INO_CLOSE_ON_LOCK, &CIFS_I(d_inode(cfile->dentry))->flags);

	if (cap_unix(tcon->ses) &&
	    (CIFS_UNIX_FCNTL_CAP & le64_to_cpu(tcon->fsUnixInfo.Capability)) &&
	    ((cifs_sb->mnt_cifs_flags & CIFS_MOUNT_NOPOSIXBRL) == 0))
		posix_lck = true;
	/*
	 * BB add code here to normalize offset and length to account for
	 * negative length which we can not accept over the wire.
	 */
	if (IS_GETLK(cmd)) {
		rc = cifs_getlk(file, flock, type, wait_flag, posix_lck, xid);
		free_xid(xid);
		return rc;
	}

	if (!lock && !unlock) {
		/*
		 * if no lock or unlock then nothing to do since we do not
		 * know what it is
		 */
		free_xid(xid);
		return -EOPNOTSUPP;
	}

	rc = cifs_setlk(file, flock, type, wait_flag, posix_lck, lock, unlock,
			xid);
	free_xid(xid);
	return rc;
}

/*
 * update the file size (if needed) after a write. Should be called with
 * the inode->i_lock held
 */
void
cifs_update_eof(struct cifsInodeInfo *cifsi, loff_t offset,
		      unsigned int bytes_written)
{
	loff_t end_of_write = offset + bytes_written;

	if (end_of_write > cifsi->server_eof)
		cifsi->server_eof = end_of_write;
}

static ssize_t
cifs_write(struct cifsFileInfo *open_file, __u32 pid, const char *write_data,
	   size_t write_size, loff_t *offset)
{
	int rc = 0;
	unsigned int bytes_written = 0;
	unsigned int total_written;
	struct cifs_tcon *tcon;
	struct TCP_Server_Info *server;
	unsigned int xid;
	struct dentry *dentry = open_file->dentry;
	struct cifsInodeInfo *cifsi = CIFS_I(d_inode(dentry));
	struct cifs_io_parms io_parms = {0};

	cifs_dbg(FYI, "write %zd bytes to offset %lld of %pd\n",
		 write_size, *offset, dentry);

	tcon = tlink_tcon(open_file->tlink);
	server = tcon->ses->server;

	if (!server->ops->sync_write)
		return -ENOSYS;

	xid = get_xid();

	for (total_written = 0; write_size > total_written;
	     total_written += bytes_written) {
		rc = -EAGAIN;
		while (rc == -EAGAIN) {
			struct kvec iov[2];
			unsigned int len;

			if (open_file->invalidHandle) {
				/* we could deadlock if we called
				   filemap_fdatawait from here so tell
				   reopen_file not to flush data to
				   server now */
				rc = cifs_reopen_file(open_file, false);
				if (rc != 0)
					break;
			}

			len = min(server->ops->wp_retry_size(d_inode(dentry)),
				  (unsigned int)write_size - total_written);
			/* iov[0] is reserved for smb header */
			iov[1].iov_base = (char *)write_data + total_written;
			iov[1].iov_len = len;
			io_parms.pid = pid;
			io_parms.tcon = tcon;
			io_parms.offset = *offset;
			io_parms.length = len;
			rc = server->ops->sync_write(xid, &open_file->fid,
					&io_parms, &bytes_written, iov, 1);
		}
		if (rc || (bytes_written == 0)) {
			if (total_written)
				break;
			else {
				free_xid(xid);
				return rc;
			}
		} else {
			spin_lock(&d_inode(dentry)->i_lock);
			cifs_update_eof(cifsi, *offset, bytes_written);
			spin_unlock(&d_inode(dentry)->i_lock);
			*offset += bytes_written;
		}
	}

	cifs_stats_bytes_written(tcon, total_written);

	if (total_written > 0) {
		spin_lock(&d_inode(dentry)->i_lock);
		if (*offset > d_inode(dentry)->i_size) {
			i_size_write(d_inode(dentry), *offset);
			d_inode(dentry)->i_blocks = (512 - 1 + *offset) >> 9;
		}
		spin_unlock(&d_inode(dentry)->i_lock);
	}
	mark_inode_dirty_sync(d_inode(dentry));
	free_xid(xid);
	return total_written;
}

struct cifsFileInfo *find_readable_file(struct cifsInodeInfo *cifs_inode,
					bool fsuid_only)
{
	struct cifsFileInfo *open_file = NULL;
	struct cifs_sb_info *cifs_sb = CIFS_SB(cifs_inode->netfs.inode.i_sb);

	/* only filter by fsuid on multiuser mounts */
	if (!(cifs_sb->mnt_cifs_flags & CIFS_MOUNT_MULTIUSER))
		fsuid_only = false;

	spin_lock(&cifs_inode->open_file_lock);
	/* we could simply get the first_list_entry since write-only entries
	   are always at the end of the list but since the first entry might
	   have a close pending, we go through the whole list */
	list_for_each_entry(open_file, &cifs_inode->openFileList, flist) {
		if (fsuid_only && !uid_eq(open_file->uid, current_fsuid()))
			continue;
		if (OPEN_FMODE(open_file->f_flags) & FMODE_READ) {
			if ((!open_file->invalidHandle)) {
				/* found a good file */
				/* lock it so it will not be closed on us */
				cifsFileInfo_get(open_file);
				spin_unlock(&cifs_inode->open_file_lock);
				return open_file;
			} /* else might as well continue, and look for
			     another, or simply have the caller reopen it
			     again rather than trying to fix this handle */
		} else /* write only file */
			break; /* write only files are last so must be done */
	}
	spin_unlock(&cifs_inode->open_file_lock);
	return NULL;
}

/* Return -EBADF if no handle is found and general rc otherwise */
int
cifs_get_writable_file(struct cifsInodeInfo *cifs_inode, int flags,
		       struct cifsFileInfo **ret_file)
{
	struct cifsFileInfo *open_file, *inv_file = NULL;
	struct cifs_sb_info *cifs_sb;
	bool any_available = false;
	int rc = -EBADF;
	unsigned int refind = 0;
	bool fsuid_only = flags & FIND_WR_FSUID_ONLY;
	bool with_delete = flags & FIND_WR_WITH_DELETE;
	*ret_file = NULL;

	/*
	 * Having a null inode here (because mapping->host was set to zero by
	 * the VFS or MM) should not happen but we had reports of on oops (due
	 * to it being zero) during stress testcases so we need to check for it
	 */

	if (cifs_inode == NULL) {
		cifs_dbg(VFS, "Null inode passed to cifs_writeable_file\n");
		dump_stack();
		return rc;
	}

	cifs_sb = CIFS_SB(cifs_inode->netfs.inode.i_sb);

	/* only filter by fsuid on multiuser mounts */
	if (!(cifs_sb->mnt_cifs_flags & CIFS_MOUNT_MULTIUSER))
		fsuid_only = false;

	spin_lock(&cifs_inode->open_file_lock);
refind_writable:
	if (refind > MAX_REOPEN_ATT) {
		spin_unlock(&cifs_inode->open_file_lock);
		return rc;
	}
	list_for_each_entry(open_file, &cifs_inode->openFileList, flist) {
		if (!any_available && open_file->pid != current->tgid)
			continue;
		if (fsuid_only && !uid_eq(open_file->uid, current_fsuid()))
			continue;
		if (with_delete && !(open_file->fid.access & DELETE))
			continue;
		if (OPEN_FMODE(open_file->f_flags) & FMODE_WRITE) {
			if (!open_file->invalidHandle) {
				/* found a good writable file */
				cifsFileInfo_get(open_file);
				spin_unlock(&cifs_inode->open_file_lock);
				*ret_file = open_file;
				return 0;
			} else {
				if (!inv_file)
					inv_file = open_file;
			}
		}
	}
	/* couldn't find useable FH with same pid, try any available */
	if (!any_available) {
		any_available = true;
		goto refind_writable;
	}

	if (inv_file) {
		any_available = false;
		cifsFileInfo_get(inv_file);
	}

	spin_unlock(&cifs_inode->open_file_lock);

	if (inv_file) {
		rc = cifs_reopen_file(inv_file, false);
		if (!rc) {
			*ret_file = inv_file;
			return 0;
		}

		spin_lock(&cifs_inode->open_file_lock);
		list_move_tail(&inv_file->flist, &cifs_inode->openFileList);
		spin_unlock(&cifs_inode->open_file_lock);
		cifsFileInfo_put(inv_file);
		++refind;
		inv_file = NULL;
		spin_lock(&cifs_inode->open_file_lock);
		goto refind_writable;
	}

	return rc;
}

struct cifsFileInfo *
find_writable_file(struct cifsInodeInfo *cifs_inode, int flags)
{
	struct cifsFileInfo *cfile;
	int rc;

	rc = cifs_get_writable_file(cifs_inode, flags, &cfile);
	if (rc)
		cifs_dbg(FYI, "Couldn't find writable handle rc=%d\n", rc);

	return cfile;
}

int
cifs_get_writable_path(struct cifs_tcon *tcon, const char *name,
		       int flags,
		       struct cifsFileInfo **ret_file)
{
	struct cifsFileInfo *cfile;
	void *page = alloc_dentry_path();

	*ret_file = NULL;

	spin_lock(&tcon->open_file_lock);
	list_for_each_entry(cfile, &tcon->openFileList, tlist) {
		struct cifsInodeInfo *cinode;
		const char *full_path = build_path_from_dentry(cfile->dentry, page);
		if (IS_ERR(full_path)) {
			spin_unlock(&tcon->open_file_lock);
			free_dentry_path(page);
			return PTR_ERR(full_path);
		}
		if (strcmp(full_path, name))
			continue;

		cinode = CIFS_I(d_inode(cfile->dentry));
		spin_unlock(&tcon->open_file_lock);
		free_dentry_path(page);
		return cifs_get_writable_file(cinode, flags, ret_file);
	}

	spin_unlock(&tcon->open_file_lock);
	free_dentry_path(page);
	return -ENOENT;
}

int
cifs_get_readable_path(struct cifs_tcon *tcon, const char *name,
		       struct cifsFileInfo **ret_file)
{
	struct cifsFileInfo *cfile;
	void *page = alloc_dentry_path();

	*ret_file = NULL;

	spin_lock(&tcon->open_file_lock);
	list_for_each_entry(cfile, &tcon->openFileList, tlist) {
		struct cifsInodeInfo *cinode;
		const char *full_path = build_path_from_dentry(cfile->dentry, page);
		if (IS_ERR(full_path)) {
			spin_unlock(&tcon->open_file_lock);
			free_dentry_path(page);
			return PTR_ERR(full_path);
		}
		if (strcmp(full_path, name))
			continue;

		cinode = CIFS_I(d_inode(cfile->dentry));
		spin_unlock(&tcon->open_file_lock);
		free_dentry_path(page);
		*ret_file = find_readable_file(cinode, 0);
		return *ret_file ? 0 : -ENOENT;
	}

	spin_unlock(&tcon->open_file_lock);
	free_dentry_path(page);
	return -ENOENT;
}

void
cifs_writedata_release(struct kref *refcount)
{
	struct cifs_writedata *wdata = container_of(refcount,
					struct cifs_writedata, refcount);
#ifdef CONFIG_CIFS_SMB_DIRECT
	if (wdata->mr) {
		smbd_deregister_mr(wdata->mr);
		wdata->mr = NULL;
	}
#endif

	if (wdata->cfile)
		cifsFileInfo_put(wdata->cfile);

	kfree(wdata);
}

/*
 * Write failed with a retryable error. Resend the write request. It's also
 * possible that the page was redirtied so re-clean the page.
 */
static void
cifs_writev_requeue(struct cifs_writedata *wdata)
{
	int rc = 0;
	struct inode *inode = d_inode(wdata->cfile->dentry);
	struct TCP_Server_Info *server;
	unsigned int rest_len = wdata->bytes;
	loff_t fpos = wdata->offset;

	server = tlink_tcon(wdata->cfile->tlink)->ses->server;
	do {
		struct cifs_writedata *wdata2;
		unsigned int wsize, cur_len;

		wsize = server->ops->wp_retry_size(inode);
		if (wsize < rest_len) {
			if (wsize < PAGE_SIZE) {
				rc = -EOPNOTSUPP;
				break;
			}
			cur_len = min(round_down(wsize, PAGE_SIZE), rest_len);
		} else {
			cur_len = rest_len;
		}

		wdata2 = cifs_writedata_alloc(cifs_writev_complete);
		if (!wdata2) {
			rc = -ENOMEM;
			break;
		}

		wdata2->sync_mode = wdata->sync_mode;
		wdata2->offset	= fpos;
		wdata2->bytes	= cur_len;
		wdata2->iter	= wdata->iter;

		iov_iter_advance(&wdata2->iter, fpos - wdata->offset);
		iov_iter_truncate(&wdata2->iter, wdata2->bytes);

		if (iov_iter_is_xarray(&wdata2->iter))
			/* Check for pages having been redirtied and clean
			 * them.  We can do this by walking the xarray.  If
			 * it's not an xarray, then it's a DIO and we shouldn't
			 * be mucking around with the page bits.
			 */
			cifs_undirty_folios(inode, fpos, cur_len);

		rc = cifs_get_writable_file(CIFS_I(inode), FIND_WR_ANY,
					    &wdata2->cfile);
		if (!wdata2->cfile) {
			cifs_dbg(VFS, "No writable handle to retry writepages rc=%d\n",
				 rc);
			if (!is_retryable_error(rc))
				rc = -EBADF;
		} else {
			wdata2->pid = wdata2->cfile->pid;
			rc = server->ops->async_writev(wdata2,
						       cifs_writedata_release);
		}

		kref_put(&wdata2->refcount, cifs_writedata_release);
		if (rc) {
			if (is_retryable_error(rc))
				continue;
			fpos += cur_len;
			rest_len -= cur_len;
			break;
		}

		fpos += cur_len;
		rest_len -= cur_len;
	} while (rest_len > 0);

	/* Clean up remaining pages from the original wdata */
	if (iov_iter_is_xarray(&wdata->iter))
		cifs_pages_write_failed(inode, fpos, rest_len);

	if (rc != 0 && !is_retryable_error(rc))
		mapping_set_error(inode->i_mapping, rc);
	kref_put(&wdata->refcount, cifs_writedata_release);
}

void
cifs_writev_complete(struct work_struct *work)
{
	struct cifs_writedata *wdata = container_of(work,
						struct cifs_writedata, work);
	struct inode *inode = d_inode(wdata->cfile->dentry);

	if (wdata->result == 0) {
		spin_lock(&inode->i_lock);
		cifs_update_eof(CIFS_I(inode), wdata->offset, wdata->bytes);
		spin_unlock(&inode->i_lock);
		cifs_stats_bytes_written(tlink_tcon(wdata->cfile->tlink),
					 wdata->bytes);
	} else if (wdata->sync_mode == WB_SYNC_ALL && wdata->result == -EAGAIN)
		return cifs_writev_requeue(wdata);

	if (wdata->result == -EAGAIN)
		cifs_pages_write_redirty(inode, wdata->offset, wdata->bytes);
	else if (wdata->result < 0)
		cifs_pages_write_failed(inode, wdata->offset, wdata->bytes);
	else
		cifs_pages_written_back(inode, wdata->offset, wdata->bytes);

	if (wdata->result != -EAGAIN)
		mapping_set_error(inode->i_mapping, wdata->result);
	kref_put(&wdata->refcount, cifs_writedata_release);
}

struct cifs_writedata *cifs_writedata_alloc(work_func_t complete)
{
	struct cifs_writedata *wdata;

	wdata = kzalloc(sizeof(*wdata), GFP_NOFS);
	if (wdata != NULL) {
		kref_init(&wdata->refcount);
		INIT_LIST_HEAD(&wdata->list);
		init_completion(&wdata->done);
		INIT_WORK(&wdata->work, complete);
	}
	return wdata;
}

static int cifs_partialpagewrite(struct page *page, unsigned from, unsigned to)
{
	struct address_space *mapping = page->mapping;
	loff_t offset = (loff_t)page->index << PAGE_SHIFT;
	char *write_data;
	int rc = -EFAULT;
	int bytes_written = 0;
	struct inode *inode;
	struct cifsFileInfo *open_file;

	if (!mapping || !mapping->host)
		return -EFAULT;

	inode = page->mapping->host;

	offset += (loff_t)from;
	write_data = kmap(page);
	write_data += from;

	if ((to > PAGE_SIZE) || (from > to)) {
		kunmap(page);
		return -EIO;
	}

	/* racing with truncate? */
	if (offset > mapping->host->i_size) {
		kunmap(page);
		return 0; /* don't care */
	}

	/* check to make sure that we are not extending the file */
	if (mapping->host->i_size - offset < (loff_t)to)
		to = (unsigned)(mapping->host->i_size - offset);

	rc = cifs_get_writable_file(CIFS_I(mapping->host), FIND_WR_ANY,
				    &open_file);
	if (!rc) {
		bytes_written = cifs_write(open_file, open_file->pid,
					   write_data, to - from, &offset);
		cifsFileInfo_put(open_file);
		/* Does mm or vfs already set times? */
		simple_inode_init_ts(inode);
		if ((bytes_written > 0) && (offset))
			rc = 0;
		else if (bytes_written < 0)
			rc = bytes_written;
		else
			rc = -EFAULT;
	} else {
		cifs_dbg(FYI, "No writable handle for write page rc=%d\n", rc);
		if (!is_retryable_error(rc))
			rc = -EIO;
	}

	kunmap(page);
	return rc;
}

/*
 * Extend the region to be written back to include subsequent contiguously
 * dirty pages if possible, but don't sleep while doing so.
 */
static void cifs_extend_writeback(struct address_space *mapping,
				  struct xa_state *xas,
				  long *_count,
				  loff_t start,
				  int max_pages,
				  loff_t max_len,
				  size_t *_len)
{
	struct folio_batch batch;
	struct folio *folio;
	unsigned int nr_pages;
	pgoff_t index = (start + *_len) / PAGE_SIZE;
	size_t len;
	bool stop = true;
	unsigned int i;

	folio_batch_init(&batch);

	do {
		/* Firstly, we gather up a batch of contiguous dirty pages
		 * under the RCU read lock - but we can't clear the dirty flags
		 * there if any of those pages are mapped.
		 */
		rcu_read_lock();

		xas_for_each(xas, folio, ULONG_MAX) {
			stop = true;
			if (xas_retry(xas, folio))
				continue;
			if (xa_is_value(folio))
				break;
			if (folio->index != index) {
				xas_reset(xas);
				break;
			}

			if (!folio_try_get(folio)) {
				xas_reset(xas);
				continue;
			}
			nr_pages = folio_nr_pages(folio);
			if (nr_pages > max_pages) {
				xas_reset(xas);
				break;
			}

			/* Has the page moved or been split? */
			if (unlikely(folio != xas_reload(xas))) {
				folio_put(folio);
				xas_reset(xas);
				break;
			}

			if (!folio_trylock(folio)) {
				folio_put(folio);
				xas_reset(xas);
				break;
			}
			if (!folio_test_dirty(folio) ||
			    folio_test_writeback(folio)) {
				folio_unlock(folio);
				folio_put(folio);
				xas_reset(xas);
				break;
			}

			max_pages -= nr_pages;
			len = folio_size(folio);
			stop = false;

			index += nr_pages;
			*_count -= nr_pages;
			*_len += len;
			if (max_pages <= 0 || *_len >= max_len || *_count <= 0)
				stop = true;

			if (!folio_batch_add(&batch, folio))
				break;
			if (stop)
				break;
		}

		xas_pause(xas);
		rcu_read_unlock();

		/* Now, if we obtained any pages, we can shift them to being
		 * writable and mark them for caching.
		 */
		if (!folio_batch_count(&batch))
			break;

		for (i = 0; i < folio_batch_count(&batch); i++) {
			folio = batch.folios[i];
			/* The folio should be locked, dirty and not undergoing
			 * writeback from the loop above.
			 */
			if (!folio_clear_dirty_for_io(folio))
				WARN_ON(1);
			folio_start_writeback(folio);
			folio_unlock(folio);
		}

		folio_batch_release(&batch);
		cond_resched();
	} while (!stop);
}

/*
 * Write back the locked page and any subsequent non-locked dirty pages.
 */
static ssize_t cifs_write_back_from_locked_folio(struct address_space *mapping,
						 struct writeback_control *wbc,
						 struct xa_state *xas,
						 struct folio *folio,
						 unsigned long long start,
						 unsigned long long end)
{
	struct inode *inode = mapping->host;
	struct TCP_Server_Info *server;
	struct cifs_writedata *wdata;
	struct cifs_sb_info *cifs_sb = CIFS_SB(inode->i_sb);
	struct cifs_credits credits_on_stack;
	struct cifs_credits *credits = &credits_on_stack;
	struct cifsFileInfo *cfile = NULL;
	unsigned long long i_size = i_size_read(inode), max_len;
	unsigned int xid, wsize;
	size_t len = folio_size(folio);
	long count = wbc->nr_to_write;
	int rc;

	/* The folio should be locked, dirty and not undergoing writeback. */
	if (!folio_clear_dirty_for_io(folio))
		WARN_ON_ONCE(1);
	folio_start_writeback(folio);

	count -= folio_nr_pages(folio);

	xid = get_xid();
	server = cifs_pick_channel(cifs_sb_master_tcon(cifs_sb)->ses);

	rc = cifs_get_writable_file(CIFS_I(inode), FIND_WR_ANY, &cfile);
	if (rc) {
		cifs_dbg(VFS, "No writable handle in writepages rc=%d\n", rc);
		goto err_xid;
	}

	rc = server->ops->wait_mtu_credits(server, cifs_sb->ctx->wsize,
					   &wsize, credits);
	if (rc != 0)
		goto err_close;

	wdata = cifs_writedata_alloc(cifs_writev_complete);
	if (!wdata) {
		rc = -ENOMEM;
		goto err_uncredit;
	}

	wdata->sync_mode = wbc->sync_mode;
	wdata->offset = folio_pos(folio);
	wdata->pid = cfile->pid;
	wdata->credits = credits_on_stack;
	wdata->cfile = cfile;
	wdata->server = server;
	cfile = NULL;

	/* Find all consecutive lockable dirty pages that have contiguous
	 * written regions, stopping when we find a page that is not
	 * immediately lockable, is not dirty or is missing, or we reach the
	 * end of the range.
	 */
	if (start < i_size) {
		/* Trim the write to the EOF; the extra data is ignored.  Also
		 * put an upper limit on the size of a single storedata op.
		 */
		max_len = wsize;
		max_len = min_t(unsigned long long, max_len, end - start + 1);
		max_len = min_t(unsigned long long, max_len, i_size - start);

		if (len < max_len) {
			int max_pages = INT_MAX;

#ifdef CONFIG_CIFS_SMB_DIRECT
			if (server->smbd_conn)
				max_pages = server->smbd_conn->max_frmr_depth;
#endif
			max_pages -= folio_nr_pages(folio);

			if (max_pages > 0)
				cifs_extend_writeback(mapping, xas, &count, start,
						      max_pages, max_len, &len);
		}
	}
	len = min_t(unsigned long long, len, i_size - start);

	/* We now have a contiguous set of dirty pages, each with writeback
	 * set; the first page is still locked at this point, but all the rest
	 * have been unlocked.
	 */
	folio_unlock(folio);
	wdata->bytes = len;

	if (start < i_size) {
		iov_iter_xarray(&wdata->iter, ITER_SOURCE, &mapping->i_pages,
				start, len);

		rc = adjust_credits(wdata->server, &wdata->credits, wdata->bytes);
		if (rc)
			goto err_wdata;

		if (wdata->cfile->invalidHandle)
			rc = -EAGAIN;
		else
			rc = wdata->server->ops->async_writev(wdata,
							      cifs_writedata_release);
		if (rc >= 0) {
			kref_put(&wdata->refcount, cifs_writedata_release);
			goto err_close;
		}
	} else {
		/* The dirty region was entirely beyond the EOF. */
		cifs_pages_written_back(inode, start, len);
		rc = 0;
	}

err_wdata:
	kref_put(&wdata->refcount, cifs_writedata_release);
err_uncredit:
	add_credits_and_wake_if(server, credits, 0);
err_close:
	if (cfile)
		cifsFileInfo_put(cfile);
err_xid:
	free_xid(xid);
	if (rc == 0) {
		wbc->nr_to_write = count;
		rc = len;
	} else if (is_retryable_error(rc)) {
		cifs_pages_write_redirty(inode, start, len);
	} else {
		cifs_pages_write_failed(inode, start, len);
		mapping_set_error(mapping, rc);
	}
	/* Indication to update ctime and mtime as close is deferred */
	set_bit(CIFS_INO_MODIFIED_ATTR, &CIFS_I(inode)->flags);
	return rc;
}

/*
 * write a region of pages back to the server
 */
static ssize_t cifs_writepages_begin(struct address_space *mapping,
				     struct writeback_control *wbc,
				     struct xa_state *xas,
				     unsigned long long *_start,
				     unsigned long long end)
{
	struct folio *folio;
	unsigned long long start = *_start;
	ssize_t ret;
	int skips = 0;

search_again:
	/* Find the first dirty page. */
	rcu_read_lock();

	for (;;) {
		folio = xas_find_marked(xas, end / PAGE_SIZE, PAGECACHE_TAG_DIRTY);
		if (xas_retry(xas, folio) || xa_is_value(folio))
			continue;
		if (!folio)
			break;

		if (!folio_try_get(folio)) {
			xas_reset(xas);
			continue;
		}

		if (unlikely(folio != xas_reload(xas))) {
			folio_put(folio);
			xas_reset(xas);
			continue;
		}

		xas_pause(xas);
		break;
	}
	rcu_read_unlock();
	if (!folio)
		return 0;

	start = folio_pos(folio); /* May regress with THPs */

	/* At this point we hold neither the i_pages lock nor the page lock:
	 * the page may be truncated or invalidated (changing page->mapping to
	 * NULL), or even swizzled back from swapper_space to tmpfs file
	 * mapping
	 */
lock_again:
	if (wbc->sync_mode != WB_SYNC_NONE) {
		ret = folio_lock_killable(folio);
		if (ret < 0)
			return ret;
	} else {
		if (!folio_trylock(folio))
			goto search_again;
	}

	if (folio->mapping != mapping ||
	    !folio_test_dirty(folio)) {
		start += folio_size(folio);
		folio_unlock(folio);
		goto search_again;
	}

	if (folio_test_writeback(folio) ||
	    folio_test_fscache(folio)) {
		folio_unlock(folio);
		if (wbc->sync_mode != WB_SYNC_NONE) {
			folio_wait_writeback(folio);
#ifdef CONFIG_CIFS_FSCACHE
			folio_wait_fscache(folio);
#endif
			goto lock_again;
		}

		start += folio_size(folio);
		if (wbc->sync_mode == WB_SYNC_NONE) {
			if (skips >= 5 || need_resched()) {
				ret = 0;
				goto out;
			}
			skips++;
		}
		goto search_again;
	}

	ret = cifs_write_back_from_locked_folio(mapping, wbc, xas, folio, start, end);
out:
	if (ret > 0)
		*_start = start + ret;
	return ret;
}

/*
 * Write a region of pages back to the server
 */
static int cifs_writepages_region(struct address_space *mapping,
				  struct writeback_control *wbc,
				  unsigned long long *_start,
				  unsigned long long end)
{
	ssize_t ret;

	XA_STATE(xas, &mapping->i_pages, *_start / PAGE_SIZE);

	do {
		ret = cifs_writepages_begin(mapping, wbc, &xas, _start, end);
		if (ret > 0 && wbc->nr_to_write > 0)
			cond_resched();
	} while (ret > 0 && wbc->nr_to_write > 0);

	return ret > 0 ? 0 : ret;
}

/*
 * Write some of the pending data back to the server
 */
static int cifs_writepages(struct address_space *mapping,
			   struct writeback_control *wbc)
{
	loff_t start, end;
	int ret;

	/* We have to be careful as we can end up racing with setattr()
	 * truncating the pagecache since the caller doesn't take a lock here
	 * to prevent it.
	 */

	if (wbc->range_cyclic && mapping->writeback_index) {
		start = mapping->writeback_index * PAGE_SIZE;
		ret = cifs_writepages_region(mapping, wbc, &start, LLONG_MAX);
		if (ret < 0)
			goto out;

		if (wbc->nr_to_write <= 0) {
			mapping->writeback_index = start / PAGE_SIZE;
			goto out;
		}

		start = 0;
		end = mapping->writeback_index * PAGE_SIZE;
		mapping->writeback_index = 0;
		ret = cifs_writepages_region(mapping, wbc, &start, end);
		if (ret == 0)
			mapping->writeback_index = start / PAGE_SIZE;
	} else if (wbc->range_start == 0 && wbc->range_end == LLONG_MAX) {
		start = 0;
		ret = cifs_writepages_region(mapping, wbc, &start, LLONG_MAX);
		if (wbc->nr_to_write > 0 && ret == 0)
			mapping->writeback_index = start / PAGE_SIZE;
	} else {
		start = wbc->range_start;
		ret = cifs_writepages_region(mapping, wbc, &start, wbc->range_end);
	}

out:
	return ret;
}

static int
cifs_writepage_locked(struct page *page, struct writeback_control *wbc)
{
	int rc;
	unsigned int xid;

	xid = get_xid();
/* BB add check for wbc flags */
	get_page(page);
	if (!PageUptodate(page))
		cifs_dbg(FYI, "ppw - page not up to date\n");

	/*
	 * Set the "writeback" flag, and clear "dirty" in the radix tree.
	 *
	 * A writepage() implementation always needs to do either this,
	 * or re-dirty the page with "redirty_page_for_writepage()" in
	 * the case of a failure.
	 *
	 * Just unlocking the page will cause the radix tree tag-bits
	 * to fail to update with the state of the page correctly.
	 */
	set_page_writeback(page);
retry_write:
	rc = cifs_partialpagewrite(page, 0, PAGE_SIZE);
	if (is_retryable_error(rc)) {
		if (wbc->sync_mode == WB_SYNC_ALL && rc == -EAGAIN)
			goto retry_write;
		redirty_page_for_writepage(wbc, page);
	} else if (rc != 0) {
		SetPageError(page);
		mapping_set_error(page->mapping, rc);
	} else {
		SetPageUptodate(page);
	}
	end_page_writeback(page);
	put_page(page);
	free_xid(xid);
	return rc;
}

static int cifs_write_end(struct file *file, struct address_space *mapping,
			loff_t pos, unsigned len, unsigned copied,
			struct page *page, void *fsdata)
{
	int rc;
	struct inode *inode = mapping->host;
	struct cifsFileInfo *cfile = file->private_data;
	struct cifs_sb_info *cifs_sb = CIFS_SB(cfile->dentry->d_sb);
	struct folio *folio = page_folio(page);
	__u32 pid;

	if (cifs_sb->mnt_cifs_flags & CIFS_MOUNT_RWPIDFORWARD)
		pid = cfile->pid;
	else
		pid = current->tgid;

	cifs_dbg(FYI, "write_end for page %p from pos %lld with %d bytes\n",
		 page, pos, copied);

	if (folio_test_checked(folio)) {
		if (copied == len)
			folio_mark_uptodate(folio);
		folio_clear_checked(folio);
	} else if (!folio_test_uptodate(folio) && copied == PAGE_SIZE)
		folio_mark_uptodate(folio);

	if (!folio_test_uptodate(folio)) {
		char *page_data;
		unsigned offset = pos & (PAGE_SIZE - 1);
		unsigned int xid;

		xid = get_xid();
		/* this is probably better than directly calling
		   partialpage_write since in this function the file handle is
		   known which we might as well	leverage */
		/* BB check if anything else missing out of ppw
		   such as updating last write time */
		page_data = kmap(page);
		rc = cifs_write(cfile, pid, page_data + offset, copied, &pos);
		/* if (rc < 0) should we set writebehind rc? */
		kunmap(page);

		free_xid(xid);
	} else {
		rc = copied;
		pos += copied;
		set_page_dirty(page);
	}

	if (rc > 0) {
		spin_lock(&inode->i_lock);
		if (pos > inode->i_size) {
			loff_t additional_blocks = (512 - 1 + copied) >> 9;

			i_size_write(inode, pos);
			/*
			 * Estimate new allocation size based on the amount written.
			 * This will be updated from server on close (and on queryinfo)
			 */
			inode->i_blocks = min_t(blkcnt_t, (512 - 1 + pos) >> 9,
						inode->i_blocks + additional_blocks);
		}
		spin_unlock(&inode->i_lock);
	}

	unlock_page(page);
	put_page(page);
	/* Indication to update ctime and mtime as close is deferred */
	set_bit(CIFS_INO_MODIFIED_ATTR, &CIFS_I(inode)->flags);

	return rc;
}

int cifs_strict_fsync(struct file *file, loff_t start, loff_t end,
		      int datasync)
{
	unsigned int xid;
	int rc = 0;
	struct cifs_tcon *tcon;
	struct TCP_Server_Info *server;
	struct cifsFileInfo *smbfile = file->private_data;
	struct inode *inode = file_inode(file);
	struct cifs_sb_info *cifs_sb = CIFS_SB(inode->i_sb);

	rc = file_write_and_wait_range(file, start, end);
	if (rc) {
		trace_cifs_fsync_err(inode->i_ino, rc);
		return rc;
	}

	xid = get_xid();

	cifs_dbg(FYI, "Sync file - name: %pD datasync: 0x%x\n",
		 file, datasync);

	if (!CIFS_CACHE_READ(CIFS_I(inode))) {
		rc = cifs_zap_mapping(inode);
		if (rc) {
			cifs_dbg(FYI, "rc: %d during invalidate phase\n", rc);
			rc = 0; /* don't care about it in fsync */
		}
	}

	tcon = tlink_tcon(smbfile->tlink);
	if (!(cifs_sb->mnt_cifs_flags & CIFS_MOUNT_NOSSYNC)) {
		server = tcon->ses->server;
		if (server->ops->flush == NULL) {
			rc = -ENOSYS;
			goto strict_fsync_exit;
		}

		if ((OPEN_FMODE(smbfile->f_flags) & FMODE_WRITE) == 0) {
			smbfile = find_writable_file(CIFS_I(inode), FIND_WR_ANY);
			if (smbfile) {
				rc = server->ops->flush(xid, tcon, &smbfile->fid);
				cifsFileInfo_put(smbfile);
			} else
				cifs_dbg(FYI, "ignore fsync for file not open for write\n");
		} else
			rc = server->ops->flush(xid, tcon, &smbfile->fid);
	}

strict_fsync_exit:
	free_xid(xid);
	return rc;
}

int cifs_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
	unsigned int xid;
	int rc = 0;
	struct cifs_tcon *tcon;
	struct TCP_Server_Info *server;
	struct cifsFileInfo *smbfile = file->private_data;
	struct inode *inode = file_inode(file);
	struct cifs_sb_info *cifs_sb = CIFS_FILE_SB(file);

	rc = file_write_and_wait_range(file, start, end);
	if (rc) {
		trace_cifs_fsync_err(file_inode(file)->i_ino, rc);
		return rc;
	}

	xid = get_xid();

	cifs_dbg(FYI, "Sync file - name: %pD datasync: 0x%x\n",
		 file, datasync);

	tcon = tlink_tcon(smbfile->tlink);
	if (!(cifs_sb->mnt_cifs_flags & CIFS_MOUNT_NOSSYNC)) {
		server = tcon->ses->server;
		if (server->ops->flush == NULL) {
			rc = -ENOSYS;
			goto fsync_exit;
		}

		if ((OPEN_FMODE(smbfile->f_flags) & FMODE_WRITE) == 0) {
			smbfile = find_writable_file(CIFS_I(inode), FIND_WR_ANY);
			if (smbfile) {
				rc = server->ops->flush(xid, tcon, &smbfile->fid);
				cifsFileInfo_put(smbfile);
			} else
				cifs_dbg(FYI, "ignore fsync for file not open for write\n");
		} else
			rc = server->ops->flush(xid, tcon, &smbfile->fid);
	}

fsync_exit:
	free_xid(xid);
	return rc;
}

/*
 * As file closes, flush all cached write data for this inode checking
 * for write behind errors.
 */
int cifs_flush(struct file *file, fl_owner_t id)
{
	struct inode *inode = file_inode(file);
	int rc = 0;

	if (file->f_mode & FMODE_WRITE)
		rc = filemap_write_and_wait(inode->i_mapping);

	cifs_dbg(FYI, "Flush inode %p file %p rc %d\n", inode, file, rc);
	if (rc) {
		/* get more nuanced writeback errors */
		rc = filemap_check_wb_err(file->f_mapping, 0);
		trace_cifs_flush_err(inode->i_ino, rc);
	}
	return rc;
}

static void
cifs_uncached_writedata_release(struct kref *refcount)
{
	struct cifs_writedata *wdata = container_of(refcount,
					struct cifs_writedata, refcount);

	kref_put(&wdata->ctx->refcount, cifs_aio_ctx_release);
	cifs_writedata_release(refcount);
}

static void collect_uncached_write_data(struct cifs_aio_ctx *ctx);

static void
cifs_uncached_writev_complete(struct work_struct *work)
{
	struct cifs_writedata *wdata = container_of(work,
					struct cifs_writedata, work);
	struct inode *inode = d_inode(wdata->cfile->dentry);
	struct cifsInodeInfo *cifsi = CIFS_I(inode);

	spin_lock(&inode->i_lock);
	cifs_update_eof(cifsi, wdata->offset, wdata->bytes);
	if (cifsi->server_eof > inode->i_size)
		i_size_write(inode, cifsi->server_eof);
	spin_unlock(&inode->i_lock);

	complete(&wdata->done);
	collect_uncached_write_data(wdata->ctx);
	/* the below call can possibly free the last ref to aio ctx */
	kref_put(&wdata->refcount, cifs_uncached_writedata_release);
}

static int
cifs_resend_wdata(struct cifs_writedata *wdata, struct list_head *wdata_list,
	struct cifs_aio_ctx *ctx)
{
	unsigned int wsize;
	struct cifs_credits credits;
	int rc;
	struct TCP_Server_Info *server = wdata->server;

	do {
		if (wdata->cfile->invalidHandle) {
			rc = cifs_reopen_file(wdata->cfile, false);
			if (rc == -EAGAIN)
				continue;
			else if (rc)
				break;
		}


		/*
		 * Wait for credits to resend this wdata.
		 * Note: we are attempting to resend the whole wdata not in
		 * segments
		 */
		do {
			rc = server->ops->wait_mtu_credits(server, wdata->bytes,
						&wsize, &credits);
			if (rc)
				goto fail;

			if (wsize < wdata->bytes) {
				add_credits_and_wake_if(server, &credits, 0);
				msleep(1000);
			}
		} while (wsize < wdata->bytes);
		wdata->credits = credits;

		rc = adjust_credits(server, &wdata->credits, wdata->bytes);

		if (!rc) {
			if (wdata->cfile->invalidHandle)
				rc = -EAGAIN;
			else {
				wdata->replay = true;
#ifdef CONFIG_CIFS_SMB_DIRECT
				if (wdata->mr) {
					wdata->mr->need_invalidate = true;
					smbd_deregister_mr(wdata->mr);
					wdata->mr = NULL;
				}
#endif
				rc = server->ops->async_writev(wdata,
					cifs_uncached_writedata_release);
			}
		}

		/* If the write was successfully sent, we are done */
		if (!rc) {
			list_add_tail(&wdata->list, wdata_list);
			return 0;
		}

		/* Roll back credits and retry if needed */
		add_credits_and_wake_if(server, &wdata->credits, 0);
	} while (rc == -EAGAIN);

fail:
	kref_put(&wdata->refcount, cifs_uncached_writedata_release);
	return rc;
}

/*
 * Select span of a bvec iterator we're going to use.  Limit it by both maximum
 * size and maximum number of segments.
 */
static size_t cifs_limit_bvec_subset(const struct iov_iter *iter, size_t max_size,
				     size_t max_segs, unsigned int *_nsegs)
{
	const struct bio_vec *bvecs = iter->bvec;
	unsigned int nbv = iter->nr_segs, ix = 0, nsegs = 0;
	size_t len, span = 0, n = iter->count;
	size_t skip = iter->iov_offset;

	if (WARN_ON(!iov_iter_is_bvec(iter)) || n == 0)
		return 0;

	while (n && ix < nbv && skip) {
		len = bvecs[ix].bv_len;
		if (skip < len)
			break;
		skip -= len;
		n -= len;
		ix++;
	}

	while (n && ix < nbv) {
		len = min3(n, bvecs[ix].bv_len - skip, max_size);
		span += len;
		max_size -= len;
		nsegs++;
		ix++;
		if (max_size == 0 || nsegs >= max_segs)
			break;
		skip = 0;
		n -= len;
	}

	*_nsegs = nsegs;
	return span;
}

static int
cifs_write_from_iter(loff_t fpos, size_t len, struct iov_iter *from,
		     struct cifsFileInfo *open_file,
		     struct cifs_sb_info *cifs_sb, struct list_head *wdata_list,
		     struct cifs_aio_ctx *ctx)
{
	int rc = 0;
	size_t cur_len, max_len;
	struct cifs_writedata *wdata;
	pid_t pid;
	struct TCP_Server_Info *server;
	unsigned int xid, max_segs = INT_MAX;

	if (cifs_sb->mnt_cifs_flags & CIFS_MOUNT_RWPIDFORWARD)
		pid = open_file->pid;
	else
		pid = current->tgid;

	server = cifs_pick_channel(tlink_tcon(open_file->tlink)->ses);
	xid = get_xid();

#ifdef CONFIG_CIFS_SMB_DIRECT
	if (server->smbd_conn)
		max_segs = server->smbd_conn->max_frmr_depth;
#endif

	do {
		struct cifs_credits credits_on_stack;
		struct cifs_credits *credits = &credits_on_stack;
		unsigned int wsize, nsegs = 0;

		if (signal_pending(current)) {
			rc = -EINTR;
			break;
		}

		if (open_file->invalidHandle) {
			rc = cifs_reopen_file(open_file, false);
			if (rc == -EAGAIN)
				continue;
			else if (rc)
				break;
		}

		rc = server->ops->wait_mtu_credits(server, cifs_sb->ctx->wsize,
						   &wsize, credits);
		if (rc)
			break;

		max_len = min_t(const size_t, len, wsize);
		if (!max_len) {
			rc = -EAGAIN;
			add_credits_and_wake_if(server, credits, 0);
			break;
		}

		cur_len = cifs_limit_bvec_subset(from, max_len, max_segs, &nsegs);
		cifs_dbg(FYI, "write_from_iter len=%zx/%zx nsegs=%u/%lu/%u\n",
			 cur_len, max_len, nsegs, from->nr_segs, max_segs);
		if (cur_len == 0) {
			rc = -EIO;
			add_credits_and_wake_if(server, credits, 0);
			break;
		}

		wdata = cifs_writedata_alloc(cifs_uncached_writev_complete);
		if (!wdata) {
			rc = -ENOMEM;
			add_credits_and_wake_if(server, credits, 0);
			break;
		}

		wdata->sync_mode = WB_SYNC_ALL;
		wdata->offset	= (__u64)fpos;
		wdata->cfile	= cifsFileInfo_get(open_file);
		wdata->server	= server;
		wdata->pid	= pid;
		wdata->bytes	= cur_len;
		wdata->credits	= credits_on_stack;
		wdata->iter	= *from;
		wdata->ctx	= ctx;
		kref_get(&ctx->refcount);

		iov_iter_truncate(&wdata->iter, cur_len);

		rc = adjust_credits(server, &wdata->credits, wdata->bytes);

		if (!rc) {
			if (wdata->cfile->invalidHandle)
				rc = -EAGAIN;
			else
				rc = server->ops->async_writev(wdata,
					cifs_uncached_writedata_release);
		}

		if (rc) {
			add_credits_and_wake_if(server, &wdata->credits, 0);
			kref_put(&wdata->refcount,
				 cifs_uncached_writedata_release);
			if (rc == -EAGAIN)
				continue;
			break;
		}

		list_add_tail(&wdata->list, wdata_list);
		iov_iter_advance(from, cur_len);
		fpos += cur_len;
		len -= cur_len;
	} while (len > 0);

	free_xid(xid);
	return rc;
}

static void collect_uncached_write_data(struct cifs_aio_ctx *ctx)
{
	struct cifs_writedata *wdata, *tmp;
	struct cifs_tcon *tcon;
	struct cifs_sb_info *cifs_sb;
	struct dentry *dentry = ctx->cfile->dentry;
	ssize_t rc;

	tcon = tlink_tcon(ctx->cfile->tlink);
	cifs_sb = CIFS_SB(dentry->d_sb);

	mutex_lock(&ctx->aio_mutex);

	if (list_empty(&ctx->list)) {
		mutex_unlock(&ctx->aio_mutex);
		return;
	}

	rc = ctx->rc;
	/*
	 * Wait for and collect replies for any successful sends in order of
	 * increasing offset. Once an error is hit, then return without waiting
	 * for any more replies.
	 */
restart_loop:
	list_for_each_entry_safe(wdata, tmp, &ctx->list, list) {
		if (!rc) {
			if (!try_wait_for_completion(&wdata->done)) {
				mutex_unlock(&ctx->aio_mutex);
				return;
			}

			if (wdata->result)
				rc = wdata->result;
			else
				ctx->total_len += wdata->bytes;

			/* resend call if it's a retryable error */
			if (rc == -EAGAIN) {
				struct list_head tmp_list;
				struct iov_iter tmp_from = ctx->iter;

				INIT_LIST_HEAD(&tmp_list);
				list_del_init(&wdata->list);

				if (ctx->direct_io)
					rc = cifs_resend_wdata(
						wdata, &tmp_list, ctx);
				else {
					iov_iter_advance(&tmp_from,
						 wdata->offset - ctx->pos);

					rc = cifs_write_from_iter(wdata->offset,
						wdata->bytes, &tmp_from,
						ctx->cfile, cifs_sb, &tmp_list,
						ctx);

					kref_put(&wdata->refcount,
						cifs_uncached_writedata_release);
				}

				list_splice(&tmp_list, &ctx->list);
				goto restart_loop;
			}
		}
		list_del_init(&wdata->list);
		kref_put(&wdata->refcount, cifs_uncached_writedata_release);
	}

	cifs_stats_bytes_written(tcon, ctx->total_len);
	set_bit(CIFS_INO_INVALID_MAPPING, &CIFS_I(dentry->d_inode)->flags);

	ctx->rc = (rc == 0) ? ctx->total_len : rc;

	mutex_unlock(&ctx->aio_mutex);

	if (ctx->iocb && ctx->iocb->ki_complete)
		ctx->iocb->ki_complete(ctx->iocb, ctx->rc);
	else
		complete(&ctx->done);
}

static ssize_t __cifs_writev(
	struct kiocb *iocb, struct iov_iter *from, bool direct)
{
	struct file *file = iocb->ki_filp;
	ssize_t total_written = 0;
	struct cifsFileInfo *cfile;
	struct cifs_tcon *tcon;
	struct cifs_sb_info *cifs_sb;
	struct cifs_aio_ctx *ctx;
	int rc;

	rc = generic_write_checks(iocb, from);
	if (rc <= 0)
		return rc;

	cifs_sb = CIFS_FILE_SB(file);
	cfile = file->private_data;
	tcon = tlink_tcon(cfile->tlink);

	if (!tcon->ses->server->ops->async_writev)
		return -ENOSYS;

	ctx = cifs_aio_ctx_alloc();
	if (!ctx)
		return -ENOMEM;

	ctx->cfile = cifsFileInfo_get(cfile);

	if (!is_sync_kiocb(iocb))
		ctx->iocb = iocb;

	ctx->pos = iocb->ki_pos;
	ctx->direct_io = direct;
	ctx->nr_pinned_pages = 0;

	if (user_backed_iter(from)) {
		/*
		 * Extract IOVEC/UBUF-type iterators to a BVEC-type iterator as
		 * they contain references to the calling process's virtual
		 * memory layout which won't be available in an async worker
		 * thread.  This also takes a pin on every folio involved.
		 */
		rc = netfs_extract_user_iter(from, iov_iter_count(from),
					     &ctx->iter, 0);
		if (rc < 0) {
			kref_put(&ctx->refcount, cifs_aio_ctx_release);
			return rc;
		}

		ctx->nr_pinned_pages = rc;
		ctx->bv = (void *)ctx->iter.bvec;
		ctx->bv_need_unpin = iov_iter_extract_will_pin(from);
	} else if ((iov_iter_is_bvec(from) || iov_iter_is_kvec(from)) &&
		   !is_sync_kiocb(iocb)) {
		/*
		 * If the op is asynchronous, we need to copy the list attached
		 * to a BVEC/KVEC-type iterator, but we assume that the storage
		 * will be pinned by the caller; in any case, we may or may not
		 * be able to pin the pages, so we don't try.
		 */
		ctx->bv = (void *)dup_iter(&ctx->iter, from, GFP_KERNEL);
		if (!ctx->bv) {
			kref_put(&ctx->refcount, cifs_aio_ctx_release);
			return -ENOMEM;
		}
	} else {
		/*
		 * Otherwise, we just pass the iterator down as-is and rely on
		 * the caller to make sure the pages referred to by the
		 * iterator don't evaporate.
		 */
		ctx->iter = *from;
	}

	ctx->len = iov_iter_count(&ctx->iter);

	/* grab a lock here due to read response handlers can access ctx */
	mutex_lock(&ctx->aio_mutex);

	rc = cifs_write_from_iter(iocb->ki_pos, ctx->len, &ctx->iter,
				  cfile, cifs_sb, &ctx->list, ctx);

	/*
	 * If at least one write was successfully sent, then discard any rc
	 * value from the later writes. If the other write succeeds, then
	 * we'll end up returning whatever was written. If it fails, then
	 * we'll get a new rc value from that.
	 */
	if (!list_empty(&ctx->list))
		rc = 0;

	mutex_unlock(&ctx->aio_mutex);

	if (rc) {
		kref_put(&ctx->refcount, cifs_aio_ctx_release);
		return rc;
	}

	if (!is_sync_kiocb(iocb)) {
		kref_put(&ctx->refcount, cifs_aio_ctx_release);
		return -EIOCBQUEUED;
	}

	rc = wait_for_completion_killable(&ctx->done);
	if (rc) {
		mutex_lock(&ctx->aio_mutex);
		ctx->rc = rc = -EINTR;
		total_written = ctx->total_len;
		mutex_unlock(&ctx->aio_mutex);
	} else {
		rc = ctx->rc;
		total_written = ctx->total_len;
	}

	kref_put(&ctx->refcount, cifs_aio_ctx_release);

	if (unlikely(!total_written))
		return rc;

	iocb->ki_pos += total_written;
	return total_written;
}

ssize_t cifs_direct_writev(struct kiocb *iocb, struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;

	cifs_revalidate_mapping(file->f_inode);
	return __cifs_writev(iocb, from, true);
}

ssize_t cifs_user_writev(struct kiocb *iocb, struct iov_iter *from)
{
	return __cifs_writev(iocb, from, false);
}

static ssize_t
cifs_writev(struct kiocb *iocb, struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct cifsFileInfo *cfile = (struct cifsFileInfo *)file->private_data;
	struct inode *inode = file->f_mapping->host;
	struct cifsInodeInfo *cinode = CIFS_I(inode);
	struct TCP_Server_Info *server = tlink_tcon(cfile->tlink)->ses->server;
	ssize_t rc;

	inode_lock(inode);
	/*
	 * We need to hold the sem to be sure nobody modifies lock list
	 * with a brlock that prevents writing.
	 */
	down_read(&cinode->lock_sem);

	rc = generic_write_checks(iocb, from);
	if (rc <= 0)
		goto out;

	if (!cifs_find_lock_conflict(cfile, iocb->ki_pos, iov_iter_count(from),
				     server->vals->exclusive_lock_type, 0,
				     NULL, CIFS_WRITE_OP))
		rc = __generic_file_write_iter(iocb, from);
	else
		rc = -EACCES;
out:
	up_read(&cinode->lock_sem);
	inode_unlock(inode);

	if (rc > 0)
		rc = generic_write_sync(iocb, rc);
	return rc;
}

ssize_t
cifs_strict_writev(struct kiocb *iocb, struct iov_iter *from)
{
	struct inode *inode = file_inode(iocb->ki_filp);
	struct cifsInodeInfo *cinode = CIFS_I(inode);
	struct cifs_sb_info *cifs_sb = CIFS_SB(inode->i_sb);
	struct cifsFileInfo *cfile = (struct cifsFileInfo *)
						iocb->ki_filp->private_data;
	struct cifs_tcon *tcon = tlink_tcon(cfile->tlink);
	ssize_t written;

	written = cifs_get_writer(cinode);
	if (written)
		return written;

	if (CIFS_CACHE_WRITE(cinode)) {
		if (cap_unix(tcon->ses) &&
		(CIFS_UNIX_FCNTL_CAP & le64_to_cpu(tcon->fsUnixInfo.Capability))
		  && ((cifs_sb->mnt_cifs_flags & CIFS_MOUNT_NOPOSIXBRL) == 0)) {
			written = generic_file_write_iter(iocb, from);
			goto out;
		}
		written = cifs_writev(iocb, from);
		goto out;
	}
	/*
	 * For non-oplocked files in strict cache mode we need to write the data
	 * to the server exactly from the pos to pos+len-1 rather than flush all
	 * affected pages because it may cause a error with mandatory locks on
	 * these pages but not on the region from pos to ppos+len-1.
	 */
	written = cifs_user_writev(iocb, from);
	if (CIFS_CACHE_READ(cinode)) {
		/*
		 * We have read level caching and we have just sent a write
		 * request to the server thus making data in the cache stale.
		 * Zap the cache and set oplock/lease level to NONE to avoid
		 * reading stale data from the cache. All subsequent read
		 * operations will read new data from the server.
		 */
		cifs_zap_mapping(inode);
		cifs_dbg(FYI, "Set Oplock/Lease to NONE for inode=%p after write\n",
			 inode);
		cinode->oplock = 0;
	}
out:
	cifs_put_writer(cinode);
	return written;
}

static struct cifs_readdata *cifs_readdata_alloc(work_func_t complete)
{
	struct cifs_readdata *rdata;

	rdata = kzalloc(sizeof(*rdata), GFP_KERNEL);
	if (rdata) {
		kref_init(&rdata->refcount);
		INIT_LIST_HEAD(&rdata->list);
		init_completion(&rdata->done);
		INIT_WORK(&rdata->work, complete);
	}

	return rdata;
}

void
cifs_readdata_release(struct kref *refcount)
{
	struct cifs_readdata *rdata = container_of(refcount,
					struct cifs_readdata, refcount);

	if (rdata->ctx)
		kref_put(&rdata->ctx->refcount, cifs_aio_ctx_release);
#ifdef CONFIG_CIFS_SMB_DIRECT
	if (rdata->mr) {
		smbd_deregister_mr(rdata->mr);
		rdata->mr = NULL;
	}
#endif
	if (rdata->cfile)
		cifsFileInfo_put(rdata->cfile);

	kfree(rdata);
}

static void collect_uncached_read_data(struct cifs_aio_ctx *ctx);

static void
cifs_uncached_readv_complete(struct work_struct *work)
{
	struct cifs_readdata *rdata = container_of(work,
						struct cifs_readdata, work);

	complete(&rdata->done);
	collect_uncached_read_data(rdata->ctx);
	/* the below call can possibly free the last ref to aio ctx */
	kref_put(&rdata->refcount, cifs_readdata_release);
}

static int cifs_resend_rdata(struct cifs_readdata *rdata,
			struct list_head *rdata_list,
			struct cifs_aio_ctx *ctx)
{
	unsigned int rsize;
	struct cifs_credits credits;
	int rc;
	struct TCP_Server_Info *server;

	/* XXX: should we pick a new channel here? */
	server = rdata->server;

	do {
		if (rdata->cfile->invalidHandle) {
			rc = cifs_reopen_file(rdata->cfile, true);
			if (rc == -EAGAIN)
				continue;
			else if (rc)
				break;
		}

		/*
		 * Wait for credits to resend this rdata.
		 * Note: we are attempting to resend the whole rdata not in
		 * segments
		 */
		do {
			rc = server->ops->wait_mtu_credits(server, rdata->bytes,
						&rsize, &credits);

			if (rc)
				goto fail;

			if (rsize < rdata->bytes) {
				add_credits_and_wake_if(server, &credits, 0);
				msleep(1000);
			}
		} while (rsize < rdata->bytes);
		rdata->credits = credits;

		rc = adjust_credits(server, &rdata->credits, rdata->bytes);
		if (!rc) {
			if (rdata->cfile->invalidHandle)
				rc = -EAGAIN;
			else {
#ifdef CONFIG_CIFS_SMB_DIRECT
				if (rdata->mr) {
					rdata->mr->need_invalidate = true;
					smbd_deregister_mr(rdata->mr);
					rdata->mr = NULL;
				}
#endif
				rc = server->ops->async_readv(rdata);
			}
		}

		/* If the read was successfully sent, we are done */
		if (!rc) {
			/* Add to aio pending list */
			list_add_tail(&rdata->list, rdata_list);
			return 0;
		}

		/* Roll back credits and retry if needed */
		add_credits_and_wake_if(server, &rdata->credits, 0);
	} while (rc == -EAGAIN);

fail:
	kref_put(&rdata->refcount, cifs_readdata_release);
	return rc;
}

static int
cifs_send_async_read(loff_t fpos, size_t len, struct cifsFileInfo *open_file,
		     struct cifs_sb_info *cifs_sb, struct list_head *rdata_list,
		     struct cifs_aio_ctx *ctx)
{
	struct cifs_readdata *rdata;
	unsigned int rsize, nsegs, max_segs = INT_MAX;
	struct cifs_credits credits_on_stack;
	struct cifs_credits *credits = &credits_on_stack;
	size_t cur_len, max_len;
	int rc;
	pid_t pid;
	struct TCP_Server_Info *server;

	server = cifs_pick_channel(tlink_tcon(open_file->tlink)->ses);

#ifdef CONFIG_CIFS_SMB_DIRECT
	if (server->smbd_conn)
		max_segs = server->smbd_conn->max_frmr_depth;
#endif

	if (cifs_sb->mnt_cifs_flags & CIFS_MOUNT_RWPIDFORWARD)
		pid = open_file->pid;
	else
		pid = current->tgid;

	do {
		if (open_file->invalidHandle) {
			rc = cifs_reopen_file(open_file, true);
			if (rc == -EAGAIN)
				continue;
			else if (rc)
				break;
		}

		if (cifs_sb->ctx->rsize == 0)
			cifs_sb->ctx->rsize =
				server->ops->negotiate_rsize(tlink_tcon(open_file->tlink),
							     cifs_sb->ctx);

		rc = server->ops->wait_mtu_credits(server, cifs_sb->ctx->rsize,
						   &rsize, credits);
		if (rc)
			break;

		max_len = min_t(size_t, len, rsize);

		cur_len = cifs_limit_bvec_subset(&ctx->iter, max_len,
						 max_segs, &nsegs);
		cifs_dbg(FYI, "read-to-iter len=%zx/%zx nsegs=%u/%lu/%u\n",
			 cur_len, max_len, nsegs, ctx->iter.nr_segs, max_segs);
		if (cur_len == 0) {
			rc = -EIO;
			add_credits_and_wake_if(server, credits, 0);
			break;
		}

		rdata = cifs_readdata_alloc(cifs_uncached_readv_complete);
		if (!rdata) {
			add_credits_and_wake_if(server, credits, 0);
			rc = -ENOMEM;
			break;
		}

		rdata->server	= server;
		rdata->cfile	= cifsFileInfo_get(open_file);
		rdata->offset	= fpos;
		rdata->bytes	= cur_len;
		rdata->pid	= pid;
		rdata->credits	= credits_on_stack;
		rdata->ctx	= ctx;
		kref_get(&ctx->refcount);

		rdata->iter	= ctx->iter;
		iov_iter_truncate(&rdata->iter, cur_len);

		rc = adjust_credits(server, &rdata->credits, rdata->bytes);

		if (!rc) {
			if (rdata->cfile->invalidHandle)
				rc = -EAGAIN;
			else
				rc = server->ops->async_readv(rdata);
		}

		if (rc) {
			add_credits_and_wake_if(server, &rdata->credits, 0);
			kref_put(&rdata->refcount, cifs_readdata_release);
			if (rc == -EAGAIN)
				continue;
			break;
		}

		list_add_tail(&rdata->list, rdata_list);
		iov_iter_advance(&ctx->iter, cur_len);
		fpos += cur_len;
		len -= cur_len;
	} while (len > 0);

	return rc;
}

static void
collect_uncached_read_data(struct cifs_aio_ctx *ctx)
{
	struct cifs_readdata *rdata, *tmp;
	struct cifs_sb_info *cifs_sb;
	int rc;

	cifs_sb = CIFS_SB(ctx->cfile->dentry->d_sb);

	mutex_lock(&ctx->aio_mutex);

	if (list_empty(&ctx->list)) {
		mutex_unlock(&ctx->aio_mutex);
		return;
	}

	rc = ctx->rc;
	/* the loop below should proceed in the order of increasing offsets */
again:
	list_for_each_entry_safe(rdata, tmp, &ctx->list, list) {
		if (!rc) {
			if (!try_wait_for_completion(&rdata->done)) {
				mutex_unlock(&ctx->aio_mutex);
				return;
			}

			if (rdata->result == -EAGAIN) {
				/* resend call if it's a retryable error */
				struct list_head tmp_list;
				unsigned int got_bytes = rdata->got_bytes;

				list_del_init(&rdata->list);
				INIT_LIST_HEAD(&tmp_list);

				if (ctx->direct_io) {
					/*
					 * Re-use rdata as this is a
					 * direct I/O
					 */
					rc = cifs_resend_rdata(
						rdata,
						&tmp_list, ctx);
				} else {
					rc = cifs_send_async_read(
						rdata->offset + got_bytes,
						rdata->bytes - got_bytes,
						rdata->cfile, cifs_sb,
						&tmp_list, ctx);

					kref_put(&rdata->refcount,
						cifs_readdata_release);
				}

				list_splice(&tmp_list, &ctx->list);

				goto again;
			} else if (rdata->result)
				rc = rdata->result;

			/* if there was a short read -- discard anything left */
			if (rdata->got_bytes && rdata->got_bytes < rdata->bytes)
				rc = -ENODATA;

			ctx->total_len += rdata->got_bytes;
		}
		list_del_init(&rdata->list);
		kref_put(&rdata->refcount, cifs_readdata_release);
	}

	/* mask nodata case */
	if (rc == -ENODATA)
		rc = 0;

	ctx->rc = (rc == 0) ? (ssize_t)ctx->total_len : rc;

	mutex_unlock(&ctx->aio_mutex);

	if (ctx->iocb && ctx->iocb->ki_complete)
		ctx->iocb->ki_complete(ctx->iocb, ctx->rc);
	else
		complete(&ctx->done);
}

static ssize_t __cifs_readv(
	struct kiocb *iocb, struct iov_iter *to, bool direct)
{
	size_t len;
	struct file *file = iocb->ki_filp;
	struct cifs_sb_info *cifs_sb;
	struct cifsFileInfo *cfile;
	struct cifs_tcon *tcon;
	ssize_t rc, total_read = 0;
	loff_t offset = iocb->ki_pos;
	struct cifs_aio_ctx *ctx;

	len = iov_iter_count(to);
	if (!len)
		return 0;

	cifs_sb = CIFS_FILE_SB(file);
	cfile = file->private_data;
	tcon = tlink_tcon(cfile->tlink);

	if (!tcon->ses->server->ops->async_readv)
		return -ENOSYS;

	if ((file->f_flags & O_ACCMODE) == O_WRONLY)
		cifs_dbg(FYI, "attempting read on write only file instance\n");

	ctx = cifs_aio_ctx_alloc();
	if (!ctx)
		return -ENOMEM;

	ctx->pos	= offset;
	ctx->direct_io	= direct;
	ctx->len	= len;
	ctx->cfile	= cifsFileInfo_get(cfile);
	ctx->nr_pinned_pages = 0;

	if (!is_sync_kiocb(iocb))
		ctx->iocb = iocb;

	if (user_backed_iter(to)) {
		/*
		 * Extract IOVEC/UBUF-type iterators to a BVEC-type iterator as
		 * they contain references to the calling process's virtual
		 * memory layout which won't be available in an async worker
		 * thread.  This also takes a pin on every folio involved.
		 */
		rc = netfs_extract_user_iter(to, iov_iter_count(to),
					     &ctx->iter, 0);
		if (rc < 0) {
			kref_put(&ctx->refcount, cifs_aio_ctx_release);
			return rc;
		}

		ctx->nr_pinned_pages = rc;
		ctx->bv = (void *)ctx->iter.bvec;
		ctx->bv_need_unpin = iov_iter_extract_will_pin(to);
		ctx->should_dirty = true;
	} else if ((iov_iter_is_bvec(to) || iov_iter_is_kvec(to)) &&
		   !is_sync_kiocb(iocb)) {
		/*
		 * If the op is asynchronous, we need to copy the list attached
		 * to a BVEC/KVEC-type iterator, but we assume that the storage
		 * will be retained by the caller; in any case, we may or may
		 * not be able to pin the pages, so we don't try.
		 */
		ctx->bv = (void *)dup_iter(&ctx->iter, to, GFP_KERNEL);
		if (!ctx->bv) {
			kref_put(&ctx->refcount, cifs_aio_ctx_release);
			return -ENOMEM;
		}
	} else {
		/*
		 * Otherwise, we just pass the iterator down as-is and rely on
		 * the caller to make sure the pages referred to by the
		 * iterator don't evaporate.
		 */
		ctx->iter = *to;
	}

	if (direct) {
		rc = filemap_write_and_wait_range(file->f_inode->i_mapping,
						  offset, offset + len - 1);
		if (rc) {
			kref_put(&ctx->refcount, cifs_aio_ctx_release);
			return -EAGAIN;
		}
	}

	/* grab a lock here due to read response handlers can access ctx */
	mutex_lock(&ctx->aio_mutex);

	rc = cifs_send_async_read(offset, len, cfile, cifs_sb, &ctx->list, ctx);

	/* if at least one read request send succeeded, then reset rc */
	if (!list_empty(&ctx->list))
		rc = 0;

	mutex_unlock(&ctx->aio_mutex);

	if (rc) {
		kref_put(&ctx->refcount, cifs_aio_ctx_release);
		return rc;
	}

	if (!is_sync_kiocb(iocb)) {
		kref_put(&ctx->refcount, cifs_aio_ctx_release);
		return -EIOCBQUEUED;
	}

	rc = wait_for_completion_killable(&ctx->done);
	if (rc) {
		mutex_lock(&ctx->aio_mutex);
		ctx->rc = rc = -EINTR;
		total_read = ctx->total_len;
		mutex_unlock(&ctx->aio_mutex);
	} else {
		rc = ctx->rc;
		total_read = ctx->total_len;
	}

	kref_put(&ctx->refcount, cifs_aio_ctx_release);

	if (total_read) {
		iocb->ki_pos += total_read;
		return total_read;
	}
	return rc;
}

ssize_t cifs_direct_readv(struct kiocb *iocb, struct iov_iter *to)
{
	return __cifs_readv(iocb, to, true);
}

ssize_t cifs_user_readv(struct kiocb *iocb, struct iov_iter *to)
{
	return __cifs_readv(iocb, to, false);
}

ssize_t
cifs_strict_readv(struct kiocb *iocb, struct iov_iter *to)
{
	struct inode *inode = file_inode(iocb->ki_filp);
	struct cifsInodeInfo *cinode = CIFS_I(inode);
	struct cifs_sb_info *cifs_sb = CIFS_SB(inode->i_sb);
	struct cifsFileInfo *cfile = (struct cifsFileInfo *)
						iocb->ki_filp->private_data;
	struct cifs_tcon *tcon = tlink_tcon(cfile->tlink);
	int rc = -EACCES;

	/*
	 * In strict cache mode we need to read from the server all the time
	 * if we don't have level II oplock because the server can delay mtime
	 * change - so we can't make a decision about inode invalidating.
	 * And we can also fail with pagereading if there are mandatory locks
	 * on pages affected by this read but not on the region from pos to
	 * pos+len-1.
	 */
	if (!CIFS_CACHE_READ(cinode))
		return cifs_user_readv(iocb, to);

	if (cap_unix(tcon->ses) &&
	    (CIFS_UNIX_FCNTL_CAP & le64_to_cpu(tcon->fsUnixInfo.Capability)) &&
	    ((cifs_sb->mnt_cifs_flags & CIFS_MOUNT_NOPOSIXBRL) == 0))
		return generic_file_read_iter(iocb, to);

	/*
	 * We need to hold the sem to be sure nobody modifies lock list
	 * with a brlock that prevents reading.
	 */
	down_read(&cinode->lock_sem);
	if (!cifs_find_lock_conflict(cfile, iocb->ki_pos, iov_iter_count(to),
				     tcon->ses->server->vals->shared_lock_type,
				     0, NULL, CIFS_READ_OP))
		rc = generic_file_read_iter(iocb, to);
	up_read(&cinode->lock_sem);
	return rc;
}

static ssize_t
cifs_read(struct file *file, char *read_data, size_t read_size, loff_t *offset)
{
	int rc = -EACCES;
	unsigned int bytes_read = 0;
	unsigned int total_read;
	unsigned int current_read_size;
	unsigned int rsize;
	struct cifs_sb_info *cifs_sb;
	struct cifs_tcon *tcon;
	struct TCP_Server_Info *server;
	unsigned int xid;
	char *cur_offset;
	struct cifsFileInfo *open_file;
	struct cifs_io_parms io_parms = {0};
	int buf_type = CIFS_NO_BUFFER;
	__u32 pid;

	xid = get_xid();
	cifs_sb = CIFS_FILE_SB(file);

	/* FIXME: set up handlers for larger reads and/or convert to async */
	rsize = min_t(unsigned int, cifs_sb->ctx->rsize, CIFSMaxBufSize);

	if (file->private_data == NULL) {
		rc = -EBADF;
		free_xid(xid);
		return rc;
	}
	open_file = file->private_data;
	tcon = tlink_tcon(open_file->tlink);
	server = cifs_pick_channel(tcon->ses);

	if (!server->ops->sync_read) {
		free_xid(xid);
		return -ENOSYS;
	}

	if (cifs_sb->mnt_cifs_flags & CIFS_MOUNT_RWPIDFORWARD)
		pid = open_file->pid;
	else
		pid = current->tgid;

	if ((file->f_flags & O_ACCMODE) == O_WRONLY)
		cifs_dbg(FYI, "attempting read on write only file instance\n");

	for (total_read = 0, cur_offset = read_data; read_size > total_read;
	     total_read += bytes_read, cur_offset += bytes_read) {
		do {
			current_read_size = min_t(uint, read_size - total_read,
						  rsize);
			/*
			 * For windows me and 9x we do not want to request more
			 * than it negotiated since it will refuse the read
			 * then.
			 */
			if (!(tcon->ses->capabilities &
				tcon->ses->server->vals->cap_large_files)) {
				current_read_size = min_t(uint,
					current_read_size, CIFSMaxBufSize);
			}
			if (open_file->invalidHandle) {
				rc = cifs_reopen_file(open_file, true);
				if (rc != 0)
					break;
			}
			io_parms.pid = pid;
			io_parms.tcon = tcon;
			io_parms.offset = *offset;
			io_parms.length = current_read_size;
			io_parms.server = server;
			rc = server->ops->sync_read(xid, &open_file->fid, &io_parms,
						    &bytes_read, &cur_offset,
						    &buf_type);
		} while (rc == -EAGAIN);

		if (rc || (bytes_read == 0)) {
			if (total_read) {
				break;
			} else {
				free_xid(xid);
				return rc;
			}
		} else {
			cifs_stats_bytes_read(tcon, total_read);
			*offset += bytes_read;
		}
	}
	free_xid(xid);
	return total_read;
}

/*
 * If the page is mmap'ed into a process' page tables, then we need to make
 * sure that it doesn't change while being written back.
 */
static vm_fault_t cifs_page_mkwrite(struct vm_fault *vmf)
{
	struct folio *folio = page_folio(vmf->page);

	/* Wait for the folio to be written to the cache before we allow it to
	 * be modified.  We then assume the entire folio will need writing back.
	 */
#ifdef CONFIG_CIFS_FSCACHE
	if (folio_test_fscache(folio) &&
	    folio_wait_fscache_killable(folio) < 0)
		return VM_FAULT_RETRY;
#endif

	folio_wait_writeback(folio);

	if (folio_lock_killable(folio) < 0)
		return VM_FAULT_RETRY;
	return VM_FAULT_LOCKED;
}

static const struct vm_operations_struct cifs_file_vm_ops = {
	.fault = filemap_fault,
	.map_pages = filemap_map_pages,
	.page_mkwrite = cifs_page_mkwrite,
};

int cifs_file_strict_mmap(struct file *file, struct vm_area_struct *vma)
{
	int xid, rc = 0;
	struct inode *inode = file_inode(file);

	xid = get_xid();

	if (!CIFS_CACHE_READ(CIFS_I(inode)))
		rc = cifs_zap_mapping(inode);
	if (!rc)
		rc = generic_file_mmap(file, vma);
	if (!rc)
		vma->vm_ops = &cifs_file_vm_ops;

	free_xid(xid);
	return rc;
}

int cifs_file_mmap(struct file *file, struct vm_area_struct *vma)
{
	int rc, xid;

	xid = get_xid();

	rc = cifs_revalidate_file(file);
	if (rc)
		cifs_dbg(FYI, "Validation prior to mmap failed, error=%d\n",
			 rc);
	if (!rc)
		rc = generic_file_mmap(file, vma);
	if (!rc)
		vma->vm_ops = &cifs_file_vm_ops;

	free_xid(xid);
	return rc;
}

/*
 * Unlock a bunch of folios in the pagecache.
 */
static void cifs_unlock_folios(struct address_space *mapping, pgoff_t first, pgoff_t last)
{
	struct folio *folio;
	XA_STATE(xas, &mapping->i_pages, first);

	rcu_read_lock();
	xas_for_each(&xas, folio, last) {
		folio_unlock(folio);
	}
	rcu_read_unlock();
}

static void cifs_readahead_complete(struct work_struct *work)
{
	struct cifs_readdata *rdata = container_of(work,
						   struct cifs_readdata, work);
	struct folio *folio;
	pgoff_t last;
	bool good = rdata->result == 0 || (rdata->result == -EAGAIN && rdata->got_bytes);

	XA_STATE(xas, &rdata->mapping->i_pages, rdata->offset / PAGE_SIZE);

	if (good)
		cifs_readahead_to_fscache(rdata->mapping->host,
					  rdata->offset, rdata->bytes);

	if (iov_iter_count(&rdata->iter) > 0)
		iov_iter_zero(iov_iter_count(&rdata->iter), &rdata->iter);

	last = (rdata->offset + rdata->bytes - 1) / PAGE_SIZE;

	rcu_read_lock();
	xas_for_each(&xas, folio, last) {
		if (good) {
			flush_dcache_folio(folio);
			folio_mark_uptodate(folio);
		}
		folio_unlock(folio);
	}
	rcu_read_unlock();

	kref_put(&rdata->refcount, cifs_readdata_release);
}

static void cifs_readahead(struct readahead_control *ractl)
{
	struct cifsFileInfo *open_file = ractl->file->private_data;
	struct cifs_sb_info *cifs_sb = CIFS_FILE_SB(ractl->file);
	struct TCP_Server_Info *server;
	unsigned int xid, nr_pages, cache_nr_pages = 0;
	unsigned int ra_pages;
	pgoff_t next_cached = ULONG_MAX, ra_index;
	bool caching = fscache_cookie_enabled(cifs_inode_cookie(ractl->mapping->host)) &&
		cifs_inode_cookie(ractl->mapping->host)->cache_priv;
	bool check_cache = caching;
	pid_t pid;
	int rc = 0;

	/* Note that readahead_count() lags behind our dequeuing of pages from
	 * the ractl, wo we have to keep track for ourselves.
	 */
	ra_pages = readahead_count(ractl);
	ra_index = readahead_index(ractl);

	xid = get_xid();

	if (cifs_sb->mnt_cifs_flags & CIFS_MOUNT_RWPIDFORWARD)
		pid = open_file->pid;
	else
		pid = current->tgid;

	server = cifs_pick_channel(tlink_tcon(open_file->tlink)->ses);

	cifs_dbg(FYI, "%s: file=%p mapping=%p num_pages=%u\n",
		 __func__, ractl->file, ractl->mapping, ra_pages);

	/*
	 * Chop the readahead request up into rsize-sized read requests.
	 */
	while ((nr_pages = ra_pages)) {
		unsigned int i, rsize;
		struct cifs_readdata *rdata;
		struct cifs_credits credits_on_stack;
		struct cifs_credits *credits = &credits_on_stack;
		struct folio *folio;
		pgoff_t fsize;

		/*
		 * Find out if we have anything cached in the range of
		 * interest, and if so, where the next chunk of cached data is.
		 */
		if (caching) {
			if (check_cache) {
				rc = cifs_fscache_query_occupancy(
					ractl->mapping->host, ra_index, nr_pages,
					&next_cached, &cache_nr_pages);
				if (rc < 0)
					caching = false;
				check_cache = false;
			}

			if (ra_index == next_cached) {
				/*
				 * TODO: Send a whole batch of pages to be read
				 * by the cache.
				 */
				folio = readahead_folio(ractl);
				fsize = folio_nr_pages(folio);
				ra_pages -= fsize;
				ra_index += fsize;
				if (cifs_readpage_from_fscache(ractl->mapping->host,
							       &folio->page) < 0) {
					/*
					 * TODO: Deal with cache read failure
					 * here, but for the moment, delegate
					 * that to readpage.
					 */
					caching = false;
				}
				folio_unlock(folio);
				next_cached += fsize;
				cache_nr_pages -= fsize;
				if (cache_nr_pages == 0)
					check_cache = true;
				continue;
			}
		}

		if (open_file->invalidHandle) {
			rc = cifs_reopen_file(open_file, true);
			if (rc) {
				if (rc == -EAGAIN)
					continue;
				break;
			}
		}

		if (cifs_sb->ctx->rsize == 0)
			cifs_sb->ctx->rsize =
				server->ops->negotiate_rsize(tlink_tcon(open_file->tlink),
							     cifs_sb->ctx);

		rc = server->ops->wait_mtu_credits(server, cifs_sb->ctx->rsize,
						   &rsize, credits);
		if (rc)
			break;
		nr_pages = min_t(size_t, rsize / PAGE_SIZE, ra_pages);
		if (next_cached != ULONG_MAX)
			nr_pages = min_t(size_t, nr_pages, next_cached - ra_index);

		/*
		 * Give up immediately if rsize is too small to read an entire
		 * page. The VFS will fall back to readpage. We should never
		 * reach this point however since we set ra_pages to 0 when the
		 * rsize is smaller than a cache page.
		 */
		if (unlikely(!nr_pages)) {
			add_credits_and_wake_if(server, credits, 0);
			break;
		}

		rdata = cifs_readdata_alloc(cifs_readahead_complete);
		if (!rdata) {
			/* best to give up if we're out of mem */
			add_credits_and_wake_if(server, credits, 0);
			break;
		}

		rdata->offset	= ra_index * PAGE_SIZE;
		rdata->bytes	= nr_pages * PAGE_SIZE;
		rdata->cfile	= cifsFileInfo_get(open_file);
		rdata->server	= server;
		rdata->mapping	= ractl->mapping;
		rdata->pid	= pid;
		rdata->credits	= credits_on_stack;

		for (i = 0; i < nr_pages; i++) {
			if (!readahead_folio(ractl))
				WARN_ON(1);
		}
		ra_pages -= nr_pages;
		ra_index += nr_pages;

		iov_iter_xarray(&rdata->iter, ITER_DEST, &rdata->mapping->i_pages,
				rdata->offset, rdata->bytes);

		rc = adjust_credits(server, &rdata->credits, rdata->bytes);
		if (!rc) {
			if (rdata->cfile->invalidHandle)
				rc = -EAGAIN;
			else
				rc = server->ops->async_readv(rdata);
		}

		if (rc) {
			add_credits_and_wake_if(server, &rdata->credits, 0);
			cifs_unlock_folios(rdata->mapping,
					   rdata->offset / PAGE_SIZE,
					   (rdata->offset + rdata->bytes - 1) / PAGE_SIZE);
			/* Fallback to the readpage in error/reconnect cases */
			kref_put(&rdata->refcount, cifs_readdata_release);
			break;
		}

		kref_put(&rdata->refcount, cifs_readdata_release);
	}

	free_xid(xid);
}

/*
 * cifs_readpage_worker must be called with the page pinned
 */
static int cifs_readpage_worker(struct file *file, struct page *page,
	loff_t *poffset)
{
	struct inode *inode = file_inode(file);
	struct timespec64 atime, mtime;
	char *read_data;
	int rc;

	/* Is the page cached? */
	rc = cifs_readpage_from_fscache(inode, page);
	if (rc == 0)
		goto read_complete;

	read_data = kmap(page);
	/* for reads over a certain size could initiate async read ahead */

	rc = cifs_read(file, read_data, PAGE_SIZE, poffset);

	if (rc < 0)
		goto io_error;
	else
		cifs_dbg(FYI, "Bytes read %d\n", rc);

	/* we do not want atime to be less than mtime, it broke some apps */
	atime = inode_set_atime_to_ts(inode, current_time(inode));
	mtime = inode_get_mtime(inode);
	if (timespec64_compare(&atime, &mtime) < 0)
		inode_set_atime_to_ts(inode, inode_get_mtime(inode));

	if (PAGE_SIZE > rc)
		memset(read_data + rc, 0, PAGE_SIZE - rc);

	flush_dcache_page(page);
	SetPageUptodate(page);
	rc = 0;

io_error:
	kunmap(page);

read_complete:
	unlock_page(page);
	return rc;
}

static int cifs_read_folio(struct file *file, struct folio *folio)
{
	struct page *page = &folio->page;
	loff_t offset = page_file_offset(page);
	int rc = -EACCES;
	unsigned int xid;

	xid = get_xid();

	if (file->private_data == NULL) {
		rc = -EBADF;
		free_xid(xid);
		return rc;
	}

	cifs_dbg(FYI, "read_folio %p at offset %d 0x%x\n",
		 page, (int)offset, (int)offset);

	rc = cifs_readpage_worker(file, page, &offset);

	free_xid(xid);
	return rc;
}

static int is_inode_writable(struct cifsInodeInfo *cifs_inode)
{
	struct cifsFileInfo *open_file;

	spin_lock(&cifs_inode->open_file_lock);
	list_for_each_entry(open_file, &cifs_inode->openFileList, flist) {
		if (OPEN_FMODE(open_file->f_flags) & FMODE_WRITE) {
			spin_unlock(&cifs_inode->open_file_lock);
			return 1;
		}
	}
	spin_unlock(&cifs_inode->open_file_lock);
	return 0;
}

/* We do not want to update the file size from server for inodes
   open for write - to avoid races with writepage extending
   the file - in the future we could consider allowing
   refreshing the inode only on increases in the file size
   but this is tricky to do without racing with writebehind
   page caching in the current Linux kernel design */
bool is_size_safe_to_change(struct cifsInodeInfo *cifsInode, __u64 end_of_file,
			    bool from_readdir)
{
	if (!cifsInode)
		return true;

	if (is_inode_writable(cifsInode) ||
		((cifsInode->oplock & CIFS_CACHE_RW_FLG) != 0 && from_readdir)) {
		/* This inode is open for write at least once */
		struct cifs_sb_info *cifs_sb;

		cifs_sb = CIFS_SB(cifsInode->netfs.inode.i_sb);
		if (cifs_sb->mnt_cifs_flags & CIFS_MOUNT_DIRECT_IO) {
			/* since no page cache to corrupt on directio
			we can change size safely */
			return true;
		}

		if (i_size_read(&cifsInode->netfs.inode) < end_of_file)
			return true;

		return false;
	} else
		return true;
}

static int cifs_write_begin(struct file *file, struct address_space *mapping,
			loff_t pos, unsigned len,
			struct page **pagep, void **fsdata)
{
	int oncethru = 0;
	pgoff_t index = pos >> PAGE_SHIFT;
	loff_t offset = pos & (PAGE_SIZE - 1);
	loff_t page_start = pos & PAGE_MASK;
	loff_t i_size;
	struct page *page;
	int rc = 0;

	cifs_dbg(FYI, "write_begin from %lld len %d\n", (long long)pos, len);

start:
	page = grab_cache_page_write_begin(mapping, index);
	if (!page) {
		rc = -ENOMEM;
		goto out;
	}

	if (PageUptodate(page))
		goto out;

	/*
	 * If we write a full page it will be up to date, no need to read from
	 * the server. If the write is short, we'll end up doing a sync write
	 * instead.
	 */
	if (len == PAGE_SIZE)
		goto out;

	/*
	 * optimize away the read when we have an oplock, and we're not
	 * expecting to use any of the data we'd be reading in. That
	 * is, when the page lies beyond the EOF, or straddles the EOF
	 * and the write will cover all of the existing data.
	 */
	if (CIFS_CACHE_READ(CIFS_I(mapping->host))) {
		i_size = i_size_read(mapping->host);
		if (page_start >= i_size ||
		    (offset == 0 && (pos + len) >= i_size)) {
			zero_user_segments(page, 0, offset,
					   offset + len,
					   PAGE_SIZE);
			/*
			 * PageChecked means that the parts of the page
			 * to which we're not writing are considered up
			 * to date. Once the data is copied to the
			 * page, it can be set uptodate.
			 */
			SetPageChecked(page);
			goto out;
		}
	}

	if ((file->f_flags & O_ACCMODE) != O_WRONLY && !oncethru) {
		/*
		 * might as well read a page, it is fast enough. If we get
		 * an error, we don't need to return it. cifs_write_end will
		 * do a sync write instead since PG_uptodate isn't set.
		 */
		cifs_readpage_worker(file, page, &page_start);
		put_page(page);
		oncethru = 1;
		goto start;
	} else {
		/* we could try using another file handle if there is one -
		   but how would we lock it to prevent close of that handle
		   racing with this read? In any case
		   this will be written out by write_end so is fine */
	}
out:
	*pagep = page;
	return rc;
}

static bool cifs_release_folio(struct folio *folio, gfp_t gfp)
{
	if (folio_test_private(folio))
		return 0;
	if (folio_test_fscache(folio)) {
		if (current_is_kswapd() || !(gfp & __GFP_FS))
			return false;
		folio_wait_fscache(folio);
	}
	fscache_note_page_release(cifs_inode_cookie(folio->mapping->host));
	return true;
}

static void cifs_invalidate_folio(struct folio *folio, size_t offset,
				 size_t length)
{
	folio_wait_fscache(folio);
}

static int cifs_launder_folio(struct folio *folio)
{
	int rc = 0;
	loff_t range_start = folio_pos(folio);
	loff_t range_end = range_start + folio_size(folio);
	struct writeback_control wbc = {
		.sync_mode = WB_SYNC_ALL,
		.nr_to_write = 0,
		.range_start = range_start,
		.range_end = range_end,
	};

	cifs_dbg(FYI, "Launder page: %lu\n", folio->index);

	if (folio_clear_dirty_for_io(folio))
		rc = cifs_writepage_locked(&folio->page, &wbc);

	folio_wait_fscache(folio);
	return rc;
}

void cifs_oplock_break(struct work_struct *work)
{
	struct cifsFileInfo *cfile = container_of(work, struct cifsFileInfo,
						  oplock_break);
	struct inode *inode = d_inode(cfile->dentry);
	struct super_block *sb = inode->i_sb;
	struct cifs_sb_info *cifs_sb = CIFS_SB(sb);
	struct cifsInodeInfo *cinode = CIFS_I(inode);
	struct cifs_tcon *tcon;
	struct TCP_Server_Info *server;
	struct tcon_link *tlink;
	int rc = 0;
	bool purge_cache = false, oplock_break_cancelled;
	__u64 persistent_fid, volatile_fid;
	__u16 net_fid;

	/*
	 * Hold a reference to the superblock to prevent it and its inodes from
	 * being freed while we are accessing cinode. Otherwise, _cifsFileInfo_put()
	 * may release the last reference to the sb and trigger inode eviction.
	 */
	cifs_sb_active(sb);
	wait_on_bit(&cinode->flags, CIFS_INODE_PENDING_WRITERS,
			TASK_UNINTERRUPTIBLE);

	tlink = cifs_sb_tlink(cifs_sb);
	if (IS_ERR(tlink))
		goto out;
	tcon = tlink_tcon(tlink);
	server = tcon->ses->server;

	server->ops->downgrade_oplock(server, cinode, cfile->oplock_level,
				      cfile->oplock_epoch, &purge_cache);

	if (!CIFS_CACHE_WRITE(cinode) && CIFS_CACHE_READ(cinode) &&
						cifs_has_mand_locks(cinode)) {
		cifs_dbg(FYI, "Reset oplock to None for inode=%p due to mand locks\n",
			 inode);
		cinode->oplock = 0;
	}

	if (inode && S_ISREG(inode->i_mode)) {
		if (CIFS_CACHE_READ(cinode))
			break_lease(inode, O_RDONLY);
		else
			break_lease(inode, O_WRONLY);
		rc = filemap_fdatawrite(inode->i_mapping);
		if (!CIFS_CACHE_READ(cinode) || purge_cache) {
			rc = filemap_fdatawait(inode->i_mapping);
			mapping_set_error(inode->i_mapping, rc);
			cifs_zap_mapping(inode);
		}
		cifs_dbg(FYI, "Oplock flush inode %p rc %d\n", inode, rc);
		if (CIFS_CACHE_WRITE(cinode))
			goto oplock_break_ack;
	}

	rc = cifs_push_locks(cfile);
	if (rc)
		cifs_dbg(VFS, "Push locks rc = %d\n", rc);

oplock_break_ack:
	/*
	 * When oplock break is received and there are no active
	 * file handles but cached, then schedule deferred close immediately.
	 * So, new open will not use cached handle.
	 */

	if (!CIFS_CACHE_HANDLE(cinode) && !list_empty(&cinode->deferred_closes))
		cifs_close_deferred_file(cinode);

	persistent_fid = cfile->fid.persistent_fid;
	volatile_fid = cfile->fid.volatile_fid;
	net_fid = cfile->fid.netfid;
	oplock_break_cancelled = cfile->oplock_break_cancelled;

	_cifsFileInfo_put(cfile, false /* do not wait for ourself */, false);
	/*
	 * MS-SMB2 3.2.5.19.1 and 3.2.5.19.2 (and MS-CIFS 3.2.5.42) do not require
	 * an acknowledgment to be sent when the file has already been closed.
	 */
	spin_lock(&cinode->open_file_lock);
	/* check list empty since can race with kill_sb calling tree disconnect */
	if (!oplock_break_cancelled && !list_empty(&cinode->openFileList)) {
		spin_unlock(&cinode->open_file_lock);
		rc = server->ops->oplock_response(tcon, persistent_fid,
						  volatile_fid, net_fid, cinode);
		cifs_dbg(FYI, "Oplock release rc = %d\n", rc);
	} else
		spin_unlock(&cinode->open_file_lock);

	cifs_put_tlink(tlink);
out:
	cifs_done_oplock_break(cinode);
	cifs_sb_deactive(sb);
}

/*
 * The presence of cifs_direct_io() in the address space ops vector
 * allowes open() O_DIRECT flags which would have failed otherwise.
 *
 * In the non-cached mode (mount with cache=none), we shunt off direct read and write requests
 * so this method should never be called.
 *
 * Direct IO is not yet supported in the cached mode.
 */
static ssize_t
cifs_direct_io(struct kiocb *iocb, struct iov_iter *iter)
{
        /*
         * FIXME
         * Eventually need to support direct IO for non forcedirectio mounts
         */
        return -EINVAL;
}

static int cifs_swap_activate(struct swap_info_struct *sis,
			      struct file *swap_file, sector_t *span)
{
	struct cifsFileInfo *cfile = swap_file->private_data;
	struct inode *inode = swap_file->f_mapping->host;
	unsigned long blocks;
	long long isize;

	cifs_dbg(FYI, "swap activate\n");

	if (!swap_file->f_mapping->a_ops->swap_rw)
		/* Cannot support swap */
		return -EINVAL;

	spin_lock(&inode->i_lock);
	blocks = inode->i_blocks;
	isize = inode->i_size;
	spin_unlock(&inode->i_lock);
	if (blocks*512 < isize) {
		pr_warn("swap activate: swapfile has holes\n");
		return -EINVAL;
	}
	*span = sis->pages;

	pr_warn_once("Swap support over SMB3 is experimental\n");

	/*
	 * TODO: consider adding ACL (or documenting how) to prevent other
	 * users (on this or other systems) from reading it
	 */


	/* TODO: add sk_set_memalloc(inet) or similar */

	if (cfile)
		cfile->swapfile = true;
	/*
	 * TODO: Since file already open, we can't open with DENY_ALL here
	 * but we could add call to grab a byte range lock to prevent others
	 * from reading or writing the file
	 */

	sis->flags |= SWP_FS_OPS;
	return add_swap_extent(sis, 0, sis->max, 0);
}

static void cifs_swap_deactivate(struct file *file)
{
	struct cifsFileInfo *cfile = file->private_data;

	cifs_dbg(FYI, "swap deactivate\n");

	/* TODO: undo sk_set_memalloc(inet) will eventually be needed */

	if (cfile)
		cfile->swapfile = false;

	/* do we need to unpin (or unlock) the file */
}

/*
 * Mark a page as having been made dirty and thus needing writeback.  We also
 * need to pin the cache object to write back to.
 */
#ifdef CONFIG_CIFS_FSCACHE
static bool cifs_dirty_folio(struct address_space *mapping, struct folio *folio)
{
	return fscache_dirty_folio(mapping, folio,
					cifs_inode_cookie(mapping->host));
}
#else
#define cifs_dirty_folio filemap_dirty_folio
#endif

const struct address_space_operations cifs_addr_ops = {
	.read_folio = cifs_read_folio,
	.readahead = cifs_readahead,
	.writepages = cifs_writepages,
	.write_begin = cifs_write_begin,
	.write_end = cifs_write_end,
	.dirty_folio = cifs_dirty_folio,
	.release_folio = cifs_release_folio,
	.direct_IO = cifs_direct_io,
	.invalidate_folio = cifs_invalidate_folio,
	.launder_folio = cifs_launder_folio,
	.migrate_folio = filemap_migrate_folio,
	/*
	 * TODO: investigate and if useful we could add an is_dirty_writeback
	 * helper if needed
	 */
	.swap_activate = cifs_swap_activate,
	.swap_deactivate = cifs_swap_deactivate,
};

/*
 * cifs_readahead requires the server to support a buffer large enough to
 * contain the header plus one complete page of data.  Otherwise, we need
 * to leave cifs_readahead out of the address space operations.
 */
const struct address_space_operations cifs_addr_ops_smallbuf = {
	.read_folio = cifs_read_folio,
	.writepages = cifs_writepages,
	.write_begin = cifs_write_begin,
	.write_end = cifs_write_end,
	.dirty_folio = cifs_dirty_folio,
	.release_folio = cifs_release_folio,
	.invalidate_folio = cifs_invalidate_folio,
	.launder_folio = cifs_launder_folio,
	.migrate_folio = filemap_migrate_folio,
};
