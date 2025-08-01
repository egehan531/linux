// SPDX-License-Identifier: GPL-2.0+
/* Copyright (C) 2014-2018 Broadcom */

#include <linux/device.h>
#include <linux/dma-mapping.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/reset.h>
#include <linux/sched/signal.h>
#include <linux/uaccess.h>

#include <drm/drm_managed.h>
#include <drm/drm_syncobj.h>
#include <uapi/drm/v3d_drm.h>

#include "v3d_drv.h"
#include "v3d_regs.h"
#include "v3d_trace.h"

static void
v3d_init_core(struct v3d_dev *v3d, int core)
{
	/* Set OVRTMUOUT, which means that the texture sampler uniform
	 * configuration's tmu output type field is used, instead of
	 * using the hardware default behavior based on the texture
	 * type.  If you want the default behavior, you can still put
	 * "2" in the indirect texture state's output_type field.
	 */
	if (v3d->ver < 40)
		V3D_CORE_WRITE(core, V3D_CTL_MISCCFG, V3D_MISCCFG_OVRTMUOUT);

	/* Whenever we flush the L2T cache, we always want to flush
	 * the whole thing.
	 */
	V3D_CORE_WRITE(core, V3D_CTL_L2TFLSTA, 0);
	V3D_CORE_WRITE(core, V3D_CTL_L2TFLEND, ~0);
}

/* Sets invariant state for the HW. */
static void
v3d_init_hw_state(struct v3d_dev *v3d)
{
	v3d_init_core(v3d, 0);
}

static void
v3d_idle_axi(struct v3d_dev *v3d, int core)
{
	V3D_CORE_WRITE(core, V3D_GMP_CFG, V3D_GMP_CFG_STOP_REQ);

	if (wait_for((V3D_CORE_READ(core, V3D_GMP_STATUS) &
		      (V3D_GMP_STATUS_RD_COUNT_MASK |
		       V3D_GMP_STATUS_WR_COUNT_MASK |
		       V3D_GMP_STATUS_CFG_BUSY)) == 0, 100)) {
		DRM_ERROR("Failed to wait for safe GMP shutdown\n");
	}
}

static void
v3d_idle_gca(struct v3d_dev *v3d)
{
	if (v3d->ver >= 41)
		return;

	V3D_GCA_WRITE(V3D_GCA_SAFE_SHUTDOWN, V3D_GCA_SAFE_SHUTDOWN_EN);

	if (wait_for((V3D_GCA_READ(V3D_GCA_SAFE_SHUTDOWN_ACK) &
		      V3D_GCA_SAFE_SHUTDOWN_ACK_ACKED) ==
		     V3D_GCA_SAFE_SHUTDOWN_ACK_ACKED, 100)) {
		DRM_ERROR("Failed to wait for safe GCA shutdown\n");
	}
}

static void
v3d_reset_by_bridge(struct v3d_dev *v3d)
{
	int version = V3D_BRIDGE_READ(V3D_TOP_GR_BRIDGE_REVISION);

	if (V3D_GET_FIELD(version, V3D_TOP_GR_BRIDGE_MAJOR) == 2) {
		V3D_BRIDGE_WRITE(V3D_TOP_GR_BRIDGE_SW_INIT_0,
				 V3D_TOP_GR_BRIDGE_SW_INIT_0_V3D_CLK_108_SW_INIT);
		V3D_BRIDGE_WRITE(V3D_TOP_GR_BRIDGE_SW_INIT_0, 0);

		/* GFXH-1383: The SW_INIT may cause a stray write to address 0
		 * of the unit, so reset it to its power-on value here.
		 */
		V3D_WRITE(V3D_HUB_AXICFG, V3D_HUB_AXICFG_MAX_LEN_MASK);
	} else {
		WARN_ON_ONCE(V3D_GET_FIELD(version,
					   V3D_TOP_GR_BRIDGE_MAJOR) != 7);
		V3D_BRIDGE_WRITE(V3D_TOP_GR_BRIDGE_SW_INIT_1,
				 V3D_TOP_GR_BRIDGE_SW_INIT_1_V3D_CLK_108_SW_INIT);
		V3D_BRIDGE_WRITE(V3D_TOP_GR_BRIDGE_SW_INIT_1, 0);
	}
}

static void
v3d_reset_v3d(struct v3d_dev *v3d)
{
	if (v3d->reset)
		reset_control_reset(v3d->reset);
	else
		v3d_reset_by_bridge(v3d);

	v3d_init_hw_state(v3d);
}

void
v3d_reset(struct v3d_dev *v3d)
{
	struct drm_device *dev = &v3d->drm;

	DRM_DEV_ERROR(dev->dev, "Resetting GPU for hang.\n");
	DRM_DEV_ERROR(dev->dev, "V3D_ERR_STAT: 0x%08x\n",
		      V3D_CORE_READ(0, V3D_ERR_STAT));
	trace_v3d_reset_begin(dev);

	/* XXX: only needed for safe powerdown, not reset. */
	if (false)
		v3d_idle_axi(v3d, 0);

	v3d_irq_disable(v3d);

	v3d_idle_gca(v3d);
	v3d_reset_v3d(v3d);

	v3d_mmu_set_page_table(v3d);
	v3d_irq_reset(v3d);

	v3d_perfmon_stop(v3d, v3d->active_perfmon, false);

	trace_v3d_reset_end(dev);
}

static void
v3d_flush_l3(struct v3d_dev *v3d)
{
	if (v3d->ver < 41) {
		u32 gca_ctrl = V3D_GCA_READ(V3D_GCA_CACHE_CTRL);

		V3D_GCA_WRITE(V3D_GCA_CACHE_CTRL,
			      gca_ctrl | V3D_GCA_CACHE_CTRL_FLUSH);

		if (v3d->ver < 33) {
			V3D_GCA_WRITE(V3D_GCA_CACHE_CTRL,
				      gca_ctrl & ~V3D_GCA_CACHE_CTRL_FLUSH);
		}
	}
}

/* Invalidates the (read-only) L2C cache.  This was the L2 cache for
 * uniforms and instructions on V3D 3.2.
 */
static void
v3d_invalidate_l2c(struct v3d_dev *v3d, int core)
{
	if (v3d->ver > 32)
		return;

	V3D_CORE_WRITE(core, V3D_CTL_L2CACTL,
		       V3D_L2CACTL_L2CCLR |
		       V3D_L2CACTL_L2CENA);
}

/* Invalidates texture L2 cachelines */
static void
v3d_flush_l2t(struct v3d_dev *v3d, int core)
{
	/* While there is a busy bit (V3D_L2TCACTL_L2TFLS), we don't
	 * need to wait for completion before dispatching the job --
	 * L2T accesses will be stalled until the flush has completed.
	 * However, we do need to make sure we don't try to trigger a
	 * new flush while the L2_CLEAN queue is trying to
	 * synchronously clean after a job.
	 */
	mutex_lock(&v3d->cache_clean_lock);
	V3D_CORE_WRITE(core, V3D_CTL_L2TCACTL,
		       V3D_L2TCACTL_L2TFLS |
		       V3D_SET_FIELD(V3D_L2TCACTL_FLM_FLUSH, V3D_L2TCACTL_FLM));
	mutex_unlock(&v3d->cache_clean_lock);
}

/* Cleans texture L1 and L2 cachelines (writing back dirty data).
 *
 * For cleaning, which happens from the CACHE_CLEAN queue after CSD has
 * executed, we need to make sure that the clean is done before
 * signaling job completion.  So, we synchronously wait before
 * returning, and we make sure that L2 invalidates don't happen in the
 * meantime to confuse our are-we-done checks.
 */
void
v3d_clean_caches(struct v3d_dev *v3d)
{
	struct drm_device *dev = &v3d->drm;
	int core = 0;

	trace_v3d_cache_clean_begin(dev);

	V3D_CORE_WRITE(core, V3D_CTL_L2TCACTL, V3D_L2TCACTL_TMUWCF);
	if (wait_for(!(V3D_CORE_READ(core, V3D_CTL_L2TCACTL) &
		       V3D_L2TCACTL_TMUWCF), 100)) {
		DRM_ERROR("Timeout waiting for TMU write combiner flush\n");
	}

	mutex_lock(&v3d->cache_clean_lock);
	V3D_CORE_WRITE(core, V3D_CTL_L2TCACTL,
		       V3D_L2TCACTL_L2TFLS |
		       V3D_SET_FIELD(V3D_L2TCACTL_FLM_CLEAN, V3D_L2TCACTL_FLM));

	if (wait_for(!(V3D_CORE_READ(core, V3D_CTL_L2TCACTL) &
		       V3D_L2TCACTL_L2TFLS), 100)) {
		DRM_ERROR("Timeout waiting for L2T clean\n");
	}

	mutex_unlock(&v3d->cache_clean_lock);

	trace_v3d_cache_clean_end(dev);
}

/* Invalidates the slice caches.  These are read-only caches. */
static void
v3d_invalidate_slices(struct v3d_dev *v3d, int core)
{
	V3D_CORE_WRITE(core, V3D_CTL_SLCACTL,
		       V3D_SET_FIELD(0xf, V3D_SLCACTL_TVCCS) |
		       V3D_SET_FIELD(0xf, V3D_SLCACTL_TDCCS) |
		       V3D_SET_FIELD(0xf, V3D_SLCACTL_UCC) |
		       V3D_SET_FIELD(0xf, V3D_SLCACTL_ICC));
}

void
v3d_invalidate_caches(struct v3d_dev *v3d)
{
	/* Invalidate the caches from the outside in.  That way if
	 * another CL's concurrent use of nearby memory were to pull
	 * an invalidated cacheline back in, we wouldn't leave stale
	 * data in the inner cache.
	 */
	v3d_flush_l3(v3d);
	v3d_invalidate_l2c(v3d, 0);
	v3d_flush_l2t(v3d, 0);
	v3d_invalidate_slices(v3d, 0);
}

/* Takes the reservation lock on all the BOs being referenced, so that
 * at queue submit time we can update the reservations.
 *
 * We don't lock the RCL the tile alloc/state BOs, or overflow memory
 * (all of which are on exec->unref_list).  They're entirely private
 * to v3d, so we don't attach dma-buf fences to them.
 */
static int
v3d_lock_bo_reservations(struct v3d_job *job,
			 struct ww_acquire_ctx *acquire_ctx)
{
	int i, ret;

	ret = drm_gem_lock_reservations(job->bo, job->bo_count, acquire_ctx);
	if (ret)
		return ret;

	for (i = 0; i < job->bo_count; i++) {
		ret = dma_resv_reserve_fences(job->bo[i]->resv, 1);
		if (ret)
			goto fail;

		ret = drm_sched_job_add_implicit_dependencies(&job->base,
							      job->bo[i], true);
		if (ret)
			goto fail;
	}

	return 0;

fail:
	drm_gem_unlock_reservations(job->bo, job->bo_count, acquire_ctx);
	return ret;
}

/**
 * v3d_lookup_bos() - Sets up job->bo[] with the GEM objects
 * referenced by the job.
 * @dev: DRM device
 * @file_priv: DRM file for this fd
 * @job: V3D job being set up
 * @bo_handles: GEM handles
 * @bo_count: Number of GEM handles passed in
 *
 * The command validator needs to reference BOs by their index within
 * the submitted job's BO list.  This does the validation of the job's
 * BO list and reference counting for the lifetime of the job.
 *
 * Note that this function doesn't need to unreference the BOs on
 * failure, because that will happen at v3d_exec_cleanup() time.
 */
static int
v3d_lookup_bos(struct drm_device *dev,
	       struct drm_file *file_priv,
	       struct v3d_job *job,
	       u64 bo_handles,
	       u32 bo_count)
{
	job->bo_count = bo_count;

	if (!job->bo_count) {
		/* See comment on bo_index for why we have to check
		 * this.
		 */
		DRM_DEBUG("Rendering requires BOs\n");
		return -EINVAL;
	}

	return drm_gem_objects_lookup(file_priv,
				      (void __user *)(uintptr_t)bo_handles,
				      job->bo_count, &job->bo);
}

static void
v3d_job_free(struct kref *ref)
{
	struct v3d_job *job = container_of(ref, struct v3d_job, refcount);
	int i;

	if (job->bo) {
		for (i = 0; i < job->bo_count; i++)
			drm_gem_object_put(job->bo[i]);
		kvfree(job->bo);
	}

	dma_fence_put(job->irq_fence);
	dma_fence_put(job->done_fence);

	if (job->perfmon)
		v3d_perfmon_put(job->perfmon);

	kfree(job);
}

static void
v3d_render_job_free(struct kref *ref)
{
	struct v3d_render_job *job = container_of(ref, struct v3d_render_job,
						  base.refcount);
	struct v3d_bo *bo, *save;

	list_for_each_entry_safe(bo, save, &job->unref_list, unref_head) {
		drm_gem_object_put(&bo->base.base);
	}

	v3d_job_free(ref);
}

void v3d_job_cleanup(struct v3d_job *job)
{
	if (!job)
		return;

	drm_sched_job_cleanup(&job->base);
	v3d_job_put(job);
}

void v3d_job_put(struct v3d_job *job)
{
	kref_put(&job->refcount, job->free);
}

int
v3d_wait_bo_ioctl(struct drm_device *dev, void *data,
		  struct drm_file *file_priv)
{
	int ret;
	struct drm_v3d_wait_bo *args = data;
	ktime_t start = ktime_get();
	u64 delta_ns;
	unsigned long timeout_jiffies =
		nsecs_to_jiffies_timeout(args->timeout_ns);

	if (args->pad != 0)
		return -EINVAL;

	ret = drm_gem_dma_resv_wait(file_priv, args->handle,
				    true, timeout_jiffies);

	/* Decrement the user's timeout, in case we got interrupted
	 * such that the ioctl will be restarted.
	 */
	delta_ns = ktime_to_ns(ktime_sub(ktime_get(), start));
	if (delta_ns < args->timeout_ns)
		args->timeout_ns -= delta_ns;
	else
		args->timeout_ns = 0;

	/* Asked to wait beyond the jiffie/scheduler precision? */
	if (ret == -ETIME && args->timeout_ns)
		ret = -EAGAIN;

	return ret;
}

static int
v3d_job_init(struct v3d_dev *v3d, struct drm_file *file_priv,
	     void **container, size_t size, void (*free)(struct kref *ref),
	     u32 in_sync, struct v3d_submit_ext *se, enum v3d_queue queue)
{
	struct v3d_file_priv *v3d_priv = file_priv->driver_priv;
	struct v3d_job *job;
	bool has_multisync = se && (se->flags & DRM_V3D_EXT_ID_MULTI_SYNC);
	int ret, i;

	*container = kcalloc(1, size, GFP_KERNEL);
	if (!*container) {
		DRM_ERROR("Cannot allocate memory for v3d job.");
		return -ENOMEM;
	}

	job = *container;
	job->v3d = v3d;
	job->free = free;

	ret = drm_sched_job_init(&job->base, &v3d_priv->sched_entity[queue],
				 v3d_priv);
	if (ret)
		goto fail;

	if (has_multisync) {
		if (se->in_sync_count && se->wait_stage == queue) {
			struct drm_v3d_sem __user *handle = u64_to_user_ptr(se->in_syncs);

			for (i = 0; i < se->in_sync_count; i++) {
				struct drm_v3d_sem in;

				if (copy_from_user(&in, handle++, sizeof(in))) {
					ret = -EFAULT;
					DRM_DEBUG("Failed to copy wait dep handle.\n");
					goto fail_deps;
				}
				ret = drm_sched_job_add_syncobj_dependency(&job->base, file_priv, in.handle, 0);

				// TODO: Investigate why this was filtered out for the IOCTL.
				if (ret && ret != -ENOENT)
					goto fail_deps;
			}
		}
	} else {
		ret = drm_sched_job_add_syncobj_dependency(&job->base, file_priv, in_sync, 0);

		// TODO: Investigate why this was filtered out for the IOCTL.
		if (ret && ret != -ENOENT)
			goto fail_deps;
	}

	kref_init(&job->refcount);

	return 0;

fail_deps:
	drm_sched_job_cleanup(&job->base);
fail:
	kfree(*container);
	*container = NULL;

	return ret;
}

static void
v3d_push_job(struct v3d_job *job)
{
	drm_sched_job_arm(&job->base);

	job->done_fence = dma_fence_get(&job->base.s_fence->finished);

	/* put by scheduler job completion */
	kref_get(&job->refcount);

	drm_sched_entity_push_job(&job->base);
}

static void
v3d_attach_fences_and_unlock_reservation(struct drm_file *file_priv,
					 struct v3d_job *job,
					 struct ww_acquire_ctx *acquire_ctx,
					 u32 out_sync,
					 struct v3d_submit_ext *se,
					 struct dma_fence *done_fence)
{
	struct drm_syncobj *sync_out;
	bool has_multisync = se && (se->flags & DRM_V3D_EXT_ID_MULTI_SYNC);
	int i;

	for (i = 0; i < job->bo_count; i++) {
		/* XXX: Use shared fences for read-only objects. */
		dma_resv_add_fence(job->bo[i]->resv, job->done_fence,
				   DMA_RESV_USAGE_WRITE);
	}

	drm_gem_unlock_reservations(job->bo, job->bo_count, acquire_ctx);

	/* Update the return sync object for the job */
	/* If it only supports a single signal semaphore*/
	if (!has_multisync) {
		sync_out = drm_syncobj_find(file_priv, out_sync);
		if (sync_out) {
			drm_syncobj_replace_fence(sync_out, done_fence);
			drm_syncobj_put(sync_out);
		}
		return;
	}

	/* If multiple semaphores extension is supported */
	if (se->out_sync_count) {
		for (i = 0; i < se->out_sync_count; i++) {
			drm_syncobj_replace_fence(se->out_syncs[i].syncobj,
						  done_fence);
			drm_syncobj_put(se->out_syncs[i].syncobj);
		}
		kvfree(se->out_syncs);
	}
}

static void
v3d_put_multisync_post_deps(struct v3d_submit_ext *se)
{
	unsigned int i;

	if (!(se && se->out_sync_count))
		return;

	for (i = 0; i < se->out_sync_count; i++)
		drm_syncobj_put(se->out_syncs[i].syncobj);
	kvfree(se->out_syncs);
}

static int
v3d_get_multisync_post_deps(struct drm_file *file_priv,
			    struct v3d_submit_ext *se,
			    u32 count, u64 handles)
{
	struct drm_v3d_sem __user *post_deps;
	int i, ret;

	if (!count)
		return 0;

	se->out_syncs = (struct v3d_submit_outsync *)
			kvmalloc_array(count,
				       sizeof(struct v3d_submit_outsync),
				       GFP_KERNEL);
	if (!se->out_syncs)
		return -ENOMEM;

	post_deps = u64_to_user_ptr(handles);

	for (i = 0; i < count; i++) {
		struct drm_v3d_sem out;

		if (copy_from_user(&out, post_deps++, sizeof(out))) {
			ret = -EFAULT;
			DRM_DEBUG("Failed to copy post dep handles\n");
			goto fail;
		}

		se->out_syncs[i].syncobj = drm_syncobj_find(file_priv,
							    out.handle);
		if (!se->out_syncs[i].syncobj) {
			ret = -EINVAL;
			goto fail;
		}
	}
	se->out_sync_count = count;

	return 0;

fail:
	for (i--; i >= 0; i--)
		drm_syncobj_put(se->out_syncs[i].syncobj);
	kvfree(se->out_syncs);

	return ret;
}

/* Get data for multiple binary semaphores synchronization. Parse syncobj
 * to be signaled when job completes (out_sync).
 */
static int
v3d_get_multisync_submit_deps(struct drm_file *file_priv,
			      struct drm_v3d_extension __user *ext,
			      void *data)
{
	struct drm_v3d_multi_sync multisync;
	struct v3d_submit_ext *se = data;
	int ret;

	if (copy_from_user(&multisync, ext, sizeof(multisync)))
		return -EFAULT;

	if (multisync.pad)
		return -EINVAL;

	ret = v3d_get_multisync_post_deps(file_priv, data, multisync.out_sync_count,
					  multisync.out_syncs);
	if (ret)
		return ret;

	se->in_sync_count = multisync.in_sync_count;
	se->in_syncs = multisync.in_syncs;
	se->flags |= DRM_V3D_EXT_ID_MULTI_SYNC;
	se->wait_stage = multisync.wait_stage;

	return 0;
}

/* Whenever userspace sets ioctl extensions, v3d_get_extensions parses data
 * according to the extension id (name).
 */
static int
v3d_get_extensions(struct drm_file *file_priv,
		   u64 ext_handles,
		   void *data)
{
	struct drm_v3d_extension __user *user_ext;
	int ret;

	user_ext = u64_to_user_ptr(ext_handles);
	while (user_ext) {
		struct drm_v3d_extension ext;

		if (copy_from_user(&ext, user_ext, sizeof(ext))) {
			DRM_DEBUG("Failed to copy submit extension\n");
			return -EFAULT;
		}

		switch (ext.id) {
		case DRM_V3D_EXT_ID_MULTI_SYNC:
			ret = v3d_get_multisync_submit_deps(file_priv, user_ext, data);
			if (ret)
				return ret;
			break;
		default:
			DRM_DEBUG_DRIVER("Unknown extension id: %d\n", ext.id);
			return -EINVAL;
		}

		user_ext = u64_to_user_ptr(ext.next);
	}

	return 0;
}

/**
 * v3d_submit_cl_ioctl() - Submits a job (frame) to the V3D.
 * @dev: DRM device
 * @data: ioctl argument
 * @file_priv: DRM file for this fd
 *
 * This is the main entrypoint for userspace to submit a 3D frame to
 * the GPU.  Userspace provides the binner command list (if
 * applicable), and the kernel sets up the render command list to draw
 * to the framebuffer described in the ioctl, using the command lists
 * that the 3D engine's binner will produce.
 */
int
v3d_submit_cl_ioctl(struct drm_device *dev, void *data,
		    struct drm_file *file_priv)
{
	struct v3d_dev *v3d = to_v3d_dev(dev);
	struct v3d_file_priv *v3d_priv = file_priv->driver_priv;
	struct drm_v3d_submit_cl *args = data;
	struct v3d_submit_ext se = {0};
	struct v3d_bin_job *bin = NULL;
	struct v3d_render_job *render = NULL;
	struct v3d_job *clean_job = NULL;
	struct v3d_job *last_job;
	struct ww_acquire_ctx acquire_ctx;
	int ret = 0;

	trace_v3d_submit_cl_ioctl(&v3d->drm, args->rcl_start, args->rcl_end);

	if (args->pad)
		return -EINVAL;

	if (args->flags &&
	    args->flags & ~(DRM_V3D_SUBMIT_CL_FLUSH_CACHE |
			    DRM_V3D_SUBMIT_EXTENSION)) {
		DRM_INFO("invalid flags: %d\n", args->flags);
		return -EINVAL;
	}

	if (args->flags & DRM_V3D_SUBMIT_EXTENSION) {
		ret = v3d_get_extensions(file_priv, args->extensions, &se);
		if (ret) {
			DRM_DEBUG("Failed to get extensions.\n");
			return ret;
		}
	}

	ret = v3d_job_init(v3d, file_priv, (void *)&render, sizeof(*render),
			   v3d_render_job_free, args->in_sync_rcl, &se, V3D_RENDER);
	if (ret)
		goto fail;

	render->start = args->rcl_start;
	render->end = args->rcl_end;
	INIT_LIST_HEAD(&render->unref_list);

	if (args->bcl_start != args->bcl_end) {
		ret = v3d_job_init(v3d, file_priv, (void *)&bin, sizeof(*bin),
				   v3d_job_free, args->in_sync_bcl, &se, V3D_BIN);
		if (ret)
			goto fail;

		bin->start = args->bcl_start;
		bin->end = args->bcl_end;
		bin->qma = args->qma;
		bin->qms = args->qms;
		bin->qts = args->qts;
		bin->render = render;
	}

	if (args->flags & DRM_V3D_SUBMIT_CL_FLUSH_CACHE) {
		ret = v3d_job_init(v3d, file_priv, (void *)&clean_job, sizeof(*clean_job),
				   v3d_job_free, 0, NULL, V3D_CACHE_CLEAN);
		if (ret)
			goto fail;

		last_job = clean_job;
	} else {
		last_job = &render->base;
	}

	ret = v3d_lookup_bos(dev, file_priv, last_job,
			     args->bo_handles, args->bo_handle_count);
	if (ret)
		goto fail;

	ret = v3d_lock_bo_reservations(last_job, &acquire_ctx);
	if (ret)
		goto fail;

	if (args->perfmon_id) {
		render->base.perfmon = v3d_perfmon_find(v3d_priv,
							args->perfmon_id);

		if (!render->base.perfmon) {
			ret = -ENOENT;
			goto fail_perfmon;
		}
	}

	mutex_lock(&v3d->sched_lock);
	if (bin) {
		bin->base.perfmon = render->base.perfmon;
		v3d_perfmon_get(bin->base.perfmon);
		v3d_push_job(&bin->base);

		ret = drm_sched_job_add_dependency(&render->base.base,
						   dma_fence_get(bin->base.done_fence));
		if (ret)
			goto fail_unreserve;
	}

	v3d_push_job(&render->base);

	if (clean_job) {
		struct dma_fence *render_fence =
			dma_fence_get(render->base.done_fence);
		ret = drm_sched_job_add_dependency(&clean_job->base,
						   render_fence);
		if (ret)
			goto fail_unreserve;
		clean_job->perfmon = render->base.perfmon;
		v3d_perfmon_get(clean_job->perfmon);
		v3d_push_job(clean_job);
	}

	mutex_unlock(&v3d->sched_lock);

	v3d_attach_fences_and_unlock_reservation(file_priv,
						 last_job,
						 &acquire_ctx,
						 args->out_sync,
						 &se,
						 last_job->done_fence);

	if (bin)
		v3d_job_put(&bin->base);
	v3d_job_put(&render->base);
	if (clean_job)
		v3d_job_put(clean_job);

	return 0;

fail_unreserve:
	mutex_unlock(&v3d->sched_lock);
fail_perfmon:
	drm_gem_unlock_reservations(last_job->bo,
				    last_job->bo_count, &acquire_ctx);
fail:
	v3d_job_cleanup((void *)bin);
	v3d_job_cleanup((void *)render);
	v3d_job_cleanup(clean_job);
	v3d_put_multisync_post_deps(&se);

	return ret;
}

/**
 * v3d_submit_tfu_ioctl() - Submits a TFU (texture formatting) job to the V3D.
 * @dev: DRM device
 * @data: ioctl argument
 * @file_priv: DRM file for this fd
 *
 * Userspace provides the register setup for the TFU, which we don't
 * need to validate since the TFU is behind the MMU.
 */
int
v3d_submit_tfu_ioctl(struct drm_device *dev, void *data,
		     struct drm_file *file_priv)
{
	struct v3d_dev *v3d = to_v3d_dev(dev);
	struct drm_v3d_submit_tfu *args = data;
	struct v3d_submit_ext se = {0};
	struct v3d_tfu_job *job = NULL;
	struct ww_acquire_ctx acquire_ctx;
	int ret = 0;

	trace_v3d_submit_tfu_ioctl(&v3d->drm, args->iia);

	if (args->flags && !(args->flags & DRM_V3D_SUBMIT_EXTENSION)) {
		DRM_DEBUG("invalid flags: %d\n", args->flags);
		return -EINVAL;
	}

	if (args->flags & DRM_V3D_SUBMIT_EXTENSION) {
		ret = v3d_get_extensions(file_priv, args->extensions, &se);
		if (ret) {
			DRM_DEBUG("Failed to get extensions.\n");
			return ret;
		}
	}

	ret = v3d_job_init(v3d, file_priv, (void *)&job, sizeof(*job),
			   v3d_job_free, args->in_sync, &se, V3D_TFU);
	if (ret)
		goto fail;

	job->base.bo = kcalloc(ARRAY_SIZE(args->bo_handles),
			       sizeof(*job->base.bo), GFP_KERNEL);
	if (!job->base.bo) {
		ret = -ENOMEM;
		goto fail;
	}

	job->args = *args;

	for (job->base.bo_count = 0;
	     job->base.bo_count < ARRAY_SIZE(args->bo_handles);
	     job->base.bo_count++) {
		struct drm_gem_object *bo;

		if (!args->bo_handles[job->base.bo_count])
			break;

		bo = drm_gem_object_lookup(file_priv, args->bo_handles[job->base.bo_count]);
		if (!bo) {
			DRM_DEBUG("Failed to look up GEM BO %d: %d\n",
				  job->base.bo_count,
				  args->bo_handles[job->base.bo_count]);
			ret = -ENOENT;
			goto fail;
		}
		job->base.bo[job->base.bo_count] = bo;
	}

	ret = v3d_lock_bo_reservations(&job->base, &acquire_ctx);
	if (ret)
		goto fail;

	mutex_lock(&v3d->sched_lock);
	v3d_push_job(&job->base);
	mutex_unlock(&v3d->sched_lock);

	v3d_attach_fences_and_unlock_reservation(file_priv,
						 &job->base, &acquire_ctx,
						 args->out_sync,
						 &se,
						 job->base.done_fence);

	v3d_job_put(&job->base);

	return 0;

fail:
	v3d_job_cleanup((void *)job);
	v3d_put_multisync_post_deps(&se);

	return ret;
}

/**
 * v3d_submit_csd_ioctl() - Submits a CSD (texture formatting) job to the V3D.
 * @dev: DRM device
 * @data: ioctl argument
 * @file_priv: DRM file for this fd
 *
 * Userspace provides the register setup for the CSD, which we don't
 * need to validate since the CSD is behind the MMU.
 */
int
v3d_submit_csd_ioctl(struct drm_device *dev, void *data,
		     struct drm_file *file_priv)
{
	struct v3d_dev *v3d = to_v3d_dev(dev);
	struct v3d_file_priv *v3d_priv = file_priv->driver_priv;
	struct drm_v3d_submit_csd *args = data;
	struct v3d_submit_ext se = {0};
	struct v3d_csd_job *job = NULL;
	struct v3d_job *clean_job = NULL;
	struct ww_acquire_ctx acquire_ctx;
	int ret;

	trace_v3d_submit_csd_ioctl(&v3d->drm, args->cfg[5], args->cfg[6]);

	if (args->pad)
		return -EINVAL;

	if (!v3d_has_csd(v3d)) {
		DRM_DEBUG("Attempting CSD submit on non-CSD hardware\n");
		return -EINVAL;
	}

	if (args->flags && !(args->flags & DRM_V3D_SUBMIT_EXTENSION)) {
		DRM_INFO("invalid flags: %d\n", args->flags);
		return -EINVAL;
	}

	if (args->flags & DRM_V3D_SUBMIT_EXTENSION) {
		ret = v3d_get_extensions(file_priv, args->extensions, &se);
		if (ret) {
			DRM_DEBUG("Failed to get extensions.\n");
			return ret;
		}
	}

	ret = v3d_job_init(v3d, file_priv, (void *)&job, sizeof(*job),
			   v3d_job_free, args->in_sync, &se, V3D_CSD);
	if (ret)
		goto fail;

	ret = v3d_job_init(v3d, file_priv, (void *)&clean_job, sizeof(*clean_job),
			   v3d_job_free, 0, NULL, V3D_CACHE_CLEAN);
	if (ret)
		goto fail;

	job->args = *args;

	ret = v3d_lookup_bos(dev, file_priv, clean_job,
			     args->bo_handles, args->bo_handle_count);
	if (ret)
		goto fail;

	ret = v3d_lock_bo_reservations(clean_job, &acquire_ctx);
	if (ret)
		goto fail;

	if (args->perfmon_id) {
		job->base.perfmon = v3d_perfmon_find(v3d_priv,
						     args->perfmon_id);
		if (!job->base.perfmon) {
			ret = -ENOENT;
			goto fail_perfmon;
		}
	}

	mutex_lock(&v3d->sched_lock);
	v3d_push_job(&job->base);

	ret = drm_sched_job_add_dependency(&clean_job->base,
					   dma_fence_get(job->base.done_fence));
	if (ret)
		goto fail_unreserve;

	v3d_push_job(clean_job);
	mutex_unlock(&v3d->sched_lock);

	v3d_attach_fences_and_unlock_reservation(file_priv,
						 clean_job,
						 &acquire_ctx,
						 args->out_sync,
						 &se,
						 clean_job->done_fence);

	v3d_job_put(&job->base);
	v3d_job_put(clean_job);

	return 0;

fail_unreserve:
	mutex_unlock(&v3d->sched_lock);
fail_perfmon:
	drm_gem_unlock_reservations(clean_job->bo, clean_job->bo_count,
				    &acquire_ctx);
fail:
	v3d_job_cleanup((void *)job);
	v3d_job_cleanup(clean_job);
	v3d_put_multisync_post_deps(&se);

	return ret;
}

int
v3d_gem_init(struct drm_device *dev)
{
	struct v3d_dev *v3d = to_v3d_dev(dev);
	u32 pt_size = 4096 * 1024;
	int ret, i;

	for (i = 0; i < V3D_MAX_QUEUES; i++)
		v3d->queue[i].fence_context = dma_fence_context_alloc(1);

	spin_lock_init(&v3d->mm_lock);
	spin_lock_init(&v3d->job_lock);
	ret = drmm_mutex_init(dev, &v3d->bo_lock);
	if (ret)
		return ret;
	ret = drmm_mutex_init(dev, &v3d->reset_lock);
	if (ret)
		return ret;
	ret = drmm_mutex_init(dev, &v3d->sched_lock);
	if (ret)
		return ret;
	ret = drmm_mutex_init(dev, &v3d->cache_clean_lock);
	if (ret)
		return ret;

	/* Note: We don't allocate address 0.  Various bits of HW
	 * treat 0 as special, such as the occlusion query counters
	 * where 0 means "disabled".
	 */
	drm_mm_init(&v3d->mm, 1, pt_size / sizeof(u32) - 1);

	v3d->pt = dma_alloc_wc(v3d->drm.dev, pt_size,
			       &v3d->pt_paddr,
			       GFP_KERNEL | __GFP_NOWARN | __GFP_ZERO);
	if (!v3d->pt) {
		drm_mm_takedown(&v3d->mm);
		dev_err(v3d->drm.dev,
			"Failed to allocate page tables. Please ensure you have DMA enabled.\n");
		return -ENOMEM;
	}

	v3d_init_hw_state(v3d);
	v3d_mmu_set_page_table(v3d);

	ret = v3d_sched_init(v3d);
	if (ret) {
		drm_mm_takedown(&v3d->mm);
		dma_free_coherent(v3d->drm.dev, 4096 * 1024, (void *)v3d->pt,
				  v3d->pt_paddr);
	}

	return 0;
}

void
v3d_gem_destroy(struct drm_device *dev)
{
	struct v3d_dev *v3d = to_v3d_dev(dev);

	v3d_sched_fini(v3d);

	/* Waiting for jobs to finish would need to be done before
	 * unregistering V3D.
	 */
	WARN_ON(v3d->bin_job);
	WARN_ON(v3d->render_job);

	drm_mm_takedown(&v3d->mm);

	dma_free_coherent(v3d->drm.dev, 4096 * 1024, (void *)v3d->pt,
			  v3d->pt_paddr);
}
