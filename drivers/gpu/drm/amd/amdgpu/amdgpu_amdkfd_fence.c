/*
 * Copyright 2016 Advanced Micro Devices, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#include <linux/fence.h>
#include <linux/spinlock.h>
#include <linux/atomic.h>
#include <linux/stacktrace.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include "amdgpu_amdkfd.h"

const struct fence_ops amd_kfd_fence_ops;
atomic_t count = ATOMIC_INIT(0);

static int amd_kfd_fence_signal(struct fence *f);

/* Eviction Fence
 * Fence helper functions to deal with KFD memory eviction.
 * Big Idea - Since KFD submissions are done by user queues, a BO cannot be
 *  evicted unless all the user queues for that process are evicted.
 *
 * All the BOs in a process share an eviction fence. When process X wants
 * to map VRAM memory but TTM can't find enough space, TTM will attempt to
 * evict BOs from its LRU list. TTM checks if the BO is in use by calling
 * ttm_bo_wait() --> fence_wait() --> amd_kfd_fence_wait().
 *
 * amd_kfd_fence_wait - will retun fail if the BO belongs to process X.
 *  Otherwise it will evict all user queues of the process to which BO
 *  belongs. Then signal the fence. This allows TTM to evict BOs from
 *  this process.
 *
 * A restore thread is created which will attempt to restore (after certain
 * time) the evicted BOs.
 */

struct amdgpu_amdkfd_fence *amdgpu_amdkfd_fence_create(unsigned context)
{
	struct amdgpu_amdkfd_fence *fence = NULL;

	fence = kzalloc(sizeof(struct amdgpu_amdkfd_fence), GFP_KERNEL);
	if (fence == NULL)
		return NULL;

	/* Get mm_struct to identify the KFD process to which the fence
	 * belongs to. Keep a refernce for mm_struct and drop in fence_put
	 */
	fence->mm = current->mm;
	atomic_inc(&fence->mm->mm_count);
	get_task_comm(fence->timeline_name, current);
	spin_lock_init(&fence->lock);

	fence->count = atomic_inc_return(&count);
	fence_init(&fence->base, &amd_kfd_fence_ops, &fence->lock,
		   context, 0);

	return fence;
}

static struct amdgpu_amdkfd_fence *to_amdgpu_amdkfd_fence(struct fence *f)
{
	struct amdgpu_amdkfd_fence *fence;

	if (!f)
		return NULL;

	fence = container_of(f, struct amdgpu_amdkfd_fence, base);
	if (fence && f->ops == &amd_kfd_fence_ops)
		return fence;

	return NULL;
}

static const char *amd_kfd_fence_get_driver_name(struct fence *f)
{
	return "amdgpu_amdkfd_fence";
}

static const char *amd_kfd_fence_get_timeline_name(struct fence *f)
{
	struct amdgpu_amdkfd_fence *fence = to_amdgpu_amdkfd_fence(f);

	return fence->timeline_name;
}

static bool amd_kfd_fence_enable_signaling(struct fence *f)
{
	return true;
}

static int amd_kfd_fence_signal(struct fence *f)
{
	unsigned long flags;
	int ret;

	spin_lock_irqsave(f->lock, flags);
	/* Set enabled bit so cb will called */
	set_bit(FENCE_FLAG_ENABLE_SIGNAL_BIT, &f->flags);
	ret = fence_signal_locked(f);
	spin_unlock_irqrestore(f->lock, flags);

	return ret;
}

/**
 * amd_kfd_fence_wait - This gets called when TTM wants to evict
 *  a KFD BO. If not already signaled, check if the fence belongs to the
 *  current process. If true, then BO cannot be evicted to make room for
 *  other BOs of the same process.  All KFD buffers from the process must be
 *  resident at the same time in order to enable its queues. So wait for
 *  timeout period and return 0.
 *
 *  Otherwise, quiesce user queue access for the fence process. Signal
 *  the fence and return timeout. This will probably result in eviction
 *  of some of the BOs.
 *
 *  Start restore thread which will try to restore the BOs after certain
 *  elapsed time
 *
 * @fence:	[in]	the fence to wait on
 * @intr:	[in]	if true, do an interruptible wait
 * @timeout:	[in]	timeout value in jiffies, or MAX_SCHEDULE_TIMEOUT
 *
 * Returns -ERESTARTSYS if interrupted, 0 if the wait timed out, or the
 * remaining timeout in jiffies on success.
 */
static signed long
amd_kfd_fence_wait(struct fence *f, bool intr, signed long timeout)
{
	unsigned long flags;
	struct amdgpu_amdkfd_fence *fence;
	signed long ret = timeout;

	fence = to_amdgpu_amdkfd_fence(f);
	if (fence == NULL)
		return -EFAULT;

	spin_lock_irqsave(f->lock, flags);
	if (test_bit(FENCE_FLAG_SIGNALED_BIT, &f->flags)) {
		/* Fence is already signaled indicates that process
		 * has been evicted.
		 */
		goto out;
	}

	if (intr && signal_pending(current)) {
		ret = -ERESTARTSYS;
		goto out;
	}
	spin_unlock_irqrestore(f->lock, flags);

	if (fence->mm != current->mm) {
		/* TODO: */
		/* The current process is not same as fence process. Evict all
		 * user queues in all devices that belongs to the fence process.
		 * Then signal the fence so that BOs of that process could be
		 * evicted if required
		 */

		/* TODO: */
		/* Start restore thread to restore all evicted BOs */
	} else {
		/* The current process is same as the fence process. Just wait
		 * for the specified timeout
		 */
		if (intr)
			__set_current_state(TASK_INTERRUPTIBLE);
		else
			__set_current_state(TASK_UNINTERRUPTIBLE);

		ret = schedule_timeout(ret);
		if (ret > 0 && intr && signal_pending(current))
			ret = -ERESTARTSYS;
	}
	return ret;
out:
	spin_unlock_irqrestore(f->lock, flags);
	return ret;
}

/**
 * amdgpu_amdkfd_fence_reset - Restart fence for next eviction cycle
 *
 * @fence: fence
 *
 * Restart the fence after all the BOs are restored.
 *
*/
int amdgpu_amdkfd_fence_reset(struct fence *f)
{
	unsigned long flags;
	bool was_set;
	struct amdgpu_amdkfd_fence *fence = to_amdgpu_amdkfd_fence(f);

	if (fence == NULL)
		return -EFAULT;

	spin_lock_irqsave(f->lock, flags);

	if (!test_bit(FENCE_FLAG_SIGNALED_BIT, &f->flags)) {
		was_set = test_and_clear_bit(FENCE_FLAG_ENABLE_SIGNAL_BIT,
					     &f->flags);
		WARN_ON(was_set);
		spin_unlock_irqrestore(f->lock, flags);
		return 0;
	}

	clear_bit(FENCE_FLAG_ENABLE_SIGNAL_BIT, &f->flags);
	clear_bit(FENCE_FLAG_SIGNALED_BIT, &f->flags);
	fence->count = atomic_inc_return(&count);
	spin_unlock_irqrestore(f->lock, flags);

	return 0;
}

/**
 * amd_kfd_fence_release - callback that fence can be freed
 *
 * @fence: fence
 *
 * This function is called when the reference count becomes zero.
 * It just RCU schedules freeing up the fence.
*/
static void amd_kfd_fence_release(struct fence *f)
{
	struct amdgpu_amdkfd_fence *fence = to_amdgpu_amdkfd_fence(f);
	/* Unconditionally signal the fence. The process is getting
	 * terminated.
	 */
	if (WARN_ON(!fence))
		return; /* Not an amdgpu_amdkfd_fence */

	mmdrop(fence->mm);
	amd_kfd_fence_signal(f);
	kfree_rcu(f, rcu);
}

const struct fence_ops amd_kfd_fence_ops = {
	.get_driver_name = amd_kfd_fence_get_driver_name,
	.get_timeline_name = amd_kfd_fence_get_timeline_name,
	.enable_signaling = amd_kfd_fence_enable_signaling,
	.signaled = NULL,
	.wait = amd_kfd_fence_wait,
	.release = amd_kfd_fence_release,
};

