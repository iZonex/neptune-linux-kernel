// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2023-2024 Intel
 * Partially based on the rdma and misc controllers, which bear the following copyrights:
 *
 * Copyright 2020 Google LLC
 * Copyright (C) 2016 Parav Pandit <pandit.parav@gmail.com>
 */

#include <linux/cgroup.h>
#include <linux/cgroup_drm.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/page_counter.h>
#include <linux/parser.h>
#include <linux/slab.h>

#include <drm/drm_device.h>
#include <drm/drm_drv.h>
#include <drm/drm_file.h>
#include <drm/drm_managed.h>

struct drmcg_device {
	spinlock_t lock;
	struct kref ref;
	struct rcu_head rcu;

	/* Protected by RCU and global spinlock */
	struct list_head dev_node;

	/* Protected by global spinlock only */
	struct list_head pools;

	/* Copy of the struct passed by device, to prevent lifetime issues */
	struct drmcgroup_device base;

	/* Name describing the card, set by drmcg_register_device */
	const char *name;

	/* Whether the device is unregistered by its caller.
	 * No new pools should be added to the device afterwards.
	 */
	bool unregistered;
};

struct drmcgroup_state {
	struct cgroup_subsys_state css;

	struct list_head pools;
};

struct drmcgroup_pool_state {
	struct drmcg_device *device;
	struct drmcgroup_state *cs;

	/* css node, RCU protected against device teardown */
	struct list_head	css_node;

	/* dev node, no RCU protection required */
	struct list_head	dev_node;

	int num_res, inited;
	struct rcu_head rcu;

	struct drmcgroup_pool_res {
		struct page_counter cnt;
	} resources[];
};

/*
 * 3 operations require locking protection:
 * - Registering and unregistering device to/from list, requires global lock.
 * - Adding a drmcgroup_pool_state to a CSS, removing when CSS is freed.
 * - Adding a drmcgroup_pool_state to a device list.
 *
 * Since for the most common operations RCU provides enough protection, I
 * do not think more granular locking makes sense. Most protection is offered
 * by RCU and the lockless operating page_counter.
 */
static DEFINE_SPINLOCK(drmcg_lock);
static LIST_HEAD(drmcg_devices);

static inline struct drmcgroup_state *
css_to_drmcs(struct cgroup_subsys_state *css)
{
	return container_of(css, struct drmcgroup_state, css);
}

static inline struct drmcgroup_state *get_current_drmcg(void)
{
	return css_to_drmcs(task_get_css(current, drm_cgrp_id));
}

static struct drmcgroup_state *parent_drmcg(struct drmcgroup_state *cg)
{
	return cg->css.parent ? css_to_drmcs(cg->css.parent) : NULL;
}

static void free_cg_pool(struct drmcgroup_pool_state *pool, bool from_rcu)
{
	list_del(&pool->dev_node);
	if (!from_rcu)
		kfree_rcu(pool, rcu);
	else
		kfree(pool);
}

static void
set_resource_min(struct drmcgroup_pool_state *pool, int i, u64 val)
{
	page_counter_set_min(&pool->resources[i].cnt, val);
}

static void
set_resource_low(struct drmcgroup_pool_state *pool, int i, u64 val)
{
	page_counter_set_low(&pool->resources[i].cnt, val);
}

static void
set_resource_max(struct drmcgroup_pool_state *pool, int i, u64 val)
{
	page_counter_set_max(&pool->resources[i].cnt, val);
}

static u64 get_resource_low(struct drmcgroup_pool_state *pool, int idx)
{
	return pool ? READ_ONCE(pool->resources[idx].cnt.low) : 0;
}

static u64 get_resource_min(struct drmcgroup_pool_state *pool, int idx)
{
	return pool ? READ_ONCE(pool->resources[idx].cnt.min) : 0;
}

static u64 get_resource_max(struct drmcgroup_pool_state *pool, int idx)
{
	return pool ? READ_ONCE(pool->resources[idx].cnt.max) : PAGE_COUNTER_MAX;
}

static u64 get_resource_current(struct drmcgroup_pool_state *pool, int idx)
{
	return pool ? page_counter_read(&pool->resources[idx].cnt) : 0;
}

static void reset_all_resource_limits(struct drmcgroup_pool_state *rpool)
{
	int i;

	for (i = 0; i < rpool->num_res; i++) {
		set_resource_min(rpool, i, 0);
		set_resource_low(rpool, i, 0);
		set_resource_max(rpool, i, PAGE_COUNTER_MAX);
	}
}

static void drmcs_offline(struct cgroup_subsys_state *css)
{
	struct drmcgroup_state *drmcs = css_to_drmcs(css);
	struct drmcgroup_pool_state *pool;

	rcu_read_lock();
	list_for_each_entry_rcu(pool, &drmcs->pools, css_node)
		reset_all_resource_limits(pool);
	rcu_read_unlock();
}

static void drmcs_free(struct cgroup_subsys_state *css)
{
	struct drmcgroup_state *drmcs = css_to_drmcs(css);
	struct drmcgroup_pool_state *pool, *next;

	spin_lock(&drmcg_lock);
	list_for_each_entry_safe(pool, next, &drmcs->pools, css_node) {
		list_del_rcu(&pool->css_node);
		free_cg_pool(pool, false);
	}
	spin_unlock(&drmcg_lock);

	synchronize_rcu();
	kfree(drmcs);
}

static struct cgroup_subsys_state *
drmcs_alloc(struct cgroup_subsys_state *parent_css)
{
	struct drmcgroup_state *drmcs = kzalloc(sizeof(*drmcs), GFP_KERNEL);
	if (!drmcs)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&drmcs->pools);
	return &drmcs->css;
}

static struct drmcgroup_pool_state *
find_cg_pool_locked(struct drmcgroup_state *drmcs, struct drmcg_device *dev)
{
	struct drmcgroup_pool_state *pool;

	list_for_each_entry_rcu(pool, &drmcs->pools, css_node, spin_locked(&drmcg_lock))
		if (pool->device == dev)
			return pool;

	return NULL;
}

static struct drmcgroup_pool_state *pool_parent(struct drmcgroup_pool_state *pool)
{
	if (!pool->resources[0].cnt.parent)
		return NULL;

	return container_of(pool->resources[0].cnt.parent, typeof(*pool), resources[0].cnt);
}

bool drmcs_evict_valuable(struct drmcgroup_pool_state *limit,
			  struct drmcgroup_device *dev,
			  int index,
			  struct drmcgroup_pool_state *test,
			  bool ignore_low,
			  bool *hit_low)
{
	struct drmcgroup_pool_state *pool = test;
	struct page_counter *climit;
	struct page_counter *ctest;
	u64 used, min, low;

	/* Special cases */
	if (limit == test || !parent_drmcg(test->cs))
		return true;

	if (limit) {
		for (pool = test; pool && limit != pool;
		     pool = pool_parent(pool)) {}

		if (!pool)
			return false;
	}
	else {
		for (limit = test; pool_parent(limit);
		     limit = pool_parent(limit)) {}
	}

	climit = &limit->resources[index].cnt;
	ctest = &test->resources[index].cnt;

	page_counter_calculate_protection(climit, ctest, true);

	/* We're not using the minimum cgroup allocation guarantee, so we can short-circuit here */
	used = page_counter_read(ctest);
	min = READ_ONCE(ctest->emin);

	if (used <= min)
		return false;

	if (!ignore_low) {
		low = READ_ONCE(ctest->low);
		if (used > low)
			return true;

		*hit_low = true;
		return false;
	}
	return true;
}
EXPORT_SYMBOL_GPL(drmcs_evict_valuable);

static struct drmcgroup_pool_state *
alloc_pool_single(struct drmcgroup_state *drmcs, struct drmcg_device *dev,
		  struct drmcgroup_pool_state **allocpool)
{
	struct drmcgroup_state *parent = parent_drmcg(drmcs);
	struct drmcgroup_pool_state *pool, *ppool = NULL;
	int i;

	if (!*allocpool) {
		pool = kzalloc(offsetof(struct drmcgroup_pool_state, resources[dev->base.num_regions]), GFP_NOWAIT);
		if (!pool)
			return ERR_PTR(-ENOMEM);
	} else {
		pool = *allocpool;
		*allocpool = NULL;
	}

	pool->device = dev;
	pool->num_res = dev->base.num_regions;
	pool->cs = drmcs;

	if (parent)
		ppool = find_cg_pool_locked(parent, dev);

	for (i = 0; i < pool->num_res; i++)
		page_counter_init(&pool->resources[i].cnt, ppool ? &ppool->resources[i].cnt : NULL);
	reset_all_resource_limits(pool);

	list_add_tail_rcu(&pool->css_node, &drmcs->pools);
	list_add_tail(&pool->dev_node, &dev->pools);

	if (!parent)
		pool->inited = true;
	else
		pool->inited = ppool ? ppool->inited : false;
	return pool;
}

static struct drmcgroup_pool_state *
get_cg_pool_locked(struct drmcgroup_state *drmcs, struct drmcg_device *dev,
		   struct drmcgroup_pool_state **allocpool)
{
	struct drmcgroup_pool_state *pool, *ppool, *retpool;
	struct drmcgroup_state *p, *pp;
	int i;

	/*
	 * Recursively create pool, we may not initialize yet on
	 * recursion, this is done as a separate step.
	 */
	for (p = drmcs; p; p = parent_drmcg(p)) {
		pool = find_cg_pool_locked(p, dev);
		if (!pool)
			pool = alloc_pool_single(p, dev, allocpool);

		if (IS_ERR(pool))
			return pool;

		if (p == drmcs && pool->inited)
			return pool;

		if (pool->inited)
			break;
	}

	retpool = pool = find_cg_pool_locked(drmcs, dev);
	for (p = drmcs, pp = parent_drmcg(drmcs); pp; p = pp, pp = parent_drmcg(p)) {
		if (pool->inited)
			break;

		/* ppool was created if it didn't exist by above loop. */
		ppool = find_cg_pool_locked(pp, dev);

		/* Fix up parent links, mark as inited. */
		for (i = 0; i < pool->num_res; i++)
			pool->resources[i].cnt.parent = &ppool->resources[i].cnt;
		pool->inited = true;

		pool = ppool;
	}

	return retpool;
}

static void drmcg_free_rcu(struct rcu_head *rcu)
{
	struct drmcg_device *dev = container_of(rcu, typeof(*dev), rcu);
	struct drmcgroup_pool_state *pool, *next;

	list_for_each_entry_safe(pool, next, &dev->pools, dev_node)
		free_cg_pool(pool, true);
	kfree(dev->name);
	kfree(dev);
}

static void drmcg_free_device(struct kref *ref)
{
	struct drmcg_device *cgdev = container_of(ref, typeof(*cgdev), ref);

	call_rcu(&cgdev->rcu, drmcg_free_rcu);
}

void drmcg_unregister_device(struct drmcgroup_device *cgdev)
{
	struct drmcg_device *dev;
	struct list_head *entry;

	if (!cgdev || !cgdev->priv)
		return;

	dev = cgdev->priv;
	cgdev->priv = NULL;

	spin_lock(&drmcg_lock);

	/* Remove from global device list */
	list_del_rcu(&dev->dev_node);

	list_for_each_rcu(entry, &dev->pools) {
		struct drmcgroup_pool_state *pool =
			container_of(entry, typeof(*pool), dev_node);

		list_del_rcu(&pool->css_node);
	}

	/*
	 * Ensure any RCU based lookups fail. Additionally,
	 * no new pools should be added to the dead device
	 * by get_cg_pool_unlocked.
	 */
	dev->unregistered = true;
	spin_unlock(&drmcg_lock);

	kref_put(&dev->ref, drmcg_free_device);
}

EXPORT_SYMBOL_GPL(drmcg_unregister_device);

int drmcg_register_device(struct drm_device *drm_dev,
			  struct drmcgroup_device *cgdev)
{
	struct drmcg_device *dev;
	char *name;

	cgdev->priv = NULL;
	if (!cgdev->num_regions)
		return 0;

	cgdev->priv = dev = kzalloc(sizeof (*dev), GFP_KERNEL);
	if (!dev)
		return -ENOMEM;
	name = kstrdup(drm_dev->unique, GFP_KERNEL);
	if (!name) {
		kfree(dev);
		cgdev->priv = NULL;
		return -ENOMEM;
	}

	INIT_LIST_HEAD(&dev->pools);
	dev->name = name;
	dev->base = *cgdev;

	kref_init(&dev->ref);

	spin_lock(&drmcg_lock);
	list_add_tail_rcu(&dev->dev_node, &drmcg_devices);
	spin_unlock(&drmcg_lock);

	return 0;
}
EXPORT_SYMBOL_GPL(drmcg_register_device);

static struct drmcg_device *drmcg_get_device(const char *name)
{
	struct drmcg_device *dev;

	list_for_each_entry_rcu(dev, &drmcg_devices, dev_node, spin_locked(&drmcg_lock))
		if (!strcmp(name, dev->name) &&
		    kref_get_unless_zero(&dev->ref))
			return dev;

	return NULL;
}

void drmcs_pool_put(struct drmcgroup_pool_state *pool)
{
	if (pool)
		css_put(&pool->cs->css);
}
EXPORT_SYMBOL_GPL(drmcs_pool_put);

static struct drmcgroup_pool_state *
get_cg_pool_unlocked(struct drmcgroup_state *cg, struct drmcg_device *dev)
{
	struct drmcgroup_pool_state *pool, *allocpool = NULL;

	/* fastpath lookup? */
	rcu_read_lock();
	pool = find_cg_pool_locked(cg, dev);
	if (pool && !READ_ONCE(pool->inited))
		pool = NULL;
	rcu_read_unlock();

	while (!pool) {
		spin_lock(&drmcg_lock);
		if (!dev->unregistered)
			pool = get_cg_pool_locked(cg, dev, &allocpool);
		else
			pool = ERR_PTR(-ENODEV);
		spin_unlock(&drmcg_lock);

		if (pool == ERR_PTR(-ENOMEM)) {
			pool = NULL;
			if (WARN_ON(allocpool))
				continue;

			allocpool = kzalloc(offsetof(struct drmcgroup_pool_state, resources[dev->base.num_regions]), GFP_KERNEL);
			if (allocpool) {
				pool = NULL;
				continue;
			}
		}
	}

	kfree(allocpool);
	return pool;
}

void drmcg_uncharge(struct drmcgroup_pool_state *pool,
		    struct drmcgroup_device *cgdev,
		    u32 index, u64 size)
{
	if (index >= cgdev->num_regions || !pool)
		return;

	page_counter_uncharge(&pool->resources[index].cnt, size);
	css_put(&pool->cs->css);
}
EXPORT_SYMBOL_GPL(drmcg_uncharge);

int drmcg_try_charge(struct drmcgroup_pool_state **drmcs,
		     struct drmcgroup_pool_state **limitcs,
		     struct drmcgroup_device *dev,
		     u32 index, u64 size)
{
	struct drmcg_device *cgdev = dev->priv;
	struct drmcgroup_state *cg;
	struct drmcgroup_pool_state *pool;
	struct page_counter *fail;
	int ret;

	*drmcs = NULL;
	if (limitcs)
		*limitcs = NULL;

	if (index >= cgdev->base.num_regions)
		return -EINVAL;

	/*
	 * hold on to css, as cgroup can be removed but resource
	 * accounting happens on css.
	 */
	cg = get_current_drmcg();

	pool = get_cg_pool_unlocked(cg, cgdev);
	if (IS_ERR(pool)) {
		ret = PTR_ERR(pool);
		goto err;
	}

	if (!page_counter_try_charge(&pool->resources[index].cnt, size, &fail)) {
		if (limitcs) {
			*limitcs = container_of(fail, struct drmcgroup_pool_state, resources[index].cnt);
			css_get(&(*limitcs)->cs->css);
		}
		ret = -EAGAIN;
		goto err;
	}

	/* On success, reference is transferred to *drmcs */
	*drmcs = pool;
	return 0;

err:
	css_put(&cg->css);
	return ret;
}
EXPORT_SYMBOL_GPL(drmcg_try_charge);

static int drmcg_capacity_show(struct seq_file *sf, void *v)
{
	struct drmcg_device *dev;
	int i;

	rcu_read_lock();
	list_for_each_entry_rcu(dev, &drmcg_devices, dev_node) {
		seq_puts(sf, dev->name);
		for (i = 0; i < dev->base.num_regions; i++)
			seq_printf(sf, " region.%s=%lld",
				   dev->base.regions[i].name,
				   dev->base.regions[i].size);
		seq_putc(sf, '\n');
	}
	rcu_read_unlock();
	return 0;
}

static s64 parse_resource(char *c, char **retname)
{
	substring_t argstr;
	char *name, *value = c;
	size_t len;
	int ret;
	u64 retval;

	name = strsep(&value, "=");
	if (!name || !value)
		return -EINVAL;

	/* Only support region setting for now */
	if (strncmp(name, "region.", 7))
		return -EINVAL;
	else
		name += 7;

	*retname = name;
	len = strlen(value);

	argstr.from = value;
	argstr.to = value + len;

	ret = match_u64(&argstr, &retval);
	if (ret >= 0) {
		if (retval > S64_MAX)
			return -EINVAL;
		if (retval > PAGE_COUNTER_MAX)
			return PAGE_COUNTER_MAX;
		return retval;
	}
	if (!strncmp(value, "max", len))
		return PAGE_COUNTER_MAX;

	/* Not u64 or max, error */
	return -EINVAL;
}

static int drmcg_parse_limits(char *options,
			      u64 *limits, char **enables)
{
	char *c;
	int num_limits = 0;

	/* parse resource options */
	while ((c = strsep(&options, " ")) != NULL) {
		s64 limit;

		if (num_limits >= DRMCG_MAX_REGIONS)
			return -EINVAL;

		limit = parse_resource(c, &enables[num_limits]);
		if (limit < 0)
			return limit;

		limits[num_limits++] = limit;
	}
	return num_limits;
}

static ssize_t drmcg_limit_write(struct kernfs_open_file *of,
				 char *buf, size_t nbytes, loff_t off,
				 void (*fn)(struct drmcgroup_pool_state *pool, int idx, u64 val))
{
	struct drmcgroup_state *drmcs = css_to_drmcs(of_css(of));
	struct drmcg_device *dev;
	struct drmcgroup_pool_state *pool;
	char *options = strstrip(buf);
	char *dev_name = strsep(&options, " ");
	u64 limits[DRMCG_MAX_REGIONS];
	u64 new_limits[DRMCG_MAX_REGIONS];
	char *regions[DRMCG_MAX_REGIONS];
	int num_limits, i;
	unsigned long set_mask = 0;
	int err = 0;

	if (!dev_name)
		return -EINVAL;

	num_limits = drmcg_parse_limits(options, limits, regions);
	if (num_limits < 0)
		return num_limits;
	if (!num_limits)
		return -EINVAL;

	/*
	 * Everything is parsed into key=value pairs now, take lock and attempt to update
	 * For good measure, set -EINVAL when a key is set twice.
	 */
	rcu_read_lock();
	dev = drmcg_get_device(dev_name);
	rcu_read_unlock();
	if (!dev)
		return -ENODEV;

	pool = get_cg_pool_unlocked(drmcs, dev);
	if (IS_ERR(pool)) {
		err = PTR_ERR(pool);
		goto err;
	}

	/* Lookup region names and set new_limits to the index */
	for (i = 0; i < num_limits; i++) {
		int j;

		for (j = 0; j < dev->base.num_regions; j++)
			if (!strcmp(regions[i], dev->base.regions[j].name))
				break;

		if (j == dev->base.num_regions ||
		    set_mask & BIT(j)) {
			err = -EINVAL;
			goto err;
		}

		set_mask |= BIT(j);
		new_limits[j] = limits[i];
	}

	/* And commit */
	for_each_set_bit(i, &set_mask, DRMCG_MAX_REGIONS)
		fn(pool, i, new_limits[i]);

err:
	kref_put(&dev->ref, drmcg_free_device);

	return err ?: nbytes;
}

static int drmcg_limit_show(struct seq_file *sf, void *v,
			    u64 (*fn)(struct drmcgroup_pool_state *, int))
{
	struct drmcgroup_state *drmcs = css_to_drmcs(seq_css(sf));
	struct drmcg_device *dev;

	rcu_read_lock();
	list_for_each_entry_rcu(dev, &drmcg_devices, dev_node) {
		struct drmcgroup_pool_state *pool = find_cg_pool_locked(drmcs, dev);

		seq_puts(sf, dev->name);

		for (int i = 0; i < dev->base.num_regions; i++) {
			u64 val = fn(pool, i);

			if (val < PAGE_COUNTER_MAX)
				seq_printf(sf, " region.%s=%lld",
					   dev->base.regions[i].name, val);
			else
				seq_printf(sf, " region.%s=max", dev->base.regions[i].name);
		}

		seq_putc(sf, '\n');
	}
	rcu_read_unlock();

	css_put(&drmcs->css);

	return 0;
}

static int drmcg_current_show(struct seq_file *sf, void *v)
{
	return drmcg_limit_show(sf, v, get_resource_current);
}

static int drmcg_min_show(struct seq_file *sf, void *v)
{
	return drmcg_limit_show(sf, v, get_resource_min);
}

static ssize_t drmcg_min_write(struct kernfs_open_file *of,
			       char *buf, size_t nbytes, loff_t off)
{
	return drmcg_limit_write(of, buf, nbytes, off, set_resource_min);
}

static int drmcg_low_show(struct seq_file *sf, void *v)
{
	return drmcg_limit_show(sf, v, get_resource_low);
}

static ssize_t drmcg_low_write(struct kernfs_open_file *of,
			       char *buf, size_t nbytes, loff_t off)
{
	return drmcg_limit_write(of, buf, nbytes, off, set_resource_low);
}

static int drmcg_max_show(struct seq_file *sf, void *v)
{
	return drmcg_limit_show(sf, v, get_resource_max);
}

static ssize_t drmcg_max_write(struct kernfs_open_file *of,
			       char *buf, size_t nbytes, loff_t off)
{
	return drmcg_limit_write(of, buf, nbytes, off, set_resource_max);
}

static struct cftype files[] = {
	{
		.name = "capacity",
		.seq_show = drmcg_capacity_show,
		.flags = CFTYPE_ONLY_ON_ROOT,
	},
	{
		.name = "current",
		.seq_show = drmcg_current_show,
	},
	{
		.name = "min",
		.write = drmcg_min_write,
		.seq_show = drmcg_min_show,
		.flags = CFTYPE_NOT_ON_ROOT,
	},
	{
		.name = "low",
		.write = drmcg_low_write,
		.seq_show = drmcg_low_show,
		.flags = CFTYPE_NOT_ON_ROOT,
	},
	{
		.name = "max",
		.write = drmcg_max_write,
		.seq_show = drmcg_max_show,
		.flags = CFTYPE_NOT_ON_ROOT,
	},
	{ } /* Zero entry terminates. */
};

struct cgroup_subsys drm_cgrp_subsys = {
	.css_alloc	= drmcs_alloc,
	.css_free	= drmcs_free,
	.css_offline	= drmcs_offline,
	.legacy_cftypes	= files,
	.dfl_cftypes	= files,
};
