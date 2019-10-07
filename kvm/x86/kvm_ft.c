#include <linux/kvm_ft.h>
#include <linux/kvm.h>
#include <linux/kvm_host.h>
#include <linux/log2.h>
#include <linux/hrtimer.h>
#include <linux/ktime.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/shared_pages_array.h>
#include <linux/time.h>
#include <linux/ktime.h>
#include <linux/module.h>
#include <linux/mmu_context.h>
#include <linux/interrupt.h>

#include <linux/sched.h>

#define SHOW_AVERAGE_FRAG   1
#undef SHOW_AVERAGE_FRAG

//#define ENABLE_PRE_DIFF 1

#if defined(ENABLE_SWAP_PTE) && defined(ENABLE_PRE_DIFF)
#error ENABLE_SWAP_PTE and ENABLE_PRE_DIFF cant co-exist.
#endif

#define PAGE_TRANSFER_TIME_MEASURE  1
#undef PAGE_TRANSFER_TIME_MEASURE

//#define SPCL    1

static int dirty_page = 0;

#ifdef PAGE_TRANSFER_TIME_MEASURE
static s64 transfer_start_time = 0;
static s64 transfer_end_time = 0;
static s64 page_transfer_start_times[3072];
static s64 page_transfer_end_times[3072];
static int page_transfer_end_times_off = 0;
static int page_transfer_offsets[3072];
static int page_transfer_offsets_off = 0;
#endif


int global_internal_time = 300;
//static int bd_predic_stop2(void);
static struct kvm_vcpu* bd_predic_stop2(struct kvm_vcpu *vcpu);
static int bd_predic_stop3(void *arg);
static enum hrtimer_restart kvm_shm_vcpu_timer_callcallback(struct hrtimer *timer);
DECLARE_TASKLET(calc_dirty_tasklet, bd_predic_stop2, 0);
DECLARE_TASKLET(calc_dirty_tasklet2, bd_predic_stop3, 0);

struct kvm_vcpu *global_vcpu;

spinlock_t transfer_lock;

struct ft_timer_q {
    atomic_t end;
    atomic_t start;
    struct hrtimer *timer[128];
};

struct ft_timer_q ft_timer = {-1,-1,0};


struct ft_multi_trans_h {
	atomic_t ft_vm_count;
};

struct ft_multi_trans_h ft_m_trans = {ATOMIC_INIT(-1)};




struct ft_send_d {
	struct kvm *kvm;
	struct socket *psock;
	struct kvmft_dirty_list *dlist;
	int count;
	int trans_index;
	int run_serial;
	int len;
};



struct diff_and_tran_kthread_descriptor {
    struct kvm *kvm;
    int trans_index;
    int conn_index;
    int conn_count;
};

static struct xmit_req {
    struct socket *psock;
    unsigned long gfn;
    struct page *page1;
    struct page *page2;
    c16x8_header_t header;
    int offsets_off;
    int trans_index;
    int run_serial;
    bool check_modify;
    bool more;
    int offsets[128];
} xmit_reqs[2][2600];
static int xmit_off[2];

struct nocopy_callback_arg {
	struct kvm *kvm;
	unsigned long gfn;
	atomic_t counter;
	int16_t send;
	int16_t sending;
};

static inline s64 time_in_us(void) {
    ktime_t val;
    val = ktime_get();
    return ktime_to_ns(val) / 1000;
}

static inline void kvmft_tcp_nodelay(struct socket *sock)
{
    int val = 1;
    kernel_setsockopt(sock, SOL_TCP, 1, (char __user *)&val, sizeof(val));
}

static inline void kvmft_tcp_unnodelay(struct socket *sock)
{
    int val = 0;
    kernel_setsockopt(sock, SOL_TCP, 1, (char __user *)&val, sizeof(val));
}

static inline void kvmft_tcp_cork(struct socket *sock)
{
    int val = 1;
    kernel_setsockopt(sock, SOL_TCP, 3, (char __user *)&val, sizeof(val));
}

static inline void kvmft_tcp_uncork(struct socket *sock)
{
    int val = 0;
    kernel_setsockopt(sock, SOL_TCP, 3, (char __user *)&val, sizeof(val));
}

#define pfn_to_virt(pfn)  __va((pfn) << PAGE_SHIFT)

extern unsigned long address_to_pte(unsigned long addr);

#define MS_TO_NS(x) (((unsigned int)x) * ((unsigned int)1E6))


static int target_latency_us;
static int epoch_time_in_us;
int p_dirty_bytes = 0;
unsigned long long p_count = 0;
unsigned long long p_average = 0;


static unsigned long pages_per_ms;

// TODO each VM should its own.
static struct mm_struct *child_mm;
static struct kvm_shmem_child maps_info;

static int modified_during_transfer_list_init(struct kvm *kvm)
{
    struct ft_modified_during_transfer_list *mdt = &kvm->mdt;
    void *records;
    records = kmalloc(sizeof(void *) * kvm->ft_context.shared_page_num, GFP_KERNEL | __GFP_ZERO);
    if (records == NULL) {
        return -ENOMEM;
    }
    mdt->records = records;
    mdt->put_off = 0;
    mdt->get_off = 0;
    mdt->size = kvm->ft_context.shared_page_num;
    return 0;
}

static void modified_during_transfer_list_free(struct kvm *kvm)
{
    struct ft_modified_during_transfer_list *mdt = &kvm->mdt;
    if (mdt->records) {
        int i;
        for (i = mdt->get_off; i < mdt->put_off; i++)
            kfree(mdt->records[i]);
        kfree(mdt->records);
        memset(mdt, 0, sizeof(*mdt));
    }
}

static void
modified_during_transfer_list_add(struct kvm *kvm,
                                  struct zerocopy_callback_arg *arg)
{
    struct ft_modified_during_transfer_list *mdt = &kvm->mdt;
    int off = __sync_fetch_and_add(&mdt->put_off, 1);
    mdt->records[off] = arg;
    smp_mb();
    wake_up(&kvm->mdt_event);
}

static void modified_during_transfer_list_reset(struct kvm *kvm)
{
    struct ft_modified_during_transfer_list *mdt = &kvm->mdt;
    mdt->put_off = 0;
    mdt->get_off = 0;
}

int kvmft_fire_timer(struct kvm_vcpu *vcpu, int moff)
{
    struct kvm *kvm = vcpu->kvm;
    struct kvmft_context *ctx = &kvm->ft_context;
    if (ctx->cur_index == moff)
        if (hrtimer_cancel(&vcpu->hrtimer)) {
            vcpu->hrtimer_pending = true;
            kvm_vcpu_kick(vcpu);
            return 1;
        }
    return 0;
}


void timer_init(struct hrtimer *hrtimer)
{
    hrtimer_init(hrtimer, CLOCK_MONOTONIC, HRTIMER_MODE_REL_PINNED);
}

void kvm_shm_start_timer2(void *info)
{
    struct kvm_vcpu *vcpu = info;
    ktime_t ktime;

//	printk("cocotion test vcpu start timer================== %p\n", vcpu);
    ktime = ktime_set(0, vcpu->epoch_time_in_us * 1000);
	//smp_call_function_single(7, timer_init, &vcpu->hrtimer, true);
    //hrtimer_start(&vcpu->hrtimer, ktime, HRTIMER_MODE_REL_PINNED);
    hrtimer_start(&vcpu->hrtimer, ktime, HRTIMER_MODE_REL);
    vcpu->mark_start_time = ktime_get();
//	printk("@@markstart = %ld\n", vcpu->mark_start_time);
//	printk("cocotion test vcpu end start timer================== %p\n", vcpu);
}



void kvm_shm_start_timer(struct kvm_vcpu *vcpu)
{
	ktime_t ktime;

    ktime = ktime_set(0, vcpu->epoch_time_in_us * 1000);
    hrtimer_start(&vcpu->hrtimer, ktime, HRTIMER_MODE_REL);
    //hrtimer_start(&vcpu->hrtimer, ktime, HRTIMER_MODE_REL_PINNED);
	//smp_call_function_single(7, timer_init, &vcpu->hrtimer, true);
}

static void spcl_kthread_notify_abandon(struct kvm *kvm);

void kvm_shm_timer_cancel(struct kvm_vcpu *vcpu)
{
    spcl_kthread_notify_abandon(vcpu->kvm);
	hrtimer_cancel(&vcpu->hrtimer);
}

static int bd_predic_stop3(void *arg)
{
	struct kvm_vcpu *vcpu = (struct kvm_vcpu *) arg;

	while(!kthread_should_stop()) {

		wait_event_interruptible(vcpu->kvm->calc_event, vcpu->kvm->ft_kick
				|| kthread_should_stop());


		if(kthread_should_stop())
			break;

		static unsigned long long total_count = 0;
		static unsigned long long time = 0;
		static unsigned long long dodo = 0;

		struct kvm_vcpu *rvcpu;

		rvcpu = bd_predic_stop2(vcpu);

		vcpu->kvm->ft_kick = 0;
		if(rvcpu) {
    		ktime_t ktime = ktime_set(0, rvcpu->nextT * 1000);
    		hrtimer_start(&rvcpu->hrtimer, ktime, HRTIMER_MODE_REL);
		}

	}
	return 0;
}


static struct kvm_vcpu* bd_predic_stop2(struct kvm_vcpu *vcpu)
{

    ktime_t start = ktime_get();
    struct kvm *kvm = vcpu->kvm;


    struct kvmft_context *ctx;
    ctx = &kvm->ft_context;


    struct kvmft_dirty_list *dlist;
    dlist = ctx->page_nums_snapshot_k[ctx->cur_index];


    int beta;

	s64 istart = time_in_us();
    int current_dirty_byte = bd_calc_dirty_bytes(kvm, ctx, dlist);

	int current_load_mem_rate = kvm->last_load_mem_rate;
	int dt = time_in_us()-istart;
//	printk("cocotion test dt = %d\n", dt);
	if(dt > 0) {
	    current_load_mem_rate = kvm->f_count*4096/dt;
    }

//	kvm->load_mem_rate = kvm->last_load_mem_rate+2*current_load_mem_rate;
//	kvm->load_mem_rate/=3;
	kvm->load_mem_rate = current_load_mem_rate;
//
//	kvm->load_mem_rate=current_load_mem_rate;


	kvm->last_load_mem_rate = current_load_mem_rate;

	//if(kvm->load_mem_rate < 200)
	//	kvm->load_mem_rate = 200;

//	printk("load_mem_rate = %d\n", kvm->load_mem_rate);

	int load_mem_bytes = dlist->put_off*4096;
	//kvm->load_mem_bytes = load_mem_bytes;


	ktime_t now = ktime_get();
	ktime_t diff = ktime_sub(now, vcpu->mark_start_time);
    int epoch_run_time = ktime_to_us(diff);


	int dirty_diff = current_dirty_byte - vcpu->old_dirty_count;
	vcpu->old_dirty_count = current_dirty_byte;
	int dirty_diff_rate = dirty_diff/(epoch_run_time - vcpu->old_runtime);

	vcpu->old_runtime = epoch_run_time;

    ktime_t diff2 = ktime_sub(ktime_get(), start);
   	int difftime2 = ktime_to_us(diff2);

	int extra_dirty = (dirty_diff_rate * difftime2) /*+ (newcount-oldcount)*4096*/;

//    beta = current_dirty_byte/vcpu->last_trans_rate + epoch_run_time;


//	kvm->x0 = current_dirty_byte / kvm->load_mem_rate;
//	kvm->x0 = (current_dirty_byte / kvm->load_mem_rate);
//	kvm->x0 = (current_dirty_byte / kvm->last_send_rate);

/*    if(current_dirty_byte < 40960)
        current_dirty_byte = 40960;
    if(load_mem_bytes < 40960)
        load_mem_bytes = 40960;
*/
/*    if(current_dirty_byte < 80000)
        current_dirty_byte = 80000;
    if(load_mem_bytes < 80000)
        load_mem_bytes = 80000;
*/

	if(kvm->last_send_rate < 100)
		kvm->last_send_rate = 100;
	if(kvm->current_send_rate < 100)
		kvm->current_send_rate = 100;
	if(kvm->load_mem_rate < 100)
		kvm->load_mem_rate = 100;

	int current_send_rate = (kvm->last_send_rate+2*kvm->current_send_rate)/3;

	int tmp0 = current_dirty_byte / current_send_rate;
	int tmp1 = load_mem_bytes / kvm->load_mem_rate;

//    if(tmp0 == 0) tmp0 = current_dirty_byte ;
 //   if(tmp1 == 0) tmp1 = load_mem_bytes ;

   // if(tmp0 == 0) tmp0 = 24 ;
    //if(tmp1 == 0) tmp1 = 204;

    //if(tmp0 > 0)
        kvm->x0 = tmp0;
    //if(tmp1 > 0)
        kvm->x1 = tmp1;

    //if(kvm->x0 < 150) kvm->x0 = 150;
    //if(kvm->x1 < 150) kvm->x1 = 150;
//	beta = kvm->x0*kvm->w0 + kvm->x1*kvm->w1;
//	beta = kvm->x0*kvm->w0 + kvm->x1*kvm->w1 + kvm->w2;

//    if(current_dirty_byte == 0) {
  //      beta = kvm->w3;
 //   } else {
    //    beta = kvm->x0*kvm->w0 + kvm->x1*kvm->w1 + kvm->w2;
////////////////////cocotion test ////////////////////////////////////
//
/*
		if(kvm->x0 > kvm->x00 ) {
			kvm->last_disspatch_time_smaller_count++;
		} //else {
		//	kvm->last_disspatch_time_smaller_count=0;
		//}

		if(kvm->last_disspatch_time_smaller_count == 2) {
		    //kvm->w0 = kvm->w0 + (kvm->learningR*kvm->x0*(1))/1000;
		    //kvm->w1 = kvm->w1 + (kvm->learningR*kvm->x1*(1))/1000;
			kvm->x0 += (kvm->x0-kvm->x00);

	//		kvm->last_disspatch_time_smaller_count=0;
		}
*/
////////////////////cocotion test ////////////////////////////////////

        beta = kvm->x0*kvm->w0 + kvm->x1*kvm->w1 + kvm->w3;
   //     beta = kvm->x0*kvm->w0 + kvm->x1*kvm->w1;
    //}

	int beta2 = beta;

    //beta = kvm->x0*kvm->w0 + kvm->x1*kvm->w1 + kvm->w2;
	beta/= 1000;
	beta += epoch_run_time;

//	beta += (current_dirty_byte/1000);
	//printk("epoch_run_time = %d, beta = %d, w0 = %d, w1 = %d, x0 = %d, x1 = %d mem_rate = %d, current_dirty_byte = %d, load_mem_bytes = %d\n", \
	//		epoch_run_time, beta, kvm->w0, kvm->w1, kvm->x0, kvm->x1, kvm->load_mem_rate, current_dirty_byte, load_mem_bytes);

//    beta = current_dirty_byte/vcpu->last_trans_rate + epoch_run_time;
//	if(epoch_run_time >= target_latency_us-1000 || beta>= target_latency_us-1000) {
//	if(epoch_run_time >= target_latency_us-1000 || beta>= target_latency_us-700) {
//	if(epoch_run_time >= target_latency_us-1000 || beta>= target_latency_us) {
	if(epoch_run_time >= target_latency_us-1000 || beta>= target_latency_us - kvm->latency_bias) {
//	if(epoch_run_time >= target_latency_us-1000 || beta>= target_latency_us-kvm->w2) {

	//	if(epoch_run_time < target_latency_us-1000) {
        	kvm->x00 = kvm->x0;
        	kvm->x01 = kvm->x1;
			kvm->w2 = current_dirty_byte;
			kvm->e_latency = beta;
			kvm->e_trans_latency = beta2;
			kvm->load_mem_bytes = load_mem_bytes;
			kvm->e_load_mem_rate = kvm->load_mem_rate;
			kvm->e_current_send_rate = current_send_rate;
			kvm->e_epoch_runtime = epoch_run_time;
	//	}
//			kvm->last_disspatch_time_smaller_count=0;

    	vcpu->hrtimer_pending = true;
        vcpu->run->exit_reason = KVM_EXIT_HRTIMER;
        kvm_vcpu_kick(vcpu);


		return NULL;
    }

//	if(kvm->x0 > kvm->x00 )
//		kvm->last_disspatch_time_smaller_count--;

    diff = ktime_sub(ktime_get(), start);

	int difftime = ktime_to_us(diff);
    int t = global_internal_time - difftime;

	if(t < 20) {
    	return bd_predic_stop2(vcpu);
    }
	vcpu->nextT = t;

	return vcpu;
}

static enum hrtimer_restart kvm_shm_vcpu_timer_callback(
        struct hrtimer *timer)
{

	struct kvm_vcpu *vcpu = hrtimer_to_vcpu(timer);

	struct kvm *kvm = vcpu->kvm;

	if(kvm->ft_cmp_tsk) {
		wake_up_process(kvm->ft_cmp_tsk);
	}
	wake_up(&kvm->calc_event);
	kvm->ft_kick = 1;



//		smp_call_function_single(7, bd_predic_stop3, vcpu, false);

    return HRTIMER_NORESTART;
}

static enum hrtimer_restart kvm_shm_vcpu_timer_callcallback(struct hrtimer *timer)
{
    //smp_call_function_single(7, kvm_shm_vcpu_timer_callback, timer, false);
	kvm_shm_vcpu_timer_callback(timer);
	return HRTIMER_NORESTART;
}


// timer for triggerring ram transfer
// called in vcpu_create..
void kvm_shm_setup_vcpu_hrtimer(void *info)
{
    struct kvm_vcpu *vcpu = info;

    struct hrtimer *hrtimer = &vcpu->hrtimer;

	//smp_call_function_single(7, timer_init, hrtimer, true);
    //hrtimer_init(hrtimer, CLOCK_MONOTONIC, HRTIMER_MODE_REL_PINNED);
    hrtimer_init(hrtimer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
    hrtimer->function = &kvm_shm_vcpu_timer_callcallback;
    vcpu->hrtimer_pending = false;

	//global_vcpu = vcpu;

}



/* Kernel build-in
static inline void clear_bit_le(unsigned nr, char *addr)
{
    addr[nr / 8] &= ~(1 << (nr % 8));
}
*/

static int prepare_for_page_backup(struct kvmft_context *ctx, int i)
{
    unsigned long pfn;
    int size;

    ctx->page_nums_snapshot_page[i] = alloc_pages(GFP_KERNEL|__GFP_ZERO,
                                                 ctx->page_nums_page_order);
    if (ctx->page_nums_snapshot_page[i] == NULL) {
        return -ENOMEM;
    }

    pfn = page_to_pfn(ctx->page_nums_snapshot_page[i]);
    ctx->page_nums_snapshot_k[i] = pfn_to_virt(pfn);

    size = ctx->shared_page_num / 8 + !!(ctx->shared_page_num % 8);
    ctx->page_nums_snapshot_k[i]->spcl_bitmap = kzalloc(size, GFP_KERNEL);
    if (!ctx->page_nums_snapshot_k[i]->spcl_bitmap)
        return -ENOMEM;

    ctx->shared_pages_snapshot_k[i] = kzalloc(
        sizeof (void *) * ctx->shared_page_num, GFP_KERNEL);
    if (!ctx->shared_pages_snapshot_k[i])
        return -ENOMEM;

    ctx->shared_pages_snapshot_pages[i] = kzalloc(
        sizeof (struct page *) * ctx->shared_page_num, GFP_KERNEL);
    if (!ctx->shared_pages_snapshot_pages[i])
        return -ENOMEM;

    printk("%s shared_snapshot_pages %p\n", __func__, ctx->shared_pages_snapshot_k[i]);
    return 0;
}

int kvm_shm_extend(struct kvm *kvm, struct kvm_shmem_extend *ext)
{
    struct kvmft_context *ctx = &kvm->ft_context;
    int ret;

    if (ctx->max_desc_count >= KVM_MAX_MIGRATION_DESC) {
        printk("%s exceed maximum %d\n", __func__, KVM_MAX_MIGRATION_DESC);
        return -1;
    }

    ctx->page_nums_snapshot_k = krealloc(ctx->page_nums_snapshot_k,
                                        sizeof(struct kvmft_dirty_list *)
                                        * (ctx->max_desc_count + 1),
                                        GFP_KERNEL | __GFP_ZERO);
    if (ctx->page_nums_snapshot_k == NULL) {
        return -ENOMEM;
    }

    ctx->page_nums_snapshot_page = krealloc(ctx->page_nums_snapshot_page,
                                           sizeof(struct page *)
                                           * (ctx->max_desc_count + 1),
                                           GFP_KERNEL | __GFP_ZERO);
    if (ctx->page_nums_snapshot_page == NULL) {
        return -ENOMEM;
    }

    ctx->shared_pages_snapshot_k = krealloc(ctx->shared_pages_snapshot_k,
                                           sizeof(void **)
                                           * (ctx->max_desc_count + 1),
                                           GFP_KERNEL | __GFP_ZERO);
    if (ctx->shared_pages_snapshot_k == NULL) {
        return -ENOMEM;
    }

    ctx->shared_pages_snapshot_pages = krealloc(ctx->shared_pages_snapshot_pages,
                                               sizeof(struct page **)
                                               * (ctx->max_desc_count + 1),
                                               GFP_KERNEL | __GFP_ZERO);
    if (ctx->shared_pages_snapshot_pages == NULL) {
        return -ENOMEM;
    }

    ret = prepare_for_page_backup(ctx, ctx->max_desc_count);
    if (ret != 0) {
        return ret;
    }

    ext->page_nums_size = 1 << ctx->page_nums_page_order;
    ext->page_nums_pfn_snapshot = page_to_pfn(ctx->page_nums_snapshot_page[ctx->max_desc_count]);
    printk("%s share_num pfn %ld\n", __func__, ext->page_nums_pfn_snapshot);

    ctx->max_desc_count++;

    return 0;
}

struct page *kvm_shm_alloc_page(struct kvm *kvm,
        struct kvm_shm_alloc_pages *param)
{
    struct kvmft_context *ctx = &kvm->ft_context;
    struct page *page = alloc_pages(GFP_KERNEL, param->order);

	if (param->index1 == -1 && param->index2 == -1)
		goto out;

    if (page) {
        if (param->index1 > ctx->max_desc_count || param->index2 >= ctx->shared_page_num) {
            printk("%s index1 %d index2 %d\n", __func__, param->index1, param->index2);
            __free_pages(page, param->order);
            return NULL;
        }
        ctx->shared_pages_snapshot_k[param->index1][param->index2] =
            pfn_to_virt(page_to_pfn(page));
        ctx->shared_pages_snapshot_pages[param->index1][param->index2] = page;
    }
out:
    return page;
}

static void kvm_shm_free_trackable(struct kvm *kvm)
{
	int i;

	if (!kvm->trackable_list)
		return;

	for (i = 0; i < kvm->trackable_list_len; ++i) {
		struct kvm_trackable *kt = kvm->trackable_list + i;
		if (kt->ppte) {
			kfree(kt->ppte);
			kt->ppte = NULL;
		}
		if (kt->page) {
			kfree(kt->page);
			kt->page = NULL;
		}
	}

	kfree(kvm->trackable_list);
	kvm->trackable_list = NULL;
}

// log == NULL
int kvm_shm_start_log_share_dirty_pages(struct kvm *kvm,
        struct kvm_collect_log *log)
{
    struct kvm_memory_slot *memslot;
    struct kvmft_context *ctx;
	struct kvm_memslots *slots;
	bool is_dirty = false;

	ctx = &kvm->ft_context;

	mutex_lock(&kvm->slots_lock);
	spin_lock(&kvm->mmu_lock);

	slots = kvm_memslots(kvm);

	kvm_for_each_memslot(memslot, slots) {
		unsigned long i, mask, n;
		unsigned long *dirty_bitmap;
		if (!memslot->dirty_bitmap)
			continue;

		dirty_bitmap = memslot->dirty_bitmap;
		n = kvm_dirty_bitmap_bytes(memslot);

		for (i = 0; i < n / sizeof(long); ++i) {
			gfn_t offset;
			if (!dirty_bitmap[i])
				continue;

			is_dirty = true;
			mask = xchg(&dirty_bitmap[i], 0);

			offset = i * BITS_PER_LONG;
			kvm_mmu_write_protect_pt_masked(kvm, memslot, offset, mask);
		}
	}

	if (is_dirty)
		kvm_flush_remote_tlbs(kvm);

	spin_unlock(&kvm->mmu_lock);
	mutex_unlock(&kvm->slots_lock);

	ctx->log_full = false;
    return 0;
}

static int clear_dirty_bitmap(struct kvm *kvm,
                              int cur_index,
                              struct kvmft_dirty_list *list)
{
	struct kvm_memory_slot *memslot;
    int i;

    for (i = list->put_off - 1; i >= 0; --i) {
        unsigned long gfn = list->pages[i];
        unsigned long *dirty_bitmap;
        memslot = gfn_to_memslot(kvm, gfn);
        dirty_bitmap = memslot->epoch_dirty_bitmaps.kaddr[cur_index];
        if (!test_and_clear_bit(gfn - memslot->base_gfn, dirty_bitmap)) {
            printk("%s %ld not set in bitmap.\n", __func__, gfn);
            return -EINVAL;
        }
    }
    return 0;
}


// check all page numbers in list is set in dirty_bitmaps
static int confirm_dirty_bitmap_match(struct kvm *kvm, int cur_index,
                                    struct kvmft_dirty_list *list)
{
	struct kvm_memory_slot *memslot;
    int i;

    for (i = list->put_off - 1; i >= 0; --i) {
        unsigned long gfn = list->pages[i];
        unsigned long *dirty_bitmap;
        memslot = gfn_to_memslot(kvm, gfn);
        dirty_bitmap = memslot->lock_dirty_bitmap;
        if (!test_bit(gfn - memslot->base_gfn, dirty_bitmap)) {
            printk("%s %8d %ld not set in prev.\n", __func__, i, gfn);
            //return -EINVAL;
        }
        dirty_bitmap = memslot->epoch_dirty_bitmaps.kaddr[cur_index];
        if (!test_bit(gfn - memslot->base_gfn, dirty_bitmap)) {
            printk("%s %8d %ld not set in dirty.\n", __func__, i, gfn);
            //return -EINVAL;
        }
    }
    return 0;
}

static int confirm_prev_dirty_bitmap_clear(struct kvm *kvm, int cur_index)
{
	struct kvm_memslots *slots;
	struct kvm_memory_slot *memslot;

	slots = kvm_memslots(kvm);

	kvm_for_each_memslot(memslot, slots) {
		gfn_t base;
		unsigned long npages;
		unsigned long *dirty_bitmap;
		int i;
		dirty_bitmap = memslot->lock_dirty_bitmap;
        if (!dirty_bitmap)
            continue;
		base = memslot->base_gfn;
        npages = memslot->npages;
        /*
        the commented for loop below is to check which bit is still set and we can know it from
        the kernel msg. But using for loop to check is too slow, so we change the checking method.
        If you want to check if the bitmap is not clear and want to know which bit is still set,
        you can uncomment the for loop to get these information.
        */

		/*for (i = 0; i < npages; ++i) {
			if (test_bit(i, dirty_bitmap)) {
				printk("%s %x is still set.\n", __func__, (long)base + i);
//                return -EINVAL;
			}
		}*/

        if(*dirty_bitmap != 0)
            printk("%s is still set.\n", __func__);
	}
    return 0;
}


struct socket *sockfd_lookup(int fd, int *err);
int kernel_sendpage(struct socket *sock, struct page *page, int offset,
			size_t size, int flags);

ssize_t do_tcp_sendpage_frag(struct sock *sk, struct page *page, int *offsets,
              int size_per_frag, int count, int flags);


static void kvmft_protect_all_gva_spcl_pages(struct kvm *kvm, int cur_index)
{
	struct kvm_memory_slot *last_memslot = NULL;
    struct kvmft_context *ctx;
    struct kvmft_dirty_list *dlist;
    int i, count;

    ctx = &kvm->ft_context;
    dlist = ctx->page_nums_snapshot_k[cur_index];

    count = dlist->gva_spcl_pages_off;
    if (count == 0)
        return;
    dlist->gva_spcl_pages_off = 0;

    spin_lock(&kvm->mmu_lock);
    for (i = 0; i < count; i++) {
        unsigned long gfn = dlist->gva_spcl_pages[i];
        if (!last_memslot || !in_memslot(last_memslot, gfn))
            last_memslot = gfn_to_memslot(kvm, gfn);
        if (unlikely(!last_memslot)) {
            printk("%s no memslot for [%d] %lx\n", __func__, i, gfn);
            continue;
        }
        kvm_mmu_write_protect_single_fast(kvm, last_memslot,
            gfn - last_memslot->base_gfn);
    }
    kvm_flush_remote_tlbs(kvm);
    spin_unlock(&kvm->mmu_lock);
}

static int spcl_backup_dirty_list_all_mark_dirty(struct kvm *kvm)
{
    struct kvmft_context *ctx = &kvm->ft_context;
    struct kvmft_dirty_list *dlist;
    int i, r = 0, count = ctx->spcl_backup_dirty_num;

    if (count == 0) {
        dlist = ctx->page_nums_snapshot_k[ctx->cur_index];
        dlist->spcl_put_off = 0;
        return r;
    }

    s64 start_time, end_time;
    static s64 max_time = 0;
    start_time = time_in_us();

    for (i = count - 1; i >= 0; --i) {
        gfn_t gfn = ctx->spcl_backup_dirty_list[i];
        void *hva = (void *)gfn_to_hva(kvm, gfn);
        if (kvm->spcl_run_serial == 0)
            goto out;
        r = kvmft_page_dirty(kvm, gfn, hva, true, NULL);
        if (r)
            goto out;
        extern void kvm_mmu_remove_write_protect_single(struct kvm *kvm, gfn_t gfn);
        spin_lock(&kvm->mmu_lock);
        kvm_mmu_remove_write_protect_single(kvm, gfn);
        spin_unlock(&kvm->mmu_lock);
    }
out:
    kvm_flush_remote_tlbs(kvm);

    end_time = time_in_us();
    if (end_time - start_time > max_time) {
        max_time = end_time - start_time;
        printk("%s %ld\n", __func__, max_time);
    }

    dlist = ctx->page_nums_snapshot_k[ctx->cur_index];
    dlist->spcl_put_off = dlist->put_off;

    return r;
}

static int spcl_kthread_mark_dirty_func(void *opaque)
{
    struct kvm *kvm = opaque;
    static uint32_t run_serial = 0;

    use_mm(kvm->qemu_mm);

    while (!kthread_should_stop()) {
        wait_event_interruptible(kvm->spcl_event,
            kvm->spcl_run_serial != run_serial || kthread_should_stop());
        if (kthread_should_stop())
            break;
        if (kvm->spcl_run_serial == run_serial)
            continue;
        run_serial = kvm->spcl_run_serial;
        if (kvm->spcl_run_serial > 0) {
            if (spcl_backup_dirty_list_all_mark_dirty(kvm))
                break;
        }
    }

    unuse_mm(kvm->qemu_mm);
    return 0;
}

static int spcl_kthread_create(struct kvm *kvm)
{
    int ret = 0;

    init_waitqueue_head(&kvm->spcl_event);

    kvm->spcl_kthread = kthread_run(&spcl_kthread_mark_dirty_func,
        kvm, "spcl_mark_dirty_func");
    if (IS_ERR(kvm->spcl_kthread)) {
        ret = -PTR_ERR(kvm->spcl_kthread);
        printk("%s failed to kthread_run %d\n", __func__, ret);
        kvm->spcl_kthread = NULL;
    }

    return ret;
}

static void spcl_kthread_destroy(struct kvm *kvm)
{
    if (kvm->spcl_kthread) {
        kthread_stop(kvm->spcl_kthread);
        kvm->spcl_kthread = NULL;
    }
}

static void spcl_kthread_notify_abandon(struct kvm *kvm)
{
#ifndef SPCL
    return;
#endif
    kvm->spcl_run_serial = 0;
    wake_up(&kvm->spcl_event);
}

static void spcl_kthread_notify_new(struct kvm *kvm, uint32_t run_serial)
{
#ifndef SPCL
    return;
#endif
    kvm->spcl_run_serial = run_serial;
    wake_up(&kvm->spcl_event);
}

static inline int transfer_16x8_page_with_offs(struct socket *psock,
                                               unsigned long gfn,
                                               struct page *page1,
                                               struct page *page2,
                                               c16x8_header_t *header,
                                               int *offsets,
                                               int offsets_off,
                                               struct kvm *kvm,
                                               int trans_index,
                                               int run_serial,
                                               bool check_modify,
                                               bool more);

static int kvmft_xmit_func(void *opaque)
{
    struct kvm *kvm = opaque;
    int serial = -1, off = 0;

    use_mm(kvm->qemu_mm);

    while (!kthread_should_stop()) {
        wait_event_interruptible(kvm->xmit_event, kthread_should_stop() ||
            kvm->xmit_serial != serial || kvm->xmit_off != off);
        if (kthread_should_stop())
            break;
        if (kvm->xmit_serial != serial) {
            serial = kvm->xmit_serial;
            off = 0;
        }
        while (off < kvm->xmit_off) {
            struct xmit_req *req = &xmit_reqs[serial][off];
            smp_mb();
            //printk("%s %lx @%d-%d\n", __func__, req->gfn, serial, off);
            int ret = transfer_16x8_page_with_offs(req->psock,
                                        req->gfn,
                                        req->page1,
                                        req->page2,
                                        &req->header,
                                        req->offsets,
                                        req->offsets_off,
                                        kvm,
                                        req->trans_index,
                                        req->run_serial,
                                        req->check_modify,
                                        req->more);
            if (ret < 0) {
                printk("%s fail %d\n", __func__, ret);
                break;
            }
            ++off;
        }
    }

    unuse_mm(kvm->qemu_mm);
    return 0;
}

static int xmit_kthread_create(struct kvm *kvm)
{
    int ret = 0;

    init_waitqueue_head(&kvm->xmit_event);

    // TODO disable xmit kthread
    return ret;

    kvm->xmit_kthread = kthread_run(&kvmft_xmit_func, kvm, "kvmft_xmit");
    if (IS_ERR(kvm->xmit_kthread)) {
        ret = -PTR_ERR(kvm->xmit_kthread);
        printk("%s failed to kthread_run %d\n", __func__, ret);
        kvm->xmit_kthread = NULL;
    }

    return ret;
}

static void xmit_kthread_destroy(struct kvm *kvm)
{
    if (kvm->xmit_kthread) {
        kthread_stop(kvm->xmit_kthread);
        kvm->xmit_kthread = NULL;
    }
}

static void xmit_kthread_notify_index(struct kvm *kvm, int index)
{
    kvm->xmit_serial = index;
    wake_up(&kvm->xmit_event);
}

static void xmit_kthread_notify_off(struct kvm *kvm, int off)
{
    kvm->xmit_off = off;
    wake_up(&kvm->xmit_event);
}

int kvm_shm_flip_sharing(struct kvm *kvm, __u32 cur_index, __u32 run_serial)
{
    struct kvmft_context *ctx = &kvm->ft_context;
    struct kvmft_master_slave_conn_info *info =
        &ctx->master_slave_info[cur_index];
	#ifdef ft_debug_mode_enable
	printk("kvm_shm_flip_sharing cur_index = %x\n", cur_index);
	#endif
    //kvmft_protect_all_gva_spcl_pages(kvm, ctx->cur_index);
//	confirm_prev_dirty_bitmap_clear(kvm, cur_index); //cocotion disable

    ctx->cur_index = cur_index;
    info->run_serial = run_serial;
    ctx->log_full = false;

    //printk("%s start run %d run_serial = %d\n", __func__, cur_index, run_serial);

    spcl_kthread_notify_new(kvm, run_serial);

    return 0;
}

int kvm_shm_enable(struct kvm *kvm)
{
    struct kvmft_context *ctx = &kvm->ft_context;
    ctx->shm_enabled = !ctx->shm_enabled;
    printk("%s shm_enabled %d\n", __func__, ctx->shm_enabled);


	kvm->load_mem_rate = 3800;
	kvm->last_load_mem_rate = 3800;
	kvm->last_send_rate = 3800;
	kvm->current_send_rate = 100;
	kvm->w0 = 1000;
	kvm->w1 = 1000;
	kvm->w2 = 1000;
	kvm->w3 = 1500000;
//	kvm->w3 = 1000000;
	kvm->w4 = 1000;
	kvm->wc = 0;
	kvm->wn = 0;
    kvm->x00 = 0;
    kvm->x01 = 0;

	kvm->latency_bias = 0;
	kvm->last_disspatch_time_smaller_count = 0;
//	kvm->ft_id = atomic_read(&ft_m_trans.ft_vm_count);
//	atomic_inc_return(&ft_m_trans.ft_vm_count);



	init_waitqueue_head(&kvm->calc_event);
	kvm->ft_cmp_tsk = kthread_create(bd_predic_stop3, kvm->vcpus[0], "cmp thread");
	if(IS_ERR(kvm->ft_cmp_tsk)) {
		kvm->ft_cmp_tsk = NULL;
		return 0;
	}

//	kthread_bind(kvm->ft_cmp_tsk, kvm->ft_id);
	kthread_bind(kvm->ft_cmp_tsk, 7);

    return 0;
}

static int wait_for_other_mark(struct kvm_memory_slot *memslot,
                           int cur_index,
                           unsigned long gfn_off,
                           int seconds)
{
    unsigned long delay = jiffies + seconds*HZ;
    volatile unsigned long *bitmap = memslot->epoch_dirty_bitmaps.kaddr[cur_index];
    while (!test_bit(gfn_off, bitmap)) {
        if (time_after(jiffies, delay)) {
            printk(KERN_ERR"%s %llx timeout.\n", __func__, gfn_off + memslot->base_gfn);
            return -1;
        }
        if (!in_atomic()) {
            cond_resched();
        }
    }
    return 0;
}

static int inline is_gfn_transferring(unsigned long gfn, struct kvm_memory_slot *memslot)
{
    return test_bit(gfn - memslot->base_gfn, memslot->backup_transfer_bitmap);
}

int replace_userspace_pte_page(struct task_struct *tsk,
             unsigned long addr, struct page *old, struct page *to);

// called by dirty threads
static void try_put_gfn_in_diff_req_list(struct kvm *kvm,
                                    struct kvm_memory_slot *memslot,
                                    unsigned long gfn)
{
    struct kvmft_context *ctx;
    unsigned long gfn_off;

	ctx = &kvm->ft_context;
    gfn_off = gfn - memslot->base_gfn;

    if (ctx->diff_req_list_cur != NULL) {    // previous epoch is still transfering
        int prev_index = ((ctx->cur_index - 1) + ctx->max_desc_count) % ctx->max_desc_count;
        volatile void *prev_bitmap = memslot->epoch_dirty_bitmaps.kaddr[prev_index];
        if (test_bit(gfn_off, prev_bitmap)) {   // dirtied by previous too
            if (!test_and_set_bit(gfn_off, memslot->backup_transfer_bitmap)) { // but gfn not yet transfered
                struct diff_req_list *prev_list = ctx->diff_req_list[prev_index];
                diff_req_list_put(prev_list, gfn, memslot);
                //if (prev_list->off % 20 == 0) {
                    wake_up(&kvm->diff_req_event);
                //}
            }
        }
    }
}

static inline void memcpy_avx_32(uint8_t *a, uint8_t *b)
{
    asm volatile("vmovdqa %0,%%ymm0" : : "m" (b[0]));
    asm volatile("vmovntdq %%ymm0,%0" : : "m" (a[0]));
}

static inline void memcpy_page_avx(uint8_t *a, uint8_t *b)
{
    size_t n = 0;

    kernel_fpu_begin();
    while (n < 4096) {
        memcpy_avx_32(a + n, b + n);
        n += 32;
    }
    kernel_fpu_end();
}

static inline void memcpy_page(void *dst, void *src)
{
    size_t n = 4096;
    uint64_t *src_u64 = (uint64_t *)src;
    uint64_t *dst_u64 = (uint64_t *)dst;

    while (n) {
        *dst_u64++ = *src_u64++;
        n -= sizeof(uint64_t);
    }
}

static inline void memcpy_page_ermsb(void *dst, void *src)
{
    __asm__ __volatile__ ("rep movsb"
    : /* no outputs */
    : "c" (4096), "D" (dst), "S" (src));
}

unsigned long ept_gva;
void kvmft_set_ept_gva(unsigned long gva)
{
    ept_gva = gva & ~0xfff;
}
EXPORT_SYMBOL(kvmft_set_ept_gva);

static int ept_gva_list_off = 0;
static int ept_gva_can_early = 0;
static unsigned long ept_gva_list[1024*5];

static void ept_gva_search(unsigned long gva)
{
    int i;

    for (i = 0; i < ept_gva_list_off; i++) {
        if (ept_gva_list[i] == gva)
            ++ept_gva_can_early;
    }
}

static void ept_gva_insert(unsigned long gva)
{
    int i;

    for (i = 0; i < ept_gva_list_off; i++) {
        if (ept_gva_list[i] == gva)
            return;
    }
    ept_gva_list[ept_gva_list_off++] = gva;
}

static void ept_gva_new(unsigned long gva)
{
    ept_gva_search(gva);
    ept_gva_insert(gva -   0x1000);
    ept_gva_insert(gva - 2*0x1000);
    ept_gva_insert(gva - 3*0x1000);
    ept_gva_insert(gva);
    ept_gva_insert(gva +   0x1000);
    ept_gva_insert(gva + 2*0x1000);
    ept_gva_insert(gva + 3*0x1000);
}

static void ept_gva_reset(int count)
{
    if (ept_gva_list_off >= 100)
        printk("%s\t%4d\t%4d\t%4d\n", __func__, ept_gva_can_early, ept_gva_list_off, count);
    ept_gva_list_off = 0;
    ept_gva_can_early = 0;
}

void kvmft_prepare_upcall(struct kvm_vcpu *vcpu)
{
    struct kvm *kvm = vcpu->kvm;
	struct kvmft_context *ctx;
    struct kvmft_dirty_list *dlist;
    static uint32_t *gfn_list = NULL;
    int i;

	ctx = &kvm->ft_context;
    dlist = ctx->page_nums_snapshot_k[ctx->cur_index];

    if (gfn_list == NULL) {
        gfn_list = (void *)gfn_to_hva(kvm, 16384);
    }

    gfn_list[0] = dlist->put_off;
    for (i = 0; i < dlist->put_off; i++)
        gfn_list[i+1] = (uint32_t)dlist->pages[i];
}

// backup data in snapshot mode.
// for pte, record list
// for other, backup whole page
// caller should put_page(replacer_pfn)
int kvmft_page_dirty(struct kvm *kvm, unsigned long gfn,
        void *orig, bool is_user, unsigned long *replacer_pfn)
{
	struct kvmft_context *ctx;
    struct kvmft_dirty_list *dlist;
	void **shared_pages_k;
    struct kvm_memory_slot *memslot;
    unsigned long gfn_off;
    int put_index;

	if (unlikely(!kvm_shm_is_enabled(kvm)))
		return 0;

	ctx = &kvm->ft_context;
    dlist = ctx->page_nums_snapshot_k[ctx->cur_index];

    memslot = gfn_to_memslot(kvm, gfn);
    if (unlikely(!memslot)) {
        printk(KERN_ERR"%s can't find memslot for %lx\n", __func__, gfn);
        memslots_dump(kvm);
        return -ENOENT;
    }
    if (!memslot->lock_dirty_bitmap) {
        printk("%s no lock_dirty_bitmap for %lx\n", __func__, gfn);
        printk("%s base_gfn %lx npages %lx\n", __func__, memslot->base_gfn, memslot->npages);
        memslots_dump(kvm);
        return -ENOENT;
    }
    BUG_ON(!memslot->lock_dirty_bitmap);

    gfn_off = gfn - memslot->base_gfn;
	#ifdef ft_debug_mode_enable
	printk("kvmft_page_dirty gfn = %x \n",gfn);
	#endif

    if (unlikely(test_and_set_bit(gfn_off, memslot->lock_dirty_bitmap)))
        return wait_for_other_mark(memslot, ctx->cur_index, gfn_off, 5);

    //ept_gva_new(ept_gva);

    put_index = __sync_fetch_and_add(&dlist->put_off, 1);
    if (unlikely(put_index >= ctx->shared_page_num)) {
		printk(KERN_ERR"%s (%d) missing dirtied page in snapshot mode %p %ld.\n",
				__func__, put_index, orig, gfn);
		return -1;
	}

    //printk("%s (%d) %d %lx\n", __func__, ctx->cur_index, put_index, gfn);

    ((uint16_t *)memslot->epoch_gfn_to_put_offs.kaddr[ctx->cur_index])[gfn_off] = put_index;
	dlist->pages[put_index] = gfn;

	shared_pages_k = ctx->shared_pages_snapshot_k[ctx->cur_index];
	orig = (void *)((unsigned long)orig & ~0x0FFFULL);

	if (is_user) {
		int copied = __copy_from_user(shared_pages_k[put_index], orig, 4096);
		if (unlikely(copied)) {
			printk(KERN_ERR"%s copy from user failed %lx (%p) %d.\n", __func__,
					(long)gfn, orig, copied);
            return -1;
		}
	} else {
		//memcpy_page(shared_pages_k[put_index], orig);
		memcpy_page_ermsb(shared_pages_k[put_index], orig);
        //memcpy_page_avx(shared_pages_k[put_index], orig);
	}

    if (unlikely(test_and_set_bit(gfn_off, memslot->epoch_dirty_bitmaps.kaddr[ctx->cur_index]))) {
        printk(KERN_ERR"%s dirty_bit set before lock_dirty_bit %d %ld\n", __func__, ctx->cur_index, (long)gfn);
        return -1;
    }

	//Now collect the largest collectable dirty pages
	if (unlikely(put_index >= ctx->shared_watermark))
		ctx->log_full = true;

#ifdef ENABLE_PRE_DIFF
    try_put_gfn_in_diff_req_list(kvm, memslot, gfn);
#endif

#ifdef ENABLE_SWAP_PTE
    if (is_user && replacer_pfn && is_gfn_transferring(gfn, memslot)) {
        struct page *to = ctx->shared_pages_snapshot_pages[ctx->cur_index][put_index];
        struct page *old = gfn_to_page(kvm, gfn);
        int ret;
        ret = replace_userspace_pte_page(current, orig, old, to);
        #ifdef DEBUG_SWAP_PTE
        printk("%s %lx is under transferring, repl ret %d \n", __func__, gfn, ret);
        printk("!PageAnon(old) %d PageCompound(old) %d page_mapcount(old) %d\n",
            !PageAnon(old), PageCompound(old), page_mapcount(old));
        #endif
        if (ret < 0) {
            clear_bit(gfn - memslot->base_gfn, memslot->backup_transfer_bitmap);
            #ifdef DEBUG_SWAP_PTE
            printk("%s failed, clear bit\n", __func__);
            #endif
        } else if (ret == 0) {
            struct page *page = alloc_pages(GFP_KERNEL, 0);
            ctx->shared_pages_snapshot_pages[ctx->cur_index][put_index] = page;
            ctx->shared_pages_snapshot_k[ctx->cur_index][put_index] = pfn_to_virt(page_to_pfn(page));
            *replacer_pfn = page_to_pfn(to);
            #ifdef DEBUG_SWAP_PTE
            printk("%s replace %lx to %lx\n", __func__, page_to_pfn(old), page_to_pfn(to));
            printk("%s succeed, alloc new snapshot page\n", __func__);
            #endif
        } else { //if (ret == 1) {
            #ifdef DEBUG_SWAP_PTE
            printk("%s changed, do nothing\n", __func__);
            #endif
            /* PTE no longer points to old, do nothing */
        }
        kvm_release_page_clean(old);
    }
#endif

    return 0;
}

void kvm_shm_notify_vcpu_destroy(struct kvm_vcpu *vcpu)
{
    if (vcpu->hrtimer_running) {
        vcpu->hrtimer_running = false;
    }
	hrtimer_cancel(&vcpu->hrtimer);
}

#if 0
static int unmap_process_vmas(struct mm_struct *mm,
        void *maps_starts[], void *maps_ends[],
        int maps_len)
{
    struct vm_area_struct *mpnt;
    int i, ret;

    // Maps maybed splitted or deleted during.
    for (i = 0; i < maps_len; ++i) {
        for (mpnt = mm->mmap; mpnt; mpnt = mpnt->vm_next) {
           if (mpnt->vm_start <= (unsigned long)maps_starts[i] &&
                   mpnt->vm_end >= (unsigned long)maps_ends[i]) {
               unsigned long size = (unsigned long)maps_ends[i]
                   - (unsigned long)maps_starts[i];
               ret = zap_page_range(mpnt, (unsigned long)maps_starts[i], size, NULL);
               printk("%s [%lx:%lx] %x\n", __func__,
                       (long)mpnt->vm_start, (long)mpnt->vm_end, ret);
               break;
           }
        }
    }

    return 0;
}
#endif

int kvm_shm_set_child_pid(struct kvm_shmem_child *info)
{
    //struct task_struct *cp;
    //pid_t pid = (pid_t)info->child_pid;

    maps_info = *info;

	return 0;
#if 0

    cp = find_task_by_vpid(pid);
    if (!cp)
        return -EINVAL;

    child_mm = cp->mm;
    if (!child_mm)
        return -EINVAL;

    //get_task_mm(cp);

    return unmap_process_vmas(child_mm, maps_info.maps_starts,
            maps_info.maps_ends, maps_info.maps_len);
#endif
}

int kvm_shm_sync_dev_pages(void)
{
    if (!child_mm)
        return -EINVAL;
	return -ENOENT;
}


int kvm_shm_report_trackable(struct kvm *kvm,
						struct kvm_shmem_report_trackable *t)
{
	int i, j;
	unsigned long addr;
	int ret = -ENOMEM;
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	printk("%s %d\n", __func__, __LINE__);
	if (t->trackable_count > KVM_SHM_REPORT_TRACKABLE_COUNT)
		return -EINVAL;

	printk("%s %d\n", __func__, __LINE__);
	if (t->trackable_count <= 0)
		return -EINVAL;

	printk("%s %d\n", __func__, __LINE__);
	if (kvm->trackable_list)
		return -EEXIST;

	printk("%s %d\n", __func__, __LINE__);
	kvm->trackable_list = kmalloc(sizeof(struct kvm_trackable)*t->trackable_count,
								GFP_KERNEL | __GFP_ZERO);
	if (!kvm->trackable_list)
		return -ENOMEM;

	printk("%s %d\n", __func__, __LINE__);
	for (i = 0; i < t->trackable_count; ++i) {
		struct kvm_trackable *kt = kvm->trackable_list + i;
		struct vm_area_struct *vma;
		// validate size is 4096*x, addr is userspace.
		if ((unsigned long)t->ptrs[i] >= TASK_SIZE_MAX ||
				(unsigned long)t->ptrs[i] + t->sizes[i] >= TASK_SIZE_MAX) {
			ret = -EINVAL;
			goto err_out;
		}
		if (t->sizes[i] <= 0 || t->sizes[i] % 4096 != 0) {
			ret = -EINVAL;
			goto err_out;
		}
		vma = find_vma(current->mm, (unsigned long)t->ptrs[i]);
		if (!vma) {
			ret = -EINVAL;
			goto err_out;
		}
		kt->ptr = t->ptrs[i];
		kt->size = t->sizes[i];
		kt->ppte = kmalloc(sizeof(pte_t *)*(kt->size/4096),
							GFP_KERNEL | __GFP_ZERO);
		kt->page = kmalloc(sizeof(struct page *)*(kt->size/4096),
							GFP_KERNEL | __GFP_ZERO);
		if (!kt->ppte || !kt->page)
			goto err_out;

		addr = (unsigned long)kt->ptr;
		for (j = 0; j < kt->size/4096; ++j) {
			if (is_vm_hugetlb_page(vma)) {
				ret = -EINVAL;
				goto err_out;
			} else {
				pgd = pgd_offset(current->mm, addr);
				ret = -ENOENT;
				if (pgd_none(*pgd) || unlikely(pgd_bad(*pgd))) {
					goto err_out;
				}
				pud = pud_offset(pgd, addr);
				if (pud_none(*pud) || unlikely(pud_bad(*pud))) {
					goto err_out;
				}
				pmd = pmd_offset(pud, addr);
				if (pmd_none(*pmd) || unlikely(pmd_bad(*pmd))) {
					goto err_out;
				}
				// NOTE, in 64bit, all kernel pages are mapped.
                // we only support 64bit kernel.
				if (sizeof(long) != 8) {
					ret = -EINVAL;
					goto err_out;
				}
                // NOTE, maybe we are unlucky? swapped out..
                // we don't deal with it.
				pte = pte_offset_map(pmd, addr);
				if (!pte_present(*pte)) {
					goto err_out;
				}
			}

			kt->ppte[j] = pte;
			kt->page[j] = pte_page(*pte);
			if (!kt->page[j]) {
				ret = -ENOENT;
				goto err_out;
			}
            // TODO get_page in case page is swapped out.
			if (pte_dirty(*pte)) {
                set_page_dirty(kt->page[j]);
				set_pte(pte, pte_mkclean(*pte));
				__flush_tlb_single(addr);
				// update_mmu_cache
			}
			addr += 4096;
		}
	}
	kvm->trackable_list_len = t->trackable_count;
	return 0;
err_out:
	kvm_shm_free_trackable(kvm);
	return ret;
}

int kvm_shm_collect_trackable_dirty(struct kvm *kvm,
									void * __user bitmap)
{
	static char bm[KVM_SHM_REPORT_TRACKABLE_COUNT/8] = {0};
	int i, j, bytes, count = 0;
	unsigned long addr;
	for (i = 0; i < kvm->trackable_list_len; ++i) {
		struct kvm_trackable *kt = kvm->trackable_list + i;
		int dirty = 0;
		addr = (unsigned long)kt->ptr;
		for (j = 0; j < kt->size/4096; ++j) {
			if (pte_dirty(*kt->ppte[j])) {
                set_page_dirty(kt->page[j]);
				set_pte(kt->ppte[j], pte_mkclean(*kt->ppte[j]));
				__flush_tlb_single(addr);
				dirty = 1;
			}
            addr += 4096;
		}
		if (dirty) {
			set_bit(i, (long *)bm);
			++count;
		} else {
			clear_bit(i, (long *)bm);
		}
	}

	bytes = kvm->trackable_list_len / 8;
	if (kvm->trackable_list_len % 8)
		++bytes;

	i = copy_to_user(bitmap, bm, bytes);

	if (i < 0)
		return i;
	return count;
}

int kvm_vm_ioctl_get_dirty_log_batch(struct kvm *kvm, __u32 cur_index)
{
    struct kvm_memslots *slots;
	struct kvm_memory_slot *memslot;
    struct kvmft_context *ctx = &kvm->ft_context;
    struct kvmft_dirty_list *dlist;
    int i;

    if (cur_index != ctx->cur_index) {
        printk("%s cur_index not same\n", __func__);
        return -EINVAL;
    }

    dlist = ctx->page_nums_snapshot_k[cur_index];

    //printk("%s cindex %d putoff %d\n", __func__, cur_index, dlist->put_off);

	//mutex_lock(&kvm->slots_lock);

	slots = kvm_memslots(kvm);

	kvm_for_each_memslot(memslot, slots) {
        if (!memslot->epoch_dirty_bitmaps.kaddr[cur_index])
            continue;
        /*
		if (!memslot->dirty_bitmap)
			continue;
        if (memslot->dirty_bitmap != memslot->epoch_dirty_bitmaps[cur_index]) {
            printk("%s sort epoch_dirty_bitmaps to cur_index %p != %p.\n",
                  __func__,
                  memslot->dirty_bitmap,
                  memslot->epoch_dirty_bitmaps[cur_index]);
            return -EINVAL;
        }
        */
        // TODO swap disabled
        //memslot->dirty_bitmap = memslot->epoch_dirty_bitmaps[!cur_index];
	}

    //if (confirm_dirty_bitmap_match(kvm, cur_index, dlist))
    //    return -EINVAL;

	spin_lock(&kvm->mmu_lock);
    for (i = dlist->put_off - 1; i >= 0; --i) {
        unsigned long gfn = dlist->pages[i];
        memslot = gfn_to_memslot(kvm, gfn);
        kvm_mmu_write_protect_single(kvm, memslot, gfn-memslot->base_gfn);
        clear_bit(gfn - memslot->base_gfn, memslot->lock_dirty_bitmap);
        clear_bit(gfn - memslot->base_gfn, memslot->epoch_dirty_bitmaps.kaddr[cur_index]);
    }
    kvm_flush_remote_tlbs(kvm);
	spin_unlock(&kvm->mmu_lock);

    if (confirm_prev_dirty_bitmap_clear(kvm, cur_index))
        return -EINVAL;

    ctx->log_full = false;

	//mutex_unlock(&kvm->slots_lock);

    return 0;
}

int kvm_vm_ioctl_ft_protect_speculative_and_prepare_next_speculative(struct kvm *kvm, __u32 cur_index)
{
	struct kvm_memory_slot *last_memslot = NULL;
    struct kvm_memslots *slots;
    struct kvmft_context *ctx = &kvm->ft_context;
    struct kvmft_dirty_list *dlist;
    int i, count, start;

    // TODO spcl_backup_dirty_list is used by other purpose
    return -1;

    dlist = ctx->page_nums_snapshot_k[cur_index];

    // only protect pages in spcl_backup_dirty_list spcl_backup_dirty_num
    // clear lock_dirty_bitmap for all
    slots = kvm_memslots(kvm);

	spin_lock(&kvm->mmu_lock);

    count = 500;
    if (dlist->put_off < 500)
        count = dlist->put_off;
    start = dlist->put_off - count;
    ctx->spcl_backup_dirty_num = count;

    for (i = 0; i < start; i++) {
        unsigned long gfn = dlist->pages[i];
        if (!last_memslot || !in_memslot(last_memslot, gfn))
            last_memslot = gfn_to_memslot(kvm, gfn);
        kvm_mmu_write_protect_single(kvm, last_memslot, gfn - last_memslot->base_gfn);
        //printk("%s %d p %lx\n", __func__, cur_index, gfn);
    }
    if (start > 0)
        kvm_flush_remote_tlbs(kvm);

    count = dlist->put_off;
    for (i = 0; i < count; i++) {
        unsigned long gfn = dlist->pages[i];
        if (!last_memslot || !in_memslot(last_memslot, gfn))
            last_memslot = gfn_to_memslot(kvm, gfn);
        clear_bit(gfn - last_memslot->base_gfn, last_memslot->lock_dirty_bitmap);
        //printk("%s cl %lx\n", __func__, gfn);
    }

	spin_unlock(&kvm->mmu_lock);

    memcpy(ctx->spcl_backup_dirty_list, dlist->pages + start, sizeof(dlist->pages[0]) * ctx->spcl_backup_dirty_num);

    return 0;
}

// test the speed of copying pages
static void kvmft_test_copy_all_dirty_pages(struct kvm *kvm, int *gfns, int count)
{
    static void *backup_pages[4096];
    static bool backup_pages_ok = false;
    int i;

    if (count == 0)
        return;

    if (!backup_pages_ok) {
        for (i = 0; i < 4096; i++) {
            backup_pages[i] = kmalloc(4096, GFP_KERNEL);
            // temp testing function, don't need to free
        }
        backup_pages_ok = true;
    }

    s64 start = time_in_us();

    for (i = 0; i < count; i++) {
        unsigned int gfn = gfns[i];
        void *hva = (void *)gfn_to_hva(kvm, gfn);
        memcpy_page_ermsb(backup_pages[i], hva);
    }

    s64 end = time_in_us();
    if (count > 1000)
        printk("%s %4d %ldus\n", __func__, count, end-start);
}

extern bool kvm_mmu_clear_spte_dirty_bit(struct kvm *kvm, gfn_t gfn);

static void spcl_sort_real_dirty_via_spte(struct kvm *kvm,
    struct kvmft_dirty_list *dlist)
{
    struct kvmft_context *ctx = &kvm->ft_context;
    int i, off = 0, count = dlist->spcl_put_off;
    volatile unsigned long *bitmap = dlist->spcl_bitmap;

    for (i = 0; i < count; ++i) {
        gfn_t gfn = dlist->pages[i];
        if (kvm_mmu_clear_spte_dirty_bit(kvm, gfn)) {
            ctx->spcl_backup_dirty_list[off++] = gfn;
            set_bit(i, bitmap);
        }
        /*else {
            struct kvm_memory_slot *slot = gfn_to_memslot(kvm, gfn);
            kvm_mmu_write_protect_single_fast(kvm, slot, gfn - slot->base_gfn);
            //printk("%s (%d) %d %lx not dirty in spte\n", __func__, ctx->cur_index, i, gfn);
        }*/
    }
    kvm_flush_remote_tlbs(kvm);

    i = dlist->put_off - dlist->spcl_put_off;
    BUG_ON(i < 0);
    memcpy(ctx->spcl_backup_dirty_list + off,
        dlist->pages + dlist->spcl_put_off,
        sizeof(dlist->pages[0]) * i);

    ctx->spcl_backup_dirty_num = off + i;
    //printk("%s\t%4d\t%4d\t%4d\n", __func__, off, dlist->spcl_put_off, dlist->put_off);
}

int kvm_vm_ioctl_ft_write_protect_dirty(struct kvm *kvm, __u32 cur_index)
{
	struct kvm_memory_slot *last_memslot = NULL;
    struct kvmft_context *ctx = &kvm->ft_context;
    struct kvmft_dirty_list *dlist;
    int i, count;

    if (cur_index != ctx->cur_index) {
        printk("%s %p cur_index != ctx->cur_index: %d != %d\n", __func__, ctx, cur_index, ctx->cur_index);
        return -EINVAL;
    }

    dlist = ctx->page_nums_snapshot_k[cur_index];
    count = dlist->put_off;
	#ifdef ft_debug_mode_enable
	printk("count = %d\n", count);
	printk("cur_index = %d\n", cur_index);
	#endif

	//mutex_lock(&kvm->slots_lock);

	spin_lock(&kvm->mmu_lock);
    for (i = 0; i < count; i++) {
        gfn_t gfn = dlist->pages[i];
		#ifdef ft_debug_mode_enable
		printk("kvm_vm_ioctl_ft_write_protect_dirty gfn = %x\n", gfn);
		#endif
        if (!last_memslot || !in_memslot(last_memslot, gfn))
            last_memslot = gfn_to_memslot(kvm, gfn);
        clear_bit(gfn - last_memslot->base_gfn, last_memslot->lock_dirty_bitmap);
        kvm_mmu_write_protect_single_fast(kvm, last_memslot, gfn - last_memslot->base_gfn);
    }
    if (count > 0)
        kvm_flush_remote_tlbs(kvm);
	spin_unlock(&kvm->mmu_lock);

#ifdef SPCL
    spcl_sort_real_dirty_via_spte(kvm, dlist);
#endif

    //kvmft_test_copy_all_dirty_pages(kvm, dlist->pages, count);

	//mutex_unlock(&kvm->slots_lock);

    return 0;
}

int kvm_vm_ioctl_clear_dirty_bitmap(struct kvm *kvm, __u32 cur_index)
{
    struct kvmft_context *ctx = &kvm->ft_context;
    struct kvmft_dirty_list *dlist;
    int r;

    dlist = ctx->page_nums_snapshot_k[cur_index];

    r = clear_dirty_bitmap(kvm, cur_index, dlist);
    return r;
}

int kvm_vm_ioctl_adjust_dirty_tracking(struct kvm* kvm, int diff)
{
    struct kvmft_context *ctx = &kvm->ft_context;
    int new_watermark = ctx->shared_watermark;

    if (diff > 0)
        new_watermark -= 10;
    else
        new_watermark += 10;
    if (new_watermark + 1024 < ctx->shared_page_num) {
        if (new_watermark > 0) {
            ctx->shared_watermark = new_watermark;
            printk("%s watermark to %d\n", __func__, new_watermark);
        }
    }
    return 0;
}

int kvm_vm_ioctl_adjust_epoch(struct kvm* kvm, unsigned long newepoch)
{
    kvm->vcpus[0]->epoch_time_in_us = newepoch;
    //printk("%s new epoch is %lu\n", __func__, newepoch);

    return 0;
}

ssize_t do_tcp_sendpage_frag3(struct sock *sk, struct page *page, int *offsets,
             int fcount, size_t fsize, int flags);

int ktcp_send(struct socket *sock, char *buf, int len)
{
    struct msghdr msg;
    struct iovec iov;
    int size, done = 0;
    mm_segment_t oldfs;

/*
	msg.msg_controllen = 0; //cocotion
    msg.msg_flags = MSG_DONTWAIT | MSG_NOSIGNAL; //cocotion
    msg.msg_name = 0; //cocotion
    msg.msg_namelen = 0; //cocotion
*/

    while (done < len) {
        iov.iov_base = buf + done;
        iov.iov_len = len - done;

        //msg.msg_control = NULL;
        msg.msg_controllen = 0; //cocotion
        msg.msg_flags = MSG_DONTWAIT | MSG_NOSIGNAL; //cocotion
        //msg.msg_iov = &iov;
        //msg.msg_iovlen = 1;
	#if LINUX_VERSION_CODE < KERNEL_VERSION(3,19,0)
      		msg.msg_iov = &iov;
      		msg.msg_iovlen = 1;
	#else
	     iov_iter_init(&msg.msg_iter, READ, &iov, 1, len - done);
	#endif

        msg.msg_name = 0; //cocotion
        msg.msg_namelen = 0; //cocotion

        oldfs = get_fs();
        set_fs(KERNEL_DS);
		size = sock_sendmsg(sock, &msg);
        set_fs(oldfs);

        if (size == -EAGAIN)
            continue;
        else if (size < 0)
            return size;
        else
            done += size;
    }
    return done;
}

// 32 * 4 bytes
static inline int memcmp_avx_128_fake(uint8_t *a, uint8_t *b, int offset, int *offsets, int *offsets_off)
{
    unsigned long eflags0, eflags1, eflags2, eflags3;
    int result;
    int index = *offsets_off;

    eflags0 = !(get_cycles() % 5);
    eflags1 = !(get_cycles() % 5);
    eflags2 = !(get_cycles() % 5);
    eflags3 = !(get_cycles() % 5);

    if (eflags0) {
        offsets[index++] = offset;
    }
    if (eflags1) {
        offsets[index++] = offset + 32;
    }
    if (eflags2) {
        offsets[index++] = offset + 64;
    }
    if (eflags3) {
        offsets[index++] = offset + 96;
    }

    *offsets_off = index;

    result = eflags0 | (eflags1 << 1) | (eflags2 << 2) | (eflags3 << 3);

    return result;
}

static inline int memcmp_avx_32(uint8_t *a, uint8_t *b)
{
    unsigned long eflags;

    //kernel_fpu_begin();

    asm volatile("vmovdqa %0,%%ymm0" : : "m" (a[0]));
    asm volatile("vmovdqa %0,%%ymm1" : : "m" (b[0]));

    asm volatile("vxorpd %ymm0,%ymm1,%ymm2");
    asm volatile("vxorpd %ymm3,%ymm3,%ymm3");
    asm volatile("vptest %ymm2, %ymm3");
    asm volatile("pushf \n\t pop %0" : "=&r"(eflags));

    //kernel_fpu_end();

    return !(eflags & X86_EFLAGS_CF);
}

// gfn | 1
// size
// header
// content
static inline int transfer_16x8_page_diff(unsigned long gfn,
                                          struct page *page1,
                                          struct page *page2,
                                          c16x8_header_t *header,
                                          int *offsets)
{
    char *backup = kmap_atomic(page1);
    char *page = kmap_atomic(page2);
    int i;
    int offsets_off = 0;

    header->gfn = gfn << 12 | 1;
    memset(header->h, 0, sizeof(header->h));

    // TODO disable diff
#if 0
    for (i = 0; i < 4096; i += 32) {
        int j = i / 32;
        if (j < 32) {
            offsets[offsets_off++] = i;
            header->h[i / 256] |= (1 << ((i % 256) / 32));
        }
    }
    goto mock_out;
#endif

    kernel_fpu_begin();

    for (i = 0; i < 4096; i += 32) {
        int r = memcmp_avx_32(backup + i, page + i);
        if (r) {
            offsets[offsets_off++] = i;
            header->h[i / 256] |= (1 << ((i % 256) / 32));
        }
    }

    kernel_fpu_end();

mock_out:
    header->size = sizeof(header->h) + offsets_off * 32;

    kunmap_atomic(backup);
    kunmap_atomic(page);

    return offsets_off;
}

static inline int memcmp_avx_128(uint8_t *a, uint8_t *b, int offset, int *offsets, int *offsets_off)
{
    unsigned long eflags0, eflags1, eflags2, eflags3;
    int result;
    int index = *offsets_off;

    //kernel_fpu_begin();

    asm volatile("prefetchnta %0" : : "m" (a[0]));
    asm volatile("prefetchnta %0" : : "m" (b[0]));
    asm volatile("prefetchnta %0" : : "m" (a[32]));
    asm volatile("prefetchnta %0" : : "m" (b[32]));

    asm volatile("vmovdqa %0,%%ymm0" : : "m" (a[0]));
    asm volatile("vmovdqa %0,%%ymm1" : : "m" (b[0]));
    asm volatile("vmovdqa %0,%%ymm4" : : "m" (a[32]));
    asm volatile("vmovdqa %0,%%ymm5" : : "m" (b[32]));

    asm volatile("prefetchnta %0" : : "m" (a[64]));
    asm volatile("prefetchnta %0" : : "m" (b[64]));
    asm volatile("prefetchnta %0" : : "m" (a[96]));
    asm volatile("prefetchnta %0" : : "m" (b[96]));

    asm volatile("vmovdqa %0,%%ymm8" : : "m" (a[64]));
    asm volatile("vmovdqa %0,%%ymm9" : : "m" (b[64]));
    asm volatile("vmovdqa %0,%%ymm12" : : "m" (a[96]));
    asm volatile("vmovdqa %0,%%ymm13" : : "m" (b[96]));

    asm volatile("vxorpd %ymm0,%ymm1,%ymm2");
    asm volatile("vxorpd %ymm3,%ymm3,%ymm3");
    asm volatile("vptest %ymm2, %ymm3");
    asm volatile("pushf \n\t pop %0" : "=&r"(eflags0));
    eflags0 = !(eflags0 & X86_EFLAGS_CF);

    asm volatile("vxorpd %ymm4,%ymm5,%ymm6");
    asm volatile("vxorpd %ymm7,%ymm7,%ymm7");
    asm volatile("vptest %ymm6, %ymm7");
    asm volatile("pushf \n\t pop %0" : "=&r"(eflags1));
    eflags1 = !(eflags1 & X86_EFLAGS_CF);

    asm volatile("vxorpd %ymm8,%ymm9,%ymm10");
    asm volatile("vxorpd %ymm11,%ymm11,%ymm11");
    asm volatile("vptest %ymm10, %ymm11");
    asm volatile("pushf \n\t pop %0" : "=&r"(eflags2));
    eflags2 = !(eflags2 & X86_EFLAGS_CF);

    asm volatile("vxorpd %ymm12,%ymm13,%ymm14");
    asm volatile("vxorpd %ymm15,%ymm15,%ymm15");
    asm volatile("vptest %ymm14, %ymm15");
    asm volatile("pushf \n\t pop %0" : "=&r"(eflags3));
    eflags3 = !(eflags3 & X86_EFLAGS_CF);

    //kernel_fpu_end();

    if (eflags0) {
        offsets[index++] = offset;
    }
    if (eflags1) {
        offsets[index++] = offset + 32;
    }
    if (eflags2) {
        offsets[index++] = offset + 64;
    }
    if (eflags3) {
        offsets[index++] = offset + 96;
    }

    *offsets_off = index;

    result = eflags0 | (eflags1 << 1) | (eflags2 << 2) | (eflags3 << 3);

    return result;
}

// 32 * 4 bytes
static inline int memcmp_avx_128_new(uint8_t *a, uint8_t *b, int offset, int *offsets, int *offsets_off)
{
    unsigned long eflags0, eflags1, eflags2, eflags3;
    int result;
    int index = *offsets_off;

    //kernel_fpu_begin();

    asm volatile("vxorpd %ymm0,%ymm0,%ymm0");

    asm volatile("vmovdqa %0,%%ymm1" : : "m" (a[0]));
    asm volatile("vxorpd %0,%%ymm1,%%ymm1" : : "m" (b[0]));
    asm volatile("vptest %ymm1, %ymm0");
    asm volatile("pushf \n\t pop %0" : "=&r"(eflags0));
    eflags0 = !(eflags0 & X86_EFLAGS_CF);

    asm volatile("vmovdqa %0,%%ymm2" : : "m" (a[32]));
    asm volatile("vxorpd %0,%%ymm2,%%ymm2" : : "m" (b[32]));
    asm volatile("vptest %ymm2, %ymm0");
    asm volatile("pushf \n\t pop %0" : "=&r"(eflags1));
    eflags1 = !(eflags1 & X86_EFLAGS_CF);

    asm volatile("vmovdqa %0,%%ymm3" : : "m" (a[64]));
    asm volatile("vxorpd %0,%%ymm3,%%ymm3" : : "m" (b[64]));
    asm volatile("vptest %ymm3, %ymm0");
    asm volatile("pushf \n\t pop %0" : "=&r"(eflags2));
    eflags2 = !(eflags2 & X86_EFLAGS_CF);

    asm volatile("vmovdqa %0,%%ymm4" : : "m" (a[96]));
    asm volatile("vxorpd %0,%%ymm4,%%ymm4" : : "m" (b[96]));
    asm volatile("vptest %ymm4, %ymm0");
    asm volatile("pushf \n\t pop %0" : "=&r"(eflags3));
    eflags3 = !(eflags3 & X86_EFLAGS_CF);

    //kernel_fpu_end();

    if (eflags0) {
        offsets[index++] = offset;
    }
    if (eflags1) {
        offsets[index++] = offset + 32;
    }
    if (eflags2) {
        offsets[index++] = offset + 64;
    }
    if (eflags3) {
        offsets[index++] = offset + 96;
    }

    *offsets_off = index;

    result = eflags0 | (eflags1 << 1) | (eflags2 << 2) | (eflags3 << 3);

    return result;
}

static void transfer_finish_callback(struct kvm *kvm, unsigned long gfn, int trans_index);

static inline int transfer_16x8_page_with_offs(struct socket *psock,
                                               unsigned long gfn,
                                               struct page *page1,
                                               struct page *page2,
                                               c16x8_header_t *header,
                                               int *offsets,
                                               int offsets_off,
                                               struct kvm *kvm,
                                               int trans_index,
                                               int run_serial,
                                               bool check_modify,
                                               bool more)
{
    struct zerocopy_callback_arg *arg;
    int flags = MSG_DONTWAIT | MSG_NOSIGNAL | (MSG_MORE * more);
    int err;

    err = ktcp_send(psock, header, sizeof(*header));
    if (err < 0)
        return err;

    arg = kmalloc(sizeof(*arg), GFP_KERNEL | __GFP_ZERO);
    arg->kvm = kvm;
    arg->gfn = gfn;
    arg->page1 = page1;
    arg->trans_index = trans_index;
    arg->run_serial = run_serial;
    arg->check_modify = check_modify;
//    page2->net_priv = arg;

    //printk("%s %d %lx\n", __func__, trans_index, gfn);

    do {
        err = do_tcp_sendpage_frag3(psock->sk, page2, offsets, offsets_off, 32, flags);
    } while (err == -EAGAIN);

    if (err < 0) {
        return err;
    } else if (err != offsets_off*32) {
        printk("%s do_tcp_sendpage_frag3 return %d\n", __func__, err);
        return -1;
    }

    return sizeof(*header) + offsets_off*32;
}

static struct page *find_later_backup(struct kvm *kvm,
                                      unsigned long gfn,
                                      int trans_index,
                                      int run_serial);

// gfn | 1
// size
// header
// content
static inline int transfer_16x8_page(struct socket *psock,
                                     unsigned long gfn,
                                     struct page *page1,
                                     struct page *page2,
                                     struct kvm *kvm,
                                     int trans_index,
                                     int run_serial,
                                     bool check_modify,
                                     bool more)
{
    struct xmit_req *req = &xmit_reqs[trans_index][xmit_off[trans_index]];
    c16x8_header_t header;
    int offsets_off;
    int offsets[128];

retry:
    offsets_off = transfer_16x8_page_diff(gfn,
                                          page1,
                                          page2,
                                          &header,
                                          offsets);

    #ifdef PAGE_TRANSFER_TIME_MEASURE
    if (page_transfer_offsets_off < 1024) {
        page_transfer_offsets[page_transfer_offsets_off++] = offsets_off;
    }
    #endif

    if (offsets_off == 0) {
        if (check_modify && (page2 = find_later_backup(kvm, gfn, trans_index, run_serial))) {
            check_modify = false;
            goto retry;
        } else
            transfer_finish_callback(kvm, gfn, trans_index);
        return 0;
    }

    // TODO disable transfer
    //transfer_finish_callback(kvm, gfn, trans_index);
    //return 0;

    //printk("%s %lx @%d-%d\n", __func__, gfn, trans_index, xmit_off[trans_index]);

/*
    req->psock = psock;
    req->gfn = gfn;
    req->page1 = page1;
    req->page2 = page2;
    req->offsets_off = offsets_off;
    req->trans_index = trans_index;
    req->run_serial = run_serial;
    req->check_modify = check_modify;
    req->more = more;
    smp_mb();
    xmit_kthread_notify_off(kvm, ++xmit_off[trans_index]);

    return sizeof(req->header) + offsets_off*32;
    */

    return transfer_16x8_page_with_offs(psock,
                                        gfn,
                                        page1,
                                        page2,
                                        &header,
                                        offsets,
                                        offsets_off,
                                        kvm,
                                        trans_index,
                                        run_serial,
                                        check_modify,
                                        more);
}

static int wait_for_next_transfer(struct kvm *kvm)
{
    int ret;
    do {
        wait_event_interruptible(kvm->trans_queue_event,
                                 kfifo_len(&kvm->trans_queue) > 0 ||
                                 kthread_should_stop());
        if (kthread_should_stop()) {
            return -1;
        }
    } while (kfifo_get(&kvm->trans_queue, &ret) == 0);
    return ret;
}

static void queue_and_notify_next_transfer(struct kvm *kvm, int index)
{
    kfifo_put(&kvm->trans_queue, &index);
    wake_up(&kvm->trans_queue_event);
}

#ifdef PAGE_TRANSFER_TIME_MEASURE
static void dump_page_transfer_times(void)
{
    int i;

    for (i = 0; i < page_transfer_end_times_off; i++)
        printk("%s\tstart\t%ld\t%ld\t%d\n", __func__,
            page_transfer_start_times[i],
            page_transfer_end_times[i],
            page_transfer_offsets[i]);
}
#endif

static int send_mdt(struct kvm *kvm, int trans_index);

static int wait_for_mdt_and_transfer_complete(struct kvm *kvm, int trans_index, int *len)
{
    struct kvmft_context *ctx = &kvm->ft_context;
    struct kvmft_master_slave_conn_info *info =
        &ctx->master_slave_info[trans_index];
    int ret, ret0, i;

    //printk("%s %d\n", __func__, *len);

    do {
        {
            #ifdef PAGE_TRANSFER_TIME_MEASURE
            s64 done_time = time_in_us();
            if (done_time - transfer_start_time > 20000) {
                printk("%s before_wait, already takes %ldms %ld %ld\n", __func__, (done_time - transfer_start_time) / 1000, done_time, transfer_end_time);
            }
            #endif
        }
        ret0 = wait_event_interruptible(kvm->mdt_event,
                                        !atomic_read(&kvm->pending_page_num[trans_index]) ||
                                        __sync_fetch_and_add(&kvm->mdt.put_off, 0) - kvm->mdt.get_off > 0);

        if (atomic_read(&kvm->pending_page_num[trans_index]) == 0) {
            // TODO how to check trans_ret error?
            //*len += ctx->trans_ret;
            modified_during_transfer_list_reset(kvm);

            #ifdef PAGE_TRANSFER_TIME_MEASURE
            transfer_end_time = time_in_us();
            if (transfer_end_time - transfer_start_time > 8000) {
                printk("%s transfer takes %ldms %ld %ld\n", __func__, (transfer_end_time - transfer_start_time) / 1000, transfer_start_time, transfer_end_time);
                printk("%s mdt put_off %d\n", __func__, kvm->mdt.put_off);
                dump_page_transfer_times();
            }
            transfer_start_time = 0;
            transfer_end_time = 0;
            page_transfer_end_times_off = 0;
            page_transfer_offsets_off = 0;
            #endif

            for (i = 1; i < info->nsocks; ++i) {
                //printk("%s len = %d %d %d\n", __func__, *len, i, info->trans_ret[i]);
                *len += info->trans_ret[i];
                info->trans_ret[i] = 0;
            }

            return 0;
        }

        if (kvm->mdt.put_off > kvm->mdt.get_off) {
            ret = send_mdt(kvm, trans_index);
            if (ret < 0) {
                return ret;
            }
            //printk("%s send_mdt %d\n", __func__, ret);
            *len += ret;
        }

        if (ret0 != 0) {
            {
                #ifdef PAGE_TRANSFER_TIME_MEASURE
                s64 done_time = time_in_us();
                if (done_time - transfer_start_time > 20000) {
                    printk("%s return intr to qemu, already takes %ldms %ld %ld\n", __func__, (done_time - transfer_start_time) / 1000, done_time, transfer_end_time);
                }
                #endif
            }
            return -EINTR;
        }
    } while (true);
    return 0;
}

static void transfer_finish_callback(struct kvm *kvm, unsigned long gfn, int trans_index)
{

	struct kvm_memory_slot *memslot = NULL;

    //printk("%s %d pending_page_num = %d\n", __func__, trans_index, atomic_read(&kvm->pending_page_num[trans_index]) - 1);
    #ifdef PAGE_TRANSFER_TIME_MEASURE
    if (page_transfer_end_times_off < 1024) {
        page_transfer_end_times[page_transfer_end_times_off++] = time_in_us();
    } else {
        printk("%s page_transfer_end_times_off reset\n", __func__);
        page_transfer_end_times_off = 0;
    }
    #endif
    if (atomic_dec_return(&kvm->pending_page_num[trans_index]) == 0) {
        #ifdef PAGE_TRANSFER_TIME_MEASURE
        s64 done_time = time_in_us();
        if (done_time - transfer_start_time > 20000) {
            printk("%s pending=0 takes %ldms %ld %ld\n", __func__, (done_time - transfer_start_time) / 1000, done_time, transfer_end_time);
        }
        #endif
        //printk("%s mdt %d/%d\n", __func__, kvm->mdt.put_off, kvm->ft_context.page_nums_snapshot_k[trans_index]->put_off);
        smp_mb();
        wake_up(&kvm->mdt_event);
    }

    //printk("%s %lx %d\n", __func__, gfn, kvm->pending_page_num[trans_index]);

    memslot = gfn_to_memslot(kvm, gfn);
    if (memslot)
        clear_bit(gfn - memslot->base_gfn, memslot->epoch_dirty_bitmaps.kaddr[trans_index]);
}

/*
static void kvm_shm_tcp_get_callback(struct page *page)
{
	struct zerocopy_callback_arg *arg = page->net_priv;

    if (arg) {
        atomic_inc(&arg->counter);
    }
}
*/

static int set_transfer_return_backup(struct kvm *kvm, unsigned long gfn)
{
    struct kvm_memory_slot *slot;

    slot = gfn_to_memslot(kvm, gfn);
    return test_and_set_bit(gfn - slot->base_gfn, slot->backup_transfer_bitmap);
}

#ifdef ENABLE_SWAP_PTE
static int clear_transfer_return_old(struct kvm *kvm, unsigned long gfn)
{
    struct kvm_memory_slot *slot;

    slot = gfn_to_memslot(kvm, gfn);
    return test_and_clear_bit(gfn - slot->base_gfn, slot->backup_transfer_bitmap);
}
#endif

static void clear_backup_transfer_bitmap(struct kvm *kvm, unsigned long gfn)
{
    struct kvm_memory_slot *slot;

    slot = gfn_to_memslot(kvm, gfn);
    clear_bit(gfn - slot->base_gfn, slot->backup_transfer_bitmap);
}

#if 0
static void kvm_shm_tcp_put_callback(struct page *page)
{
    struct zerocopy_callback_arg *arg = page->net_priv;

    return;

    if (arg && atomic_dec_return(&arg->counter) == 0) {
        struct page *backup = NULL;
        // TODO disable mdt
        if (false && arg->check_modify) {
            // for gfn_to_page
            kvm_release_page_clean(page);
#ifdef ENABLE_SWAP_PTE
            // if bit still set, then nothing happened.
            // else if bit cleared, we need to re-transmit.
            if (!clear_transfer_return_old(arg->kvm, arg->gfn)) {
                #ifdef DEBUG_SWAP_PTE
                printk("%s %lx switch PTE failed, need to transfer backup again.\n", __func__, arg->gfn);
                #endif
                backup = find_later_backup(arg->kvm,
                                           arg->gfn,
                                           arg->trans_index,
                                           arg->run_serial);
            }
#else
            backup = find_later_backup(arg->kvm,
                                       arg->gfn,
                                       arg->trans_index,
                                       arg->run_serial);
#endif
        }
        if (backup != NULL) {
            arg->page2 = backup;
            modified_during_transfer_list_add(arg->kvm, arg);
        } else {
            transfer_finish_callback(arg->kvm, arg->gfn, arg->trans_index);
            kfree(arg);
        }
        page->net_priv = NULL;
    }
}
#endif

static struct page *find_later_backup(struct kvm *kvm,
                                      unsigned long gfn,
                                      int trans_index,
                                      int run_serial)
{
    struct kvmft_context *ctx = &kvm->ft_context;
    struct kvmft_master_slave_conn_info *info;
    struct kvm_memory_slot *slot;
    volatile void **bitmaps;
    volatile unsigned int **gfn_to_put_off;
    unsigned long start_addr;
    int off;

    slot = gfn_to_memslot(kvm, gfn);
    gfn_to_put_off = (volatile unsigned int **)slot->epoch_gfn_to_put_offs.kaddr;
    bitmaps = (volatile void **)slot->epoch_dirty_bitmaps.kaddr;
    start_addr = gfn - slot->base_gfn;

    off = trans_index;
    do {
        off = (off + 1) % ctx->max_desc_count;
        info = &ctx->master_slave_info[off];
        if (info->run_serial <= run_serial)
            break;
        else {
            volatile void *bitmap = bitmaps[off];
#ifdef DEBUG_SWAP_PTE
            //printk("%s index %d off %d test_bit %d\n", __func__, trans_index, off, test_bit(start_addr, bitmap));
#endif
            if (test_bit(start_addr, bitmap)) {
                int j = ((uint16_t *)gfn_to_put_off[off])[start_addr];
                return ctx->shared_pages_snapshot_pages[off][j];
            }
        }
    } while (1);
    return NULL;
}

static inline int zerocopy_send_one_page_diff(struct socket *psock,
                                       struct kvm *kvm,
                                       unsigned long gfn,
                                       int index,
                                       int trans_index,
                                       int run_serial,
                                       bool more)
{
    struct kvmft_context *ctx = &kvm->ft_context;
    struct page *page1, *page2;
    int ret;
    bool check_modify = false;

    page1 = ctx->shared_pages_snapshot_pages[trans_index][index];
    page2 = find_later_backup(kvm, gfn, trans_index, run_serial);

    if (page2 == NULL) {
#ifdef ENABLE_SWAP_PTE
        struct kvm_memory_slot *slot;
        slot = gfn_to_memslot(kvm, gfn);
        // when swap-pte is enabled, check_modify == true && bit is set
        if (test_and_set_bit(gfn - slot->base_gfn, slot->backup_transfer_bitmap)) {
            #ifdef DEBUG_SWAP_PTE
            printk("%s backup bit is already set, wrong!\n", __func__);
            #endif
        }
#endif
        page2 = gfn_to_page(kvm, gfn);
        check_modify = true;
    }

    ret = transfer_16x8_page(psock,
                             gfn,
                             page1,
                             page2,
                             kvm,
                             trans_index,
                             run_serial,
                             check_modify,
                             more);
    if (!ret && check_modify) {
        kvm_release_page_clean(page2);
    }
    return ret;
}

static int send_mdt(struct kvm *kvm, int trans_index)
{
    struct kvmft_context *ctx = &kvm->ft_context;
    struct kvmft_master_slave_conn_info *info =
        &ctx->master_slave_info[trans_index];
    struct socket *psock;
    struct ft_modified_during_transfer_list *mdt = &kvm->mdt;
    int i, ret, len = 0;

    psock = info->socks[0];

    for (i = mdt->get_off; i < mdt->put_off; ++i) {
        struct zerocopy_callback_arg *arg = mdt->records[i];
        if (arg == NULL)
            return len;
        ret = transfer_16x8_page(psock,
                                 arg->gfn,
                                 arg->page1,
                                 arg->page2,
                                 kvm,
                                 arg->trans_index,
                                 arg->run_serial,
                                 false,
                                 i < mdt->put_off - 1);
        if (ret < 0) {
            return ret;
        }
        kfree(arg);
        mdt->records[i] = NULL;
        len += ret;
        mdt->get_off++;
    }

    return len;
}

static void clear_all_backup_transfer_bitmap(struct kvm *kvm, int index)
{
    struct kvmft_context *ctx = &kvm->ft_context;
    struct kvmft_dirty_list *list = ctx->page_nums_snapshot_k[index];
    struct kvm_memory_slot *slot;
    int i;

    for (i = 0; i < list->put_off; i++) {
        unsigned long gfn = list->pages[i];
        slot = gfn_to_memslot(kvm, gfn);
        clear_bit(gfn - slot->base_gfn, slot->backup_transfer_bitmap);
    }
}

static inline int gfn_in_diff_list(struct kvm *kvm,
                                unsigned long gfn)
{
    struct kvm_memory_slot *slot;
    slot = gfn_to_memslot(kvm, gfn);
    return test_and_set_bit(gfn - slot->base_gfn,
            slot->backup_transfer_bitmap);
}

static inline void notify_diff_req_list_change(struct kvm *kvm, int index)
{
    struct kvmft_context *ctx;

    ctx = &kvm->ft_context;
    ctx->diff_req_list_cur = ctx->diff_req_list[index];
    wake_up(&kvm->diff_req_event);
}

static void take_over_diff_req_list(struct kvm *kvm)
{
    struct kvmft_context *ctx;

    ctx = &kvm->ft_context;
    ctx->diff_req_list_cur = NULL;
    wake_up(&kvm->diff_req_event);
}

static int transfer_diff_req_list(struct kvm *kvm,
                                struct socket *psock,
                                int trans_index)
{
    struct kvmft_context *ctx = &kvm->ft_context;
    struct kvmft_master_slave_conn_info *info =
        &ctx->master_slave_info[trans_index];
    struct diff_req_list *list = ctx->diff_req_list[trans_index];
    int count, i, ret = 0, len = 0;
    int run_serial = info->run_serial;
    int next_trans_index = (trans_index + 1) % ctx->max_desc_count;

    int helped = 0;

    count = list->off;
    if (count == 0)
        return 0;

    for (i = 0; i < count; i++) {
        struct diff_req *req = list->reqs[i];
        unsigned long gfn = req->gfn;

        if (req->offsets_off == DIFF_REQ_OFFSETS_OFF_NO) {
            struct kvm_memory_slot *slot = req->memslot;
            unsigned long gfn_off = gfn - slot->base_gfn;
            int index = ((uint16_t *)slot->epoch_gfn_to_put_offs.kaddr[trans_index])[gfn_off];
            ret = zerocopy_send_one_page_diff(psock,
                                              kvm,
                                              gfn,
                                              index,
                                              trans_index,
                                              run_serial,
                                              i < count - 1);
        } else if (req->offsets_off > 0) {
            struct kvm_memory_slot *slot = req->memslot;
            unsigned long gfn_off = gfn - slot->base_gfn;
            int next_index = ((uint16_t *)slot->epoch_gfn_to_put_offs.kaddr[next_trans_index])[gfn_off];
            struct page *page = ctx->shared_pages_snapshot_pages[next_trans_index][next_index];
            ++helped;
            ret = transfer_16x8_page_with_offs(psock,
                                                gfn,
                                                NULL,
                                                page,
                                                &req->header,
                                                req->offsets,
                                                req->offsets_off,
                                                kvm,
                                                trans_index,
                                                run_serial,
                                                false,
                                                i < count - 1);
        } else {    // req->offsets_off == 0
            transfer_finish_callback(kvm, gfn, trans_index);
            continue;
        }

        if (ret < 0) {
            goto out;
        }
        len += ret;
    }
    ret = len;
    //printk("%s\thelped\t%8d\t%8d\n", __func__, helped, count);
out:
    diff_req_list_clear(list);
    return ret;
}

static int __diff_to_buf(unsigned long gfn, struct page *page1,
    struct page *page2, uint8_t *buf)
{
    c16x8_header_t *header;
    uint8_t *block;
    char *backup = kmap_atomic(page1);
    char *page = kmap_atomic(page2);
    int i;

    header = (c16x8_header_t *)buf;
    block = buf + sizeof(*header);

    header->gfn = gfn << 12 | 1;
    memset(header->h, 0, sizeof(header->h));

    kernel_fpu_begin();

    for (i = 0; i < 4096; i += 32) {
        if (memcmp_avx_32(backup + i, page + i)) {
            header->h[i / 256] |= (1 << ((i % 256) / 32));
            memcpy(block, page + i, 32);
            block += 32;
        }
    }

    kernel_fpu_end();

    if (block == buf + sizeof(*header)) {
		#ifdef ft_debug_mode_enable
        printk("warning: not found diff page\n");
		#endif
        memset(header->h, 0xff, 16 * sizeof(__u8));
        memcpy(block, page, 4096);
        block += 4096;
    }

    kunmap_atomic(backup);
    kunmap_atomic(page);

    if (block == buf + sizeof(*header))
        return 0;

    header->size = sizeof(header->h) + (block - (buf + sizeof(*header)));
    return block - buf;
}

static int kvmft_diff_to_buf(struct kvm *kvm, unsigned long gfn,
    int index, uint8_t *buf, int trans_index, int run_serial)
{
    struct kvmft_context *ctx = &kvm->ft_context;
    struct page *page1, *page2;
    bool check_modify = false;
    int ret;

    page1 = ctx->shared_pages_snapshot_pages[trans_index][index];
    page2 = find_later_backup(kvm, gfn, trans_index, run_serial);

    if (page2 == NULL) {
        page2 = gfn_to_page(kvm, gfn);
        check_modify = true;
    }

    ret = __diff_to_buf(gfn, page1, page2, buf);

    if (check_modify) {
        page2 = find_later_backup(kvm, gfn, trans_index, run_serial);
        if (page2 != NULL)
            ret = __diff_to_buf(gfn, page1, page2, buf);
    }

    return ret;
}

static int spcl_transfer_check(struct kvmft_dirty_list *dlist, int index)
{
    return index < dlist->spcl_put_off &&
        !test_and_clear_bit(index, dlist->spcl_bitmap);
}

struct dirtyinfo {
	struct kvm *kvm;
	struct socket *sock;
	struct kvmft_dirty_list *dlist;
	int start;
	int end;
	int trans_index;
	int run_serial;
	int ret;
};

static int new_kvmft_transfer_list(void *info)
{
	struct dirtyinfo *ft_info = info;
	struct kvm *kvm = ft_info->kvm;
	struct kvm *sock = ft_info->sock;
	struct kvmft_dirty_list *dlist = ft_info->dlist;
	int start = ft_info->start;
	int end = ft_info->end;
	int trans_index = ft_info->trans_index;
	int run_serial = ft_info->run_serial;

    int ret, i;
    int len = 0, total = 0;
    uint8_t *buf;
    unsigned int *gfns = dlist->pages;

#ifdef PAGE_TRANSFER_TIME_MEASURE
    transfer_start_time = time_in_us();
    page_transfer_end_times_off = end;
#endif

    buf = kmalloc(64 * 1024 + 8192, GFP_KERNEL);
    if (!buf)
        return -ENOMEM;

    kvmft_tcp_unnodelay(sock);

    for (i = start; i < end; ++i) {
        unsigned long gfn = gfns[i];

#ifdef PAGE_TRANSFER_TIME_MEASURE
        page_transfer_start_times[i] = time_in_us();
#endif

#ifdef SPCL
        if (spcl_transfer_check(dlist, i))
            continue;
#endif

        len += kvmft_diff_to_buf(kvm, gfn, i, buf + len,
            trans_index, run_serial);
        if (len >= 64 * 1024) {
            ret = ktcp_send(sock, buf, len);
            if (ret < 0)
                goto free;
            total += len;
            len = 0;
        }
    }

    if (len > 0) {
        ret = ktcp_send(sock, buf, len);
        if (ret < 0)
            goto free;
        total += len;
    }

    kvmft_tcp_nodelay(sock);
/*
	p_count++;
	p_average+=abs(total-p_dirty_bytes);
	printk("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");
	printk("cocotion test diffbytes = %d\n", p_average/p_count);
	printk("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");
	*/
//	printk("cocotion test ok fucking kvm = %p, cpuid = %d\n", kvm, smp_processor_id());

#ifdef PAGE_TRANSFER_TIME_MEASURE
    transfer_end_time = time_in_us();
    if (transfer_end_time - transfer_start_time > 3000) {
        printk("%s already takes %ldms dirty page %d\n", __func__,
            (transfer_end_time - transfer_start_time) / 1000, end);
    }
    if (transfer_end_time - transfer_start_time > 10000) {
        dump_page_transfer_times();
    }

#endif

    ret = total;
free:
    kfree(buf);

	ft_info->ret = ret;


	return ret;

}

//void sched_yield(void){
//	struct rq_flags rf;
/*    struct rq *rq;

    local_irq_disable();
    rq = this_rq();
    rq_lock(rq, &rf);

    schedstat_inc(rq->yld_count);
    current->sched_class->yield_task(rq);

    preempt_disable();
    rq_unlock(rq, &rf);
    sched_preempt_enable_no_resched();

    schedule();
*/

//}

static int kvmft_transfer_list(struct kvm *kvm, struct socket *sock,
    struct kvmft_dirty_list *dlist, int start, int end,
    int trans_index, int run_serial)
{
    int ret, i;
    int len = 0, total = 0;
    uint8_t *buf;
    unsigned int *gfns = dlist->pages;

#ifdef PAGE_TRANSFER_TIME_MEASURE
    transfer_start_time = time_in_us();
    page_transfer_end_times_off = end;
#endif

    buf = kmalloc(64 * 1024 + 8192, GFP_KERNEL);
    if (!buf)
        return -ENOMEM;

    kvmft_tcp_unnodelay(sock);
    //kvmft_tcp_nodelay(sock);

	int cmp_t = 0;
	int send_t = 0;
	s64 istart;


	kvm->load_pages = end;

    for (i = start; i < end; ++i) {
        unsigned long gfn = gfns[i];

#ifdef PAGE_TRANSFER_TIME_MEASURE
        page_transfer_start_times[i] = time_in_us();
#endif

#ifdef SPCL
        if (spcl_transfer_check(dlist, i))
            continue;
#endif

		istart = time_in_us();

        len += kvmft_diff_to_buf(kvm, gfn, i, buf + len,
            trans_index, run_serial);

		cmp_t+=time_in_us()-istart;

		//preempt_disable();
//		spin_lock(&transfer_lock);

		istart = time_in_us();
        if (len >= 64 * 1024) {
            ret = ktcp_send(sock, buf, len);
            if (ret < 0)
                goto free;
            total += len;
            len = 0;
        }
		send_t += time_in_us()-istart;

        int tmp_send_r;
	    if(send_t > 0)
		    tmp_send_r = total/send_t;
	    if(tmp_send_r > 200)
		    kvm->current_send_rate = tmp_send_r;
//		spin_unlock(&transfer_lock);
		//preempt_enable(); //cocotion fucking think
		//sched_yield();
		//schedule();
	}

//	spin_lock(&transfer_lock);

	istart = time_in_us();
    if (len > 0) {
        ret = ktcp_send(sock, buf, len);
        if (ret < 0)
            goto free;
        total += len;
    }
	send_t += time_in_us()-istart;

	int tmp_send_r;
	if(send_t > 0)
		tmp_send_r = total/send_t;
	if(tmp_send_r > 200)
		kvm->current_send_rate = tmp_send_r;

//	spin_unlock(&transfer_lock);

    kvmft_tcp_nodelay(sock);
/*
	p_count++;
	p_average+=abs(total-p_dirty_bytes);
	printk("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");
	printk("cocotion test diffbytes = %d\n", p_average/p_count);
	printk("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");
	*/
//	printk("cocotion test ok fucking kvm = %p, cpuid = %d\n", kvm, smp_processor_id());

#ifdef PAGE_TRANSFER_TIME_MEASURE
    transfer_end_time = time_in_us();
    if (transfer_end_time - transfer_start_time > 3000) {
        printk("%s already takes %ldms dirty page %d\n", __func__,
            (transfer_end_time - transfer_start_time) / 1000, end);
    }
    if (transfer_end_time - transfer_start_time > 10000) {
        dump_page_transfer_times();
    }

#endif

    ret = total;
free:
    kfree(buf);

	if(cmp_t > 0)
		kvm->last_load_mem_rate = end*4096/cmp_t;
	if(send_t > 0)
		kvm->last_send_rate = total/send_t;
	//if(kvm->last_load_mem_rate < 200)
	//	kvm->last_load_mem_rate = 200;
	//if(kvm->last_send_rate < 100)
	//	kvm->last_send_rate = 100;
//	printk("compress time = %d, load_mem_rate = %d\n", cmp_t, kvm->load_mem_rate);
//	printk("send time = %d\n", send_t);




	return ret;
}

static int kvmft_transfer_list_old(struct kvm *kvm, struct socket *sock,
    int *gfns, int start, int end, int trans_index, int run_serial)
{
    int ret, i;
    int len = 0;

    kvmft_tcp_unnodelay(sock);
    //kvmft_tcp_cork(sock);

    for (i = start; i < end; ++i) {
        unsigned long gfn = gfns[i];

#ifdef PAGE_TRANSFER_TIME_MEASURE
        page_transfer_start_times[i] = time_in_us();
#endif

        ret = zerocopy_send_one_page_diff(sock,
                                          kvm,
                                          gfn,
                                          i,
                                          trans_index,
                                          run_serial,
                                          i < end - 1);
        if (ret < 0)
            return ret;
        len += ret;
    }

    //kvmft_tcp_uncork(sock);
    kvmft_tcp_nodelay(sock);

    return len;
}

static void __decrement_pending_tran_num(struct kvm *kvm,
    struct kvmft_context *ctx)
{
    if (__sync_add_and_fetch(&ctx->pending_tran_num, -1) == 0)
        wake_up(&ctx->tran_event);
}

static int diff_and_tran_kthread_func(void *opaque)
{
    struct diff_and_tran_kthread_descriptor *desc = opaque;
    struct kvm *kvm = desc->kvm;
    struct kvmft_context *ctx = &kvm->ft_context;
    struct kvmft_master_slave_conn_info *info =
        &ctx->master_slave_info[desc->trans_index];
    struct socket *sock = info->socks[desc->conn_index];
    struct kvmft_dirty_list *dlist = ctx->page_nums_snapshot_k[desc->trans_index];
    struct sched_param param = {.sched_priority = MAX_RT_PRIO - 1};
    int run_serial = 0;
    int start, end;
    int i, ret = 0, len;

    use_mm(kvm->qemu_mm);

//    sched_setscheduler(current, SCHED_FIFO, &param);
    //sched_setscheduler(current, SCHED_RR, &param);

    while (!kthread_should_stop()) {
        wait_event_interruptible(info->events[desc->conn_index],
            (dlist->put_off > 0 && info->run_serial != run_serial) || kthread_should_stop());
        if (kthread_should_stop())
            break;

        run_serial = info->run_serial;
        if (dlist->put_off == 0)
            continue;

        start = desc->conn_index * dlist->put_off / desc->conn_count;
        end = (desc->conn_index + 1) * dlist->put_off / desc->conn_count;
        len = 0;

/*		struct dirtyinfo *ft_info;
		ft_info->kvm = kvm;
		ft_info->sock = sock;
		ft_info->dlist = dlist;
		ft_info->start = start;
		ft_info->end = end;
		ft_info->trans_index = desc->trans_index;
		ft_info->run_serial = run_serial;
*/

        if (end > start)
            len = kvmft_transfer_list(kvm, sock, dlist,
                start, end, desc->trans_index, info->run_serial);
// 			smp_call_function_single(7, new_kvmft_transfer_list, ft_info, true);
//		len = ft_info->ret;
        //printk("%s trans_index %d conn %d (%d=>%d)\n", __func__, desc->trans_index, desc->conn_index, start, end);
        //printk("%s (%d/%d) %d %lx\n", __func__, desc->trans_index, desc->conn_index, i, gfn);

#if 0
        kvmft_tcp_unnodelay(sock);
        kvmft_tcp_cork(sock);

        for (i = start; i < end; i++) {
            unsigned long gfn = dlist->pages[i];

#ifdef PAGE_TRANSFER_TIME_MEASURE
            page_transfer_start_times[i] = time_in_us();
#endif

            ret = zerocopy_send_one_page_diff(sock,
                                              kvm,
                                              gfn,
                                              i,
                                              desc->trans_index,
                                              info->run_serial,
                                              i < end - 1);
            if (ret < 0) {
                // TODO how to report error properly?
                info->trans_ret[desc->conn_index] = ret;
                printk("%s err %d\n", __func__, ret);
                goto out;
            }
            len += ret;
        }

        kvmft_tcp_uncork(sock);
        kvmft_tcp_nodelay(sock);
#endif
        info->trans_ret[desc->conn_index] = len;
        __decrement_pending_tran_num(kvm, ctx);
        //printk("%s trans_index %d len %d\n", __func__, desc->trans_index, len);
    }
out:
    unuse_mm(kvm->qemu_mm);
    return ret;
}

static int __wait_for_tran_num(struct kvm *kvm, int trans_index)
{
    struct kvmft_context *ctx = &kvm->ft_context;
    struct kvmft_master_slave_conn_info *info =
        &ctx->master_slave_info[trans_index];

    while (true) {
        int ret = wait_event_interruptible(ctx->tran_event,
            __sync_fetch_and_add(&ctx->pending_tran_num, 0) == 0);
        if (__sync_fetch_and_add(&ctx->pending_tran_num, 0) == 0) {
            int i, len = 0;
            for (i = 0; i < info->nsocks; ++i) {
                if (info->trans_ret[i] < 0)
                    return info->trans_ret[i];
                len += info->trans_ret[i];
                info->trans_ret[i] = 0;
            }
            return len;
        }
        if (ret != 0)
            return -EINTR;
    }
}
/*
static int diff_and_transfer_all2(void *ftinfo)
{
	struct ft_send_d *ft_d = ftinfo;
	struct kvm *kvm = ft_d->kvm;
	int trans_index = ft_d->trans_index;
	int max_conn    = ft_d->max_conn;

    struct socket *psock;
    struct kvmft_context *ctx = &kvm->ft_context;
    struct kvmft_master_slave_conn_info *info =
        &ctx->master_slave_info[trans_index];
    struct kvmft_dirty_list *dlist = ctx->page_nums_snapshot_k[trans_index];
    int count, i, ret = 0, len = 0;
    int run_serial = info->run_serial;

#ifdef ENABLE_PRE_DIFF
    int skipped = 0;
#endif

	psock = info->socks[0];

    BUG_ON(!psock);

#ifdef ENABLE_SWAP_PTE
    clear_all_backup_transfer_bitmap(kvm, trans_index);
#endif

	if (dlist->put_off == 0) {
		ft_d->ram_len = 0;
        return 0;
	}

    // wake up other diff_and_tran_kthread
    for (i = 1; i < info->nsocks; ++i)
        wake_up(&info->events[i]);

    kvm->xmit_off = 0;
    xmit_off[trans_index] = 0;
    xmit_kthread_notify_index(kvm, run_serial);

    count = dlist->put_off / max_conn;

#ifdef ENABLE_PRE_DIFF
    ctx->diff_req_list[trans_index]->diff_off = 0;
    ctx->diff_req_list[trans_index]->off = 0;
    notify_diff_req_list_change(kvm, trans_index);
#endif

    len = kvmft_transfer_list(kvm, psock, dlist,
        0, count, trans_index, run_serial);
    if (len < 0) {
		ft_d->ram_len = len;
        return len;
	}
    info->trans_ret[0] = len;
    __decrement_pending_tran_num(kvm, ctx);
    //printk("%s trans_index %d len %d\n", __func__, trans_index, len);

#if 0
    kvmft_tcp_unnodelay(psock);
    kvmft_tcp_cork(psock);

    for (i = 0; i < count; i++) {
        unsigned long gfn = dlist->pages[i];

#ifdef SPCL
        if (spcl_transfer_check(dlist, i)) {
            transfer_finish_callback(kvm, gfn, trans_index);
            continue;
        }
#endif

#ifdef PAGE_TRANSFER_TIME_MEASURE
        page_transfer_start_times[i] = time_in_us();
#endif

        //printk("%s %d %lx\n", __func__, i, gfn);
#ifdef ENABLE_PRE_DIFF
        if (gfn_in_diff_list(kvm, gfn)) {
            ++skipped;
            continue;
        }
#endif
        ret = zerocopy_send_one_page_diff(psock,
                                          kvm,
                                          gfn,
                                          i,
                                          trans_index,
                                          run_serial,
                                          i < count - 1);
        if (ret < 0) {
            return ret;
        }
        len += ret;
    }

    kvmft_tcp_uncork(psock);
    kvmft_tcp_nodelay(psock);
#endif

#ifdef ENABLE_PRE_DIFF
    take_over_diff_req_list(kvm);
    if (count > 0) {
        //if (skipped > 0)
        //    printk("%s\tskipped\t%8d\t%8d\n", __func__, skipped, count);
        ret = transfer_diff_req_list(kvm, psock, trans_index);
        if (ret < 0) {
			ft_d->ram_len = ret;
            return ret;
        }
        len += ret;
        clear_all_backup_transfer_bitmap(kvm, trans_index);
    }
#endif

    {
        #ifdef PAGE_TRANSFER_TIME_MEASURE
        s64 done_time = time_in_us();
        if (done_time - transfer_start_time > 20000) {
            printk("%s already takes %ldms %ld %ld\n", __func__, (done_time - transfer_start_time) / 1000, done_time, transfer_end_time);
        }
        #endif
    }

//    return __wait_for_tran_num(kvm, trans_index);
	ret = __wait_for_tran_num(kvm, trans_index);
	ft_d->ram_len = ret;
	return ret;
}
*/
static int diff_and_transfer_all(struct kvm *kvm, int trans_index, int max_conn)
{
    struct socket *psock;
    struct kvmft_context *ctx = &kvm->ft_context;
    struct kvmft_master_slave_conn_info *info =
        &ctx->master_slave_info[trans_index];
    struct kvmft_dirty_list *dlist = ctx->page_nums_snapshot_k[trans_index];
    int count, i, ret = 0, len = 0;
    int run_serial = info->run_serial;

#ifdef ENABLE_PRE_DIFF
    int skipped = 0;
#endif

    psock = info->socks[0];

    BUG_ON(!psock);

#ifdef ENABLE_SWAP_PTE
    clear_all_backup_transfer_bitmap(kvm, trans_index);
#endif

    if (dlist->put_off == 0)
        return 0;

    // wake up other diff_and_tran_kthread
    for (i = 1; i < info->nsocks; ++i)
        wake_up(&info->events[i]);

    kvm->xmit_off = 0;
    xmit_off[trans_index] = 0;
    xmit_kthread_notify_index(kvm, run_serial);

    count = dlist->put_off / max_conn;

#ifdef ENABLE_PRE_DIFF
    ctx->diff_req_list[trans_index]->diff_off = 0;
    ctx->diff_req_list[trans_index]->off = 0;
    notify_diff_req_list_change(kvm, trans_index);
#endif
/*
	struct dirtyinfo ft_info;
	ft_info.kvm = kvm;
	ft_info.sock = psock;
	ft_info.dlist = dlist;
	ft_info.start = 0;
	ft_info.end = count;
	ft_info.trans_index = trans_index;
	ft_info.run_serial = run_serial;
*/
    len = kvmft_transfer_list(kvm, psock, dlist,
        0, count, trans_index, run_serial);
//	new_kvmft_transfer_list(&ft_info);
	//work_on_cpu(6, new_kvmft_transfer_list, &ft_info);
//	smp_call_function_single(6, new_kvmft_transfer_list, &ft_info, true);
//	len = ft_info.ret;

    if (len < 0)
        return len;
    info->trans_ret[0] = len;
    __decrement_pending_tran_num(kvm, ctx);
    //printk("%s trans_index %d len %d\n", __func__, trans_index, len);

#if 0
    kvmft_tcp_unnodelay(psock);
    kvmft_tcp_cork(psock);

    for (i = 0; i < count; i++) {
        unsigned long gfn = dlist->pages[i];

#ifdef SPCL
        if (spcl_transfer_check(dlist, i)) {
            transfer_finish_callback(kvm, gfn, trans_index);
            continue;
        }
#endif

#ifdef PAGE_TRANSFER_TIME_MEASURE
        page_transfer_start_times[i] = time_in_us();
#endif

        //printk("%s %d %lx\n", __func__, i, gfn);
#ifdef ENABLE_PRE_DIFF
        if (gfn_in_diff_list(kvm, gfn)) {
            ++skipped;
            continue;
        }
#endif
        ret = zerocopy_send_one_page_diff(psock,
                                          kvm,
                                          gfn,
                                          i,
                                          trans_index,
                                          run_serial,
                                          i < count - 1);
        if (ret < 0) {
            return ret;
        }
        len += ret;
    }

    kvmft_tcp_uncork(psock);
    kvmft_tcp_nodelay(psock);
#endif

#ifdef ENABLE_PRE_DIFF
    take_over_diff_req_list(kvm);
    if (count > 0) {
        //if (skipped > 0)
        //    printk("%s\tskipped\t%8d\t%8d\n", __func__, skipped, count);
        ret = transfer_diff_req_list(kvm, psock, trans_index);
        if (ret < 0) {
            return ret;
        }
        len += ret;
        clear_all_backup_transfer_bitmap(kvm, trans_index);
    }
#endif

    {
        #ifdef PAGE_TRANSFER_TIME_MEASURE
        s64 done_time = time_in_us();
        if (done_time - transfer_start_time > 20000) {
            printk("%s already takes %ldms %ld %ld\n", __func__, (done_time - transfer_start_time) / 1000, done_time, transfer_end_time);
        }
        #endif
    }

    return __wait_for_tran_num(kvm, trans_index);

    //printk("%s %d\n", __func__, len);
    /*
    ret = wait_for_mdt_and_transfer_complete(kvm, trans_index, &len);
    if (ret != 0) {
        kvm->trans_len[trans_index] = len;
        return ret;
    }

    return len;
    */
}

static inline struct diff_req_list *wait_for_next_diff_req_list(struct kvm *kvm)
{
    struct kvmft_context *ctx = &kvm->ft_context;
    wait_event_interruptible(kvm->diff_req_event,
                             ctx->diff_req_list_cur != NULL ||
                                 kthread_should_stop());
    return (struct diff_req_list *)ctx->diff_req_list_cur;
}

static inline int handle_diff_request(struct kvm *kvm,
                                    struct diff_req_list *list,
                                    int off)
{
    struct kvmft_context *ctx = &kvm->ft_context;
    struct diff_req *req;
    struct page *page1, *page2;
    struct kvm_memory_slot *slot;
    int next_epoch, gfn_index, gfn_off;

    if (off >= list->off) {
        return -1;
    }

    req = list->reqs[off];
    slot = req->memslot;
    gfn_off = req->gfn - slot->base_gfn;

    gfn_index = ((uint16_t *)slot->epoch_gfn_to_put_offs.kaddr[list->trans_index])[gfn_off];
    page1 = ctx->shared_pages_snapshot_pages[list->trans_index][gfn_index];

    next_epoch = (list->trans_index + 1) % ctx->max_desc_count;
    gfn_index = ((uint16_t *)slot->epoch_gfn_to_put_offs.kaddr[next_epoch])[gfn_off];
    page2 = ctx->shared_pages_snapshot_pages[next_epoch][gfn_index];

    req->offsets_off = transfer_16x8_page_diff(req->gfn,
                                              page1,
                                              page2,
                                              &req->header,
                                              req->offsets);
    return 0;
}
/*
int work_mycpu(int cpu, void *data)
{
	int err;
	get_online_cpus();
	if(!cpu_online(cpu))
		err = -EINVAL;
	else {
		if (in_interrupt())
			err = work_on_cpu(cpu, diff_and_transfer_all2, data);
		else
			smp_call_function_single(cpu, diff_and_transfer_all2, data, true);
	}
	put_online_cpus();
	return err;

}
*/

static int diff_thread_func(void *data)
{
    struct kvm *kvm = data;
    struct kvmft_context *ctx = &kvm->ft_context;

    allow_signal(SIGKILL);

    while (!kthread_should_stop()) {
        struct diff_req_list *list;
        int off;

        list = wait_for_next_diff_req_list(kvm);
        if (list == NULL) {
            continue;
        }

        off = list->diff_off;

        do {
            int ret = handle_diff_request(kvm, list, off);
            if (ret != 0) {
                break;
            }
            off++;
        } while (ctx->diff_req_list_cur == list);

        list->diff_off = off;
    }

    return 0;
}

int kvm_start_kernel_transfer(struct kvm *kvm,
                              int trans_index,
                              int ram_fd,
                              int intr,
                              int conn_index,
                              int max_conn)
{
    struct kvmft_context *ctx = &kvm->ft_context;
    struct kvmft_master_slave_conn_info *info =
        &ctx->master_slave_info[trans_index];
    struct socket *sock;
    int err;
    int ram_len, ret;

    if (max_conn <= 0 || max_conn > 8) {
        return -EINVAL;
    }

    if (conn_index < 0 || conn_index >= max_conn) {
        return -EINVAL;
    }

    #ifdef PAGE_TRANSFER_TIME_MEASURE
    if (transfer_start_time == 0 && conn_index == 0) {
        transfer_start_time = time_in_us();
    }
    #endif

    if (conn_index == 0 && !intr) {
        struct kvmft_dirty_list *list = ctx->page_nums_snapshot_k[trans_index];
        if (atomic_read(&kvm->pending_page_num[trans_index]) != 0)
            return -EINVAL;
        //atomic_set(&kvm->pending_page_num[trans_index], list->put_off);
        dirty_page = list->put_off;

        ctx->pending_tran_num = max_conn;

        //ept_gva_reset(list->put_off);
        //return 0;
    }

    //printk("%s index %d intr %d conn_index %d\n", __func__, trans_index, intr, conn_index);

    if (conn_index == 0) {
        if (intr) {
            {
                #ifdef PAGE_TRANSFER_TIME_MEASURE
                s64 done_time = time_in_us();
                if (done_time - transfer_start_time > 20000) {
                    printk("%s return from intr, already takes %ldms %ld %ld\n", __func__, (done_time - transfer_start_time) / 1000, done_time, transfer_end_time);
                }
                #endif
            }

            return __wait_for_tran_num(kvm, trans_index);
            /*
            ret = wait_for_mdt_and_transfer_complete(kvm, trans_index, &kvm->trans_len[trans_index]);
            if (ret == 0) {
                ret = kvm->trans_len[trans_index];
                kvm->trans_len[trans_index] = 0;
            }
            return ret;
            */
        }
    }

    sock = info->socks[conn_index];

    if (conn_index == 0) {

        ram_len = diff_and_transfer_all(kvm, trans_index, max_conn);
	  	//smp_call_function_single(7, diff_and_transfer_all2, &ft_d, true);
		//work_on_cpu(7, diff_and_transfer_all2, &ft_d);
		//int err = work_mycpu(7, &ft_d);
			//diff_and_transfer_all2(&ft_d);
		//	printk("cocotion test cannot work on single CPU here\n");
		//}
		//ram_len = ft_d.ram_len;
        if (ram_len < 0) {
            return ram_len;
        }
    } else {
        // TODO
        //return diff_and_transfer_second_half(kvm, trans_index, conn_index, max_conn);
    }

    return ram_len;
}

#if 0
int kvmft_vcpu_alloc_shared_all_state(struct kvm_vcpu *vcpu,
        struct kvm_vcpu_get_shared_all_state *state)
{
    struct page *page;
    size_t size, order;
    int ret;

    size = sizeof(struct kvm_cpu_state);
    size = size / 4096 + !!(size % 4096);
    order = ilog2(size);
    if ((1 << order) < size)
        ++order;

    page = alloc_pages(GFP_KERNEL, order);
    if (!page)
        return -ENOMEM;

    vcpu->shared_all_state_page = page;
    vcpu->shared_all_state = kmap(page);
    vcpu->shared_all_state_order = order;

    state->pfn = page_to_pfn(page);
    state->order = order;
    return 0;
}
#endif

void kvmft_gva_spcl_unprotect_page(struct kvm *kvm, unsigned long gfn)
{
    struct kvmft_context *ctx;
    struct kvmft_dirty_list *dlist;
    int put_index;

	if (unlikely(!kvm_shm_is_enabled(kvm)))
		return;

	ctx = &kvm->ft_context;
    dlist = ctx->page_nums_snapshot_k[ctx->cur_index];

    if (unlikely(!dlist->gva_spcl_pages))
        dlist->gva_spcl_pages = kzalloc(sizeof(dlist->gva_spcl_pages[0]) *
            ctx->shared_page_num, GFP_KERNEL);

    if (unlikely(!dlist->gva_spcl_pages))
        return;

    put_index = __sync_fetch_and_add(&dlist->gva_spcl_pages_off, 1);
    if (unlikely(put_index >= ctx->shared_page_num)) {
        __sync_fetch_and_add(&dlist->gva_spcl_pages_off, -1);
        return;
    }

	dlist->gva_spcl_pages[put_index] = gfn;
}

int kvmft_ioctl_set_master_slave_sockets(struct kvm *kvm,
    struct kvmft_set_master_slave_sockets *socks)
{
    struct kvmft_context *ctx = &kvm->ft_context;
    struct kvmft_master_slave_conn_info *info;
    int i;

    if (socks->trans_index >= KVM_MAX_MIGRATION_DESC)
        return -EINVAL;

    if (!socks->nsocks)
        return -EINVAL;

    info = &ctx->master_slave_info[socks->trans_index];

    // TODO free when tearing down ft_context
    info->socks = kmalloc(sizeof(struct socket *) * socks->nsocks, GFP_KERNEL);
    if (!info->socks)
        return -ENOMEM;

    info->kthreads = kmalloc(sizeof(struct task_struct *) * socks->nsocks, GFP_KERNEL);
    if (!info->kthreads)
        return -ENOMEM;

    info->events = kmalloc(sizeof(wait_queue_head_t) * socks->nsocks, GFP_KERNEL);
    if (!info->events)
        return -ENOMEM;

    info->trans_ret = kmalloc(sizeof(info->trans_ret[0]) * socks->nsocks, GFP_KERNEL);
    if (!info->trans_ret)
        return -ENOMEM;

    for (i = 0; i < socks->nsocks; ++i) {
        struct socket *sock;
        int err;
        sock = sockfd_lookup(socks->socks[i], &err);
        if (sock == NULL)
            return err;
        info->socks[i] = sock;
    }
    info->nsocks = socks->nsocks;

    for (i = 1; i < socks->nsocks; ++i) {
        struct task_struct *tp;
        struct diff_and_tran_kthread_descriptor *desc;

        desc = kmalloc(sizeof(*desc), GFP_KERNEL | __GFP_ZERO);
        if (!desc)
            return -ENOMEM;
        desc->kvm = kvm;
        desc->trans_index = socks->trans_index;
        desc->conn_index = i;
        desc->conn_count = socks->nsocks;

        init_waitqueue_head(&info->events[i]);

        tp = kthread_run(&diff_and_tran_kthread_func, desc,
            "kvmdat/%d/%d", socks->trans_index, i);
        if (IS_ERR(tp)) {
            kfree(desc);
            return -PTR_ERR(tp);
        }
        info->kthreads[i] = tp;
    }

    return 0;
}

static void master_slave_conn_free(struct kvm *kvm)
{
    struct kvmft_context *ctx = &kvm->ft_context;
    struct kvmft_master_slave_conn_info *info;
    int i, j;

    for (i = 0; i < ctx->max_desc_count; ++i) {
        info = &ctx->master_slave_info[i];
        for (j = 1; j < info->nsocks; ++j)
            if (info->kthreads[j])
                kthread_stop(info->kthreads[j]);
    }

    for (i = 0; i < ctx->max_desc_count; ++i) {
        info = &ctx->master_slave_info[i];
        kfree(info->socks);
        kfree(info->kthreads);
        kfree(info->events);
        kfree(info->trans_ret);
    }
}

void kvm_shm_exit(struct kvm *kvm)
{
    struct kvmft_context *ctx = &kvm->ft_context;
    int i, j, len;

    spcl_kthread_destroy(kvm);
    xmit_kthread_destroy(kvm);

	//net_set_tcp_zero_copy_callbacks(NULL, NULL);

	if (kvm->trackable_list)
		kvm_shm_free_trackable(kvm);

    /*
       for (j = 0; j < 2; ++j) {
       if (shmem->dirty_bitmap_pages[j]) {
       __free_pages(shmem->dirty_bitmap_pages[j],
       shmem->dirty_bitmap_pages_order);
       shmem->dirty_bitmap_pages[j] = NULL;
       shmem->dirty_bitmap_k[j] = NULL;
       }
       }
     */

    len = ctx->shared_page_num;

    for (j = 0; j < ctx->max_desc_count; ++j) {
        if (ctx->page_nums_snapshot_page && ctx->page_nums_snapshot_page[j]) {
            if (ctx->page_nums_snapshot_k[j]->spcl_bitmap)
                kfree(ctx->page_nums_snapshot_k[j]->spcl_bitmap);
            __free_pages(ctx->page_nums_snapshot_page[j], ctx->page_nums_page_order);
            ctx->page_nums_snapshot_page[j] = NULL;
            ctx->page_nums_snapshot_k[j] = NULL;
        }
        if (ctx->shared_pages_snapshot_pages && ctx->shared_pages_snapshot_pages[j]) {
            for (i = 0; i < len; ++i) {
                if (ctx->shared_pages_snapshot_pages[j][i]) {
                    __free_pages(ctx->shared_pages_snapshot_pages[j][i], 0);
                    ctx->shared_pages_snapshot_pages[j][i] = NULL;
                }
            }
            kfree(ctx->shared_pages_snapshot_pages[j]);
            kfree(ctx->shared_pages_snapshot_k[j]);
            ctx->shared_pages_snapshot_pages[j] = NULL;
            ctx->shared_pages_snapshot_k[j] = NULL;
        }
    }

    kfree(ctx->page_nums_snapshot_k);
    kfree(ctx->page_nums_snapshot_page);
    kfree(ctx->shared_pages_snapshot_k);
    kfree(ctx->shared_pages_snapshot_pages);

    kfifo_free(&kvm->trans_queue);

    modified_during_transfer_list_free(kvm);

#ifdef ENABLE_PRE_DIFF
    ctx->diff_req_list_cur = NULL;
    wake_up(&kvm->diff_req_event);
    msleep(40);
    if (kvm->diff_kthread) {
        kthread_stop(kvm->diff_kthread);
        kvm->diff_kthread = NULL;
    }

    for (j = 0; j < ctx->max_desc_count; ++j) {
        struct diff_req_list *tmp = ctx->diff_req_list[j];
        if (tmp) {
            diff_req_list_free(tmp);
            ctx->diff_req_list[j] = NULL;
        }
    }
    diff_req_exit();
#endif

    if (ctx->spcl_backup_dirty_list)
        kfree(ctx->spcl_backup_dirty_list);

    master_slave_conn_free(kvm);
}

unsigned long kvm_get_put_off(struct kvm *kvm, int cur_index){
	struct kvmft_dirty_list *dlist;
    struct kvmft_context *ctx = &kvm->ft_context;
	dlist = ctx->page_nums_snapshot_k[cur_index];
	return dlist->put_off;
}

int kvm_reset_put_off(struct kvm *kvm, int cur_index){
    struct kvmft_dirty_list *dlist;
    struct kvmft_context *ctx = &kvm->ft_context;
    dlist = ctx->page_nums_snapshot_k[cur_index];
	dlist->put_off = 0;
    return 0;
}

int kvm_shm_init(struct kvm *kvm, struct kvm_shmem_init *info)
{
    int ret = -ENOMEM;
    unsigned long i;
    unsigned long cnt;
    struct kvmft_context *ctx = &kvm->ft_context;

	spin_lock_init(&transfer_lock);

    // maximum integer is 2147*1e6
    if (info->epoch_time_in_ms > 2100) {
        printk("%s epoch_time_in_ms too bit, must be less then 2100\n",
                __func__);
        return -EINVAL;
    }

    if (ctx->page_nums_snapshot_k != NULL) {
        printk("%s called twice\n", __func__);
        return -EINVAL;
    }

    ctx->page_nums_snapshot_k = kmalloc(sizeof(struct kvmft_dirty_list *)
                                       * KVM_DIRTY_BITMAP_INIT_COUNT,
                                       GFP_KERNEL | __GFP_ZERO);
    if (ctx->page_nums_snapshot_k == NULL) {
        return -ENOMEM;
    }

    ctx->page_nums_snapshot_page = kmalloc(sizeof(struct page *)
                                          * KVM_DIRTY_BITMAP_INIT_COUNT,
                                          GFP_KERNEL | __GFP_ZERO);
    if (ctx->page_nums_snapshot_page == NULL) {
        return -ENOMEM;
    }

    ctx->shared_pages_snapshot_k = kmalloc(sizeof(void **)
                                          * KVM_DIRTY_BITMAP_INIT_COUNT,
                                          GFP_KERNEL | __GFP_ZERO);
    if (ctx->shared_pages_snapshot_k == NULL) {
        return -ENOMEM;
    }

    ctx->shared_pages_snapshot_pages = kmalloc(sizeof(struct page **)
                                          * KVM_DIRTY_BITMAP_INIT_COUNT,
                                          GFP_KERNEL | __GFP_ZERO);
    if (ctx->shared_pages_snapshot_pages == NULL) {
        return -ENOMEM;
    }

    ctx->max_desc_count = KVM_DIRTY_BITMAP_INIT_COUNT;

	target_latency_us = info->epoch_time_in_ms * 1000;
	epoch_time_in_us = info->epoch_time_in_ms * 1000;

    kvm->vcpus[0]->epoch_time_in_us = info->epoch_time_in_ms * 1000;
    pages_per_ms = info->pages_per_ms;

    ctx->shared_page_num = info->shared_page_num; // + 1024; // 1024 is guard
    ctx->shared_watermark = info->shared_watermark;
    ctx->cur_index = KVM_SHM_INIT_INDEX;

    // allocate shared_dirty_page_nums, include safe guard.
    i = sizeof (struct kvmft_dirty_list);
    i += sizeof (unsigned long) * ctx->shared_page_num;
    i = i / 4096 + !!(i % 4096);
    cnt = ilog2(i);
    if ((1 << cnt) < i)
        ++cnt;

    ctx->page_nums_page_order = cnt;
    info->page_nums_size = 1 << cnt;

    for (i = 0; i < KVM_DIRTY_BITMAP_INIT_COUNT; ++i) {
        ret = prepare_for_page_backup(ctx, i);
        info->page_nums_pfn_snapshot[i] = page_to_pfn(ctx->page_nums_snapshot_page[i]);
		//spin_lock_init(&ctx->page_nums_snapshot_k[i]->lock);
    }

    // pages that read from disk
    // java program, webjbb
    // sacrifice one core,
    // DMA engine -- william

//	net_set_tcp_zero_copy_callbacks(kvm_shm_tcp_get_callback, kvm_shm_tcp_put_callback);

#ifdef ENABLE_PRE_DIFF
    ret = diff_req_init();
    if (ret) {
        goto err_free;
    }
    for (i = 0; i < KVM_DIRTY_BITMAP_INIT_COUNT; ++i) {
        struct diff_req_list *tmp = diff_req_list_new();
        if (!tmp) {
            ret = -ENOMEM;
            goto err_free;
        }
        tmp->trans_index = i;
        ctx->diff_req_list[i] = tmp;
    }
	init_waitqueue_head(&kvm->diff_req_event);
    ctx->diff_req_list_cur = NULL;

    kvm->diff_kthread = kthread_run(&diff_thread_func, kvm, "ft_diff");
    if (IS_ERR(kvm->diff_kthread)) {
        ret = -PTR_ERR(kvm->diff_kthread);
        printk("%s failed to kthread_run %d\n", __func__, ret);
        kvm->diff_kthread = NULL;
        goto err_free;
    }
#endif

    kvm->qemu_mm = current->mm;

    ret = spcl_kthread_create(kvm);
    if (ret)
        goto err_free;

    ret = xmit_kthread_create(kvm);
    if (ret)
        goto err_free;

	//init_waitqueue_head(&kvm->trans_queue_event);
	init_waitqueue_head(&kvm->mdt_event);

    if (modified_during_transfer_list_init(kvm))
        goto err_free;

    ctx->spcl_backup_dirty_list = kmalloc(sizeof(ctx->spcl_backup_dirty_list[0]) *
            info->shared_page_num, GFP_KERNEL);
    if (!ctx->spcl_backup_dirty_list)
        goto err_free;

    init_waitqueue_head(&ctx->tran_event);

    return 0;

err_free:
    kvm_shm_exit(kvm);
    return ret;
}


static void __bd_average_update(struct kvmft_context *ctx)
{
    int sum_const = 0, sum_latency = 0, sum_rate = 0;
    int i;

    for (i = 0; i < BD_HISTORY_MAX; ++i) {
        sum_const += ctx->bd_average_consts[i];
        sum_latency += ctx->bd_average_latencies[i];
        sum_rate += ctx->bd_average_rates[i];
    }

    ctx->bd_average_const = sum_const / BD_HISTORY_MAX;
    ctx->bd_average_latency = sum_latency / BD_HISTORY_MAX;
    ctx->bd_average_rate = sum_rate / BD_HISTORY_MAX;
}

static void __bd_average_init(struct kvmft_context *ctx)
{
    int i;

    for (i = 0; i < BD_HISTORY_MAX; ++i) {
        ctx->bd_average_consts[i] = 300;
        ctx->bd_average_latencies[i] = 10000;
        ctx->bd_average_rates[i] = 300;
    }
    ctx->bd_average_put_off = 0;

    __bd_average_update(ctx);
}

// latency = runtime + constant + dirty_page_number / rate
void kvmft_bd_update_latency(struct kvm *kvm, struct kvmft_update_latency *update)
{
    struct kvmft_context *ctx;
    int i, put_off;

    ctx = &kvm->ft_context;
    put_off = ctx->bd_average_put_off;

    ctx->bd_average_latencies[put_off] = update->latency_us;
    ctx->bd_average_consts[put_off] = (update->latency_us - update->runtime_us - update->trans_us);

	ctx->bd_alpha = update->alpha;

	kvm->vcpus[0]->last_trans_rate = update->last_trans_rate;

    if (update->trans_us > 0) {
        ctx->bd_average_rates[put_off] = update->dirty_page * 1000 / update->trans_us;
    } else {
        ctx->bd_average_rates[put_off] = 100000;
    }
    if(ctx->bd_average_rates[put_off] == 0)
        ctx->bd_average_rates[put_off] = 100000;

    __bd_average_update(ctx);

    ctx->bd_average_put_off = (put_off + 1) % BD_HISTORY_MAX;

	int latency_us = update->latency_us;

	//printk(" =====>>>>>>>>>>>>>vmid = %d, latency_us = %d, w0 = %d, w1 = %d, w2 = %d, w3 = %d, x0 = %d, x1 = %d, dirty_page = %d\n", \
			kvm->ft_id, latency_us, kvm->w0, kvm->w1, kvm->w2, kvm->w3, kvm->x0, kvm->x1, update->dirty_page);

    update->w0 = kvm->w0;
    update->w1 = kvm->w1;
    update->w3 = kvm->w3;
    update->x0 = kvm->x00;
    update->x1 = kvm->x01;

	update->last_load_mem_rate = kvm->last_load_mem_rate;
	update->load_mem_rate      = kvm->e_load_mem_rate;
	update->last_send_rate     = kvm->last_send_rate;
	update->current_send_rate  = kvm->e_current_send_rate;
	update->load_mem_bytes     = kvm->load_mem_bytes;


	update->real_load_mem_bytes = kvm->load_pages*4096;

	update->e_dirty_bytes = kvm->w2;
	update->e_latency = kvm->e_latency;

	update->e_runtime = kvm->e_epoch_runtime;
	update->e_trans   = kvm->e_trans_latency/1000;

	static int learningR = 600;
	//static int learningR = 1000;

	int runtime_bias = update->runtime_us - update->e_runtime;
	if(latency_us > 11000 && (latency_us - runtime_bias) <= 11000) {
		update->learningR = learningR;
		kvm->learningR = learningR;
		return;
	}

	if(kvm->x00 == 0 || kvm->x01 == 0 || (kvm->w0 == 1000 && kvm->w1 == 1000)) {
		//kvm->w3 = update->trans_us * 1000;
		int w3 = kvm->w3 + (update->trans_us - update->e_trans) * 1000;
		if (w3 < 0)
			kvm->w3 = 0;
	}

	if(latency_us > 11000 && (((update->trans_us - update->e_trans) > 8000) || (update->trans_us > 8000))) {
		update->learningR = learningR;
		kvm->learningR = learningR;
		return;
	}
/*
	if(kvm->w3 > 0) {
		int d = kvm->e_epoch_runtime - update->runtime_us;
		if(d > 0 && d < 100)  {
			kvm->w3 = 0;
		} else if (d < 0 && d > -100) {
			kvm->w3 = 0;
		}
    	update->w3 = kvm->w3;
		return ;
	}
*/

//	update->last_load_mem_rate = kvm->last_load_mem_rate;


//	int learningR = 800;
	//static int learningR = 600; //best
//	int learningR = 100;
	static int lc = 0;
	static int miss = 0;
	static int hit = 0;
	static int latency_diff = 0;
	lc++;
	if(lc == 50) {
		//kvm->latency_bias = latency_diff/50;
		lc = 0;
	//	miss = 0;
	//	hit = 0;
		learningR = 600;
//		learningR = 1000;
		latency_diff = 0;
	}

	if(miss > 10) {
		//learningR = 600;
		learningR = 600;
	//	miss = 0;
	}

//    int e_trans_us = kvm->x00*kvm->w0 + kvm->x01*kvm->w1 + kvm->w3;
    int e_trans_us = kvm->e_trans_latency;
	e_trans_us /= 1000;

	int trans_bias = 500;

	if(latency_us <= target_latency_us + 1000 && latency_us >= target_latency_us -1000) {
		update->learningR = learningR;
		kvm->learningR = learningR;
	//	trans_bias = 650;
		return;
	}

	latency_diff += (latency_us - kvm->e_latency);

	int trans_diff = update->trans_us - e_trans_us;
	int fixlatency = latency_us - trans_diff;

	/*
	if(fixlatency < target_latency_us - 1000 || fixlatency > target_latency_us + 1000) {
		if(kvm->w3 > 0) {
			int d = kvm->e_epoch_runtime - update->runtime_us;
			if(d > 0 && d < 100)  {
				kvm->w3 = 0;
			} else if (d < 0 && d > -100) {
				kvm->w3 = 0;
			}
    		update->w3 = kvm->w3;
		} else if(latency_us > target_latency_us + 1000) {
			kvm->w3 += (latency_us-(target_latency_us+1000))*1000;
    	} else if (latency_us < target_latency_us - 1000) {
        	int w3 = kvm->w3 - ((target_latency_us-1000)-latency_us)*1000;
			if(w3 < 0) w3 = 0;
			kvm->w3 = w3;
		}
		update->learningR = learningR;
		kvm->learningR = learningR;
		return;
	}*/

	//if (latency_us > target_latency_us + 1000) {
//	if(e_trans_us < update->trans_us - trans_bias) {
	if(e_trans_us < update->trans_us ) {
        if(update->dirty_page != 0) {
		    kvm->w0 = kvm->w0 + (learningR*kvm->x00*(1))/1000;
		    kvm->w1 = kvm->w1 + (learningR*kvm->x01*(1))/1000;
        }
	//	else {
			//kvm->w3 += (latency_us-(target_latency_us+1000))*1000;
			//kvm->w3 += ((update->trans_us - 1000) - e_trans_us );
//			kvm->w3 += (update->trans_us - e_trans_us )*1000;
//		}

		//if(kvm->w0 == 1000 && kvm->w1 == 1000 && update->dirty_page != 0) {
		//	kvm->w3 += ((update->trans_us - 1000) - e_trans_us );
		//}
//		kvm->w3 = kvm->w3 + (learningR*kvm->w3*(1))/1000 + update->trans_us - e_trans_us;

		learningR = (learningR * 1000) / 1200; //@@
		//if(learningR < 0)
			//learningR = 0;

		miss++;
		//hit = 0;
	//	kvm->w2+=200;
	//	if(kvm->w2 > 1000) kvm->w2 = 1000;


	/*	if(kvm->w3 > 0) {
			int d = kvm->e_epoch_runtime - update->runtime_us;
			if(d > 0 && d < 100)  {
				kvm->w3 = 0;
			} else if (d < 0 && d > -100) {
				kvm->w3 = 0;
			}
    		update->w3 = kvm->w3;
		}
*/


//    } else if (latency_us < target_latency_us - 1000) {
//    } else if (e_trans_us > update->trans_us + trans_bias) {
    } else if (e_trans_us > update->trans_us) {
        if(update->dirty_page != 0) {
		    kvm->w0 = kvm->w0 + (learningR*kvm->x00*(-1))/1000;
		    kvm->w1 = kvm->w1 + (learningR*kvm->x01*(-1))/1000;
		} //else {
        	//kvm->w3 -= ((target_latency_us-1000)-latency_us)*1000;
        //	kvm->w3 -= ((update->trans_us-1000)-e_trans_us)*1000;
		//	if(kvm->w3 < 0) kvm->w3 = 0;
		//	int w3 = kvm->w3 - (e_trans_us - update->trans_us)*1000;
		//	if(w3 < 0) kvm->w3 = 0;
		//}
		if(kvm->w0 < 1000 ) kvm->w0 = 1000;
		if(kvm->w1 < 1000 ) kvm->w1 = 1000;

//		int w3 = kvm->w3 + (learningR*kvm->w3*(-1))/1000 - (e_trans_us - update->trans_us);
//		if(w3 < 0) w3 = 0;
//		kvm->w3 = w3;

/*		if(kvm->w3 > 0) {
			int d = kvm->e_epoch_runtime - update->runtime_us;
			if(d > 0 && d < 100)  {
				kvm->w3 = 0;
			} else if (d < 0 && d > -100) {
				kvm->w3 = 0;
			}
    		update->w3 = kvm->w3;
		} //else if(kvm->w0 == 1000 && kvm->w1 == 1000) {
*/
/*
		if(kvm->w0 == 1000 && kvm->w1 == 1000) {
			if(latency_us > target_latency_us + 1000) {
				kvm->w3 += (latency_us-(target_latency_us+1000))*1000;
    		} else if (latency_us < target_latency_us - 1000) {
        		int w3 = kvm->w3 - ((target_latency_us-1000)-latency_us)*1000;
				if(w3 < 0) w3 = 0;
				kvm->w3 = w3;
			}
		}
*/

//		if(kvm->w0 == 1000 && kvm->w1 == 1000 && update->dirty_page != 0) {
 //       	kvm->w3 -= ((update->trans_us-1000)-e_trans_us)*1000;
//			if(kvm->w3 < 0) kvm->w3 = 0;
//		}

        //kvm->w3 -= ((target_latency_us-1000)-latency_us)*1000;
        //if(kvm->w3 < 0) kvm->w3 = 0;

		learningR = (learningR * 1000) / 1200; //@@
		//if(learningR < 0)
		//	learningR = 0;

		miss++;
	//	kvm->w2-=200;
	//	if(kvm->w2 < 0) kvm->w2 = 0;
//		hit = 0;
	} /*else{
		if(kvm->w3 > 0) {
			int d = kvm->e_epoch_runtime - update->runtime_us;
			if(d > 0 && d < 100)  {
				kvm->w3 = 0;
			} else if (d < 0 && d > -100) {
				kvm->w3 = 0;
			}
    		update->w3 = kvm->w3;
		} else if(latency_us > target_latency_us + 1000) {
			kvm->w3 += (latency_us-(target_latency_us+1000))*1000;
    	} else if (latency_us < target_latency_us - 1000) {
        	int w3 = kvm->w3 - ((target_latency_us-1000)-latency_us)*1000;
			if(w3 < 0) w3 = 0;
			kvm->w3 = w3;
		}
//		miss--;
	//	learningR--;
	//	if(learningR < 0)
	//		learningR = 0;
	//	hit++;
	//	if(hit > 80 && miss > 10) {
	//		learningR = 600;
	//		hit = 0;
	//		miss = 0;
	//	}
	}*/
	update->learningR = learningR;
	kvm->learningR = learningR;

}
int bd_calc_dirty_bytes(struct kvm *kvm, struct kvmft_context *ctx, struct kvmft_dirty_list *dlist)
{
    struct page *page1, *page2;
    int i, j, count, total_dirty_bytes = 0;

    dlist = ctx->page_nums_snapshot_k[ctx->cur_index];
    count = dlist->put_off;

    int total_zero_len = 0;
    int invalid_count = 0;

    //(7,2)
    int n = 7;
    //int p = 2;
    int p = 2;

	int k = 0;
    int real_count = 0;

    for (i = n; i < count; i+=(n+p)) {
        for(k = 0; (k < p) && (i+k < count); k++){
 //
        real_count++;

        gfn_t gfn = dlist->pages[i];

        page1 = ctx->shared_pages_snapshot_pages[ctx->cur_index][i];


        struct task_struct *current_backup = get_cpu_var(current_task);
        struct task_struct *kvm_task = kvm->vcpus[0]->task;
        if(current_backup != kvm_task) {
            __this_cpu_write(current_task, kvm_task);
        }

            pfn_t pfn = gfn_to_pfn_atomic(kvm, gfn);
            page2 = pfn_to_page(pfn);

		__this_cpu_write(current_task, current_backup);
        put_cpu_var(current_task);

        int len = 0;

        char *page = kmap_atomic(page2);
        char *backup = kmap_atomic(page1) ;

        int j,k;

        kernel_fpu_begin();
        for (j = 0; j < 4096; j += 32) {
            len += 32 * (!!memcmp_avx_32(backup + j, page + j));
        }
        kernel_fpu_end();


        kunmap_atomic(page);
        kunmap_atomic(backup);

        if(len == 0) {
            total_zero_len++;
            len = 4096;
        }

        total_dirty_bytes += len;
        }
    }
    total_dirty_bytes += 28*count;

	if(real_count != 0)
	    total_dirty_bytes = (total_dirty_bytes/real_count)*count;

	kvm->f_count = real_count;

    if (count > 0) {
        return total_dirty_bytes;
    }
    return 0;
}

/*
int bd_calc_dirty_bytes(struct kvm *kvm, struct kvmft_context *ctx, struct kvmft_dirty_list *dlist)
{
    struct page *page1, *page2;
    int i, j, count, total_dirty_bytes = 0;

    dlist = ctx->page_nums_snapshot_k[ctx->cur_index];
    count = dlist->put_off;

    int total_zero_len = 0;
    int invalid_count = 0;

    int n = 7;
    int p = 2;
    int k = 0;
    int real_count = 0;

    for (i = n; i < count; i+=(n+p)) {
        for(k = 0; (k < p) && (i+k < count); k++){
 //
        real_count++;

        gfn_t gfn = dlist->pages[i];

        page1 = ctx->shared_pages_snapshot_pages[ctx->cur_index][i];


        struct task_struct *current_backup = get_cpu_var(current_task);
        struct task_struct *kvm_task = kvm->vcpus[0]->task;
        if(current_backup != kvm_task) {
            __this_cpu_write(current_task, kvm_task);
        }

            pfn_t pfn = gfn_to_pfn_atomic(kvm, gfn);
            page2 = pfn_to_page(pfn);

		__this_cpu_write(current_task, current_backup);
        put_cpu_var(current_task);

        int len = 0;

        char *page = kmap_atomic(page2);
        char *backup = kmap_atomic(page1) ;

        int j,k;

        kernel_fpu_begin();
        for (j = 0; j < 4096; j += 32) {
            len += 32 * (!!memcmp_avx_32(backup + j, page + j));
        }
        kernel_fpu_end();


        kunmap_atomic(page);
        kunmap_atomic(backup);

        if(len == 0) {
            total_zero_len++;
            len = 4096;
        }

        total_dirty_bytes += len;
        }
    }
    total_dirty_bytes += 28*count;

	if(real_count != 0)
	    total_dirty_bytes = (total_dirty_bytes/real_count)*count;

	kvm->f_count = real_count;

    if (count > 0) {
        return total_dirty_bytes;
    }
    return 0;
}
*/


