#include <linux/kvm_ft.h>
            //pass_time_us_threshold -=((exceeds_rate-0.03)*100);
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


#include "irq.h"
#include "mmu.h"
#include "x86.h"
#include "kvm_cache_regs.h"
#include "cpuid.h"

#include <asm/types.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/swap.h>
#include <linux/hugetlb.h>

#include <linux/srcu.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include <asm/page.h>
#include <asm/cmpxchg.h>
#include <asm/io.h>
#include <asm/vmx.h>
















//#define ft_debug_bd

#define SHOW_AVERAGE_FRAG   1
#undef SHOW_AVERAGE_FRAG

//#define ENABLE_PRE_DIFF 1

#if defined(ENABLE_SWAP_PTE) && defined(ENABLE_PRE_DIFF)
#error ENABLE_SWAP_PTE and ENABLE_PRE_DIFF cant co-exist.
#endif

#define PAGE_TRANSFER_TIME_MEASURE  1
#undef PAGE_TRANSFER_TIME_MEASURE

//#define SPCL    1

int total_dirty_bytes = 0;
//static long total_count = 0;
//static long total_bytes = 0;
int dirty_bytes_per_pages = 0;
int global_dirty_count = 0;
//struct page* global_pages;
unsigned long global_addr = 0;
int global_sample_dirty_page_count = 0;


struct page *bad_page;

static DEFINE_SPINLOCK(myftlock);


//int global_time_record_in_timer_callback = 0;

int z_count = 0;

int update_flag = 0;

int global_diff_gfn_count = 0;
int global_diff_pfn_count = 0;

static int bd_predic_stop2(unsigned long data);

//struct kvmft_context *global_ft_ctx;
struct hrtimer global_hrtimer;
struct kvm *global_kvm; 
DECLARE_TASKLET(calc_dirty_tasklet, bd_predic_stop2, 0);
//int first_timer = 1;
//struct kvmft_update_latency global_update;
//global_update.last_trans_rate = 100;
int global_last_trans_rate = 100;


struct kvm_vcpu *global_vcpu;
const int max_latency = 29700;

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

static long int target_latency_us;
static unsigned long epoch_time_in_us;
static unsigned long pages_per_ms;

static int w_a = 10;
static int w_b = -1;
static int w_c = -6;
static int w_d = -9;
static int x_a, x_b, x_c, x_d;
static long int p_out;
static long int p_out_max = 0;
static long int p_out_min = 0;
static long int p_left_time = 2000;
//int p_left_time_weight = 1;
static long int p_rang = 700;
static int alpha = 100;

static int bd_page_fault_check = 1;

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

void kvm_shm_start_timer2(void)
{
    ktime_t ktime;

    ktime = ktime_set(0, epoch_time_in_us * 1000);
    hrtimer_start(&global_hrtimer, ktime, HRTIMER_MODE_REL);

}

void kvm_shm_start_timer(struct kvm_vcpu *vcpu)
{
    ktime_t ktime;

    ktime = ktime_set(0, epoch_time_in_us * 1000);
    hrtimer_start(&vcpu->hrtimer, ktime, HRTIMER_MODE_REL);
}

static void spcl_kthread_notify_abandon(struct kvm *kvm);

void kvm_shm_timer_cancel(struct kvm_vcpu *vcpu)
{
    spcl_kthread_notify_abandon(vcpu->kvm);
    //hrtimer_cancel(&vcpu->hrtimer);
    hrtimer_cancel(&global_hrtimer);
}

//static int bd_predic_stop2(void)
static int bd_predic_stop2(unsigned long data)
{

    struct kvmft_context *ctx;
    ctx = &global_kvm->ft_context;
    

    struct kvmft_dirty_list *dlist;
    dlist = ctx->page_nums_snapshot_k[ctx->cur_index];
/*   
    static unsigned long count = 0;
    static unsigned long calc_dirty_time = 0;
    static int old1   = 0;
    static int old2   = 0;
    static unsigned long other = 0;

    count++;
 */
//    s64 epoch_run_time = time_in_us() - dlist->epoch_start_time;

/*
  //  if(count == 30) {
    if(count > 1 && count <= 30) {
        other = other + epoch_run_time - old1 - old2;
        printk("cocotion test other is %d\n", other);
        //printk("cocotion test original other = %ld\n", global_ other);
 //       global_other = global_other + epoch_run_time - old1 - old2;   
        printk("cocotion test epoch_run_time is %ld\n", epoch_run_time);
        printk("cocotion test old1 is %ld\n", old1);
        printk("cocotion test old2 is %ld\n", old2);
     //   printk("cocotion test other is %ld\n", global_other);
        printk("cocotion test other average time= %ld\n", other/(count-1));
    }
*/
  /*  if(count > 1) {
        other = other + epoch_run_time - old1 - old2;
        printk("cocotion test other average time= %ld\n", other/(count-1));
    }

    old1 = epoch_run_time;
*/
    //printk("cocotion test epoch_run_time 1 = %d\n", epoch_run_time);
    
    int current_dirty_byte = bd_calc_dirty_bytes(ctx, dlist);


    s64 epoch_run_time = time_in_us() - dlist->epoch_start_time;

/*
    calc_dirty_time = calc_dirty_time + time_in_us() - dlist->epoch_start_time - epoch_run_time;
 
   old2 = time_in_us() - dlist->epoch_start_time - epoch_run_time ;   

 
    printk("cocotion test average calc_dirty_time  = %ld\n", calc_dirty_time/count);
*/

    printk("cocotion my test dirty_byte = %d\n", current_dirty_byte);
     
    if(global_last_trans_rate < 400) global_last_trans_rate = 400;
 
    int beta = current_dirty_byte/global_last_trans_rate + epoch_run_time;

 
//    if(epoch_run_time >= target_latency_us ) {
    if(beta >= target_latency_us ) {
        
//        printk("cocotion test need takesnapshot\n");

        global_vcpu->hrtimer_pending = true;
        kvm_vcpu_kick(global_vcpu);
        //old1 = old2 = count = calc_dirty_time = other = 0 ;
        
    }
    else {
        kvm_shm_start_timer2();
 //       printk("cocotion test: start new timer\n");
    }
 

    int r = 1000;

    return r;
}



static enum hrtimer_restart kvm_shm_vcpu_timer_callback(
        struct hrtimer *timer)
{
        //cocotion test
    extern ktime_t global_mark_time, global_mark_start_time;
    extern u64 runtime_difftime;
    //ktime_t val; 
    global_mark_time = ktime_get();
    //global_mark_time = ktime_to_ns(val) / 1000;

//    global_time_record_in_timer_callback = ktime_to_ns(val) / 1000; 
     

    ktime_t diff = ktime_sub(global_mark_time, global_mark_start_time);
    runtime_difftime = ktime_to_us(diff);



    //struct kvm_vcpu *vcpu = hrtimer_to_vcpu(timer);

    //spcl_kthread_notify_abandon(vcpu->kvm);

    //vcpu->hrtimer_pending = true;
    //kvm_vcpu_kick(vcpu);

    //bd_predic_stop2();


/*
    unsigned long mycr3 = task_pid_nr(current);
    if(global_vcpu->mycr3 != mycr3) {
        printk("cocotion test my pid when tasklet ###= 0x%016llx\n", mycr3);
        printk("cocotion test my pid when VMexit ###= 0x%016llx\n", global_vcpu->mycr3);
    }
    else {
        printk("cocotion test my pid when tasklet ok same !!!@@@= 0x%016llx\n", mycr3);
    }
*/




    tasklet_schedule(&calc_dirty_tasklet);

    return HRTIMER_NORESTART;
}

// timer for triggerring ram transfer
// called in vcpu_create..
void kvm_shm_setup_vcpu_hrtimer(struct kvm_vcpu *vcpu)
{
    //struct hrtimer *hrtimer = &vcpu->hrtimer;
    struct hrtimer *hrtimer = &global_hrtimer;

    //hrtimer_init(hrtimer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
    hrtimer_init(hrtimer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
    hrtimer->function = &kvm_shm_vcpu_timer_callback;
    vcpu->hrtimer_pending = false;

    global_vcpu = vcpu; 
    printk("kvm_shm_setup_vcpu_hrtimer vcpu = %p\n",vcpu);
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

    //ctx->dirty_pages_via_gfn = kzalloc(
     //   sizeof (struct page *) * ctx->shared_page_num, GFP_KERNEL);
    //if (!ctx->dirty_pages_via_gfn)
     //   return -ENOMEM;
    
    ctx->gfn_pfn_sync_list = kzalloc(
        sizeof (struct  gfn_pfn_sync) * 262144, GFP_KERNEL);
    if (!ctx->gfn_pfn_sync_list)
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
//    struct page *page2 = alloc_pages(GFP_KERNEL, param->order);

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
    
 //   if (page2) {
  //      ctx->dirty_pages_via_gfn[param->index2] = page2;         
   // }
    //(ctx->gfn_pfn_sync_list)[param->index2].flag = 0;
    
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
        for (i = 0; i < npages; ++i) {
            if (test_bit(i, dirty_bitmap)) {
                printk("%s %x is still set.\n", __func__, (long)base + i);
//                return -EINVAL;
            }
        }
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
    struct kvmft_dirty_list *dlist;

    #ifdef ft_debug_mode_enable
    printk("kvm_shm_flip_sharing cur_index = %x\n", cur_index);
    #endif
    //kvmft_protect_all_gva_spcl_pages(kvm, ctx->cur_index);
    confirm_prev_dirty_bitmap_clear(kvm, cur_index);

    ctx->cur_index = cur_index;
    info->run_serial = run_serial;
//    printk("cocotion in flip_sharing: cur_index = %d\n", cur_index);
//    printk("cocotion in flip_sharing: run_serial = %d\n", run_serial);

    ctx->log_full = false;
    ctx->bd_average_dirty_bytes = 100;

    bd_page_fault_check = 1;
    update_flag = 0;

    if(!ctx->gfn_pfn_sync_list) {
        ctx->gfn_pfn_sync_list = kzalloc(
        sizeof (struct  gfn_pfn_sync) * 262144, GFP_KERNEL);
    } else {
        int i;
        for(i = 0; i < 262144; i++)
            (ctx->gfn_pfn_sync_list)[i].flag = 0;
    }

    dlist = ctx->page_nums_snapshot_k[cur_index];

    //printk("%s start run %d run_serial = %d\n", __func__, cur_index, run_serial);

    dlist->epoch_start_time = time_in_us(); 

    spcl_kthread_notify_new(kvm, run_serial);

    return 0;
}

int kvm_shm_enable(struct kvm *kvm)
{
    struct kvmft_context *ctx = &kvm->ft_context;
    ctx->shm_enabled = !ctx->shm_enabled;
    printk("%s shm_enabled %d\n", __func__, ctx->shm_enabled);
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

/*
static int bd_predic_stop2(void)
{
    struct kvmft_dirty_list *dlist;
    dlist = global_ft_ctx->page_nums_snapshot_k[global_ft_ctx->cur_index];
    
    s64 epoch_run_time = time_in_us() - dlist->epoch_start_time;
    int current_dirty_byte = bd_calc_dirty_bytes(global_ft_ctx, dlist);
   
    if(epoch_run_time >= target_latency_us ) {
        printk("cocotion test need takesnapshot\n");
        global_vcpu->hrtimer_pending = true;
        kvm_vcpu_kick(global_vcpu);
        
    }
    else {
        kvm_shm_start_timer2();
    }
 

    int r = 1000;

    return r;
}
*/


static int bd_predic_stop(struct kvm *kvm,
    struct kvmft_dirty_list *dlist, int put_off, struct kvmft_update_latency *update)
{
    struct kvmft_context *ctx;
    ctx = &kvm->ft_context;
   
    s64 epoch_run_time = time_in_us() - dlist->epoch_start_time;

    //ctx->bd_average_dirty_bytes = kvmft_ioctl_bd_calc_dirty_bytes(kvm);

    //*dirty_bytes = ctx->bd_average_dirty_bytes * put_off;
    //*dirty_bytes = kvmft_ioctl_bd_calc_dirty_bytes(kvm);

    int current_dirty_byte = kvmft_ioctl_bd_calc_dirty_bytes(kvm);

    //update->dirty_byte = kvmft_ioctl_bd_calc_dirty_bytes(kvm);
    //update->dirty_page = global_dirty_count;



    //int beta = put_off*ctx->bd_average_dirty_bytes/ctx->bd_average_rate + epoch_run_time;
//    int beta = *dirty_bytes/ctx->bd_average_rate + epoch_run_time;
//    int beta = update->dirty_byte/ctx->bd_average_rate + epoch_run_time;

/*

    int predict_transfer_rate;
    int predict_dirty_rate;
    if(update_flag == 1) {
        //update->count = 0;
        int diff_bytes = current_dirty_byte - update->dirty_byte;
        update->dirty_byte = current_dirty_byte;
        int diff_time = epoch_run_time - update->epoch_time_us;
        update->epoch_time_us = epoch_run_time;
        
        //int real_dirty_rate = diff_bytes/diff_time;
        //predict_transfer_rate = ctx->bd_alpha - real_dirty_rate;  
        
        predict_dirty_rate = diff_bytes/(diff_time+1);
        predict_dirty_rate = 500*predict_dirty_rate;
        if(predict_dirty_rate == 0) predict_dirty_rate = 100;
          
    }
    else {
        update->dirty_byte = current_dirty_byte;
        //update->dirty_page = global_dirty_count;
        update->epoch_time_us = epoch_run_time;
        update_flag = 1;
        return 500;
        //return 10;
    }

*/






//    printk("cocotion test predic_trans_rate = %d\n", update->predic_trans_rate);

    //if(update->last_trans_rate < 100) update->last_trans_rate = 100;

//    int beta = current_dirty_byte/ctx->bd_alpha + epoch_run_time;

    //if(update->last_trans_rate < 200) update->last_trans_rate = 200;

    int beta = current_dirty_byte/update->last_trans_rate + epoch_run_time;
    //int beta = current_dirty_byte/update->predic_trans_rate + epoch_run_time;


//    int beta = current_dirty_byte/predict_transfer_rate + epoch_run_time;

  //  printk("@@@@@@@@@@@@@@@@@@@@@check if take snapshot\n");
 //   printk("current dirty byte = %d\n", current_dirty_byte);
  //  printk("current run time = %d\n", epoch_run_time);
   // printk("last trans rate = %d\n", update->last_trans_rate);
   // printk("current beta = %d\n", beta);


 
/* 
    printk("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");
    printk("epoch_run_time = %d\n", epoch_run_time);
    printk("cocotion test put_off = %ld\n", put_off);
    printk("cocotion test bd_average_dirty_bytes = %d\n", ctx->bd_average_dirty_bytes);
    printk("cocotion test bd_average_rate = %d\n", ctx->bd_average_rate);
    printk("cocotion test ctx->bd_alpha = %d\n", ctx->bd_alpha);
    printk("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");
*/

//    printk("cocotion test beta + ctx->bd_alpha = %d\n", beta + ctx->bd_alpha);
    //if((beta + ctx->bd_alpha) >= target_latency_us*94/100) {
//    if((beta + ctx->bd_alpha) >= (target_latency_us-1000)) {
//    if((beta) >= (target_latency_us-1000)) {
//    if((beta + ctx->bd_alpha) >= (target_latency_us-1000)) {
 //   printk("@@@@@@@@@@@@@@@@@@@@@cocotion test ok jump\n");
//        printk("cocotion test ok jump beta + ctx->bd_alpha = %d\n", beta + ctx->bd_alpha);


 //   update->beta = beta;
/*
    printk("cocotion test ok jump @@@================================\n");
    printk("current_dirty_byte = %d\n", current_dirty_byte);
    printk("(last trans_rate) = %d\n", update->last_trans_rate);
    printk("epoch_run_time = %d\n", epoch_run_time);
    printk("beta = %d\n", beta);
*/



/*
    int diff_bytes = current_dirty_byte - update->dirty_byte;
    update->dirty_byte = current_dirty_byte;
    int diff_time = epoch_run_time - update->epoch_time_us;
    update->epoch_time_us = epoch_run_time;
    int real_dirty_rate = diff_bytes/diff_time;
 */

//   printk("real dirty rate = %d\n", predict_dirty_rate);

    //printk("cocotion test end jump @@@================================\n");

  //      return -1;
   // }
//    printk("@@@@@@@@@@@@@@@@@@@@@cocotion test nexT try\n");
    //printk("cocotion test nextT jump? beta + ctx->bd_alpha = %d\n", beta + ctx->bd_alpha);

//    int predict_dirty_rate;

/*
    //printk("cocotion test update_flag = %d\n", update_flag);
    if(update_flag == 1) {
        //update->count = 0;
        int diff_bytes = current_dirty_byte - update->dirty_byte;
        //printk("current dirty byte = %d\n", current_dirty_byte);
        //printk("older dirty byte = %d\n", update->dirty_byte);
        //printk("diff bytes = %d\n", diff_bytes);
        update->dirty_byte = current_dirty_byte;
        int diff_time = epoch_run_time - update->epoch_time_us;
        printk("diff_time = %d\n", diff_time);
        update->epoch_time_us = epoch_run_time;
        
        predict_dirty_rate = diff_bytes/diff_time;
    }
    else {
        update->dirty_byte = current_dirty_byte;
        //printk("cocotion test update->dirty_byte = %d\n", update->dirty_byte);
        //update->dirty_page = global_dirty_count;
        update->epoch_time_us = epoch_run_time;
        update_flag = 1;
        return 500;
    }

*/
 //   if(predict_dirty_rate < 10) predict_dirty_rate = 10;

/*

    //int x = put_off*ctx->bd_average_dirty_bytes;
    //int x = dirty_bytes;
    //int x = update->dirty_byte;
    int x = current_dirty_byte;
    //int R = ctx->bd_average_rate;
    //int R = ctx->bd_alpha;
    int R = update->last_trans_rate;
    //int R = update->predic_trans_rate;
    int E = epoch_run_time;
    int y = target_latency_us;


    //predict_dirty_rate = 1;

    if(update->last_trans_rate == 0) update->last_trans_rate = 200;


    //return ((y-E-ctx->bd_alpha)*R-x)/(100+R);
    //int r = ((y-E-ctx->bd_alpha)*R-x)/(1000+R);
    //int r = ((y-E-5000)*R-x)/(1000+R);
    //int r = ((y-E-4000)*R-x)/(700+R);
    //int r = ((y-E-ctx->bd_alpha)*700-x)/1400;
    //int r = ((y-E-3000)*700-x)/1400;
    //int r = ((y-E-ctx->bd_alpha)*R-x)/700;

    //int r = ((y-E-ctx->bd_alpha)*R-x)/(predict_dirty_rate+R);
    int r = ((y-E-1000)*(R)-x)/(predict_dirty_rate+R);
*/

//    r = (y-1000-E)/2;

//    r -=500;

/*
    printk("cocotion test start @@@find nexT================================\n");

    printk("cocotion test predict rate = %d\n", predict_dirty_rate);
    printk("cocotion test now runtime = %d\n", E);
    //printk("cocotion test bd_alpha (predict trans_rate) = %d\n", ctx->bd_alpha);
    printk("cocotion test  (predict trans_rate) = %d\n", R);
    printk("cocotion test current_dirty_byte = %d\n", x);
    printk("nexT = %d\n", r);

    printk("cocotion test  ================================\n");
*/
    //int r = ((y-E-4000)*R-x)/(700+R);

    //int r = 100;
    //printk("cocotion test r = %d\n", r);


    int r = 1000;
//    return (r<0)?0:r; 
    return r;

//    return ((y-E-ctx->bd_alpha)*R-x)/(100+R);

}





#define FACTOR_SHOOTUP 130

static bool __bd_check_dirty_page_number(struct kvm *kvm,
    struct kvmft_dirty_list *dlist, int put_off)
{
    //return kvmft_ioctl_bd_calc_left_runtime(kvm) <= 0;

    struct kvmft_context *ctx;

    ctx = &kvm->ft_context;

    s64 epoch_run_time = time_in_us() - dlist->epoch_start_time;
/*
    s64 left_time = target_latency_us - epoch_run_time;


    int p_out = w_a * left_time + w_b * bd_average_rate + w_c * bd_average_dirty_bytes + w_d * put_off; 

    if(p_out <= 0) return true;

    return false;

*/

    // alpha
    //s64 left_time = max_latency - ctx->bd_alpha - (int)epoch_run_time;
    // const
    s64 left_time = max_latency - (int)epoch_run_time + ctx->bd_average_const;
    // const & alpha
    //s64 left_time = max_latency - ctx->bd_alpha - (int)epoch_run_time + ctx->bd_average_const;
    //if (left_time > max_latency - epoch_run_time)
    //    left_time = max_latency - epoch_run_time - 1000;

    // if average dirty bytes raise a lot, more time to transfer
    int factor = 100; 
    if (ctx->bd_average_dirty_bytes >= ctx->bd_last_average_dirty_bytes * 130 / 100) {
        factor = FACTOR_SHOOTUP;
    }    
    if (put_off >= ctx->bd_last_dp_num*130/100) {
        factor = factor * FACTOR_SHOOTUP / 100; 
    }    

    if (factor != 100) {
        left_time -= put_off;
    }    

    int transfer_rate = ctx->bd_average_rate;
    if (transfer_rate / 500 > ctx->bd_average_dirty_bytes && ctx->bd_average_dirty_bytes) {
        transfer_rate = ctx->bd_average_dirty_bytes * 500; 
    }    

    if (ctx->bd_average_dirty_bytes <= 300) {
        if (put_off * 1000 / 600 >= left_time) {
            ctx->bd_last_dp_num = put_off;
            return true;
        }    
    } else {
        if (put_off >= left_time * transfer_rate * 1024 *100/factor / ctx->bd_average_dirty_bytes / 1000) {
            ctx->bd_last_dp_num = put_off;
            return true;
        }    
    }    

    return false;
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

/*
    if (ctx->bd_average_rate >= 500000)
        ctx->bd_average_rate = 500000;
    else if (ctx->bd_average_rate < 50000)
        ctx->bd_average_rate = 50000;
*/                                                                                                             
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

//    global_update.last_trans_rate = update->last_trans_rate;


    if (update->trans_us > 0) { 
        ctx->bd_average_rates[put_off] = update->dirty_page * 1000 / update->trans_us;
    } else {
        ctx->bd_average_rates[put_off] = 100000;
    }    
    if(ctx->bd_average_rates[put_off] == 0)
        ctx->bd_average_rates[put_off] = 100000;

    __bd_average_update(ctx);


    ctx->bd_average_put_off = (put_off + 1) % BD_HISTORY_MAX;
 
}

int kvmft_bd_page_fault_check()
{
    //bd_page_fault_check = ~bd_page_fault_check;
//    if(bd_page_fault_check) 
 //   {
  //      bd_page_fault_check = 0;
        return 1; 
   // }
    //else return 0;
}

int kvmft_pfn_dirty(struct kvm *kvm, unsigned long gfn, pfn_t pfn)
{
    
    if (unlikely(!kvm_shm_is_enabled(kvm)))
        return 0;
    
    struct kvmft_context *ctx;
    ctx = &kvm->ft_context;
   
    struct kvm_memory_slot *memslot;
    unsigned long gfn_off;

    memslot = gfn_to_memslot(kvm, gfn);
    if (unlikely(!memslot)) {
        printk(KERN_ERR"%s can't find memslot for %lx\n", __func__, gfn);
        memslots_dump(kvm);
        return -ENOENT;
    }


    gfn_off = gfn - memslot->base_gfn;

    global_sample_dirty_page_count++;

    //printk("----------------------\n");
    //printk("cocotion test gfn = %ld\n", gfn);
    //printk("cocotion test gfn_off = %ld\n", gfn_off);


    (ctx->gfn_pfn_sync_list)[gfn_off].pfn = pfn;
    (ctx->gfn_pfn_sync_list)[gfn_off].flag = 1;

    //printk("cocotion test gfn pfn flag = %d\n", (ctx->gfn_pfn_sync_list)[gfn_off].flag);
    //printk("cocotion test gfn pfn = %ld\n", (ctx->gfn_pfn_sync_list)[gfn_off].pfn);


    //printk("----------------------\n");

/*
    struct page *mypage;

    PageReserved(mypage = pfn_to_page(pfn));
    char *backup = kmap_atomic(mypage);
        
        int j,k;
        for (j = 0; j < 4096; j += 32) {
            for(k = 0; k<32; k++) {
                printk("cocotion test backup = %d\n", (backup+j)[k]) ;
            }
        }

 
    kunmap_atomic(backup);
*/

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

    if (unlikely(test_and_set_bit(gfn_off, memslot->lock_dirty_bitmap))) {
        int r = wait_for_other_mark(memslot, ctx->cur_index, gfn_off, 5);
        return r;
    }
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
    
//    printk("cocotion test orig = %d\n", *(char*)shared_pages_k[put_index]);

    if (unlikely(test_and_set_bit(gfn_off, memslot->epoch_dirty_bitmaps.kaddr[ctx->cur_index]))) {
        printk(KERN_ERR"%s dirty_bit set before lock_dirty_bit %d %ld\n", __func__, ctx->cur_index, (long)gfn);
        return -1;
    }

    //ctx->bd_average_dirty_bytes = kvmft_ioctl_bd_calc_dirty_bytes(kvm);

    if (unlikely(put_index >= dlist->dirty_stop_num))
        ctx->log_full = true;



    //unsigned long addr = gfn_to_hva(kvm, gfn);
    //global_addr = gfn_to_hva(kvm, gfn);
    //void *addr = (void*) gfn_to_hva(kvm, gfn);
    //mm_mpin(addr, 4096);

    //struct page *page = gfn_to_page(kvm, gfn);
    //char *testpage = kmap_atomic(global_page);
    //kunmap_atomic(global_page);


    //SetPageReserved(page);

    //mlock_vma_page(page);


    //munlock_vma_page(page);

    //printk("cocotion test addr = %d\n", *(char*)addr);

//    uint64_t pa = gfn_to_gpa(gfn);
//    void *addr = gpa_to_hva(pa);

    //global_page = gfn_to_page(kvm, gfn);
    //ctx->dirty_pages_via_gfn[gfn_off] = gfn_to_page(kvm, gfn);
    //ctx->dirty_pages_via_gfn[0] = gfn_to_page(kvm, gfn);
    //global_pages = gfn_to_page(kvm, gfn);
        //gfn_to_page(kvm, gfn);

   
//     if (bd_page_fault_check && hrtimer_cancel(&global_vcpu->hrtimer)) {
 //       global_vcpu->hrtimer_pending = true;
  //      global_vcpu->run->exit_reason = KVM_EXIT_HRTIMER;
   //     kvm_vcpu_kick(global_vcpu);
    //    bd_page_fault_check = 0;
     //}

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
    //hrtimer_cancel(&vcpu->hrtimer);
    hrtimer_cancel(&global_hrtimer);
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
    epoch_time_in_us = newepoch;
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

    while (done < len) {
        iov.iov_base = buf + done;
        iov.iov_len = len - done;

        //msg.msg_control = NULL;
        msg.msg_controllen = 0;
        msg.msg_flags = MSG_DONTWAIT | MSG_NOSIGNAL;
        //msg.msg_iov = &iov;
        //msg.msg_iovlen = 1;
    #if LINUX_VERSION_CODE < KERNEL_VERSION(3,19,0)
            msg.msg_iov = &iov;
            msg.msg_iovlen = 1;
    #else
         iov_iter_init(&msg.msg_iter, READ, &iov, 1, len - done);
    #endif

        msg.msg_name = 0;
        msg.msg_namelen = 0;

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
        if (info->run_serial <= run_serial) {
            //printk("cocotion test break shit!!@@@\n");
            //printk("cocotion test info->run_serial = %d\n", info->run_serial);
            //printk("cocotion test run_serial = %d\n", run_serial);
            break;
        }
        else {
            volatile void *bitmap = bitmaps[off];
#ifdef DEBUG_SWAP_PTE
            //printk("%s index %d off %d test_bit %d\n", __func__, trans_index, off, test_bit(start_addr, bitmap));
#endif
            if (test_bit(start_addr, bitmap)) {
                int j = ((uint16_t *)gfn_to_put_off[off])[start_addr];
                //printk("cocotion test great fuck\n");
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

    dirty_bytes_per_pages = 0;

    for (i = 0; i < 4096; i += 32) {
        if (memcmp_avx_32(backup + i, page + i)) {
            header->h[i / 256] |= (1 << ((i % 256) / 32));
            memcpy(block, page + i, 32);
            block += 32;
            total_dirty_bytes +=32;
            dirty_bytes_per_pages += 32; 
        }
    }
    kernel_fpu_end();
///////////////////////////////////////////////cocotion test start


    #ifdef ft_debug_bd

    struct kvm_memory_slot *memslot;
    unsigned long gfn_off;
    memslot = gfn_to_memslot(global_kvm, gfn);
    gfn_off = gfn - memslot->base_gfn;
       
    struct kvmft_context *ctx = &global_kvm->ft_context;
    
 
    pfn_t pfn = (ctx->gfn_pfn_sync_list)[gfn_off].pfn;
        
    struct page *mypage;

    mypage = pfn_to_page(pfn);

    char *mybackup = kmap_atomic(mypage);

   
     
    int j,k;

   // pfn_t real_pfn;
  //  bool async = false;
 //   real_pfn = __gfn_to_pfn_memslot(memslot, gfn, false, &async, true, true);
//    if(real_pfn != pfn) global_diff_pfn_count++;
    pfn_t real_pfn = gfn_to_pfn(global_kvm, gfn);
    if(real_pfn != pfn) global_diff_pfn_count++;
    

    for (j = 0; j < 4096; j += 32) {
        for(k = 0; k<32; k++) {
           if((mybackup+j)[k] != (page+j)[k]) {
                //printk("diff gfn is = %d\n", gfn);
                global_diff_gfn_count++;
                goto gfndiff;
            }
        }
                
    }

gfndiff:


    kunmap_atomic(mybackup);
//////////////////////////////////////////////////cocotion test end

    #endif

//    printk("dirty bytes per page in real transfer= %d\n", dirty_bytes_per_pages);
    //printk("cocotion test total dirty bytes per page = %d\n", total_dirty_bytes_per_page);



//    printk("cocotion test @@@@@@ sizeof(*header) = %d\n", sizeof(*header));


    if (block == buf + sizeof(*header)) {
       #ifdef ft_debug_mode_enable
        printk("warning: not found diff page\n");
       #endif
        memset(header->h, 0xff, 16 * sizeof(__u8));
        memcpy(block, page, 4096);
        block += 4096;
        total_dirty_bytes += 4096;
        dirty_bytes_per_pages += 4096;

        z_count++; 
    }

    kunmap_atomic(backup);
    kunmap_atomic(page);

    if (block == buf + sizeof(*header))
        return 0;

    //printk("cocotion dirty bytes per pages = %d\n", dirty_bytes_per_pages);

    header->size = sizeof(header->h) + (block - (buf + sizeof(*header)));
    //printk("dirty bytes per page in real transfer (but real return)= %d\n", block-buf);
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
//    printk("cocotion test dirty in page = %d trans_index = %d\n", ret, trans_index);

    if (check_modify) {
        page2 = find_later_backup(kvm, gfn, trans_index, run_serial);
        if (page2 != NULL)
            ret = __diff_to_buf(gfn, page1, page2, buf);
    }

//    if(ret != dirty_bytes_per_pages+28) {
 //       printk("return bytes is %d\n", ret);
  //      printk("but d bytes per pages & head is %d\n", dirty_bytes_per_pages);
    
   // }

    return ret;
}

static int spcl_transfer_check(struct kvmft_dirty_list *dlist, int index)
{
    return index < dlist->spcl_put_off &&
        !test_and_clear_bit(index, dlist->spcl_bitmap);
}

static int kvmft_transfer_list(struct kvm *kvm, struct socket *sock,
    struct kvmft_dirty_list *dlist, int start, int end,
    int trans_index, int run_serial)
{
    int ret, i;
    int len = 0, total = 0;
    uint8_t *buf;
    unsigned int *gfns = dlist->pages;


    

    #ifdef ft_debug_bd
    int my_dirty_bytes_count = bd_calc_dirty_bytes(&kvm->ft_context, dlist);
    printk("##########cocotion test final my dirty bytes count = %d\n", my_dirty_bytes_count);
    #endif

#ifdef PAGE_TRANSFER_TIME_MEASURE
    transfer_start_time = time_in_us();
    page_transfer_end_times_off = end;
#endif

    buf = kmalloc(64 * 1024 + 8192, GFP_KERNEL);
    if (!buf)
        return -ENOMEM;

    kvmft_tcp_unnodelay(sock);


    int total_bytes = 0;
    total_dirty_bytes = 0;
    z_count = 0;
  //  printk("cocotion test before transfer the page num is %d\n", end-start);
    for (i = start; i < end; ++i) {
        unsigned long gfn = gfns[i];

//        printk("============== cocotion test transfer gfn = %d\n", gfn);

#ifdef PAGE_TRANSFER_TIME_MEASURE
        page_transfer_start_times[i] = time_in_us();
#endif

#ifdef SPCL
        if (spcl_transfer_check(dlist, i))
            continue;
#endif

        len += kvmft_diff_to_buf(kvm, gfn, i, buf + len,
            trans_index, run_serial);
        total_bytes+=len;
        if (len >= 64 * 1024) {
            ret = ktcp_send(sock, buf, len);
            if (ret < 0)
                goto free;
            total += len;
            len = 0;
        }
    }
    //total_count++;
    //printk("cocotion test total dirty bytes = %ld\n", total_dirty_bytes);
    //printk("cocotion test real transfer dirty bytes = %ld\n", total_bytes);
  //  printk("cocotion test real dirty bytes = %d\n", total_dirty_bytes_per_page);
    //printk("cocotion test @@total transfer bytes = %ld\n", total_bytes);
//    total_bytes = 0;
    if (len > 0) {
        ret = ktcp_send(sock, buf, len);
        if (ret < 0)
            goto free;
        total += len;
    }



    #ifdef ft_debug_bd
printk("cocotion test ============= tranfer start\n");
    printk("cocotion test count trans is %d\n", end-start);
    printk("cocotion test total bytes transfer is %d\n", total);
    printk("cocotion test real zero-count =  %d\n", z_count);
    printk("cocotion test diff gfn total is %d\n", global_diff_gfn_count);
    printk("cocotion test diff pfn total is %d\n", global_diff_pfn_count);

    printk("cocotion test global_sample_dirty_page_count = %d\n", global_sample_dirty_page_count);
    global_sample_dirty_page_count = 0;

    global_diff_pfn_count = 0;
    global_diff_gfn_count = 0;

printk("cocotion test ============= tranfer end\n");
    #endif



    kvmft_tcp_nodelay(sock);

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

    sched_setscheduler(current, SCHED_FIFO, &param);

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

        if (end > start)
            len = kvmft_transfer_list(kvm, sock, dlist,
                start, end, desc->trans_index, info->run_serial);

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

    len = kvmft_transfer_list(kvm, psock, dlist,
        0, count, trans_index, run_serial);
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
        if (ram_len < 0) {
            return ram_len;
        }
    } else {
        // TODO
        //return diff_and_transfer_second_half(kvm, trans_index, conn_index, max_conn);
    }

//    if (ram_len == 0) { 
 //       ctx->bd_last_average_dirty_bytes = 0; 
  //  } else {
   //     ctx->bd_last_average_dirty_bytes = ram_len / ctx->page_nums_snapshot_k[trans_index]->put_off;
    //}    



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

//    for(i = 0; i < len; ++i) {
       // if(ctx->dirty_pages_via_gfn[i]) {
      //      __free_pages(ctx->dirty_pages_via_gfn[i], 0);
     //       ctx->dirty_pages_via_gfn[i] = NULL;
     //   }
    //}


    kfree(ctx->page_nums_snapshot_k);
    kfree(ctx->page_nums_snapshot_page);
    kfree(ctx->shared_pages_snapshot_k);
    kfree(ctx->shared_pages_snapshot_pages);

    //kfree(ctx->dirty_pages_via_gfn);
    kfree(ctx->gfn_pfn_sync_list);

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

    __free_page(bad_page);
}

int kvm_shm_init(struct kvm *kvm, struct kvm_shmem_init *info)
{
    int ret = -ENOMEM;
    unsigned long i;
    unsigned long cnt;
    struct kvmft_context *ctx = &kvm->ft_context;

    global_kvm = kvm;

    bad_page = alloc_page(GFP_KERNEL | __GFP_ZERO);
    if(bad_page == NULL) {
        goto err_free;     
    }


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
    p_left_time = 2500;
    bd_page_fault_check = 1;
    epoch_time_in_us = info->epoch_time_in_ms * 1000;
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

//  net_set_tcp_zero_copy_callbacks(kvm_shm_tcp_get_callback, kvm_shm_tcp_put_callback);

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

    __bd_average_init(ctx);
    
    ctx->bd_alpha = 1000;   // start alpha is 1ms

    return 0;

err_free:
    kvm_shm_exit(kvm);
    return ret;
}

int kvmft_ioctl_bd_set_alpha(struct kvm *kvm, int alpha)
{
    struct kvmft_context *ctx;

    ctx = &kvm->ft_context;
    ctx->bd_alpha = alpha;

    return 0;
}   


static bool kvm_is_mmio_pfn(pfn_t pfn)
{
   if (pfn_valid(pfn))
       return !is_zero_pfn(pfn) && PageReserved(pfn_to_page(pfn));

   return true;
}


struct page *gfn_to_page_atomic(struct kvm *kvm, gfn_t gfn)
{
   pfn_t pfn;

   pfn = gfn_to_pfn_atomic(kvm, gfn);
   if (!kvm_is_mmio_pfn(pfn))
       return pfn_to_page(pfn);

   WARN_ON(kvm_is_mmio_pfn(pfn));

   get_page(bad_page);
   return bad_page;
}

#include <linux/pid.h>
#include <asm/io.h>

unsigned long pid_to_cr3(int pid)
{
    struct task_struct *task;
    struct mm_struct *mm;
    void *cr3_virt;
    unsigned long cr3_phys;

    task = pid_task(find_vpid(pid), PIDTYPE_PID);

    if (task == NULL)
        return 0; // pid has no task_struct

    mm = task->mm;

    // mm can be NULL in some rare cases (e.g. kthreads)
    // when this happens, we should check active_mm
    if (mm == NULL) {
        mm = task->active_mm;
    }

    if (mm == NULL)
        return 0; // this shouldn't happen, but just in case

    cr3_virt = (void *) mm->pgd;
    cr3_phys = virt_to_phys(cr3_virt);

    return cr3_phys;
}


#define __ex(x) __kvm_handle_fault_on_reboot(x)
#define __ex_clear(x, reg) \
	____kvm_handle_fault_on_reboot(x, "xor " reg " , " reg)

static __always_inline unsigned long vmcs_readl(unsigned long field)
{
	unsigned long value;

	asm volatile (__ex_clear(ASM_VMX_VMREAD_RDX_RAX, "%0")
		      : "=a"(value) : "d"(field) : "cc");
	return value;
}

static __always_inline u64 vmcs_read64(unsigned long field)
{
#ifdef CONFIG_X86_64
	return vmcs_readl(field);
#else
	return vmcs_readl(field) | ((u64)vmcs_readl(field+1) << 32);
#endif
}


//#include <linux/pid.h>
//#include <asm/io.h>


int bd_calc_dirty_bytes(struct kvmft_context *ctx, struct kvmft_dirty_list *dlist)
{
    struct page *page1, *page2;
    int i, j, count, total_dirty_bytes = 0;
   
//    spin_lock(&myftlock);
 
    dlist = ctx->page_nums_snapshot_k[ctx->cur_index];
    count = dlist->put_off;

//    printk("cocotion test dirty page count = %d\n", count);

    int total_zero_len = 0;
    int invalid_count = 0;
            
    //unsigned long mycr3 = task_pid_nr(current);
    unsigned long mycr3 = pid_to_cr3(task_pid_nr(current));
    
    //if(global_vcpu->mycr3 == mycr3)
    for (i = 0; i < count; ++i) {
//        spin_lock(&myftlock);
        gfn_t gfn = dlist->pages[i];

        page1 = ctx->shared_pages_snapshot_pages[ctx->cur_index][i];
 
        struct kvm_memory_slot *memslot;
        unsigned long gfn_off;
        memslot = gfn_to_memslot(global_kvm, gfn);
        gfn_off = gfn - memslot->base_gfn;

        if((ctx->gfn_pfn_sync_list)[gfn_off].flag == 1) {
            pfn_t pfn = (ctx->gfn_pfn_sync_list)[gfn_off].pfn;

            page2 = pfn_to_page(pfn);
            //page2 = gfn_to_page_atomic(global_kvm, gfn);

        //cocotion now testing
//            pfn_t pfn = (ctx->gfn_pfn_sync_list)[0].pfn;

            
//extern void mysetcr3(struct kvm_vcpu *vcpu, unsigned long cr3);
            //unsigned long mycr3 = pid_to_cr3(task_pid_nr(current));
            //unsigned long mycr3 = task_pid_nr(current);
            

            //unsigned long mycr3 = vmcs_read64(EPT_POINTER);

            //__asm__("movl %0, %%CR3" : "=r"(global_vcpu->mycr3)); 
           
 //           int no = 100; 
//            __asm__("movl %0, %%ebx;" : "=r"(no));
            
           // __asm__("movl %0, %%cr3;" : "=r"(global_vcpu->mycr3));

            //asm volatile("movq %0,%%cr3" : : "r" (global_vcpu->mycr3));
        
            //printk("cocotion test my pid when tasklet = 0x%016llx\n", task_pid_nr(current));

           // if((ctx->gfn_pfn_sync_list)[0].flag == 1 && global_vcpu->mycr3 == mycr3){
           // gfn_t mygfn = (ctx->gfn_pfn_sync_list)[0].pfn;
            

            //gfn_to_pfn_atomic(global_kvm, mygfn);
            //gfn_to_page_atomic(global_kvm, mygfn);

            //printk("cocotion test my pid when tasklet (same) = 0x%016llx\n", mycr3);

            
            //if (global_vcpu->mycr3 != mycr3) break;
            //if (global_vcpu->mycr3 == mycr3) continue;
            //pfn_t mypfn = gfn_to_pfn(global_kvm, gfn);
            //page2 = gfn_to_page_atomic(global_kvm, mygfn);
            //printk("cocotion test my page = 0x%016llx\n", page2);
            //break; 
//            printk("cocotion test my pid when tasklet(same) = 0x%016llx\n", mycr3);
 //           printk("cocotion test my pid when VMexit(same) = 0x%016llx\n", global_vcpu->mycr3);
            
            //kvm_mmu_load(global_vcpu);
            
	        //global_vcpu->arch.mmu.set_cr3(global_vcpu, global_vcpu->arch.mmu.root_hpa);


//    printk("cocotion test my EPTP when tasklet = 0x%016llx\n", vmcs_read64(EPT_POINTER));
 
 //   printk("cocotion test my pid when tasklet = 0x%016llx\n", task_pid_nr(current));


            //spin_lock(&global_kvm->mmu_lock);
            //gfn_to_page_atomic(global_kvm, mygfn);
            //gfn_to_pfn_atomic(global_kvm, mygfn);
            //gfn_t mygfn = (ctx->gfn_pfn_sync_list)[0].pfn;
            //kvm_vcpu_gfn_to_pfn_atomic(global_vcpu, mygfn);
            //spin_unlock(&global_kvm->mmu_lock);
                //vmx_set_cr3(global_vcpu, global_vcpu->mycr3);
            //    mysetcr3(global_vcpu, global_vcpu->mycr3);
//                printk("cocotion test guest exit use CR3= %ld\n", global_vcpu->mycr3);
 //               printk("cocotion test guest exit use CR3(2)= %ld\n", kvm_read_cr3(global_vcpu));
                //printk("cocotion test in host use CR3 = %ld\n", pid_to_cr3(task_pid_nr(current)));
            //}
            //else if (global_vcpu->mycr3 != mycr3){
                //printk("cocotion test my pid when tasklet = 0x%016llx\n", mycr3);
                //printk("cocotion test my pid when VMexit = 0x%016llx\n", global_vcpu->mycr3);
                
            //}


 //           pfn_to_page(pfn);
//            (ctx->gfn_pfn_sync_list)[0].flag = 0;

   //     }

   /*     page2 = gfn_to_page_atomic(global_kvm, gfn); 
        if(page2 == bad_page) {
            printk("cocotion test yes you got bad page\n");
            continue;
        }
*/
        //spin_lock(&global_kvm->mmu_lock);
        //page2 = gfn_to_page(global_kvm, gfn);
        //spin_unlock(&global_kvm->mmu_lock);


        char *backup = kmap_atomic(page1);
        char *page = kmap_atomic(page2);

        int len = 0;
        kernel_fpu_begin();
        for (j = 0; j < 4096; j += 32) {
            len += 32 * (!!memcmp_avx_32(backup + j, page + j));
        }
        kernel_fpu_end();
        kunmap_atomic(backup);
        kunmap_atomic(page);

        if(len == 0) {
            total_zero_len++; 
            len = 4096;
        }




        total_dirty_bytes+=len;
        }


//        struct kvm_memory_slot *memslot;
 //       unsigned long gfn_off;
  //      memslot = gfn_to_memslot(global_kvm, gfn);
   //     gfn_off = gfn - memslot->base_gfn;

        //while((ctx->gfn_pfn_sync_list)[gfn_off].flag == 0);

        //printk("cocotion test gfn pfn sync flag = %d\n", (ctx->gfn_pfn_sync_list)[gfn_off].pfn);

/*

        int len = 0;

        if((ctx->gfn_pfn_sync_list)[gfn_off].flag == 1) {
            pfn_t pfn = (ctx->gfn_pfn_sync_list)[gfn_off].pfn;
            //(ctx->gfn_pfn_sync_list)[gfn_off].flag = 0; 
        
            struct page *mypage;

            //int pagereserved = PageReserved(mypage = pfn_to_page(pfn));
            mypage = pfn_to_page(pfn);
            //if(!pfn_valid(pfn) || pagereserved) invalid_count++;
        

            char *page = kmap_atomic(mypage);
   
            char *backup = kmap_atomic(page1) ;
        
            int j,k;
            
            kernel_fpu_begin();
            for (j = 0; j < 4096; j += 32) {
                //for(k = 0; k<32; k++) {
                 //   if((page+j)[k] != (backup+j)[k]) {
                  //      len += 32;
                   //     break; 
                    //}
                //}
                len += 32 * (!!memcmp_avx_32(backup + j, page + j));
                
            }
            kernel_fpu_end();

 
            kunmap_atomic(page);
            kunmap_atomic(backup);
            
            if(len == 0) {
                total_zero_len++; 
                len = 4096;
            }

            //printk("===============in flag gfn = %d\n", gfn);
            invalid_count++;
        }    
   //     else {
    
            //page2 = gfn_to_page(kvm, gfn);
            
            //pfn_t pfn;
            //struct kvm_memory_slot *slot;
            //bool async = false;
            //pfn = __gfn_to_pfn_memslot(slot, gfn, false, &async, true, true);

            //struct page *mypage = pfn_to_page(pfn);


            //printk("===============not in flag gfn = %d\n", gfn);
    //    }


//        if(len == 0) {
 //           total_zero_len++; 
  //          len = 4096;
   //     }
       
    //    printk("cocotion test len = %d\n", len) ;
        total_dirty_bytes += len;
*/
    }

    total_dirty_bytes += 28*count;



    #ifdef ft_debug_bd

    printk("total dirty bytes (not real)= %d\n", total_dirty_bytes) ;
    
    printk("cocotion test total_zero_len (not real) = %d\n", total_zero_len);
  //  printk("cocotion test invalid count (not real)= %d\n", invalid_count);
    printk("cocotion test total count (not real)= %d\n", count);
    
    printk("@@@@@@@@@@@@@cocotion test invalid count (not real)= %d\n", invalid_count);
    #endif
        
    if (count > 0) {
  //      spin_unlock(&myftlock);
        return total_dirty_bytes; 
    }
 //   spin_unlock(&myftlock);
    return 0;
}


int kvmft_ioctl_bd_calc_dirty_bytes(struct kvm *kvm)
{
    struct kvmft_context *ctx = &kvm->ft_context;
    struct kvmft_dirty_list *dlist;
    //void **snapshot_pages;
    struct page *page1, *page2;
    int i, j, count, total_dirty_bytes = 0;


    dlist = ctx->page_nums_snapshot_k[ctx->cur_index];
    //snapshot_pages = ctx->shared_pages_snapshot_k[ctx->cur_index];

//    printk("cocotion test begain ==================\n");
    count = dlist->put_off;
    //printk("cocotion in filter print %d\n", count);
    global_dirty_count = count;
    for (i = 0; i < count; ++i) {
        gfn_t gfn = dlist->pages[i];

        page1 = ctx->shared_pages_snapshot_pages[ctx->cur_index][i];
        page2 = find_later_backup(kvm, gfn, ctx->cur_index, ctx->master_slave_info[ctx->cur_index].run_serial);

        if(page2 == NULL) {
            page2 = gfn_to_page(kvm, gfn);
        }
        char *backup = kmap_atomic(page1);
        char *page = kmap_atomic(page2);

        kernel_fpu_begin();
        int len = 0;
        int dirty_bytes = 0;
        for (j = 0; j < 4096; j += 32) {
            len += 32 * (!!memcmp_avx_32(backup + j, page + j));
            //dirty_bytes += 32 * (!!memcmp_avx_32(backup + j, page + j));
            dirty_bytes += 32;
        }
        kernel_fpu_end();
        kunmap_atomic(backup);
        kunmap_atomic(page);

        if(len == 0) len = 4096;

        total_dirty_bytes += len;


//        printk("@@cocotion test total dirty bytes per page before take snapshot= %d\n", len);
        
    }
    total_dirty_bytes += 28*count;
//    printk("@@cocotion test count = %d\n", count);
    printk("@@cocotion test total dirty bytes before take snapshot= %d\n", total_dirty_bytes);
    

    if (count > 0) {
        //ctx->bd_average_dirty_bytes = dirty_bytes / count;
        
        //if (ctx->bd_average_dirty_bytes < 100)
            //ctx->bd_average_dirty_bytes = 100;
       // return ctx->bd_average_dirty_bytes;
        //I just want to send the all dirty bytes
        return total_dirty_bytes; 
    }

    return 0;
}

int kvmft_ioctl_bd_get_runtime(struct kvm *kvm, int *epoch_runtime)
{
    
    extern ktime_t global_mark_start_time;
    struct kvmft_context *ctx = &kvm->ft_context;
    struct kvmft_dirty_list *dlist;
    int ret; 

    dlist = ctx->page_nums_snapshot_k[ctx->cur_index];
    //*epoch_runtime = time_in_us() - dlist->epoch_start_time;
    *epoch_runtime = ktime_to_us(ktime_sub(ktime_get(), global_mark_start_time));
//    printk("cocotion test %d\n", *epoch_runtime);
}

int kvmft_ioctl_bd_runtime_exceeds(struct kvm *kvm, int *epoch_runtime)
{
    struct kvmft_context *ctx = &kvm->ft_context;
    struct kvmft_dirty_list *dlist;
    int ret; 

    dlist = ctx->page_nums_snapshot_k[ctx->cur_index];
    *epoch_runtime = time_in_us() - dlist->epoch_start_time;
//        printk    cocotion test epoch_runtim = %d\n", *epoch_runtime);
    if(*epoch_runtime >= target_latency_us)
     return 1;
    else return 0; 

}


int kvmft_ioctl_bd_calc_left_runtime(struct kvm *kvm)
{
    struct kvmft_context *ctx = &kvm->ft_context;
    struct kvmft_dirty_list *dlist;
    int ret; 

    dlist = ctx->page_nums_snapshot_k[ctx->cur_index];

    s64 epoch_run_time = time_in_us() - dlist->epoch_start_time;
    return epoch_run_time;

/*



    if(epoch_run_time > 10000) printk("epoch_run_time = %ld\n", epoch_run_time);  

 
    //cocotion test 
    if(epoch_run_time > 5 * 1000) return 0;

    // if average dirty bytes raise a lot, more time to transfer
    int factor = 100; 
    if (ctx->bd_average_dirty_bytes >= ctx->bd_last_average_dirty_bytes * 130 / 100) {
        factor = FACTOR_SHOOTUP;
    }    
    if (dlist->put_off >= ctx->bd_last_dp_num*130/100) {
        factor = factor * FACTOR_SHOOTUP / 100; 
    }    

    int transfer_rate = ctx->bd_average_rate;
    if (transfer_rate / 500 > ctx->bd_average_dirty_bytes && ctx->bd_average_dirty_bytes) {
        transfer_rate = ctx->bd_average_dirty_bytes * 500; 
    }    

    if (ctx->bd_average_dirty_bytes <= 300) {
        ret = max_latency - epoch_run_time - dlist->put_off * 1000 / 600; 
    } else {
        ret = max_latency - epoch_run_time - dlist->put_off * ctx->bd_average_dirty_bytes * 1000 / transfer_rate * factor/100;
        if (factor != 100) 
            ret -= dlist->put_off;
    }    
*/
        /*   
    if (dlist->put_off >= ctx->bd_last_dp_num*140/100) {
        // 4/3 is for slave loading time prediction
        ret = max_latency - epoch_run_time - dlist->put_off * ctx->bd_average_dirty_bytes * 1000 / (ctx->bd_average_rate * 75 / 100);
    } else {
        ret = max_latency - epoch_run_time - dlist->put_off * ctx->bd_average_dirty_bytes * 1000 / (ctx->bd_average_rate * 100 / 100);
    }
    */
/*
    if (ret <= 0) { 
        ctx->bd_last_dp_num = dlist->put_off;
    }    
  
 
    return ret;*/ 
}

int kvmft_ioctl_bd_predic_stop(struct kvm *kvm, struct kvmft_update_latency *update)
{
    struct kvmft_context *ctx;
    struct kvmft_dirty_list *dlist;
    int put_index;

    ctx = &kvm->ft_context;
    dlist = ctx->page_nums_snapshot_k[ctx->cur_index];
   
    return bd_predic_stop(kvm, dlist, dlist->put_off, update); 
 
}

void updateW(int e)
{
    w_a = w_a + (x_a/10 * e);
    w_b = w_b + (x_b/10000 * e);
    w_c = w_c + (x_c/10 * e);
    w_d = w_d + (x_d/10 * e);
/*
    printk("cocotion test w_a = %d\n", w_a);
    printk("cocotion test w_b = %d\n", w_b);
    printk("cocotion test w_c = %d\n", w_c);
    printk("cocotion test w_d = %d\n", w_d);
    printk("=============================\n");*/
}

int kvmft_ioctl_bd_perceptron(int latency_us)
{

/*
    if((latency_us <= target_latency_us) && (latency_us >= (target_latency_us - p_rang))){
        if(p_out > p_out_max) p_out_max = p_out;
        if(p_out < p_out_min) p_out_min = p_out;
    }
    else {
        if(p_out > p_out_max)
            updateW(-1);
        else if(p_out < p_out_min)
            updateW(1);
    
        if(latency_us > target_latency_us) { 
            p_out_max-=latency_us;
            p_out_min-=latency_us;
        }
        else {
            p_out_max+=latency_us;
            p_out_min+=latency_us;
        }
        p_left_time+=exceeds_factor;
     }
*/
    return 1;
}


int kvmft_ioctl_bd_check_dirty_page_number(struct kvm *kvm)
{
    struct kvmft_context *ctx;
    struct kvmft_dirty_list *dlist;
    int put_index;

    ctx = &kvm->ft_context;
    dlist = ctx->page_nums_snapshot_k[ctx->cur_index];

 //   if(kvmft_ioctl_bd_predic_stop(kvm)) {
  //      ctx->log_full = true;
   //     return 1;
 //   }
                                                                                                                                                                                                                    
    return 0;
}



