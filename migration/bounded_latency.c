#include "qemu/osdep.h"
#include "migration/migration.h"
#include "migration/cuju-kvm-share-mem.h"
#include "sysemu/kvm.h"
#include <linux/kvm.h>
#include "qmp-commands.h"

struct kvmft_update_latency mybdupdate;
int bd_alpha = 5000;

void bd_reset_epoch_timer(void)
{

//	int bd_time_slot_us = 6986;
	int bd_time_slot_us = 100;

	Error *err = NULL;
	qmp_cuju_adjust_epoch((unsigned int)bd_time_slot_us, &err);
	if (err) {
		error_report_err(err);
		return;
	}

}


int cuju_put_sync_local_VM_sig(int stage)
{
	return kvm_vm_ioctl(kvm_state, KVMFT_BD_SYNC_SIG, &stage);
}

int cuju_sync_local_VM_ok(int stage)
{
	return kvm_vm_ioctl(kvm_state, KVMFT_BD_SYNC_CHECK, &stage);
}

int cuju_get_dirty(int index)
{
	return kvm_vm_ioctl(kvm_state, KVMFT_BD_GET_DIRTY, &index);
}

int cuju_wait(void) {
	return kvm_vm_ioctl(kvm_state, KVMFT_BD_WAIT, NULL);
}


int kvmft_bd_update_latency(int dirty_page, int runtime_us, int trans_us, int latency_us)
{
    struct kvmft_update_latency update;

    update.dirty_page = dirty_page;
    update.runtime_us = runtime_us;
    update.trans_us = trans_us;
    update.latency_us = latency_us;

    update.last_trans_rate = mybdupdate.last_trans_rate;

	update.alpha = bd_alpha;

    return kvm_vm_ioctl(kvm_state, KVMFT_BD_UPDATE_LATENCY, &update);
}




