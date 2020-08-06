#include "qemu/osdep.h"
#include "migration/migration.h"
#include "migration/cuju-kvm-share-mem.h"
#include "sysemu/kvm.h"
#include <linux/kvm.h>
#include "qmp-commands.h"

void bd_set_timer_fire(void)
{
	int bd_time_slot_us = 1000;

	Error *err = NULL;
	qmp_cuju_adjust_epoch((unsigned int)bd_time_slot_us, &err);
	if (err) {
		error_report_err(err);
		return;
	}

}

int kvmft_bd_update_latency(MigrationState *s)
{

    int runtime_us = (int)((s->snapshot_start_time - s->run_real_start_time) * 1000000);
    int latency_us = (int)((s->recv_ack1_time - s->run_real_start_time) * 1000000);
    int trans_us = (int)((s->recv_ack1_time - s->snapshot_start_time) * 1000000);
	int dirty_len = s->ram_len;

    struct kvmft_update_latency update;
	update.dirty_pfns_len = s->dirty_pfns_len;
	update.dirty_len      = dirty_len;
	update.runtime_us     = runtime_us;
	update.trans_us       = trans_us;
	update.latency_us     = latency_us;
	update.cur_index      = s->cur_off;

    int r = kvm_vm_ioctl(kvm_state, KVMFT_BD_UPDATE_LATENCY, &update);



	static unsigned long long total = 0;
	static unsigned long long totalruntime = 0;
	static unsigned long long totallatency = 0;
	static unsigned long long totaltrans = 0;
	static unsigned long long totaldirty = 0;
	static unsigned long long exceed = 0;
	static unsigned long long less = 0;
	static unsigned long long ok = 0;
	static unsigned long long runtime_err = 0;
	static unsigned long long last_transfer_impact_error = 0;
	static unsigned long long total_uncompress_dirty = 0;

	static int last_trans_time;

	int e_runtime = update.e_runtime;


	totalruntime += runtime_us;
	totallatency += latency_us;
	totaltrans   += trans_us;
	totaldirty   += dirty_len;
	total_uncompress_dirty += s->dirty_pfns_len*4096;

	total++;



	if(latency_us <= EPOCH_TIME_IN_MS*1000 + 1000 && latency_us >= EPOCH_TIME_IN_MS*1000 - 1000) {
		ok++;
	} else if (latency_us > EPOCH_TIME_IN_MS*1000+1000) {
		exceed++;

		latency_us-=runtime_us;
		latency_us+=e_runtime;
		if(latency_us <= EPOCH_TIME_IN_MS*1000 + 1000 && latency_us >= EPOCH_TIME_IN_MS*1000 - 1000) {
			runtime_err++;
		} else if (last_trans_time > runtime_us) {
			last_transfer_impact_error++;
		}

	} else {
		less++;
	}




	last_trans_time = trans_us;


	double exceed_per, less_per, ok_per, runtime_err_per, last_transfer_impact_error_per;

	if(total % 500 == 0) {
		exceed_per = (double)exceed*100/total;
		less_per = (double)less*100/total;
		ok_per = (double)ok*100/total;
		runtime_err_per = (double)runtime_err*100/total;
		last_transfer_impact_error_per = (double)last_transfer_impact_error*100/total;

		printf("exceed = %lf\n", exceed_per);
		printf("less = %lf\n", less_per);
		printf("ok = %lf\n", ok_per);
		printf("runtime_err = %lf\n", runtime_err_per);
		printf("last trans impact err = %lf\n", last_transfer_impact_error_per);
		printf("transfer rate predic err = %lf\n", exceed_per+less_per-runtime_err_per-last_transfer_impact_error_per);


		printf("ave runtime = %lld\n", totalruntime/total);
		printf("ave trans = %lld\n", totaltrans/total);
		printf("ave latency = %lld\n", totallatency/total);
		printf("ave dirty = %lld\n", totaldirty/total);
		printf("ave uncompress = %lld\n", total_uncompress_dirty/total);

	}

/*    struct kvmft_update_latency update;

    update.dirty_page = dirty_page;
    update.runtime_us = runtime_us;
    update.trans_us = trans_us;
    update.latency_us = latency_us;

    update.last_trans_rate = mybdupdate.last_trans_rate;

    return kvm_vm_ioctl(kvm_state, KVMFT_BD_UPDATE_LATENCY, &update);
	*/
//	int runtime_us = (int)((s->snapshot_start_time - s->run_real_start_time) * 1000000);
//	printf("runtime = %d\n", runtime_us);
	return r;
}
