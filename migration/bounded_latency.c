#include "qemu/osdep.h"
#include "migration/migration.h"
#include "migration/cuju-kvm-share-mem.h"
#include "sysemu/kvm.h"
#include <linux/kvm.h>
#include "qmp-commands.h"

struct kvmft_update_latency mybdupdate;
int bd_alpha = 0;

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



int kvmft_bd_update_latency(int dirty_page, int runtime_us, int trans_us, int latency_us, MigrationState *s)
{
    struct kvmft_update_latency update;

    update.dirty_page = dirty_page;
    update.runtime_us = runtime_us;
    update.trans_us = trans_us;
    update.latency_us = latency_us;

    update.last_trans_rate = mybdupdate.last_trans_rate;

	update.alpha = bd_alpha;

//    return kvm_vm_ioctl(kvm_state, KVMFT_BD_UPDATE_LATENCY, &update);
    int r = kvm_vm_ioctl(kvm_state, KVMFT_BD_UPDATE_LATENCY, &update);

	int id = get_vm_id();
	static int c0 = 0;
	static int c01 = 0;
	static int c1 = 0;

	if(id == 0) {
		FILE *pFile;
   		char pbuf[200];
    	pFile = fopen("runtime_latency_trans_rate.txt", "a");
    	if(pFile != NULL){
        	sprintf(pbuf, "%d ", update.w0);
        	fputs(pbuf, pFile);
        	sprintf(pbuf, "%d ", update.w1);
        	fputs(pbuf, pFile);
        	sprintf(pbuf, "%d ", update.w3);
        	fputs(pbuf, pFile);
        	sprintf(pbuf, "%d ", update.x0);
        	fputs(pbuf, pFile);
        	sprintf(pbuf, "%d ", update.x1);
        	fputs(pbuf, pFile);
        	sprintf(pbuf, "%d ", runtime_us);
        	fputs(pbuf, pFile);
        	sprintf(pbuf, "%d ", update.e_runtime);
        	fputs(pbuf, pFile);

			sprintf(pbuf, "%d ", trans_us);
        	fputs(pbuf, pFile);
//			int expect = update.x0*update.w0 + update.x1*update.w1;//+update.w3;
//			expect/=1000;
        	sprintf(pbuf, "%d ", update.e_trans);
        	fputs(pbuf, pFile);
        	sprintf(pbuf, "%d ", latency_us);
        	fputs(pbuf, pFile);
        	sprintf(pbuf, "%d ", update.e_latency);
        	fputs(pbuf, pFile);
        	sprintf(pbuf, "%d ", update.last_load_mem_rate);
        	fputs(pbuf, pFile);
        	sprintf(pbuf, "%d ", update.load_mem_rate);
        	fputs(pbuf, pFile);
        	sprintf(pbuf, "%d ", update.last_send_rate);
        	fputs(pbuf, pFile);
        	sprintf(pbuf, "%d ", update.current_send_rate);
        	fputs(pbuf, pFile);
        	sprintf(pbuf, "%d ", update.load_mem_bytes);
        	fputs(pbuf, pFile);
        	sprintf(pbuf, "%d ", update.real_load_mem_bytes);
        	fputs(pbuf, pFile);
        	sprintf(pbuf, "%d ", dirty_page);
        	fputs(pbuf, pFile);
        	sprintf(pbuf, "%d ", update.e_dirty_bytes);
        	fputs(pbuf, pFile);
        	sprintf(pbuf, "%d ", update.learningR);
        	fputs(pbuf, pFile);


			int runtime_bias = runtime_us - update.e_runtime;
//			if(runtime_us > 10000)
			//if(latency_us > 11000 && (latency_us - runtime_bias) <=11000)
			//	c0++;

			//sprintf(pbuf, "%d ", c0);
        	//fputs(pbuf, pFile);
			//if(runtime_us > 10000) {
			if(latency_us > 11000 && (latency_us - runtime_bias) <=11000) {
				c0++;

				sprintf(pbuf, "@@@ %d ", runtime_us);
        		fputs(pbuf, pFile);

				int after_kvm_to_qemu_time = runtime_us - (int)((s->after_kick_vcpu_time - s->run_real_start_time) * 1000000);
				sprintf(pbuf, "%d ", after_kvm_to_qemu_time);
        		fputs(pbuf, pFile);

				if (after_kvm_to_qemu_time < 10)
					c01++;

				int before_lock_iothread_time =  (int)((s->before_lock_iothread_time - s->after_kick_vcpu_time) * 1000000);

				sprintf(pbuf, "%d ", before_lock_iothread_time);
        		fputs(pbuf, pFile);

				int lock_iothread_time =  (int)((s->snapshot_start_time-s->before_lock_iothread_time) * 1000000);
				sprintf(pbuf, "%d ", lock_iothread_time);
        		fputs(pbuf, pFile);

			}
			sprintf(pbuf, "%d ", c0);
        	fputs(pbuf, pFile);

			sprintf(pbuf, "%d ", c01);
        	fputs(pbuf, pFile);

			sprintf(pbuf, "%d ", c1);
        	fputs(pbuf, pFile);
			int snapshot_time =  (int)((s->snapshot_start_time-s->snapshot_finish_time) * 1000000);
			if(snapshot_time > 1000) {
				c1++;
				sprintf(pbuf, "QQQ %d ", snapshot_time);
        		fputs(pbuf, pFile);
			}



        		fputs("\n", pFile);


    	}
    	else
        	printf("no profile\n");

		fclose(pFile);
	}
	return r;
}


int create_vm_id(void)
{
	return kvm_vm_ioctl(kvm_state, KVMFT_BD_CREATE_VM_ID, NULL);
}
int get_vm_id(void)
{
	return kvm_vm_ioctl(kvm_state, KVMFT_BD_GET_VM_ID, NULL);
}


