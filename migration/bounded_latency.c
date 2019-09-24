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



int kvmft_bd_update_latency(int dirty_page, int runtime_us, int trans_us, int latency_us)
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

	   FILE *pFile;
   char pbuf[200];
    pFile = fopen("runtime_latency_trans_rate.txt", "a");
    if(pFile != NULL){
        sprintf(pbuf, "%d ", update.w0);
        fputs(pbuf, pFile);
//        sprintf(pbuf, "%d ", update.w1);
 //       fputs(pbuf, pFile);
        sprintf(pbuf, "%d ", update.w3);
        fputs(pbuf, pFile);
//        sprintf(pbuf, "%d ", update.w4);
 //       fputs(pbuf, pFile);
        sprintf(pbuf, "%d ", update.x0);
        fputs(pbuf, pFile);
  //      sprintf(pbuf, "%d ", update.x1);
   //     fputs(pbuf, pFile);
    //    sprintf(pbuf, "%d ", update.x2);
     //   fputs(pbuf, pFile);
      //  sprintf(pbuf, "%d ", update.x1 + update.x0);
       // fputs(pbuf, pFile);
        sprintf(pbuf, "%d ", trans_us);
        fputs(pbuf, pFile);
//		int expect = update.x0 + update.x1 + update.x2/update.w4 + update.w3;
//		int expect = update.x0*update.w0/1000 + update.w3;
		int expect = update.x0*update.w0/1000;
		//expect/=1000;
        sprintf(pbuf, "%d ", expect);
        fputs(pbuf, pFile);
        sprintf(pbuf, "%d\n", latency_us);
        fputs(pbuf, pFile);
    }
    else
        printf("no profile\n");
    fclose(pFile);

	return r;
}

int get_vm_id(void)
{
	return kvm_vm_ioctl(kvm_state, KVMFT_BD_GET_VM_ID, NULL);
}


