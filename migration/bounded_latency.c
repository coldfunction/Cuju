#include "qemu/osdep.h"
#include "migration/migration.h"
#include "migration/cuju-kvm-share-mem.h"
#include "sysemu/kvm.h"
#include <linux/kvm.h>
#include "qmp-commands.h"

int first_enter = 1;
static int bd_target = EPOCH_TIME_IN_MS * 1000;
int bd_alpha = 1000; // initial alpha is 1 ms
float bd_time_slot_us;                                                                                                                                                                     
float p_bd_time_slot_us = EPOCH_TIME_IN_MS*1000/20;

extern unsigned long pass_time_us_threshold;
int average_exceed_runtime_us = EPOCH_TIME_IN_MS * 1000;
int average_ok_runtime_us = EPOCH_TIME_IN_MS * 1000/3 - 100;
int bd_time_slot_adjust = -100;   

int kvmft_bd_set_alpha(int alpha); 


int kvmft_bd_set_alpha(int alpha)
{
    return kvm_vm_ioctl(kvm_state, KVMFT_BD_SET_ALPHA, &alpha);
}                                                                                                                                                                                                                   
/*
static int kvmft_bd_check_dirty_page_number(void)
{
    return kvm_vm_ioctl(kvm_state, KVMFT_BD_CHECK_DIRTY_PAGE_NUMBER);
}                                                                                                                                                                                                                   
*/

static int kvmft_bd_predic_stop(void)
{
    int dirty_bytes = 0;
    int r;
    r = kvm_vm_ioctl(kvm_state, KVMFT_BD_PREDIC_STOP, &dirty_bytes);
//    printf("cocotion test dirty_bytes = %d\n", dirty_bytes);

//    if(r) {


        FILE *pFile;

        pFile = fopen("mydirty.txt", "a");
        char pbuf[200];
        if(pFile != NULL){
            sprintf(pbuf, "%d\n", dirty_bytes);
            fputs(pbuf, pFile);                                                                                                                      
        }    
        else
            printf("no profile\n");
        fclose(pFile); 
 //   }

    return r;
}


/*
static int bd_calc_left_runtime(void)                                                                                                                                                                               
{
    return kvm_vm_ioctl(kvm_state, KVMFT_BD_CALC_LEFT_RUNTIME);
}
*/


//static FILE *bdofile = NULL; 
//static FILE *ofile = NULL;

void bd_update_stat(int dirty_num, 
                    double tran_time_s, 
                    double delay_time_s, 
                    double run_time_s, 
                    double invoke_commit1_s, 
                    double recv_ack1_s, 
                    int ram_len, 
                    int average_predict)
{
    kvmft_bd_set_alpha(bd_alpha);
/*
    if (delay_time_s * 1000 * 1000 > bd_target * 110 / 100) {
        bd_alpha += 200;
        kvmft_bd_set_alpha(bd_alpha);
    } else if (delay_time_s * 1000 * 1000 > bd_target * 102 / 100) {                                                                                                                                                
        bd_alpha += 50; 
        kvmft_bd_set_alpha(bd_alpha);
    } else if (delay_time_s * 1000 * 1000 >= bd_target * 98 / 100) {
        // [98%, 102%]
        // slowly back off
        bd_alpha += 10; 
        kvmft_bd_set_alpha(bd_alpha);
    } else {
        bd_alpha -= 25; 
        kvmft_bd_set_alpha(bd_alpha);
    }   
*/
/*    if (ofile == NULL) {
        ofile = fopen("/tmp/bd_delay", "w");
        assert(ofile);
    }   
*/
    //if (dirty_num < 500)
    //    return;

/*
    fprintf(ofile, "%.4lf\t%.4lf\t%.4lf\t%.4lf\t%.4lf\t%d\t%d\t%d\t%d\t%d\n", delay_time_s * 1000,
        tran_time_s * 1000,
        run_time_s * 1000,
        invoke_commit1_s * 1000,
        recv_ack1_s * 1000,
        dirty_num,
        (int)(ram_len / (tran_time_s * 1000)),
        ram_len / (dirty_num?dirty_num:1),
        average_predict,
        bd_alpha);
*/
}

int kvmft_bd_perceptron(int latency_us)
{
    return kvm_vm_ioctl(kvm_state, KVMFT_BD_PERCEPTRON, &latency_us);
}

int kvmft_bd_update_latency(int dirty_page, int runtime_us, int trans_us, int latency_us)
{
    struct kvmft_update_latency update;

    update.dirty_page = dirty_page;
    update.runtime_us = runtime_us;
    update.trans_us = trans_us;
    update.latency_us = latency_us;

    return kvm_vm_ioctl(kvm_state, KVMFT_BD_UPDATE_LATENCY, &update);
}

/*
static int bd_page_fault_check(void)
{
    return kvm_vm_ioctl(kvm_state, KVMFT_BD_PAGE_FAULT_CHECK);
}*/

/*
static int bd_calc_dirty_bytes(void)                                                                                                                                                                                
{
    return kvm_vm_ioctl(kvm_state, KVMFT_BD_CALC_DIRTY_BYTES);
}
*/

/*
static int bd_is_last_count(int count)
{
    if (EPOCH_TIME_IN_MS < 10) {
        return count == 10;                                                                                                                                                                                         
    } else {
        return count == EPOCH_TIME_IN_MS;
    }   
}
*/

void bd_reset_epoch_timer(void)
{
//    bd_time_slot_us = average_ok_runtime_us;
    //bd_time_slot_us = bd_target/2;
//    bd_time_slot_us = bd_target/2;
    bd_time_slot_us = 5000;

//    bd_time_slot_us = bd_target - 1000;

//    if(bd_time_slot_us < 100)
 //       bd_time_slot_us = 100;

    Error *err = NULL;
    qmp_cuju_adjust_epoch((unsigned int)bd_time_slot_us, &err);                                                                                                                                                                             
    if (err) {
        error_report_err(err);
        return;
    }    

}
/*
static int is_epoch_run_time_exceeds_target_latency(unsigned int *pass_time_us)
{
    return kvm_vm_ioctl(kvm_state, KVMFT_BD_RUNTIME_EXCEEDS, pass_time_us);
}
*/
int get_pass_time_us(unsigned int *pass_time_us)
{
    return kvm_vm_ioctl(kvm_state, KVMFT_BD_GET_RUNTIME, pass_time_us);
}


bool bd_timer_func(void)
{
    unsigned int pass_time_us;

    get_pass_time_us(&pass_time_us);
    if(pass_time_us >= bd_target*0.94) {
        //bd_page_fault_check(); 
        return false;
    }
 
    //if(bd_page_fault_check() && kvmft_bd_predic_stop())  {
//    if(bd_page_fault_check())  {
    
        FILE *pFile;

        pFile = fopen("mytime.txt", "a");
        char pbuf[200];
        if(pFile != NULL){
            sprintf(pbuf, "%d\n", pass_time_us);
            fputs(pbuf, pFile);                                                                                                                      
        }    
        else
            printf("no profile\n");
        fclose(pFile); 
   
    kvmft_bd_predic_stop();   
    get_pass_time_us(&pass_time_us);

//    if(first_enter)
//        first_enter = 0;
//    else {
//        first_enter = 1;
        return false;
//    }
        

    //printf("cocotion test take snapshot not real pass_time_us %d\n", pass_time_us);
  //      if( kvmft_bd_predic_stop()) {
//            if(first_enter)
 //               first_enter = 0; 
  //          else first_enter = 1;
//            return false;
   //     }
 //   }

//    printf("cocotion test in bd_timer_func: timer expiry = %d\n", (bd_target-pass_time_us)/2);

    Error *err = NULL;
//    qmp_cuju_adjust_epoch(10, &err);
    qmp_cuju_adjust_epoch((bd_target-pass_time_us)/2, &err);


    kvm_shmem_start_timer();
    //bd_page_fault_check(); 
    return true;                                                                                                                                                                                                      
}


