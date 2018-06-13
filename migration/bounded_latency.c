#include "qemu/osdep.h"
#include "migration/migration.h"
#include "migration/cuju-kvm-share-mem.h"
#include "sysemu/kvm.h"
#include <linux/kvm.h>
#include "qmp-commands.h"


static int bd_target = EPOCH_TIME_IN_MS * 1000;
static int bd_alpha = 1000; // initial alpha is 1 ms
static float bd_time_slot_us;                                                                                                                                                                     

extern unsigned long pass_time_us_threshold;


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
    return kvm_vm_ioctl(kvm_state, KVMFT_BD_PREDIC_STOP);
}


static int bd_calc_left_runtime(void)                                                                                                                                                                               
{
    return kvm_vm_ioctl(kvm_state, KVMFT_BD_CALC_LEFT_RUNTIME);
}



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

static int bd_calc_dirty_bytes(void)                                                                                                                                                                                
{
    return kvm_vm_ioctl(kvm_state, KVMFT_BD_CALC_DIRTY_BYTES);
}
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
    //float nvalue = BD_TIMER_RATIO * EPOCH_TIME_IN_MS * 1000;
    //if (EPOCH_TIME_IN_MS < 10)                                                                                                                                                                                      
        //bd_time_slot_us = EPOCH_TIME_IN_MS*1000/10;
        bd_time_slot_us = EPOCH_TIME_IN_MS*1000/20;
    //else
//        bd_time_slot_us = EPOCH_TIME_IN_MS*1000/10;
    //bd_time_slot_us = 250;


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
static int get_pass_time_us(unsigned int *pass_time_us)
{
    return kvm_vm_ioctl(kvm_state, KVMFT_BD_GET_RUNTIME, pass_time_us);
}


bool bd_timer_func(void)
{
    unsigned int pass_time_us;
    //if(is_epoch_run_time_exceeds_target_latency(&pass_time_us))
     //   return false;

    get_pass_time_us(&pass_time_us);
    if(pass_time_us >= bd_target) return false;
 
    static int count = 0;
    MigrationState *s = migrate_get_current();

    ++count;
/*                                                                                                                                                                                                                    
    printf("======================\n");
    printf("cocotion test count = %d\n", count);
    printf("cocotion test pass_time_us = %d\n", pass_time_us);
 */ 
    //printf("cocotion test pass_time_us_threshold = %lu\n", pass_time_us_threshold) ; 
    //printf("cocotion test bd_time_slot_us = %lu\n", (unsigned long)bd_time_slot_us) ; 
    if(pass_time_us >= pass_time_us_threshold)
        goto predic;
 
    if(pass_time_us < (bd_target/2)){
  //      printf("cocotion test keep go\n");
        kvm_shmem_start_timer();
        return true;
    }
    //else if(pass_time_us >= (bd_target/2)){
    else {
        //average dirty bytes per page
predic:
        s->average_dirty_bytes = bd_calc_dirty_bytes();
        if(/*bd_is_last_count(count) ||*/ kvmft_bd_predic_stop())  {
   //         printf("cocotion test bd_is_last_count(count) || kvmft_bd_predic_stop()\n");
            count = 0;
            return false;
        }
        int lefttime = bd_target - bd_calc_left_runtime() ;
        if(lefttime <= bd_time_slot_us){
    //        printf("cocotion test lefttime <= 200??? lefttime = %d\n", lefttime);
            count = 0;
            return false;
        }// else if (lefttime < bd_time_slot_us) {
          //  Error *err = NULL;
           // qmp_cuju_adjust_epoch((unsigned int)lefttime, &err);                                                                                                                                                              
        //} 
        Error *err = NULL;
        qmp_cuju_adjust_epoch(lefttime/20, &err);                                                                                                                                                              


        kvm_shmem_start_timer();
        return true;                                                                                                                                                                                                      
    }
    kvm_shmem_start_timer();
    return true;


/*
    if (EPOCH_TIME_IN_MS >= 10) {
        if (count < EPOCH_TIME_IN_MS/2) {
            kvm_shmem_start_timer();
            return true;
        }

        if (count == EPOCH_TIME_IN_MS/2) {
            s->average_dirty_bytes = bd_calc_dirty_bytes();
        }

        if (count > EPOCH_TIME_IN_MS/2) {
            //s->average_dirty_bytes = bd_calc_dirty_bytes();
        }

        if (bd_is_last_count(count) || kvmft_bd_check_dirty_page_number()) {
            count = 0;
            //last_dirty_bytes = 0;
            return false;
        }
        if (count >= EPOCH_TIME_IN_MS/2) {
            int lefttime = bd_calc_left_runtime();

            //fprintf(ofile, "%d %d %d\n", count, lefttime, s->average_dirty_bytes);

            //if (lefttime <= -400)
            //    printf("%s %d lefttime = %d\n", __func__, count, lefttime);
            if (lefttime <= 200) {
                count = 0;
                //last_dirty_bytes = 0;
                return false;
            } else if (lefttime < 1000) {
                Error *err = NULL;
                qmp_cuju_adjust_epoch((unsigned int)lefttime, &err);                                                                                                                                                              
            }                                                                                                                                                                                                       

            if (count == EPOCH_TIME_IN_MS-1 && lefttime >= 800) {
                Error *err = NULL;
                qmp_cuju_adjust_epoch(700, &err);                                                                                                                                                              
            }   
        }   
        kvm_shmem_start_timer();
        return true;
    } else {
      
//cocotion test 
        int predtime = bd_calc_left_runtime();
        if (predtime <= 200) {
            count = 0;
            return false;
        } 



        if (count < 5) {
            kvm_shmem_start_timer();
            return true;
        }

        if (count == 5) {
            s->average_dirty_bytes = bd_calc_dirty_bytes();
        }

        if (count > 5) {
            s->average_dirty_bytes = bd_calc_dirty_bytes();
        }

        if (bd_is_last_count(count) || kvmft_bd_check_dirty_page_number()) {
            count = 0;
            //last_dirty_bytes = 0;
            return false;
        }

        if (count >= 5) {
            int lefttime = bd_calc_left_runtime();

            //fprintf(ofile, "%d %d %d\n", count, lefttime, s->average_dirty_bytes);

            //if (lefttime <= -400)
            //    printf("%s %d lefttime = %d\n", __func__, count, lefttime);
            if (lefttime <= 200) {
                count = 0;
                //last_dirty_bytes = 0;
                return false;
            } 


            else if (lefttime < EPOCH_TIME_IN_MS*1000/10) {
                Error *err = NULL;
                qmp_cuju_adjust_epoch((unsigned int)lefttime, &err);
            }

            if (count == EPOCH_TIME_IN_MS-1 && lefttime >= EPOCH_TIME_IN_MS*1000/10-200) {
                Error *err = NULL;
                qmp_cuju_adjust_epoch(EPOCH_TIME_IN_MS*1000/10-300, &err);
            }

        }
                                                                                                                                                                                                                    
        kvm_shmem_start_timer();
        return true;

    }


    return 0;*/
}


