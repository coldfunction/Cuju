#include "qemu/osdep.h"
#include "migration/migration.h"
#include "migration/cuju-kvm-share-mem.h"
#include "sysemu/kvm.h"
#include <linux/kvm.h>
#include "qmp-commands.h"

int first_enter = 1;
//int next_time = 1000;
static int bd_target = EPOCH_TIME_IN_MS * 1000;
//int bd_alpha = 1787; // initial alpha is 1 ms
int bd_alpha = -200; // initial alpha is 1 ms
float bd_time_slot_us;
//int bd_time_slot_us_pattern[] = {4000, 5000}                                                                                                                                                                     
float p_bd_time_slot_us = EPOCH_TIME_IN_MS*1000/20;

extern unsigned long pass_time_us_threshold;

struct kvmft_update_latency mybdupdate;
//mybdupdate.last_trans_rate = 100;

//extern int time_stamp[20];
//extern int dirty_bytes_stamp[20];
//extern int dirty_pages_stamp[20];
//extern int filter_count;


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
    //int dirty_bytes = 0;
    int r;

    //struct kvmft_update_latency update;


//    r = kvm_vm_ioctl(kvm_state, KVMFT_BD_PREDIC_STOP, &dirty_bytes);
    r = kvm_vm_ioctl(kvm_state, KVMFT_BD_PREDIC_STOP, &mybdupdate);


//    printf("cocotion test dirty_bytes = %d\n", dirty_bytes);

//    if(r) {

/*
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
*/

        //dirty_pages_stamp[filter_count]   = update.dirty_page;
        //dirty_bytes_stamp[filter_count] = update.dirty_byte;
        //filter_count++;
//        printf("cocotion test filter_count = %d\n", filter_count);
 //       printf("cocotion test dirty_byte = %d\n", update.dirty_byte);
        

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
    bd_time_slot_us = 50;

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
int get_pass_time_us(int *pass_time_us)
{
    return kvm_vm_ioctl(kvm_state, KVMFT_BD_GET_RUNTIME, pass_time_us);
}


bool bd_timer_func(void)
{

    static int real_pass_time_us = 0;
    uint64_t kernel_time_us = 0;
    kvm_shm_get_time_mark_from_kernel(&kernel_time_us);
    //printf("cocotion test pass time between timer= %ld\n", kernel_time_us);

    FILE *pFile;
    pFile = fopen("timestamp.txt", "a");
    char pbuf[200];

//    if(pFile != NULL){
        sprintf(pbuf, "%ld\n", kernel_time_us);
        fputs(pbuf, pFile);                                                                                                                      
 //   }    
  //  else
   //     printf("no profile\n");
    //fclose(pFile); 
    
    //printf("%ld\n", kernel_time_us);


    int pass_time_us;
    int pass_time_us2;

    get_pass_time_us(&pass_time_us);
    //printf("cocotion test real pass time between samples = %d\n", pass_time_us);



    //printf("%d\n", pass_time_us);
    sprintf(pbuf, "%d\n", pass_time_us);
    fputs(pbuf, pFile);                                                                                                                      
    real_pass_time_us += pass_time_us;
   
    //printf("cocotion test real_pass_time_us = %d\n", real_pass_time_us);
    //printf("%d\n", real_pass_time_us);
 
//    if(pass_time_us >= bd_target*0.94) {
  //  if(pass_time_us >= bd_target-1000) {
   // if(real_pass_time_us >= bd_target-1000) {
    if(real_pass_time_us >= bd_target) {
        //next_time = 0;

        get_pass_time_us(&pass_time_us2);
        //printf("%d\n", pass_time_us2-pass_time_us);
        sprintf(pbuf, "%d\n", pass_time_us2-pass_time_us);
        fputs(pbuf, pFile);                                                                                                                      
        
        
        real_pass_time_us += (pass_time_us2-pass_time_us); 
        //printf("%d\n", real_pass_time_us);
        sprintf(pbuf, "%d\n", real_pass_time_us);
        fputs(pbuf, pFile);                                                                                                                      
      
        fputs("@\n", pFile);                                                                                                                      
        

        real_pass_time_us = 0; 

/* 
        FILE *pFile;
        int i; 
        pFile = fopen("time_stamp_and_dirty_byes.txt", "a");
        
        char pbuf[200];
        if(pFile != NULL){
            sprintf(pbuf, "%d\n", filter_count);
            fputs(pbuf, pFile);                                                                                                                      
            for(i = 0; i < filter_count; i++) {
                sprintf(pbuf, "%d\n", time_stamp[i]);
                fputs(pbuf, pFile);                                                                                                                      
                sprintf(pbuf, "%d\n", dirty_pages_stamp[i]);
                fputs(pbuf, pFile);                                                                                                                      
                sprintf(pbuf, "%d\n", dirty_bytes_stamp[i]);
                fputs(pbuf, pFile);                                                                                                                      

        real_pass_time_us = 0; 
*/
/* 
        FILE *pFile;
        int i; 
        pFile = fopen("time_stamp_and_dirty_byes.txt", "a");
        
        char pbuf[200];
        if(pFile != NULL){
            sprintf(pbuf, "%d\n", filter_count);
            fputs(pbuf, pFile);                                                                                                                      
            for(i = 0; i < filter_count; i++) {
                sprintf(pbuf, "%d\n", time_stamp[i]);
                fputs(pbuf, pFile);                                                                                                                      
                sprintf(pbuf, "%d\n", dirty_pages_stamp[i]);
                fputs(pbuf, pFile);                                                                                                                      
                sprintf(pbuf, "%d\n", dirty_bytes_stamp[i]);
                fputs(pbuf, pFile);                                                                                                                      
            }
            filter_count = 0;
        }    
        else
            printf("no profile\n");
        fclose(pFile); 
*/


//        struct kvmft_update_latency update;
 //       kvm_vm_ioctl(kvm_state, KVMFT_BD_PREDIC_STOP, &update);

        //printf("cocotion test @@@@@@@@@@@before take snapshot dirty bytes = %d\n", update.dirty_byte);

        fclose(pFile); 
        return false;
    }
 
    //if(bd_page_fault_check() && kvmft_bd_predic_stop())  {
//    if(bd_page_fault_check())  {
 

/*   
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
*/

    //time_stamp[filter_count] = pass_time_us;


 
   
    //kvmft_bd_predic_stop();   
    //get_pass_time_us(&pass_time_us);

//    if(first_enter)
 //       first_enter = 0;
  //  else {
   //     first_enter = 1;
    //    return false;
    //}

//    int nexT;
 //   if( (nexT = kvmft_bd_predic_stop()) < 0) {
  //      return false;
   // }

    
    
    //kvmft_bd_predic_stop();
    int nexT;
    if( (nexT = kvmft_bd_predic_stop()) < 0) {
    get_pass_time_us(&pass_time_us2);
    //printf("%d\n", pass_time_us2-pass_time_us);
        
    sprintf(pbuf, "%d\n", pass_time_us2-pass_time_us);
    fputs(pbuf, pFile);                                                                                                                      

    real_pass_time_us += (pass_time_us2-pass_time_us); 
    //printf("%d\n", real_pass_time_us);
    sprintf(pbuf, "%d\n", real_pass_time_us);
    fputs(pbuf, pFile);                                                                                                                      
    
    fclose(pFile); 
        return false;
    }

//    printf("cocotion test my nextT is %d\n", nexT);
    //nexT = 10;
 //   get_pass_time_us(&pass_time_us);

    Error *err = NULL;
//    qmp_cuju_adjust_epoch(10, &err);
//    printf("cocotion test (bd_target-pass_time_us)/2 = %d\n", (bd_target-pass_time_us)/2);
//    if(bd_target-pass_time_us < 0)
//    if(bd_target-1000-pass_time_us < 0)
 //       qmp_cuju_adjust_epoch(0, &err);
  //  else 
        //qmp_cuju_adjust_epoch((bd_target-pass_time_us)/2, &err);
   //     qmp_cuju_adjust_epoch(nexT, &err);
        //qmp_cuju_adjust_epoch(bd_time_slot_us, &err);
        //qmp_cuju_adjust_epoch(1000, &err);
        qmp_cuju_adjust_epoch(nexT, &err);

    get_pass_time_us(&pass_time_us2);
    //printf("%d\n", pass_time_us2-pass_time_us);
        
    sprintf(pbuf, "%d\n", pass_time_us2-pass_time_us);
    fputs(pbuf, pFile);                                                                                                                      

    real_pass_time_us += (pass_time_us2-pass_time_us); 
    //printf("%d\n", real_pass_time_us);
    sprintf(pbuf, "%d\n", real_pass_time_us);
    fputs(pbuf, pFile);                                                                                                                      
    
    fclose(pFile); 

    kvm_shmem_start_timer();
    //bd_page_fault_check(); 
    return true;                                                                                                                                                                                                      
}


