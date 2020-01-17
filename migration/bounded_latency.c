#include "qemu/osdep.h"
#include "migration/migration.h"
#include "migration/cuju-kvm-share-mem.h"
#include "sysemu/kvm.h"
#include <math.h>
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

	update.cur_index = s->cur_off;
    update.dirty_page = dirty_page;
    update.runtime_us = runtime_us;
    update.trans_us = trans_us;
    update.latency_us = latency_us;

    update.last_trans_rate = mybdupdate.last_trans_rate;

	update.alpha = bd_alpha;

	static float average_e = 0.99;
	static float average_l = 0.69;

	static int average_de = 263;
	static int average_dl = 154;

	update.average_e = average_e*1000;
	update.average_l = average_l*1000;
	update.average_de = average_de;
	update.average_dl = average_dl;

//    return kvm_vm_ioctl(kvm_state, KVMFT_BD_UPDATE_LATENCY, &update);
    int r = kvm_vm_ioctl(kvm_state, KVMFT_BD_UPDATE_LATENCY, &update);

	int id = get_vm_id();
/*	static int c0 = 0;
	static int c01 = 0;
	static int c1 = 0;
	static int c2 = 0;
	static int c3 = 0;
	static int c4 = 0;
	static int c5 = 0;

	static int last_w0 = 0;
	static int last_w1 = 0;
	static int last_w3 = 0;

	static unsigned int total_a = 0;
	static double total_diff_rate_a = 0;
	static double total_diff_rate_aa = 0;
	static unsigned int total_b = 0;
	static double total_diff_rate_b = 0;
	static double total_diff_rate_bb = 0;

	static double total_diff_time_a = 0;
	static double total_diff_time_aa = 0;
//	static unsigned int total_a_time = 0;

	static double total_diff_time_b = 0;
	static double total_diff_time_bb = 0;

	static unsigned long int stdev_count_exceed = 0;
	static unsigned long int stdev_count_less = 0;
	static unsigned long int stdev_total = 0; */
	static unsigned long int total = 0;
	//static unsigned long int abrupt = 0;

	total++;
	if(id >= 10) {
		FILE *pFile;
   		char pbuf[200];
		sprintf(pbuf, "runtime_latency_trans_rate%d.txt", id);
    	pFile = fopen(pbuf, "a");
    	if(pFile != NULL){


		//sprintf(pbuf, "%d %d %d %d %d\n", latency_us, update.diffbytes, runtime_us, trans_us, latency_us - runtime_us - trans_us);

			//if( latency_us > 11000 && (update.e_runtime+trans_us < 11000)) {
//				sprintf(pbuf, "%d, %d\n", update.e_runtime, runtime_us );
 //       		fputs(pbuf, pFile);
 			//	abrupt++;
			//}
			//sprintf(pbuf, "%f\n", (float)abrupt/total );
			sprintf(pbuf, "%d\n", dirty_page);
        	fputs(pbuf, pFile);


        //fputs(pbuf, pFile);
/*

	if(latency_us <= 11000 && latency_us >= 9000) {

		int real_dispatch_time = update.real_x0;
		int real_load_time = update.real_x1;
		int x0 = update.x0;
		int x1 = update.x1;
		if(x0 == 0)	 x0 = 1;
		if(x1 == 0)	 x1 = 1;
		if(real_dispatch_time > x0) {
			total_diff_time_a += (float)(real_dispatch_time-x0)/x0;
		} else if(real_dispatch_time <= x0) {
			total_diff_time_a += (float)(x0-real_dispatch_time)/x0;
		}

		if(real_load_time > x1) {
			total_diff_time_aa += (float)(real_load_time-x1)/x1;
		} else if(real_load_time <= x1) {
			total_diff_time_aa += (float)(x1-real_load_time)/x1;
		}



		int e_load_mem_rate = update.load_mem_rate;
		int e_send_rate = update.current_send_rate;
		if(e_load_mem_rate == 0) e_load_mem_rate = 1;
		if(e_send_rate == 0) e_send_rate = 1;


		if(e_send_rate > update.last_send_rate) {
			total_diff_rate_a += (float)(e_send_rate-update.last_send_rate)/e_send_rate;
		}
		else if(e_send_rate <= update.last_send_rate){
			total_diff_rate_a += (float)(update.last_send_rate-e_send_rate)/e_send_rate;
		}

		if(e_load_mem_rate > update.last_load_mem_rate) {
			total_diff_rate_aa += (float)(e_load_mem_rate-update.last_load_mem_rate)/e_load_mem_rate;
		} else if (e_load_mem_rate <= update.last_load_mem_rate){
			total_diff_rate_aa += (float)(update.last_load_mem_rate-e_load_mem_rate)/e_load_mem_rate;
		}

		total_a++;

	} else {
		int real_dispatch_time = update.real_x0;
		int real_load_time = update.real_x1;
		int x0 = update.x0;
		int x1 = update.x1;
		if(x0 == 0)	 x0 = 1;
		if(x1 == 0)	 x1 = 1;
		if(real_dispatch_time > x0) {
			total_diff_time_b += (float)(real_dispatch_time-x0)/x0;
		} else if(real_dispatch_time <= x0) {
			total_diff_time_b += (float)(x0-real_dispatch_time)/x0;
		}

		if(real_load_time > x1) {
			total_diff_time_bb += (float)(real_load_time-x1)/x1;
		} else if(real_load_time <= x1) {
			total_diff_time_bb += (float)(x1-real_load_time)/x1;
		}

		int e_load_mem_rate = update.load_mem_rate;
		int e_send_rate = update.current_send_rate;
		if(e_load_mem_rate == 0) e_load_mem_rate = 1;
		if(e_send_rate == 0) e_send_rate = 1;


		if(e_send_rate > update.last_send_rate) {
			total_diff_rate_b += (float)(e_send_rate-update.last_send_rate)/e_send_rate;
		}
		else if(e_send_rate <= update.last_send_rate){
			total_diff_rate_b += (float)(update.last_send_rate-e_send_rate)/e_send_rate;
		}

		if(e_load_mem_rate > update.last_load_mem_rate) {
			total_diff_rate_bb += (float)(e_load_mem_rate-update.last_load_mem_rate)/e_load_mem_rate;
		} else if (e_load_mem_rate <= update.last_load_mem_rate){
			total_diff_rate_bb += (float)(update.last_load_mem_rate-e_load_mem_rate)/e_load_mem_rate;
		}

		total_b++;

	}

        	sprintf(pbuf, "%d ", update.w0);
        	fputs(pbuf, pFile);
        	sprintf(pbuf, "%d ", update.w1);
        	fputs(pbuf, pFile);
        	sprintf(pbuf, "%d ", update.w3);
        	fputs(pbuf, pFile);
        	sprintf(pbuf, "%d ", update.w4);
        	fputs(pbuf, pFile);
        	sprintf(pbuf, "%d ", update.w5);
        	fputs(pbuf, pFile);
        	sprintf(pbuf, "$%d ", update.others_dirty0);
        	fputs(pbuf, pFile);
        	sprintf(pbuf, "%d$ ", update.others_dirty1);
        	fputs(pbuf, pFile);
        	sprintf(pbuf, "%d ", update.x0);
        	fputs(pbuf, pFile);
        	sprintf(pbuf, "%d ", update.x1);
        	fputs(pbuf, pFile);
        	sprintf(pbuf, "%d ", update.x2);
        	fputs(pbuf, pFile);
        	sprintf(pbuf, "%d ", update.x3);
        	fputs(pbuf, pFile);
        	sprintf(pbuf, "(%d ", update.real_x0);
        	fputs(pbuf, pFile);
        	sprintf(pbuf, "%d ", update.real_x1);
        	fputs(pbuf, pFile);

			sprintf(pbuf, "factor(%d, %d)", update.last_f, update.x2*100/(trans_us+1));
        	fputs(pbuf, pFile);




        	sprintf(pbuf, "%f) ", (float)update.real_x1/(update.real_x0+1));
        	fputs(pbuf, pFile);
        	sprintf(pbuf, "D(%d ", update.dirty_rate0);
        	fputs(pbuf, pFile);
        	sprintf(pbuf, "%d, ", update.dirty_rate1);
        	fputs(pbuf, pFile);

			float e_trans_f = (float)update.real_x1/update.e_trans;

        	sprintf(pbuf, "%f ) ", e_trans_f);
        	fputs(pbuf, pFile);


			sprintf(pbuf, "%d ", runtime_us);
        	fputs(pbuf, pFile);
        	sprintf(pbuf, "%d ", update.e_runtime);
        	fputs(pbuf, pFile);

			sprintf(pbuf, "(%d ", trans_us);
        	fputs(pbuf, pFile);
//			int expect = update.x0*update.w0 + update.x1*update.w1;//+update.w3;
//			expect/=1000;
        	sprintf(pbuf, "%d) ", update.e_trans);
        	fputs(pbuf, pFile);
        	sprintf(pbuf, "%d ", update.f_trans);
        	fputs(pbuf, pFile);

			sprintf(pbuf, "(%d ", latency_us);
        	fputs(pbuf, pFile);
        	sprintf(pbuf, "%d) ", update.e_latency);
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
			int waitacktime = (int)((s->recv_ack1_time - s->send_commit1_time) * 1000000);
			sprintf(pbuf, "%d ", waitacktime);
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

//			} else if (latency_us > 11000 && ( trans_us-update.e_trans > 8000)){
			} else if (latency_us > 11000 && \
					((update.trans_us - update.e_trans > 8000) || \
					 update.trans_us > 8000)) {
				sprintf(pbuf, "trans %d ", trans_us);
        		fputs(pbuf, pFile);
				c2++;
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

			sprintf(pbuf, "trans %d ", c2);
        	fputs(pbuf, pFile);


			if(last_w0 != update.w0 || last_w1 != update.w1 || last_w3 != update.w3) {
				c3++;
				c4++;
			} else {
				c4 = 0;
			}

			if(c4 >= 2) {
				c5++;
				c4 = 0;
        		fputs("=======> ", pFile);
			}

			last_w0 = update.w0;
			last_w1 = update.w1;
			last_w3 = update.w3;

			sprintf(pbuf, "diff %d ", c3);
        	fputs(pbuf, pFile);

			sprintf(pbuf, " %d ", c5);
        	fputs(pbuf, pFile);

			static unsigned int exceed;
			static unsigned int exceed_500;
			static unsigned int exceed_1000;
			static unsigned int exceed_1500;
			static unsigned int exceed_2000;
			static unsigned int exceed_2500;
			static unsigned int exceed_3000;
			static unsigned int exceed_3500;
			static unsigned int exceed_4000;

			static unsigned int less;
			static unsigned int less_500;
			static unsigned int less_1000;
			static unsigned int less_1500;
			static unsigned int less_2000;
			static unsigned int less_2500;
			static unsigned int less_3000;
			static unsigned int less_3500;
			static unsigned int less_4000;

			static unsigned int m_9000_9500;
			static unsigned int m_9500_10000;
			static unsigned int m_10000_10500;
			static unsigned int m_10500_11000;

			static double sum_e_trans_f_exceed = 0;
			static double sum_e_trans_f_less = 0;
			static unsigned long int sum_dirty_rate1_exceed = 0;
			static unsigned long int sum_dirty_rate1_less = 0;


			if(latency_us <= 9000 && latency_us < 9500)
				m_9000_9500++;
			if(latency_us <= 9500 && latency_us < 10000)
				m_9500_10000++;
			if(latency_us <= 10000 && latency_us < 10500)
				m_10000_10500++;
			if(latency_us <= 10500 && latency_us < 11000)
				m_10500_11000++;



			if(latency_us > 11000) {
				if(exceed % 5000 == 0) {
					sum_e_trans_f_exceed = average_e;
					sum_dirty_rate1_exceed = average_de;
				}
				exceed++;
				sum_e_trans_f_exceed += e_trans_f;
				sum_dirty_rate1_exceed += update.dirty_rate1;
			}
			if(latency_us > 11500)
				exceed_500++;
			if(latency_us > 12000)
				exceed_1000++;
			if(latency_us > 12500)
				exceed_1500++;
			if(latency_us > 13000)
				exceed_2000++;
			if(latency_us > 13500)
				exceed_2500++;
			if(latency_us > 14000)
				exceed_3000++;
			if(latency_us > 14500)
				exceed_3500++;
			if(latency_us > 15000)
				exceed_4000++;

			if(latency_us < 9000) {
				if(less % 5000 == 0) {
					sum_e_trans_f_less = average_l;
					sum_dirty_rate1_less = average_dl;
				}
				less++;
				sum_e_trans_f_less += e_trans_f;
				sum_dirty_rate1_less += update.dirty_rate1;
			}
			if(latency_us < 8500)
				less_500++;
			if(latency_us < 8000)
				less_1000++;
			if(latency_us < 7500)
				less_1500++;
			if(latency_us < 7000)
				less_2000++;
			if(latency_us < 6500)
				less_2500++;
			if(latency_us < 6000)
				less_3000++;
			if(latency_us < 5500)
				less_3500++;
			if(latency_us < 5000)
				less_4000++;

			if(exceed && less) {
				float average_e = (float)sum_e_trans_f_exceed/(exceed%5000+1);
				float average_l = (float)sum_e_trans_f_less/(less%5000+1);

				sprintf(pbuf, "@@ffff@@@==> (%f, %f) ", average_l, average_e);
        		fputs(pbuf, pFile);

				float average_de = (float)sum_dirty_rate1_exceed/(exceed%5000+1);
				float average_dl = (float)sum_dirty_rate1_less/(less%5000+1);

				sprintf(pbuf, "@@ddddd@@@==> (%f, %f) ", average_dl, average_de);
        		fputs(pbuf, pFile);


			}


			if(total_a) {
				sprintf(pbuf, "__a %f %f %f %f %d ", total_diff_rate_a/total_a, total_diff_rate_aa/total_a, total_diff_time_a/total_a, total_diff_time_aa/total_a, total_a);
		//		sprintf(pbuf, "__a %f %f %d ", total_diff_time_a/total_a, total_diff_time_aa/total_a, total_a);
//				sprintf(pbuf, "__a %f ", total_diff_rate_a);
        		fputs(pbuf, pFile);

			}
			if(total_b) {
				sprintf(pbuf, "__b %f %f %f %f %d ", total_diff_rate_b/total_b, total_diff_rate_bb/total_b, total_diff_time_b/total_b, total_diff_time_bb/total_b, total_b);
//				sprintf(pbuf, "__b %f %f %d ",  total_diff_time_b/total_b, total_diff_time_bb/total_b, total_b);
//				sprintf(pbuf, "__b %f ", total_diff_rate_b);
        		fputs(pbuf, pFile);
			}

			sprintf(pbuf, "latency_dis (E): %d %d %d %d %d %d %d %d %d ", \
					exceed, exceed-exceed_500, \
					exceed_500-exceed_1000, exceed_1000-exceed_1500, \
					exceed_1500-exceed_2000, exceed_2000-exceed_2500, \
					exceed_2500-exceed_3000, exceed_3000-exceed_3500, \
					exceed_3500-exceed_4000);
        	fputs(pbuf, pFile);
			sprintf(pbuf, "latency_dis (L): %d %d %d %d %d %d %d %d %d ", \
					less, less-less_500, \
					less_500-less_1000, less_1000-less_1500, \
					less_1500-less_2000, less_2000-less_2500, \
					less_2500-less_3000, less_3000-less_3500, \
					less_3500-less_4000);
        	fputs(pbuf, pFile);
			sprintf(pbuf, "latency_dis (M): %d %d %d %d ", \
					m_9000_9500, m_9500_10000, m_10000_10500, m_10500_11000);
        	fputs(pbuf, pFile);

			int count = update.load_mem_rate_rec_index;
			int i;
			sprintf(pbuf, "REC(%d, %d) ", update.log_index, count);
        	fputs(pbuf, pFile);
			unsigned long totalx = 0;
			for (i = count-1; i <= count && i >= 0; i++) {
				sprintf(pbuf, "%d ", update.load_mem_rate_rec[i]);
        		fputs(pbuf, pFile);
			}

			unsigned long int sum = 0;
			if(count > 2) {
				for (i = count-3; i < count; i++) {
				//sprintf(pbuf, "%d ", update.load_mem_rate_rec[i]);
        		//fputs(pbuf, pFile);
 					totalx += update.load_mem_rate_rec[i];
				}

//				int x = totalx/(count);
				int x = totalx/3;
				//for (i = 0; i <= count-1 && i>=0; i++) {
				for (i = count-3; i < count; i++) {
 					sum+=(x-update.load_mem_rate_rec[i])*(x-update.load_mem_rate_rec[i]);
				}
			}
			//if(count > 1)
				//sum = sum/count-1;
			if(count > 2)
				sum = sum/2;
			else sum = 1;

			unsigned long int stdev = sqrt(sum);
			if(stdev > 10000) stdev = 1;
			stdev_total+=stdev;

			if( (latency_us < 9000 || latency_us > 11000) && stdev >= 1500) {
				stdev_count_exceed++;
			}
			if( (latency_us < 9000 || latency_us > 11000) && stdev < 1500) {
				stdev_count_less++;
			}

			sprintf(pbuf, "|||||!!| %ld %f %f %ld ", stdev, (float)stdev_count_exceed/(exceed+less), (float)stdev_count_less/(exceed+less), stdev_total);
 			fputs(pbuf, pFile);


        		fputs("\n", pFile);
*/

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


