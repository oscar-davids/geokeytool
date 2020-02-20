/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"

// basic tools

#include "types.h"
#include "folder.h"
#include "memory.h"
#include "shared.h"
#include "thread.h"
#include "timer.h"

// features

#include "affinity.h"
#include "autotune.h"
#include "benchmark.h"
#include "bitmap.h"
#include "combinator.h"
#include "cpt.h"
#include "debugfile.h"
#include "dictstat.h"
#include "dispatch.h"
#include "event.h"
#include "hashes.h"
#include "hwmon.h"
#include "induct.h"
#include "interface.h"
#include "logfile.h"
#include "loopback.h"
#include "monitor.h"
#include "mpsp.h"
#include "backend.h"
#include "outfile_check.h"
#include "outfile.h"
#include "pidfile.h"
#include "potfile.h"
#include "restore.h"
#include "selftest.h"
#include "status.h"
#include "straight.h"
#include "tuningdb.h"
#include "user_options.h"
#include "wordlist.h"
#include "hashcat.h"

#ifdef WITH_BRAIN
#include "brain.h"
#endif

u32 paramround = 1024;
char chinfile[256] = {0,};
char choutfile[256] = {0,};



#if 1
// inner2_loop iterates through wordlists, then calls kernel execution

static int inner2_loop (hashcat_ctx_t *hashcat_ctx)
{
  hashes_t             *hashes              = hashcat_ctx->hashes;
  induct_ctx_t         *induct_ctx          = hashcat_ctx->induct_ctx;
  logfile_ctx_t        *logfile_ctx         = hashcat_ctx->logfile_ctx;
  backend_ctx_t        *backend_ctx         = hashcat_ctx->backend_ctx;
  restore_ctx_t        *restore_ctx         = hashcat_ctx->restore_ctx;
  status_ctx_t         *status_ctx          = hashcat_ctx->status_ctx;
  user_options_extra_t *user_options_extra  = hashcat_ctx->user_options_extra;
  user_options_t       *user_options        = hashcat_ctx->user_options;

  //status_ctx->run_main_level1   = true;
  //status_ctx->run_main_level2   = true;
  //status_ctx->run_main_level3   = true;
  status_ctx->run_thread_level1 = true;
  status_ctx->run_thread_level2 = true;

  status_ctx->devices_status = STATUS_INIT;

  logfile_generate_subid (hashcat_ctx);

  logfile_sub_msg ("START");

  status_progress_reset (hashcat_ctx);

  status_ctx->msec_paused = 0;

  status_ctx->words_off = 0;
  status_ctx->words_cur = 0;

  if (restore_ctx->restore_execute == true)
  {
    restore_ctx->restore_execute = false;

    restore_data_t *rd = restore_ctx->rd;

    status_ctx->words_off = rd->words_cur;
    status_ctx->words_cur = status_ctx->words_off;

    // --restore always overrides --skip

    user_options->skip = 0;
  }

  if (user_options->skip > 0)
  {
    status_ctx->words_off = user_options->skip;
    status_ctx->words_cur = status_ctx->words_off;

    user_options->skip = 0;
  }

  backend_session_reset (hashcat_ctx);

  cpt_ctx_reset (hashcat_ctx);

  /**
   * Update attack-mode specific stuff based on mask
   */

  if (mask_ctx_update_loop (hashcat_ctx) == -1) return 0;

  /**
   * Update attack-mode specific stuff based on wordlist
   */

  if (straight_ctx_update_loop (hashcat_ctx) == -1) return 0;

  // words base

  const u64 amplifier_cnt = user_options_extra_amplifier (hashcat_ctx);

  status_ctx->words_base = status_ctx->words_cnt / amplifier_cnt;

  EVENT (EVENT_CALCULATED_WORDS_BASE);

  if (user_options->keyspace == true)
  {
    status_ctx->devices_status = STATUS_RUNNING;

    return 0;
  }

  // restore stuff

  if (status_ctx->words_off > status_ctx->words_base)
  {
    event_log_error (hashcat_ctx, "Restore value is greater than keyspace.");

    return -1;
  }

  const u64 progress_restored = status_ctx->words_off * amplifier_cnt;

  for (u32 i = 0; i < hashes->salts_cnt; i++)
  {
    status_ctx->words_progress_restored[i] = progress_restored;
  }

  #ifdef WITH_BRAIN
  if (user_options->brain_client == true)
  {
    user_options->brain_attack = brain_compute_attack (hashcat_ctx);
  }
  #endif

  /**
   * limit kernel loops by the amplification count we have from:
   * - straight_ctx, combinator_ctx or mask_ctx for fast hashes
   * - hash iteration count for slow hashes
   * this is required for autotune
   */

  backend_ctx_devices_kernel_loops (hashcat_ctx);

  /**
   * prepare thread buffers
   */

  thread_param_t *threads_param = (thread_param_t *) hccalloc (backend_ctx->backend_devices_cnt, sizeof (thread_param_t));

  hc_thread_t *c_threads = (hc_thread_t *) hccalloc (backend_ctx->backend_devices_cnt, sizeof (hc_thread_t));

  /**
   * create autotune threads
   */

  EVENT (EVENT_AUTOTUNE_STARTING);

  status_ctx->devices_status = STATUS_AUTOTUNE;

  for (int backend_devices_idx = 0; backend_devices_idx < backend_ctx->backend_devices_cnt; backend_devices_idx++)
  {
    thread_param_t *thread_param = threads_param + backend_devices_idx;

    thread_param->hashcat_ctx = hashcat_ctx;
    thread_param->tid         = backend_devices_idx;

    hc_thread_create (c_threads[backend_devices_idx], thread_autotune, thread_param);
  }

  hc_thread_wait (backend_ctx->backend_devices_cnt, c_threads);

  //thread_param_t *thread_param = threads_param + 0;  
  //thread_param->hashcat_ctx = hashcat_ctx;
  //thread_param->tid         = 0;

  //thread_autotune(thread_param);

  EVENT (EVENT_AUTOTUNE_FINISHED);

  /**
   * find same backend devices and equal results
   */

  backend_ctx_devices_sync_tuning (hashcat_ctx);

  /**
   * autotune modified kernel_accel, which modifies backend_ctx->kernel_power_all
   */

  backend_ctx_devices_update_power (hashcat_ctx);

  /**
   * Begin loopback recording
   */

  if (user_options->loopback == true)
  {
    loopback_write_open (hashcat_ctx);
  }

  /**
   * Prepare cracking stats
   */

  hc_timer_set (&status_ctx->timer_running);

  time_t runtime_start;

  time (&runtime_start);

  status_ctx->runtime_start = runtime_start;

  /**
   * create cracker threads
   */

  EVENT (EVENT_CRACKER_STARTING);

  status_ctx->devices_status = STATUS_RUNNING;

  status_ctx->accessible = true;

  for (int backend_devices_idx = 0; backend_devices_idx < backend_ctx->backend_devices_cnt; backend_devices_idx++)
  {
    thread_param_t *thread_param = threads_param + backend_devices_idx;

    thread_param->hashcat_ctx = hashcat_ctx;
    thread_param->tid         = backend_devices_idx;

    if (user_options_extra->wordlist_mode == WL_MODE_STDIN)
    {
      hc_thread_create (c_threads[backend_devices_idx], thread_calc_stdin, thread_param);
    }
    else
    {
      hc_thread_create (c_threads[backend_devices_idx], thread_calc, thread_param);
    }
  }

  hc_thread_wait (backend_ctx->backend_devices_cnt, c_threads);

  hcfree (c_threads);

  hcfree (threads_param);

  if ((status_ctx->devices_status == STATUS_RUNNING) && (status_ctx->checkpoint_shutdown == true))
  {
    myabort_checkpoint (hashcat_ctx);
  }

  if ((status_ctx->devices_status != STATUS_CRACKED)
   && (status_ctx->devices_status != STATUS_ERROR)
   && (status_ctx->devices_status != STATUS_ABORTED)
   && (status_ctx->devices_status != STATUS_ABORTED_CHECKPOINT)
   && (status_ctx->devices_status != STATUS_ABORTED_RUNTIME)
   && (status_ctx->devices_status != STATUS_QUIT)
   && (status_ctx->devices_status != STATUS_BYPASS))
  {
    status_ctx->devices_status = STATUS_EXHAUSTED;
  }

  if (status_ctx->devices_status == STATUS_EXHAUSTED)
  {
    // the options speed-only and progress-only cause hashcat to abort quickly.
    // therefore, they will end up (if no other error occured) as STATUS_EXHAUSTED.
    // however, that can create confusion in hashcats RC, because exhausted translates to RC = 1.
    // but then having RC = 1 does not match our expection if we use for speed-only and progress-only.
    // to get hashcat to return RC = 0 we have to set it to CRACKED or BYPASS
    // note: other options like --show, --left, --benchmark, --keyspace, --backend-info, etc.
    // not not reach this section of the code, they've returned already with rc 0.

    if ((user_options->speed_only == true) || (user_options->progress_only == true))
    {
      status_ctx->devices_status = STATUS_BYPASS;
    }
  }

  // update some timer

  time_t runtime_stop;

  time (&runtime_stop);

  status_ctx->runtime_stop = runtime_stop;

  logfile_sub_uint (runtime_start);
  logfile_sub_uint (runtime_stop);
  

  if (hashcat_get_status (hashcat_ctx, status_ctx->hashcat_status_final) == -1)
  {
    fprintf (stderr, "Initialization problem: the hashcat status monitoring function returned an unexpected value\n");
  }

  status_ctx->accessible = false;

  //EVENT (EVENT_CRACKER_FINISHED); //status_benchmark (hashcat_ctx);
  status_benchmark (hashcat_ctx);

  // mark sub logfile

  logfile_sub_var_uint ("status-after-work", status_ctx->devices_status);

  logfile_sub_msg ("STOP");

  // stop loopback recording

  if (user_options->loopback == true)
  {
    loopback_write_close (hashcat_ctx);
  }

  // New induction folder check, which is a controlled recursion

  if (induct_ctx->induction_dictionaries_cnt == 0)
  {

    induct_ctx_scan (hashcat_ctx);

    while (induct_ctx->induction_dictionaries_cnt)
    {
      for (induct_ctx->induction_dictionaries_pos = 0; induct_ctx->induction_dictionaries_pos < induct_ctx->induction_dictionaries_cnt; induct_ctx->induction_dictionaries_pos++)
      {
        if (status_ctx->devices_status == STATUS_EXHAUSTED)
        {
          if (inner2_loop (hashcat_ctx) == -1) myabort (hashcat_ctx);

          if (status_ctx->run_main_level3 == false) break;
        }

        unlink (induct_ctx->induction_dictionaries[induct_ctx->induction_dictionaries_pos]);
      }

      hcfree (induct_ctx->induction_dictionaries);

      induct_ctx_scan (hashcat_ctx);
    }
  }

  return 0;
}

// inner1_loop iterates through masks, then calls inner2_loop

static int inner1_loop (hashcat_ctx_t *hashcat_ctx)
{
  restore_ctx_t  *restore_ctx   = hashcat_ctx->restore_ctx;
  status_ctx_t   *status_ctx    = hashcat_ctx->status_ctx;
  straight_ctx_t *straight_ctx  = hashcat_ctx->straight_ctx;

  //status_ctx->run_main_level1   = true;
  //status_ctx->run_main_level2   = true;
  status_ctx->run_main_level3   = true;
  status_ctx->run_thread_level1 = true;
  status_ctx->run_thread_level2 = true;

  /**
   * loop through wordlists
   */

  EVENT (EVENT_INNERLOOP2_STARTING);

  if (restore_ctx->rd)
  {
    restore_data_t *rd = restore_ctx->rd;

    if (rd->dicts_pos > 0)
    {
      straight_ctx->dicts_pos = rd->dicts_pos;

      rd->dicts_pos = 0;
    }
  }

  if (straight_ctx->dicts_cnt)
  {
    for (u32 dicts_pos = straight_ctx->dicts_pos; dicts_pos < straight_ctx->dicts_cnt; dicts_pos++)
    {
      straight_ctx->dicts_pos = dicts_pos;

      if (inner2_loop (hashcat_ctx) == -1) myabort (hashcat_ctx);

      if (status_ctx->run_main_level3 == false) break;
    }

    if (status_ctx->run_main_level3 == true)
    {
      if (straight_ctx->dicts_pos + 1 == straight_ctx->dicts_cnt) straight_ctx->dicts_pos = 0;
    }
  }
  else
  {
    if (inner2_loop (hashcat_ctx) == -1) myabort (hashcat_ctx);
  }

  EVENT (EVENT_INNERLOOP2_FINISHED);

  return 0;
}
#endif

// outer_loop iterates through hash_modes (in benchmark mode)
// also initializes stuff that depend on hash mode
static unsigned char BF_itoa64[64 + 1] = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";


void BF_encode(char *dst, const u32 *src, int size) {
    unsigned char *sptr = (unsigned char *)src;
    unsigned char *end = sptr + size;
    unsigned char *dptr = (unsigned char *)dst;
    unsigned int c1, c2;
    
    do {
        c1 = *sptr++;
        *dptr++ = BF_itoa64[c1 >> 2];
        c1 = (c1 & 0x03) << 4;
        if (sptr >= end) {
            *dptr++ = BF_itoa64[c1];
            break;
        }
        
        c2 = *sptr++;
        c1 |= c2 >> 4;
        *dptr++ = BF_itoa64[c1];
        c1 = (c2 & 0x0f) << 2;
        if (sptr >= end) {
            *dptr++ = BF_itoa64[c1];
            break;
        }
        
        c2 = *sptr++;
        c1 |= c2 >> 6;
        *dptr++ = BF_itoa64[c1];
        *dptr++ = BF_itoa64[c2 & 0x3f];
    } while(sptr < end);
}

void BF_swap(u32 *x, int count) {
    static union {
        uint16_t i;
        uint8_t  c[2];
    } is_little = { 0x0001 };
    u32 tmp;
    
    if(is_little.c[0]) {
        do {
            tmp = *x;
            tmp = (tmp << 16) | (tmp >> 16);
            *x++ = ((tmp & 0x00FF00FF) << 8) | ((tmp >> 8) & 0x00FF00FF);
        } while(--count);
    }
}

static int outer_loop (hashcat_ctx_t *hashcat_ctx)
{
  hashconfig_t   *hashconfig    = hashcat_ctx->hashconfig;
  hashes_t       *hashes        = hashcat_ctx->hashes;
  mask_ctx_t     *mask_ctx      = hashcat_ctx->mask_ctx;
  backend_ctx_t  *backend_ctx   = hashcat_ctx->backend_ctx;
  
  status_ctx_t   *status_ctx    = hashcat_ctx->status_ctx;
  straight_ctx_t *straight_ctx  = hashcat_ctx->straight_ctx;
  user_options_t *user_options  = hashcat_ctx->user_options;
  
  outcheck_ctx_t *outcheck_ctx  = hashcat_ctx->outcheck_ctx;
  restore_ctx_t  *restore_ctx   = hashcat_ctx->restore_ctx;  

  status_ctx->devices_status = STATUS_INIT;

  //status_ctx->run_main_level1   = true;
  status_ctx->run_main_level2   = true;
  status_ctx->run_main_level3   = true;
  status_ctx->run_thread_level1 = true;
  status_ctx->run_thread_level2 = true;

  /**
   * setup variables and buffers depending on hash_mode
   */

  EVENT (EVENT_HASHCONFIG_PRE);

  if (hashconfig_init (hashcat_ctx) == -1)
  {
    event_log_error (hashcat_ctx, "Invalid hash-mode '%u' selected.", user_options->hash_mode);

    return -1;
  }

  EVENT (EVENT_HASHCONFIG_POST);

  /**
   * generate hashlist filename for later use
   */

  if (hashes_init_filename (hashcat_ctx) == -1) return -1;

  /**
   * load hashes, stage 1
   */

  if (hashes_init_stage1 (hashcat_ctx) == -1) return -1;

  if ((user_options->keyspace == false) && (user_options->stdout_flag == false))
  {
    if (hashes->hashes_cnt == 0)
    {
      event_log_error (hashcat_ctx, "No hashes loaded.");

      return -1;
    }
  }

  /**
   * load hashes, stage 2, remove duplicates, build base structure
   */

  hashes->hashes_cnt_orig = hashes->hashes_cnt;

  if (hashes_init_stage2 (hashcat_ctx) == -1) return -1;

  /**
   * potfile removes
   */

  if (user_options->potfile_disable == false)
  {
    EVENT (EVENT_POTFILE_REMOVE_PARSE_PRE);

    if (user_options->loopback == true)
    {
      loopback_write_open (hashcat_ctx);
    }

    potfile_remove_parse (hashcat_ctx);

    if (user_options->loopback == true)
    {
      loopback_write_close (hashcat_ctx);
    }

    EVENT (EVENT_POTFILE_REMOVE_PARSE_POST);
  }

  /**
   * load hashes, stage 3, update cracked results from potfile
   */

  if (hashes_init_stage3 (hashcat_ctx) == -1) return -1;

  /**
   * potfile show/left handling
   */

  if (user_options->show == true)
  {
    status_ctx->devices_status = STATUS_RUNNING;

    outfile_write_open (hashcat_ctx);

    if (potfile_handle_show (hashcat_ctx) == -1) return -1;

    outfile_write_close (hashcat_ctx);

    return 0;
  }

  if (user_options->left == true)
  {
    status_ctx->devices_status = STATUS_RUNNING;

    outfile_write_open (hashcat_ctx);

    if (potfile_handle_left (hashcat_ctx) == -1) return -1;

    outfile_write_close (hashcat_ctx);

    return 0;
  }

  /**
   * check global hash count in case module developer sets a them to a specific limit
   */

  if (hashes->digests_cnt < hashconfig->hashes_count_min)
  {
    event_log_error (hashcat_ctx, "Not enough hashes loaded - minimum is %u for this hash-mode.", hashconfig->hashes_count_min);

    return -1;
  }

  if (hashes->digests_cnt > hashconfig->hashes_count_max)
  {
    event_log_error (hashcat_ctx, "Too many hashes loaded - maximum is %u for this hash-mode.", hashconfig->hashes_count_max);

    return -1;
  }

  /**
   * maybe all hashes were cracked, we can exit here
   */

  if (status_ctx->devices_status == STATUS_CRACKED)
  {
    if ((user_options->remove == true) && ((hashes->hashlist_mode == HL_MODE_FILE_PLAIN) || (hashes->hashlist_mode == HL_MODE_FILE_BINARY)))
    {
      if (hashes->digests_saved != hashes->digests_done)
      {
        const int rc = save_hash (hashcat_ctx);

        if (rc == -1) return -1;
      }
    }

    EVENT (EVENT_POTFILE_ALL_CRACKED);

    return 0;
  }

  /**
   * load hashes, stage 4, automatic Optimizers
   */

  if (hashes_init_stage4 (hashcat_ctx) == -1) return -1;

  /**
   * load hashes, selftest
   */

  if (hashes_init_selftest (hashcat_ctx) == -1) return -1;

  /**
   * load hashes, benchmark
   */

  if (hashes_init_benchmark (hashcat_ctx) == -1) return -1;

  /**
   * Done loading hashes, log results
   */

  hashes_logger (hashcat_ctx);

  /**
   * bitmaps
   */

  EVENT (EVENT_BITMAP_INIT_PRE);

  if (bitmap_ctx_init (hashcat_ctx) == -1) return -1;

  EVENT (EVENT_BITMAP_INIT_POST);

  /**
   * cracks-per-time allocate buffer
   */

  cpt_ctx_init (hashcat_ctx);

  /**
   * Wordlist allocate buffer
   */

  if (wl_data_init (hashcat_ctx) == -1) return -1;

  /**
   * straight mode init
   */

  if (straight_ctx_init (hashcat_ctx) == -1) return -1;

  /**
   * straight mode init
   */

  if (combinator_ctx_init (hashcat_ctx) == -1) return -1;

  /**
   * charsets : keep them together for more easy maintainnce
   */

  if (mask_ctx_init (hashcat_ctx) == -1) return -1;

  /**
   * prevent the user from using --skip/--limit together with maskfile and/or multiple word lists
   */

  if (user_options->skip != 0 || user_options->limit != 0)
  {
    if ((mask_ctx->masks_cnt > 1) || (straight_ctx->dicts_cnt > 1))
    {
      event_log_error (hashcat_ctx, "Use of --skip/--limit is not supported with --increment or mask files.");

      return -1;
    }
  }

  /**
   * prevent the user from using --keyspace together with maskfile and/or multiple word lists
   */

  if (user_options->keyspace == true)
  {
    if ((mask_ctx->masks_cnt > 1) || (straight_ctx->dicts_cnt > 1))
    {
      event_log_error (hashcat_ctx, "Use of --keyspace is not supported with --increment or mask files.");

      return -1;
    }
  }

  /**
   * status progress init; needs hashes that's why we have to do it here and separate from status_ctx_init
   */

  if (status_progress_init (hashcat_ctx) == -1) return -1;

  /**
   * main screen
   */

  EVENT (EVENT_OUTERLOOP_MAINSCREEN);

  /**
   * Tell user about cracked hashes by potfile
   */

  EVENT (EVENT_POTFILE_NUM_CRACKED);

  /**
   * inform the user
   */

  EVENT (EVENT_BACKEND_SESSION_PRE);

  if (backend_session_begin (hashcat_ctx) == -1) return -1;

  EVENT (EVENT_BACKEND_SESSION_POST);

  /**
   * create self-test threads
   */

  if ((user_options->self_test_disable == false) && (hashconfig->st_hash != NULL) && (hashconfig->st_pass != NULL))
  {
    EVENT (EVENT_SELFTEST_STARTING);

	#define MEM_SIZE (128)
	FILE* pinFile;
	FILE* poutFile;
	int i = 0;
	u32 workFactor = 10; //default
	//u32 paramround = 32768;
	
	char temp[MEM_SIZE];
	char tempsalt[MEM_SIZE]; 
	char pwd[MEM_SIZE] = "jianwei"; 
	char salt[MEM_SIZE] = "$2a$10$0000000000000000000000";

	pinFile = fopen(chinfile, "r");
	if (pinFile == 0)
	{
		printf("can not input file\n");		
		return -1;
	}


	poutFile = fopen(choutfile, "w+");
	if (poutFile == 0)
	{
		printf("can not out file\n");
		return -1;
	}

	int j = 0;
	for ( j = 0; j < 50; j++)
	{
		if (paramround >> j == 0)
			break;
	}
	workFactor = j - 1;

	if (workFactor < 1 || workFactor > 50)
	{
		printf("invalid argument\n");
		return  0;
	}

	//predecide salt
	sprintf(tempsalt, "$2a$%02d$0000000000000000000000", workFactor);

	int brun = 1;

    thread_param_t *threads_param = (thread_param_t *) hccalloc (backend_ctx->backend_devices_cnt, sizeof (thread_param_t));

    hc_thread_t *selftest_threads = (hc_thread_t *) hccalloc (backend_ctx->backend_devices_cnt, sizeof (hc_thread_t));

	while(brun)
	{
    status_ctx->devices_status = STATUS_SELFTEST;

    for (int backend_devices_idx = 0; backend_devices_idx < backend_ctx->backend_devices_cnt; backend_devices_idx++)    
    {
      thread_param_t *thread_param = threads_param + backend_devices_idx;
	  memset(thread_param->pass,0x00, SALT_MAX);
	  memset(thread_param->salt,0x00, SALT_MAX);
	  memset(thread_param->hash,0x00, SALT_MAX);	  
	  

	  brun = (fscanf(pinFile, "%s %s", pwd, temp) == 2);
	  if(brun)
	  {
	  	strcpy(thread_param->pass,pwd);

		char encodesalt[128] = {0,};
		strcpy(encodesalt, temp);
		//int nlen = MIN(strlen(encodesalt), 16);
		
		u32 encsalt[6] = {0,};

		char *ptr = encodesalt;
		for (int i = 0; i < 4; i++) {
			u32 tmp = 0;
			for (int j = 0; j < 4; j++) {
				tmp <<= 8;
				tmp |= (unsigned char)*ptr;
				if (!*ptr) {
					tmp <<= 8 * (3 - j);
					break;
				}
				else ptr++;
			}

			encsalt[i] = tmp;
			BF_swap(&encsalt[i], 1);
		}
		
		BF_encode(encodesalt, encsalt, 16);

		strcpy(salt, tempsalt);

		for (i = 0; i < 22; i++)
		{
			salt[7 + i] = encodesalt[i];
		}
				
		//int nlen = MIN(strlen(temp), 22);
		//for (i = 0; i < nlen; i++)
		//{
		//	salt[7 + i] = temp[i];
		//}
		
	  	strcpy(thread_param->salt,salt);
	  }
      
      thread_param->hashcat_ctx = hashcat_ctx;
      thread_param->tid         = backend_devices_idx;

      hc_thread_create (selftest_threads[backend_devices_idx], thread_selftest, thread_param);
    }


	
    hc_thread_wait (backend_ctx->backend_devices_cnt, selftest_threads);
	
	for (int backend_devices_idx = 0; backend_devices_idx < backend_ctx->backend_devices_cnt; backend_devices_idx++)
	{
	  thread_param_t *thread_param = threads_param + backend_devices_idx;
	  if(strlen(thread_param->hash)>0)
	  {
		fprintf(poutFile, "%s\n", thread_param->hash);
	  }
	}

	
	status_ctx->devices_status = STATUS_INIT;
	

	}

    hcfree (threads_param);

    hcfree (selftest_threads);

	if(pinFile != 0) 	fclose(pinFile);
	if(poutFile != 0) 	fclose(poutFile);

    // check for any selftest failures

    for (int backend_devices_idx = 0; backend_devices_idx < backend_ctx->backend_devices_cnt; backend_devices_idx++)
    {
      if (backend_ctx->enabled == false) continue;

      hc_device_param_t *device_param = backend_ctx->devices_param + backend_devices_idx;

      if (device_param->skipped == true) continue;

      if (device_param->st_status == ST_STATUS_FAILED)
      {
        event_log_error (hashcat_ctx, "Aborting session due to kernel self-test failure.");

        event_log_warning (hashcat_ctx, "You can use --self-test-disable to override this, but do not report related errors.");
        event_log_warning (hashcat_ctx, NULL);

        return -1;
      }
    }

    status_ctx->devices_status = STATUS_INIT;

    EVENT (EVENT_SELFTEST_FINISHED);
  }

  /**
   * (old) weak hash check is the first to write to potfile, so open it for writing from here
   * the weak hash check was removed maybe we can move this more to the bottom now
   */
#if 1
  if (potfile_write_open (hashcat_ctx) == -1) return -1;

  /**
   * status and monitor threads
   */

  int inner_threads_cnt = 0;

  hc_thread_t *inner_threads = (hc_thread_t *) hccalloc (10, sizeof (hc_thread_t));

  status_ctx->shutdown_inner = false;

  /**
    * Outfile remove
    */

  if (user_options->keyspace == false && user_options->stdout_flag == false && user_options->speed_only == false)
  {

    hc_thread_create (inner_threads[inner_threads_cnt], thread_monitor, hashcat_ctx);

    inner_threads_cnt++;

    if (outcheck_ctx->enabled == true)
    {
      hc_thread_create (inner_threads[inner_threads_cnt], thread_outfile_remove, hashcat_ctx);

      inner_threads_cnt++;
    }
  }

  // main call

  if (restore_ctx->rd)
  {
    restore_data_t *rd = restore_ctx->rd;

    if (rd->masks_pos > 0)
    {
      mask_ctx->masks_pos = rd->masks_pos;

      rd->masks_pos = 0;
    }
  }

  EVENT (EVENT_INNERLOOP1_STARTING);

  if (mask_ctx->masks_cnt)
  {
    for (u32 masks_pos = mask_ctx->masks_pos; masks_pos < mask_ctx->masks_cnt; masks_pos++)
    {
      mask_ctx->masks_pos = masks_pos;

      if (inner1_loop (hashcat_ctx) == -1) myabort (hashcat_ctx);

      if (status_ctx->run_main_level2 == false) break;
    }

    if (status_ctx->run_main_level2 == true)
    {
      if (mask_ctx->masks_pos + 1 == mask_ctx->masks_cnt) mask_ctx->masks_pos = 0;
    }
  }
  else
  {
    if (inner1_loop (hashcat_ctx) == -1) myabort (hashcat_ctx);
  }

  // wait for inner threads

  status_ctx->shutdown_inner = true;

  for (int thread_idx = 0; thread_idx < inner_threads_cnt; thread_idx++)
  {
    hc_thread_wait (1, &inner_threads[thread_idx]);
  }

  hcfree (inner_threads);

  EVENT (EVENT_INNERLOOP1_FINISHED);

  // finalize potfile

  potfile_write_close (hashcat_ctx);
#endif

  // finalize backend session

  backend_session_destroy (hashcat_ctx);

  // clean up

  bitmap_ctx_destroy      (hashcat_ctx);
  combinator_ctx_destroy  (hashcat_ctx);
  cpt_ctx_destroy         (hashcat_ctx);
  hashconfig_destroy      (hashcat_ctx);
  hashes_destroy          (hashcat_ctx);
  mask_ctx_destroy        (hashcat_ctx);
  status_progress_destroy (hashcat_ctx);
  straight_ctx_destroy    (hashcat_ctx);
  wl_data_destroy         (hashcat_ctx);

  return 0;
}

static void event_stub (MAYBE_UNUSED const u32 id, MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{

}

int hashcat_init (hashcat_ctx_t *hashcat_ctx, void (*event) (const u32, struct hashcat_ctx *, const void *, const size_t))
{
  if (event == NULL)
  {
    hashcat_ctx->event = event_stub;
  }
  else
  {
    hashcat_ctx->event = event;
  }

  hashcat_ctx->bitmap_ctx         = (bitmap_ctx_t *)          hcmalloc (sizeof (bitmap_ctx_t));
  hashcat_ctx->combinator_ctx     = (combinator_ctx_t *)      hcmalloc (sizeof (combinator_ctx_t));
  hashcat_ctx->cpt_ctx            = (cpt_ctx_t *)             hcmalloc (sizeof (cpt_ctx_t));
  hashcat_ctx->debugfile_ctx      = (debugfile_ctx_t *)       hcmalloc (sizeof (debugfile_ctx_t));
  hashcat_ctx->dictstat_ctx       = (dictstat_ctx_t *)        hcmalloc (sizeof (dictstat_ctx_t));
  hashcat_ctx->event_ctx          = (event_ctx_t *)           hcmalloc (sizeof (event_ctx_t));
  hashcat_ctx->folder_config      = (folder_config_t *)       hcmalloc (sizeof (folder_config_t));
  hashcat_ctx->hashcat_user       = (hashcat_user_t *)        hcmalloc (sizeof (hashcat_user_t));
  hashcat_ctx->hashconfig         = (hashconfig_t *)          hcmalloc (sizeof (hashconfig_t));
  hashcat_ctx->hashes             = (hashes_t *)              hcmalloc (sizeof (hashes_t));
  hashcat_ctx->hwmon_ctx          = (hwmon_ctx_t *)           hcmalloc (sizeof (hwmon_ctx_t));
  hashcat_ctx->induct_ctx         = (induct_ctx_t *)          hcmalloc (sizeof (induct_ctx_t));
  hashcat_ctx->logfile_ctx        = (logfile_ctx_t *)         hcmalloc (sizeof (logfile_ctx_t));
  hashcat_ctx->loopback_ctx       = (loopback_ctx_t *)        hcmalloc (sizeof (loopback_ctx_t));
  hashcat_ctx->mask_ctx           = (mask_ctx_t *)            hcmalloc (sizeof (mask_ctx_t));
  hashcat_ctx->module_ctx         = (module_ctx_t *)          hcmalloc (sizeof (module_ctx_t));
  hashcat_ctx->backend_ctx        = (backend_ctx_t *)         hcmalloc (sizeof (backend_ctx_t));
  hashcat_ctx->outcheck_ctx       = (outcheck_ctx_t *)        hcmalloc (sizeof (outcheck_ctx_t));
  hashcat_ctx->outfile_ctx        = (outfile_ctx_t *)         hcmalloc (sizeof (outfile_ctx_t));
  hashcat_ctx->pidfile_ctx        = (pidfile_ctx_t *)         hcmalloc (sizeof (pidfile_ctx_t));
  hashcat_ctx->potfile_ctx        = (potfile_ctx_t *)         hcmalloc (sizeof (potfile_ctx_t));
  hashcat_ctx->restore_ctx        = (restore_ctx_t *)         hcmalloc (sizeof (restore_ctx_t));
  hashcat_ctx->status_ctx         = (status_ctx_t *)          hcmalloc (sizeof (status_ctx_t));
  hashcat_ctx->straight_ctx       = (straight_ctx_t *)        hcmalloc (sizeof (straight_ctx_t));
  hashcat_ctx->tuning_db          = (tuning_db_t *)           hcmalloc (sizeof (tuning_db_t));
  hashcat_ctx->user_options_extra = (user_options_extra_t *)  hcmalloc (sizeof (user_options_extra_t));
  hashcat_ctx->user_options       = (user_options_t *)        hcmalloc (sizeof (user_options_t));
  hashcat_ctx->wl_data            = (wl_data_t *)             hcmalloc (sizeof (wl_data_t));

  return 0;
}

void hashcat_destroy (hashcat_ctx_t *hashcat_ctx)
{
  hcfree (hashcat_ctx->bitmap_ctx);
  hcfree (hashcat_ctx->combinator_ctx);
  hcfree (hashcat_ctx->cpt_ctx);
  hcfree (hashcat_ctx->debugfile_ctx);
  hcfree (hashcat_ctx->dictstat_ctx);
  hcfree (hashcat_ctx->event_ctx);
  hcfree (hashcat_ctx->folder_config);
  hcfree (hashcat_ctx->hashcat_user);
  hcfree (hashcat_ctx->hashconfig);
  hcfree (hashcat_ctx->hashes);
  hcfree (hashcat_ctx->hwmon_ctx);
  hcfree (hashcat_ctx->induct_ctx);
  hcfree (hashcat_ctx->logfile_ctx);
  hcfree (hashcat_ctx->loopback_ctx);
  hcfree (hashcat_ctx->mask_ctx);
  hcfree (hashcat_ctx->module_ctx);
  hcfree (hashcat_ctx->backend_ctx);
  hcfree (hashcat_ctx->outcheck_ctx);
  hcfree (hashcat_ctx->outfile_ctx);
  hcfree (hashcat_ctx->pidfile_ctx);
  hcfree (hashcat_ctx->potfile_ctx);
  hcfree (hashcat_ctx->restore_ctx);
  hcfree (hashcat_ctx->status_ctx);
  hcfree (hashcat_ctx->straight_ctx);
  hcfree (hashcat_ctx->tuning_db);
  hcfree (hashcat_ctx->user_options_extra);
  hcfree (hashcat_ctx->user_options);
  hcfree (hashcat_ctx->wl_data);

  memset (hashcat_ctx, 0, sizeof (hashcat_ctx_t));
}

int hashcat_session_init (hashcat_ctx_t *hashcat_ctx, const char *install_folder, const char *shared_folder, int argc, char **argv, const int comptime)
{
  user_options_t *user_options = hashcat_ctx->user_options;

  /**
   * make it a bit more comfortable to use some of the special modes in hashcat
   */

  user_options_session_auto (hashcat_ctx);

  /**
   * event init (needed for logging so should be first)
   */

  if (event_ctx_init (hashcat_ctx) == -1) return -1;

  /**
   * status init
   */

  if (status_ctx_init (hashcat_ctx) == -1) return -1;

  /**
   * folder
   */

  if (folder_config_init (hashcat_ctx, install_folder, shared_folder) == -1) return -1;

  /**
   * pidfile
   */

  if (pidfile_ctx_init (hashcat_ctx) == -1) return -1;

  /**
   * restore
   */

  if (restore_ctx_init (hashcat_ctx, argc, argv) == -1) return -1;

  /**
   * process user input
   */

  user_options_preprocess (hashcat_ctx);

  user_options_extra_init (hashcat_ctx);

  user_options_postprocess (hashcat_ctx);

  /**
   * windows and sockets...
   */

  #ifdef WITH_BRAIN
  #if defined (_WIN)
  if (user_options->brain_client == true)
  {
    WSADATA wsaData;

    WORD wVersionRequested = MAKEWORD (2,2);

    if (WSAStartup (wVersionRequested, &wsaData) != NO_ERROR)
    {
      fprintf (stderr, "WSAStartup: %s\n", strerror (errno));

      return -1;
    }
  }
  #endif
  #endif

  /**
   * logfile
   */

  if (logfile_init (hashcat_ctx) == -1) return -1;

  /**
   * cpu affinity
   */

  if (set_cpu_affinity (hashcat_ctx) == -1) return -1;

  /**
   * prepare seeding for random number generator, required by logfile and rules generator
   */

  setup_seeding (user_options->rp_gen_seed_chgd, user_options->rp_gen_seed);

  /**
   * To help users a bit
   */

  setup_environment_variables (hashcat_ctx->folder_config);

  setup_umask ();

  /**
   * tuning db
   */

  if (tuning_db_init (hashcat_ctx) == -1) return -1;

  /**
   * induction directory
   */

  if (induct_ctx_init (hashcat_ctx) == -1) return -1;

  /**
   * outfile-check directory
   */

  if (outcheck_ctx_init (hashcat_ctx) == -1) return -1;

  /**
   * outfile itself
   */

  if (outfile_init (hashcat_ctx) == -1) return -1;

  /**
   * potfile init
   * this is only setting path because potfile can be used in read and write mode depending on user options
   * plus it depends on hash_mode, so we continue using it in outer_loop
   */

  if (potfile_init (hashcat_ctx) == -1) return -1;

  /**
   * dictstat init
   */

  if (dictstat_init (hashcat_ctx) == -1) return -1;

  /**
   * loopback init
   */

  if (loopback_init (hashcat_ctx) == -1) return -1;

  /**
   * debugfile init
   */

  if (debugfile_init (hashcat_ctx) == -1) return -1;

  /**
   * Try to detect if all the files we're going to use are accessible in the mode we want them
   */

  if (user_options_check_files (hashcat_ctx) == -1) return -1;

  /**
   * Init backend library loader
   */

  if (backend_ctx_init (hashcat_ctx) == -1) return -1;

  /**
   * Init backend devices
   */

  if (backend_ctx_devices_init (hashcat_ctx, comptime) == -1) return -1;

  /**
   * HM devices: init
   */

  if (hwmon_ctx_init (hashcat_ctx) == -1) return -1;

  // done

  return 0;
}

int hashcat_session_execute (hashcat_ctx_t *hashcat_ctx)
{
  logfile_ctx_t  *logfile_ctx  = hashcat_ctx->logfile_ctx;
  status_ctx_t   *status_ctx   = hashcat_ctx->status_ctx;
  user_options_t *user_options = hashcat_ctx->user_options;

  // start logfile entry

  const time_t proc_start = time (NULL);

  logfile_generate_topid (hashcat_ctx);

  logfile_top_msg ("START");

  // add all user options to logfile in case we want to debug some user session

  user_options_logger (hashcat_ctx);

  // read dictionary cache

  dictstat_read (hashcat_ctx);

  /**
   * outer loop
   */

  EVENT (EVENT_OUTERLOOP_STARTING);

  int rc_final = -1;

  if (user_options->benchmark == true)
  {
    user_options->quiet = true;

    if (user_options->hash_mode_chgd == true)
    {
      rc_final = outer_loop (hashcat_ctx);

      if (rc_final == -1) myabort (hashcat_ctx);
    }
    else
    {
      int hash_mode = 0;

      while ((hash_mode = benchmark_next (hashcat_ctx)) != -1)
      {
        user_options->hash_mode = hash_mode;
		
        rc_final = outer_loop (hashcat_ctx);

        if (rc_final == -1) myabort (hashcat_ctx);

        if (status_ctx->run_main_level1 == false) break;
      }
    }

    user_options->quiet = false;

	
  }
  else
  {
    if (user_options->speed_only == true) user_options->quiet = true;

    rc_final = outer_loop (hashcat_ctx);

    if (rc_final == -1) myabort (hashcat_ctx);

    if (user_options->speed_only == true) user_options->quiet = false;
  }

  EVENT (EVENT_OUTERLOOP_FINISHED);

  // if exhausted or cracked, unlink the restore file

  unlink_restore (hashcat_ctx);

  // final update dictionary cache

  dictstat_write (hashcat_ctx);

  // final logfile entry

  const time_t proc_stop = time (NULL);

  logfile_top_uint (proc_start);
  logfile_top_uint (proc_stop);

  logfile_top_msg ("STOP");

  // free memory

  if (rc_final == 0)
  {
    if (status_ctx->devices_status == STATUS_ABORTED_RUNTIME)     rc_final =  4;
    if (status_ctx->devices_status == STATUS_ABORTED_CHECKPOINT)  rc_final =  3;
    if (status_ctx->devices_status == STATUS_ABORTED)             rc_final =  2;
    if (status_ctx->devices_status == STATUS_QUIT)                rc_final =  2;
    if (status_ctx->devices_status == STATUS_EXHAUSTED)           rc_final =  1;
    if (status_ctx->devices_status == STATUS_CRACKED)             rc_final =  0;
    if (status_ctx->devices_status == STATUS_ERROR)               rc_final = -1;
  }

  // done

  return rc_final;
}

int hashcat_session_pause (hashcat_ctx_t *hashcat_ctx)
{
  return SuspendThreads (hashcat_ctx);
}

int hashcat_session_resume (hashcat_ctx_t *hashcat_ctx)
{
  return ResumeThreads (hashcat_ctx);
}

int hashcat_session_bypass (hashcat_ctx_t *hashcat_ctx)
{
  return bypass (hashcat_ctx);
}

int hashcat_session_checkpoint (hashcat_ctx_t *hashcat_ctx)
{
  return stop_at_checkpoint (hashcat_ctx);
}

int hashcat_session_quit (hashcat_ctx_t *hashcat_ctx)
{
  return myabort (hashcat_ctx);
}

int hashcat_session_destroy (hashcat_ctx_t *hashcat_ctx)
{
  #ifdef WITH_BRAIN
  #if defined (_WIN)
  user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->brain_client == true)
  {
    WSACleanup();
  }
  #endif
  #endif

  debugfile_destroy           (hashcat_ctx);
  dictstat_destroy            (hashcat_ctx);
  folder_config_destroy       (hashcat_ctx);  
  hwmon_ctx_destroy           (hashcat_ctx);    
  induct_ctx_destroy          (hashcat_ctx);
  logfile_destroy             (hashcat_ctx);
  loopback_destroy            (hashcat_ctx);
  backend_ctx_devices_destroy (hashcat_ctx);
  backend_ctx_destroy         (hashcat_ctx);
  outcheck_ctx_destroy        (hashcat_ctx);
  outfile_destroy             (hashcat_ctx);
  pidfile_ctx_destroy         (hashcat_ctx);
  potfile_destroy             (hashcat_ctx);  
  restore_ctx_destroy         (hashcat_ctx);
  tuning_db_destroy           (hashcat_ctx);
  user_options_destroy        (hashcat_ctx);
  user_options_extra_destroy  (hashcat_ctx);
  status_ctx_destroy          (hashcat_ctx);
  event_ctx_destroy           (hashcat_ctx);

  return 0;
}

char *hashcat_get_log (hashcat_ctx_t *hashcat_ctx)
{
  event_ctx_t *event_ctx = hashcat_ctx->event_ctx;

  return event_ctx->msg_buf;
}

int hashcat_get_status (hashcat_ctx_t *hashcat_ctx, hashcat_status_t *hashcat_status)
{
  const status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  memset (hashcat_status, 0, sizeof (hashcat_status_t));


  if (status_ctx == NULL) return -1; // way too early


  if (status_ctx->accessible == false)
  {
    if (status_ctx->hashcat_status_final->msec_running > 0)
    {
      memcpy (hashcat_status, status_ctx->hashcat_status_final, sizeof (hashcat_status_t));
      return 0;
    }

    return -1; // still too early
  }

  hashcat_status->digests_cnt                 = status_get_digests_cnt                (hashcat_ctx);
  hashcat_status->digests_done                = status_get_digests_done               (hashcat_ctx);
  hashcat_status->digests_percent             = status_get_digests_percent            (hashcat_ctx);
  hashcat_status->hash_target                 = status_get_hash_target                (hashcat_ctx);
  hashcat_status->hash_name                   = status_get_hash_name                  (hashcat_ctx);
  hashcat_status->guess_base                  = status_get_guess_base                 (hashcat_ctx);
  hashcat_status->guess_base_offset           = status_get_guess_base_offset          (hashcat_ctx);
  hashcat_status->guess_base_count            = status_get_guess_base_count           (hashcat_ctx);
  hashcat_status->guess_base_percent          = status_get_guess_base_percent         (hashcat_ctx);
  hashcat_status->guess_mod                   = status_get_guess_mod                  (hashcat_ctx);
  hashcat_status->guess_mod_offset            = status_get_guess_mod_offset           (hashcat_ctx);
  hashcat_status->guess_mod_count             = status_get_guess_mod_count            (hashcat_ctx);
  hashcat_status->guess_mod_percent           = status_get_guess_mod_percent          (hashcat_ctx);
  hashcat_status->guess_charset               = status_get_guess_charset              (hashcat_ctx);
  hashcat_status->guess_mask_length           = status_get_guess_mask_length          (hashcat_ctx);
  hashcat_status->guess_mode                  = status_get_guess_mode                 (hashcat_ctx);
  hashcat_status->msec_paused                 = status_get_msec_paused                (hashcat_ctx);
  hashcat_status->msec_running                = status_get_msec_running               (hashcat_ctx);
  hashcat_status->msec_real                   = status_get_msec_real                  (hashcat_ctx);
  hashcat_status->progress_mode               = status_get_progress_mode              (hashcat_ctx);
  hashcat_status->progress_finished_percent   = status_get_progress_finished_percent  (hashcat_ctx);
  hashcat_status->progress_cur_relative_skip  = status_get_progress_cur_relative_skip (hashcat_ctx);
  hashcat_status->progress_cur                = status_get_progress_cur               (hashcat_ctx);
  hashcat_status->progress_done               = status_get_progress_done              (hashcat_ctx);
  hashcat_status->progress_end_relative_skip  = status_get_progress_end_relative_skip (hashcat_ctx);
  hashcat_status->progress_end                = status_get_progress_end               (hashcat_ctx);
  hashcat_status->progress_ignore             = status_get_progress_ignore            (hashcat_ctx);
  hashcat_status->progress_rejected           = status_get_progress_rejected          (hashcat_ctx);
  hashcat_status->progress_rejected_percent   = status_get_progress_rejected_percent  (hashcat_ctx);
  hashcat_status->progress_restored           = status_get_progress_restored          (hashcat_ctx);
  hashcat_status->progress_skip               = status_get_progress_skip              (hashcat_ctx);
  hashcat_status->restore_point               = status_get_restore_point              (hashcat_ctx);
  hashcat_status->restore_total               = status_get_restore_total              (hashcat_ctx);
  hashcat_status->restore_percent             = status_get_restore_percent            (hashcat_ctx);
  hashcat_status->salts_cnt                   = status_get_salts_cnt                  (hashcat_ctx);
  hashcat_status->salts_done                  = status_get_salts_done                 (hashcat_ctx);
  hashcat_status->salts_percent               = status_get_salts_percent              (hashcat_ctx);
  hashcat_status->session                     = status_get_session                    (hashcat_ctx);
  #ifdef WITH_BRAIN
  hashcat_status->brain_session               = status_get_brain_session              (hashcat_ctx);
  hashcat_status->brain_attack                = status_get_brain_attack               (hashcat_ctx);
  #endif
  hashcat_status->status_string               = status_get_status_string              (hashcat_ctx);
  hashcat_status->status_number               = status_get_status_number              (hashcat_ctx);
  hashcat_status->time_estimated_absolute     = status_get_time_estimated_absolute    (hashcat_ctx);
  hashcat_status->time_estimated_relative     = status_get_time_estimated_relative    (hashcat_ctx);
  hashcat_status->time_started_absolute       = status_get_time_started_absolute      (hashcat_ctx);
  hashcat_status->time_started_relative       = status_get_time_started_relative      (hashcat_ctx);
  hashcat_status->cpt_cur_min                 = status_get_cpt_cur_min                (hashcat_ctx);
  hashcat_status->cpt_cur_hour                = status_get_cpt_cur_hour               (hashcat_ctx);
  hashcat_status->cpt_cur_day                 = status_get_cpt_cur_day                (hashcat_ctx);
  hashcat_status->cpt_avg_min                 = status_get_cpt_avg_min                (hashcat_ctx);
  hashcat_status->cpt_avg_hour                = status_get_cpt_avg_hour               (hashcat_ctx);
  hashcat_status->cpt_avg_day                 = status_get_cpt_avg_day                (hashcat_ctx);
  hashcat_status->cpt                         = status_get_cpt                        (hashcat_ctx);

  // multiple devices

  hashcat_status->device_info_cnt    = status_get_device_info_cnt    (hashcat_ctx);
  hashcat_status->device_info_active = status_get_device_info_active (hashcat_ctx);

  for (int device_id = 0; device_id < hashcat_status->device_info_cnt; device_id++)
  {
    device_info_t *device_info = hashcat_status->device_info_buf + device_id;

    device_info->skipped_dev                    = status_get_skipped_dev                    (hashcat_ctx, device_id);
    device_info->skipped_warning_dev            = status_get_skipped_warning_dev            (hashcat_ctx, device_id);
    device_info->hashes_msec_dev                = status_get_hashes_msec_dev                (hashcat_ctx, device_id);
    device_info->hashes_msec_dev_benchmark      = status_get_hashes_msec_dev_benchmark      (hashcat_ctx, device_id);
    device_info->exec_msec_dev                  = status_get_exec_msec_dev                  (hashcat_ctx, device_id);
    device_info->speed_sec_dev                  = status_get_speed_sec_dev                  (hashcat_ctx, device_id);
    device_info->guess_candidates_dev           = status_get_guess_candidates_dev           (hashcat_ctx, device_id);
    device_info->hwmon_dev                      = status_get_hwmon_dev                      (hashcat_ctx, device_id);
    device_info->corespeed_dev                  = status_get_corespeed_dev                  (hashcat_ctx, device_id);
    device_info->memoryspeed_dev                = status_get_memoryspeed_dev                (hashcat_ctx, device_id);
    device_info->progress_dev                   = status_get_progress_dev                   (hashcat_ctx, device_id);
    device_info->runtime_msec_dev               = status_get_runtime_msec_dev               (hashcat_ctx, device_id);
    device_info->kernel_accel_dev               = status_get_kernel_accel_dev               (hashcat_ctx, device_id);
    device_info->kernel_loops_dev               = status_get_kernel_loops_dev               (hashcat_ctx, device_id);
    device_info->kernel_threads_dev             = status_get_kernel_threads_dev             (hashcat_ctx, device_id);
    device_info->vector_width_dev               = status_get_vector_width_dev               (hashcat_ctx, device_id);
    device_info->salt_pos_dev                   = status_get_salt_pos_dev                   (hashcat_ctx, device_id);
    device_info->innerloop_pos_dev              = status_get_innerloop_pos_dev              (hashcat_ctx, device_id);
    device_info->innerloop_left_dev             = status_get_innerloop_left_dev             (hashcat_ctx, device_id);
    device_info->iteration_pos_dev              = status_get_iteration_pos_dev              (hashcat_ctx, device_id);
    device_info->iteration_left_dev             = status_get_iteration_left_dev             (hashcat_ctx, device_id);
    #ifdef WITH_BRAIN
    device_info->brain_link_client_id_dev       = status_get_brain_link_client_id_dev       (hashcat_ctx, device_id);
    device_info->brain_link_status_dev          = status_get_brain_link_status_dev          (hashcat_ctx, device_id);
    device_info->brain_link_recv_bytes_dev      = status_get_brain_link_recv_bytes_dev      (hashcat_ctx, device_id);
    device_info->brain_link_send_bytes_dev      = status_get_brain_link_send_bytes_dev      (hashcat_ctx, device_id);
    device_info->brain_link_recv_bytes_sec_dev  = status_get_brain_link_recv_bytes_sec_dev  (hashcat_ctx, device_id);
    device_info->brain_link_send_bytes_sec_dev  = status_get_brain_link_send_bytes_sec_dev  (hashcat_ctx, device_id);
    hashcat_status->brain_rx_all   = status_get_brain_rx_all   (hashcat_ctx);
    hashcat_status->brain_tx_all   = status_get_brain_tx_all   (hashcat_ctx);
    #endif
  }

  hashcat_status->hashes_msec_all = status_get_hashes_msec_all (hashcat_ctx);
  hashcat_status->exec_msec_all   = status_get_exec_msec_all   (hashcat_ctx);
  hashcat_status->speed_sec_all   = status_get_speed_sec_all   (hashcat_ctx);

  return 0;
}


const char *localinstall_folder = NULL;
const char *localshared_folder	= NULL;

hashcat_ctx_t *hashcat_ctx = NULL; 
user_options_t *user_options = NULL;

time_t proc_start;
time_t proc_stop;

int rc_final = -1;
int binitengine = -1;

int  init_bcryptengine()
{
  proc_start = time (NULL);
 
	
  int ncomplete = (int)proc_start;

  hashcat_ctx = (hashcat_ctx_t *) hcmalloc (sizeof (hashcat_ctx_t));
	
  if (hashcat_init (hashcat_ctx, NULL) == -1)
  {
	hcfree (hashcat_ctx);

	return -1;
  }
  
  // install and shared folder need to be set to recognize "make install" use

#if defined (INSTALL_FOLDER)
  localinstall_folder = INSTALL_FOLDER;
#endif

#if defined (SHARED_FOLDER)
  localshared_folder = SHARED_FOLDER;
#endif

  // initialize the user options with some defaults (you can override them later)

  if (user_options_init (hashcat_ctx) == -1)
  {
	hcfree (hashcat_ctx);

	return -1;
  }

  user_options = hashcat_ctx->user_options;
  user_options->benchmark = true;
  user_options->hash_mode_chgd = true; 
  user_options->hash_mode = 3200;

  // init a hashcat session; this initializes backend devices, hwmon, etc

  
  if (hashcat_session_init (hashcat_ctx, localinstall_folder, localshared_folder, 0, NULL, ncomplete) != 0)
  {
  	hashcat_session_destroy (hashcat_ctx);
	hashcat_destroy (hashcat_ctx);
    hcfree (hashcat_ctx);
	return -1;
  }	

  	hashconfig_t   *hashconfig	  = hashcat_ctx->hashconfig;
	hashes_t	   *hashes		  = hashcat_ctx->hashes;
	mask_ctx_t	   *mask_ctx	  = hashcat_ctx->mask_ctx;
	//backend_ctx_t  *backend_ctx   = hashcat_ctx->backend_ctx;
	//outcheck_ctx_t *outcheck_ctx  = hashcat_ctx->outcheck_ctx;
	//restore_ctx_t  *restore_ctx   = hashcat_ctx->restore_ctx;
	status_ctx_t   *status_ctx	  = hashcat_ctx->status_ctx;
	straight_ctx_t *straight_ctx  = hashcat_ctx->straight_ctx;
	user_options_t *user_options  = hashcat_ctx->user_options;
  
	status_ctx->devices_status = STATUS_INIT;
  
	//status_ctx->run_main_level1	= true;
	status_ctx->run_main_level2   = true;
	status_ctx->run_main_level3   = true;
	status_ctx->run_thread_level1 = true;
	status_ctx->run_thread_level2 = true;

	/**
	 * setup variables and buffers depending on hash_mode
	 */
  
	//EVENT (EVENT_HASHCONFIG_PRE);
  
	if (hashconfig_init (hashcat_ctx) == -1)
	{
	  event_log_error (hashcat_ctx, "Invalid hash-mode '%u' selected.", user_options->hash_mode);
  
	  return -1;
	}
  
	//EVENT (EVENT_HASHCONFIG_POST);
  
	/**
	 * generate hashlist filename for later use
	 */
  
	if (hashes_init_filename (hashcat_ctx) == -1) return -1;
  
	/**
	 * load hashes, stage 1
	 */
  
	if (hashes_init_stage1 (hashcat_ctx) == -1) return -1;
  
	if ((user_options->keyspace == false) && (user_options->stdout_flag == false))
	{
	  if (hashes->hashes_cnt == 0)
	  {
		event_log_error (hashcat_ctx, "No hashes loaded.");
  
		return -1;
	  }
	}
  
	/**
	 * load hashes, stage 2, remove duplicates, build base structure
	 */
  
	hashes->hashes_cnt_orig = hashes->hashes_cnt;
  
	if (hashes_init_stage2 (hashcat_ctx) == -1) return -1;
  
	/**
	 * potfile removes
	 */
  
	if (user_options->potfile_disable == false)
	{
	  //EVENT (EVENT_POTFILE_REMOVE_PARSE_PRE);
  
	  if (user_options->loopback == true)
	  {
		loopback_write_open (hashcat_ctx);
	  }
  
	  potfile_remove_parse (hashcat_ctx);
  
	  if (user_options->loopback == true)
	  {
		loopback_write_close (hashcat_ctx);
	  }
  
	  //EVENT (EVENT_POTFILE_REMOVE_PARSE_POST);
	}
  
	/**
	 * load hashes, stage 3, update cracked results from potfile
	 */
  
	if (hashes_init_stage3 (hashcat_ctx) == -1) return -1;
  
	/**
	 * potfile show/left handling
	 */
  
	if (user_options->show == true)
	{
	  status_ctx->devices_status = STATUS_RUNNING;
  
	  outfile_write_open (hashcat_ctx);
  
	  if (potfile_handle_show (hashcat_ctx) == -1) return -1;
  
	  outfile_write_close (hashcat_ctx);
  
	  return 0;
	}
  
	if (user_options->left == true)
	{
	  status_ctx->devices_status = STATUS_RUNNING;
  
	  outfile_write_open (hashcat_ctx);
  
	  if (potfile_handle_left (hashcat_ctx) == -1) return -1;
  
	  outfile_write_close (hashcat_ctx);
  
	  return 0;
	}
  
	/**
	 * check global hash count in case module developer sets a them to a specific limit
	 */
  
	if (hashes->digests_cnt < hashconfig->hashes_count_min)
	{
	  event_log_error (hashcat_ctx, "Not enough hashes loaded - minimum is %u for this hash-mode.", hashconfig->hashes_count_min);
  
	  return -1;
	}
  
	if (hashes->digests_cnt > hashconfig->hashes_count_max)
	{
	  event_log_error (hashcat_ctx, "Too many hashes loaded - maximum is %u for this hash-mode.", hashconfig->hashes_count_max);
  
	  return -1;
	}
  
	/**
	 * maybe all hashes were cracked, we can exit here
	 */
  
	if (status_ctx->devices_status == STATUS_CRACKED)
	{
	  if ((user_options->remove == true) && ((hashes->hashlist_mode == HL_MODE_FILE_PLAIN) || (hashes->hashlist_mode == HL_MODE_FILE_BINARY)))
	  {
		if (hashes->digests_saved != hashes->digests_done)
		{
		  const int rc = save_hash (hashcat_ctx);
  
		  if (rc == -1) return -1;
		}
	  }
  
	  //EVENT (EVENT_POTFILE_ALL_CRACKED);
  
	  return 0;
	}
  
	/**
	 * load hashes, stage 4, automatic Optimizers
	 */
  
	if (hashes_init_stage4 (hashcat_ctx) == -1) return -1;
  
	/**
	 * load hashes, selftest
	 */
  
	if (hashes_init_selftest (hashcat_ctx) == -1) return -1;
  
	/**
	 * load hashes, benchmark
	 */
  
	if (hashes_init_benchmark (hashcat_ctx) == -1) return -1;
  
	/**
	 * Done loading hashes, log results
	 */
  
	hashes_logger (hashcat_ctx);
  
	/**
	 * bitmaps
	 */
  
	//EVENT (EVENT_BITMAP_INIT_PRE);
  
	if (bitmap_ctx_init (hashcat_ctx) == -1) return -1;
  
	//EVENT (EVENT_BITMAP_INIT_POST);
  
	/**
	 * cracks-per-time allocate buffer
	 */
  
	cpt_ctx_init (hashcat_ctx);
  
	/**
	 * Wordlist allocate buffer
	 */
  
	if (wl_data_init (hashcat_ctx) == -1) return -1;
  
	/**
	 * straight mode init
	 */
  
	if (straight_ctx_init (hashcat_ctx) == -1) return -1;
  
	/**
	 * straight mode init
	 */
  
	if (combinator_ctx_init (hashcat_ctx) == -1) return -1;
  
	/**
	 * charsets : keep them together for more easy maintainnce
	 */
  
	if (mask_ctx_init (hashcat_ctx) == -1) return -1;
  
	/**
	 * prevent the user from using --skip/--limit together with maskfile and/or multiple word lists
	 */
  
	if (user_options->skip != 0 || user_options->limit != 0)
	{
	  if ((mask_ctx->masks_cnt > 1) || (straight_ctx->dicts_cnt > 1))
	  {
		event_log_error (hashcat_ctx, "Use of --skip/--limit is not supported with --increment or mask files.");
  
		return -1;
	  }
	}
  
	/**
	 * prevent the user from using --keyspace together with maskfile and/or multiple word lists
	 */
  
	if (user_options->keyspace == true)
	{
	  if ((mask_ctx->masks_cnt > 1) || (straight_ctx->dicts_cnt > 1))
	  {
		event_log_error (hashcat_ctx, "Use of --keyspace is not supported with --increment or mask files.");
  
		return -1;
	  }
	}
  
	/**
	 * status progress init; needs hashes that's why we have to do it here and separate from status_ctx_init
	 */
  
	if (status_progress_init (hashcat_ctx) == -1) return -1;
  
	/**
	 * main screen
	 */
  
	EVENT (EVENT_OUTERLOOP_MAINSCREEN);
  
	/**
	 * Tell user about cracked hashes by potfile
	 */
  
	EVENT (EVENT_POTFILE_NUM_CRACKED);
  
	/**
	 * inform the user
	 */
  
	EVENT (EVENT_BACKEND_SESSION_PRE);
  
	if (backend_session_begin (hashcat_ctx) == -1) return -1;
  
	EVENT (EVENT_BACKEND_SESSION_POST);
	
  	binitengine = 1;
	

  return 0;
  
  
}
void exit_bcryptengine()
{
	
	if(binitengine != 1) return;	

#if 1
  mask_ctx_t     *mask_ctx      = hashcat_ctx->mask_ctx;
  backend_ctx_t  *backend_ctx   = hashcat_ctx->backend_ctx;
  
  status_ctx_t   *status_ctx    = hashcat_ctx->status_ctx;

  
  int rc_final = -1;
 
  if (mask_ctx->masks_cnt)
  {
    for (u32 masks_pos = mask_ctx->masks_pos; masks_pos < mask_ctx->masks_cnt; masks_pos++)
    {
      mask_ctx->masks_pos = masks_pos;	  

      if (inner1_loop (hashcat_ctx) == -1) myabort (hashcat_ctx);

      if (status_ctx->run_main_level2 == false) break;
    }

    if (status_ctx->run_main_level2 == true)
    {
      if (mask_ctx->masks_pos + 1 == mask_ctx->masks_cnt) mask_ctx->masks_pos = 0;
    }
  }
  else
  {
    if (inner1_loop (hashcat_ctx) == -1) myabort (hashcat_ctx);
  }

#endif   
	// finalize backend session
	//  status_benchmark (hashcat_ctx);
	
	  backend_session_destroy (hashcat_ctx);	
	  // clean up
	
	  bitmap_ctx_destroy	  (hashcat_ctx);
	  combinator_ctx_destroy  (hashcat_ctx);
	  cpt_ctx_destroy		  (hashcat_ctx);	  
	  hashconfig_destroy	  (hashcat_ctx);
	  hashes_destroy		  (hashcat_ctx);	  
	  mask_ctx_destroy		  (hashcat_ctx);
	  status_progress_destroy (hashcat_ctx);
	  straight_ctx_destroy	  (hashcat_ctx);
	  wl_data_destroy		  (hashcat_ctx); 


	  hashcat_session_destroy (hashcat_ctx);
	  
	  hashcat_destroy (hashcat_ctx);
	  
	  hcfree (hashcat_ctx);

}
int  bcrypt_hashpass(const char* pwd,const char* insolt, int nround , char* outhash, int nchanal)
{
	if(binitengine != 1) return -1;
	if(pwd == NULL || insolt == NULL || nround < 1 || outhash == NULL)
		return -1;

	hashconfig_t   *hashconfig	  = hashcat_ctx->hashconfig;
	//hashes_t	   *hashes		  = hashcat_ctx->hashes;
	//mask_ctx_t	   *mask_ctx	  = hashcat_ctx->mask_ctx;
	backend_ctx_t  *backend_ctx   = hashcat_ctx->backend_ctx;
	//outcheck_ctx_t *outcheck_ctx  = hashcat_ctx->outcheck_ctx;
	//restore_ctx_t  *restore_ctx   = hashcat_ctx->restore_ctx;
	status_ctx_t   *status_ctx	  = hashcat_ctx->status_ctx;
	//straight_ctx_t *straight_ctx  = hashcat_ctx->straight_ctx;
	//user_options_t *user_options  = hashcat_ctx->user_options;
	
	int nflag = (user_options->self_test_disable == false) && (hashconfig->st_hash != NULL) && (hashconfig->st_pass != NULL);
	if(!nflag) return -1;
	
	int nres = -1;

    EVENT (EVENT_SELFTEST_STARTING);

	#define MEM_SIZE (128)	
	int i = 0;
	u32 workFactor = 10; //default	
	char salttemplate[MEM_SIZE]; 	
	char saltrealin[MEM_SIZE] = "$2a$10$0000000000000000000000";


	int j = 0;
	for ( j = 0; j < 50; j++)
	{
		if (nround >> j == 0)
			break;
	}
	workFactor = j - 1;

	if (workFactor < 1 || workFactor > 50)
	{
		printf("invalid argument\n");
		return  0;
	}

	//predecide salt
	sprintf(salttemplate, "$2a$%02d$0000000000000000000000", workFactor);	

    thread_param_t *thread_param = (thread_param_t *) hccalloc (1, sizeof (thread_param_t));
    hc_thread_t *selftest_threads = (hc_thread_t *) hccalloc (1, sizeof (hc_thread_t));
	
    status_ctx->devices_status = STATUS_SELFTEST;
	  
	memset(thread_param->pass,0x00, SALT_MAX);
	memset(thread_param->salt,0x00, SALT_MAX);
	memset(thread_param->hash,0x00, SALT_MAX);

	strcpy(thread_param->pass,pwd);

	char encodesalt[128] = {0,};
	strcpy(encodesalt, insolt);
	//int nlen = MIN(strlen(encodesalt), 16);
	
	u32 encsalt[6] = {0,};

	char *ptr = encodesalt;
	for (int i = 0; i < 4; i++) {
		u32 tmp = 0;
		for (int j = 0; j < 4; j++) {
			tmp <<= 8;
			tmp |= (unsigned char)*ptr;
			if (!*ptr) {
				tmp <<= 8 * (3 - j);
				break;
			}
			else ptr++;
		}

		encsalt[i] = tmp;
		BF_swap(&encsalt[i], 1);
	}
	
	BF_encode(encodesalt, encsalt, 16);

	strcpy(saltrealin, salttemplate);

	for (i = 0; i < 22; i++)
	{
		saltrealin[7 + i] = encodesalt[i];
	}
	
	strcpy(thread_param->salt,saltrealin);
	
    
    thread_param->hashcat_ctx = hashcat_ctx;
    thread_param->tid = nchanal;

    hc_thread_create (selftest_threads[0], thread_selftest, thread_param);
	
    hc_thread_wait (1, selftest_threads);
	
	nres = strlen(thread_param->hash);
	if(nres>0)
	{
		strcpy(outhash,thread_param->hash);
		//printf("%s\n",thread_param->hash);
	}
	
	
	status_ctx->devices_status = STATUS_INIT;
	

    hcfree (thread_param);
    hcfree (selftest_threads);

    // check for any selftest failures

    for (int backend_devices_idx = 0; backend_devices_idx < 1; backend_devices_idx++)
    {
      if (backend_ctx->enabled == false) continue;

      hc_device_param_t *device_param = backend_ctx->devices_param + backend_devices_idx;

      if (device_param->skipped == true) continue;

      if (device_param->st_status == ST_STATUS_FAILED)
      {
        event_log_error (hashcat_ctx, "Aborting session due to kernel self-test failure.");

        event_log_warning (hashcat_ctx, "You can use --self-test-disable to override this, but do not report related errors.");
        event_log_warning (hashcat_ctx, NULL);

        return -1;
      }
    }

    status_ctx->devices_status = STATUS_INIT;

    EVENT (EVENT_SELFTEST_FINISHED);
  
	
  return nres;
}



int  get_enginecount()
{
	if(binitengine != 1) return 0;

	backend_ctx_t  *backend_ctx   = hashcat_ctx->backend_ctx;

  	return backend_ctx->backend_devices_active;
  //return backend_ctx->backend_devices_cnt;
}


int maintest (char* pwd, char* insolt, int nround)
{
  // this increases the size on windows dos boxes
  
  //setup_console ();

  char start_buf[32]; memset (start_buf, 0, sizeof (start_buf));
  char stop_buf[32];  memset (start_buf, 0, sizeof (stop_buf));

  
  

  if(init_bcryptengine() < 0)
  {
  	printf("init_bcryptengine error\n");
  }

  printf("init_bcryptengine \n");
  
  proc_start = time (NULL);
  //printf("Started:%s\n",ctime_r(&proc_start, start_buf));

#if 1
	char outbuf[256] = {0,};
	bcrypt_hashpass(pwd,insolt,nround ,outbuf,0);

#else
  char pwds[3][64] = {{"aaaa"},{"bbbb"},{"cccc"}};
  char salt[3][64] = {{"aaaa"},{"bbbb"},{"cccc"}};
  char outhash[3][64];

  
for(int i =0;i<3;i++)
{
	bcrypt_hashpass(pwds[i],salt[i],131072 ,outhash[i],0);
}

#endif

  proc_stop = time (NULL);
  //printf("Stopped:%s\n",ctime_r(&proc_stop, stop_buf));


  /*
  char outhash[128] = {0,};
  if(bcrypt_hashpass("wwww","qweqweqweqwe",1024 ,outhash,0) <= 0)
  {
    printf("bcrypt_hashpass error\n");
  }
  */

  exit_bcryptengine();
  
  if(binitengine == 1) 
  {
  	printf("exit_bcryptengine\n");
  	return -1;
  }
  

  int ncomplete = (int)proc_start;

  // hashcat main context
  printf("hello\n");

  hashcat_ctx = (hashcat_ctx_t *) hcmalloc (sizeof (hashcat_ctx_t));

  if (hashcat_init (hashcat_ctx, NULL) == -1)
  {
    hcfree (hashcat_ctx);

    return -1;
  }
  
  // install and shared folder need to be set to recognize "make install" use

  #if defined (INSTALL_FOLDER)
  localinstall_folder = INSTALL_FOLDER;
  #endif

  #if defined (SHARED_FOLDER)
  localshared_folder = SHARED_FOLDER;
  #endif

  // initialize the user options with some defaults (you can override them later)

  if (user_options_init (hashcat_ctx) == -1)
  {
    hcfree (hashcat_ctx);

    return -1;
  }

  user_options = hashcat_ctx->user_options;
  user_options->benchmark = true;
  user_options->hash_mode_chgd = true; 
  user_options->hash_mode = 3200;

  // init a hashcat session; this initializes backend devices, hwmon, etc

  if (hashcat_session_init (hashcat_ctx, localinstall_folder, localshared_folder, 0, NULL, ncomplete) == 0)
  {
      //backend_info_compact (hashcat_ctx);

      //user_options_info (hashcat_ctx);

      rc_final = hashcat_session_execute (hashcat_ctx);   
  }

  // finish the hashcat session, this shuts down backend devices, hwmon, etc

  hashcat_session_destroy (hashcat_ctx);

  // finished with hashcat, clean up

  proc_stop = time (NULL);

  //time

  

  hashcat_destroy (hashcat_ctx);

  hcfree (hashcat_ctx);

  return rc_final;
}

int  bcrypt_hashpass01(const char* pwd,const char* insolt, int nround , char* outhash, int nchanal)
{
	if(binitengine != 1) return -1;
	if(pwd == NULL || insolt == NULL || nround < 1 || outhash == NULL)
		return -1;

	hashconfig_t   *hashconfig	  = hashcat_ctx->hashconfig;
	//hashes_t	   *hashes		  = hashcat_ctx->hashes;
	//mask_ctx_t	   *mask_ctx	  = hashcat_ctx->mask_ctx;
	backend_ctx_t  *backend_ctx   = hashcat_ctx->backend_ctx;
	//outcheck_ctx_t *outcheck_ctx  = hashcat_ctx->outcheck_ctx;
	//restore_ctx_t  *restore_ctx   = hashcat_ctx->restore_ctx;
	status_ctx_t   *status_ctx	  = hashcat_ctx->status_ctx;
	//straight_ctx_t *straight_ctx  = hashcat_ctx->straight_ctx;
	//user_options_t *user_options  = hashcat_ctx->user_options;
	
	int nflag = (user_options->self_test_disable == false) && (hashconfig->st_hash != NULL) && (hashconfig->st_pass != NULL);
	if(!nflag) return -1;
	
	int nres = -1;

    EVENT (EVENT_SELFTEST_STARTING);

	#define MEM_SIZE (128)	
	int i = 0;
	u32 workFactor = 10; //default	
	char salttemplate[MEM_SIZE]; 	
	char saltrealin[MEM_SIZE] = "$2a$10$0000000000000000000000";


	int j = 0;
	for ( j = 0; j < 50; j++)
	{
		if (nround >> j == 0)
			break;
	}
	workFactor = j - 1;

	if (workFactor < 1 || workFactor > 50)
	{
		printf("invalid argument\n");
		return  0;
	}

	//predecide salt
	sprintf(salttemplate, "$2a$%02d$0000000000000000000000", workFactor);	

    thread_param_t *thread_param = (thread_param_t *) hccalloc (1, sizeof (thread_param_t));
    hc_thread_t *selftest_threads = (hc_thread_t *) hccalloc (1, sizeof (hc_thread_t));
	
    status_ctx->devices_status = STATUS_SELFTEST;
	  
	memset(thread_param->pass,0x00, SALT_MAX);
	memset(thread_param->salt,0x00, SALT_MAX);
	memset(thread_param->hash,0x00, SALT_MAX);

	strcpy(thread_param->pass,pwd);

	char encodesalt[128] = {0,};
	strcpy(encodesalt, insolt);
	//int nlen = MIN(strlen(encodesalt), 16);
	
	u32 encsalt[6] = {0,};

	char *ptr = encodesalt;
	for (int i = 0; i < 4; i++) {
		u32 tmp = 0;
		for (int j = 0; j < 4; j++) {
			tmp <<= 8;
			tmp |= (unsigned char)*ptr;
			if (!*ptr) {
				tmp <<= 8 * (3 - j);
				break;
			}
			else ptr++;
		}

		encsalt[i] = tmp;
		BF_swap(&encsalt[i], 1);
	}
	
	BF_encode(encodesalt, encsalt, 16);

	strcpy(saltrealin, salttemplate);

	for (i = 0; i < 22; i++)
	{
		saltrealin[7 + i] = encodesalt[i];
	}
	
	strcpy(thread_param->salt,saltrealin);
	
    
    thread_param->hashcat_ctx = hashcat_ctx;
    thread_param->tid = nchanal;

    hc_thread_create (selftest_threads[0], thread_selftest, thread_param);
	
    hc_thread_wait (1, selftest_threads);
	
	nres = strlen(thread_param->hash);
	if(nres>0)
	{
		strcpy(outhash,thread_param->hash);
		//printf("%s\n",thread_param->hash);
	}
	
	
	status_ctx->devices_status = STATUS_INIT;
	

    hcfree (thread_param);
    hcfree (selftest_threads);

    // check for any selftest failures

    for (int backend_devices_idx = 0; backend_devices_idx < 1; backend_devices_idx++)
    {
      if (backend_ctx->enabled == false) continue;

      hc_device_param_t *device_param = backend_ctx->devices_param + backend_devices_idx;

      if (device_param->skipped == true) continue;

      if (device_param->st_status == ST_STATUS_FAILED)
      {
        event_log_error (hashcat_ctx, "Aborting session due to kernel self-test failure.");

        event_log_warning (hashcat_ctx, "You can use --self-test-disable to override this, but do not report related errors.");
        event_log_warning (hashcat_ctx, NULL);

        return -1;
      }
    }

    status_ctx->devices_status = STATUS_INIT;

    EVENT (EVENT_SELFTEST_FINISHED);
  
	
  return nres;
}

int  bcrypt_hashpass02(const char* pwd,const char* insolt, int nround , char* outhash, int nchanal)
{
	if(binitengine != 1) return -1;
	if(pwd == NULL || insolt == NULL || nround < 1 || outhash == NULL)
		return -1;

	hashconfig_t   *hashconfig	  = hashcat_ctx->hashconfig;
	//hashes_t	   *hashes		  = hashcat_ctx->hashes;
	//mask_ctx_t	   *mask_ctx	  = hashcat_ctx->mask_ctx;
	backend_ctx_t  *backend_ctx   = hashcat_ctx->backend_ctx;
	//outcheck_ctx_t *outcheck_ctx  = hashcat_ctx->outcheck_ctx;
	//restore_ctx_t  *restore_ctx   = hashcat_ctx->restore_ctx;
	status_ctx_t   *status_ctx	  = hashcat_ctx->status_ctx;
	//straight_ctx_t *straight_ctx  = hashcat_ctx->straight_ctx;
	//user_options_t *user_options  = hashcat_ctx->user_options;
	
	int nflag = (user_options->self_test_disable == false) && (hashconfig->st_hash != NULL) && (hashconfig->st_pass != NULL);
	if(!nflag) return -1;
	
	int nres = -1;

    EVENT (EVENT_SELFTEST_STARTING);

	#define MEM_SIZE (128)	
	int i = 0;
	u32 workFactor = 10; //default	
	char salttemplate[MEM_SIZE]; 	
	char saltrealin[MEM_SIZE] = "$2a$10$0000000000000000000000";


	int j = 0;
	for ( j = 0; j < 50; j++)
	{
		if (nround >> j == 0)
			break;
	}
	workFactor = j - 1;

	if (workFactor < 1 || workFactor > 50)
	{
		printf("invalid argument\n");
		return  0;
	}

	//predecide salt
	sprintf(salttemplate, "$2a$%02d$0000000000000000000000", workFactor);	

    thread_param_t *thread_param = (thread_param_t *) hccalloc (1, sizeof (thread_param_t));
    hc_thread_t *selftest_threads = (hc_thread_t *) hccalloc (1, sizeof (hc_thread_t));
	
    status_ctx->devices_status = STATUS_SELFTEST;
	  
	memset(thread_param->pass,0x00, SALT_MAX);
	memset(thread_param->salt,0x00, SALT_MAX);
	memset(thread_param->hash,0x00, SALT_MAX);

	strcpy(thread_param->pass,pwd);

	char encodesalt[128] = {0,};
	strcpy(encodesalt, insolt);
	//int nlen = MIN(strlen(encodesalt), 16);
	
	u32 encsalt[6] = {0,};

	char *ptr = encodesalt;
	for (int i = 0; i < 4; i++) {
		u32 tmp = 0;
		for (int j = 0; j < 4; j++) {
			tmp <<= 8;
			tmp |= (unsigned char)*ptr;
			if (!*ptr) {
				tmp <<= 8 * (3 - j);
				break;
			}
			else ptr++;
		}

		encsalt[i] = tmp;
		BF_swap(&encsalt[i], 1);
	}
	
	BF_encode(encodesalt, encsalt, 16);

	strcpy(saltrealin, salttemplate);

	for (i = 0; i < 22; i++)
	{
		saltrealin[7 + i] = encodesalt[i];
	}
	
	strcpy(thread_param->salt,saltrealin);
	
    
    thread_param->hashcat_ctx = hashcat_ctx;
    thread_param->tid = nchanal;

    hc_thread_create (selftest_threads[0], thread_selftest, thread_param);
	
    hc_thread_wait (1, selftest_threads);
	
	nres = strlen(thread_param->hash);
	if(nres>0)
	{
		strcpy(outhash,thread_param->hash);
		//printf("%s\n",thread_param->hash);
	}
	
	
	status_ctx->devices_status = STATUS_INIT;
	

    hcfree (thread_param);
    hcfree (selftest_threads);

    // check for any selftest failures

    for (int backend_devices_idx = 0; backend_devices_idx < 1; backend_devices_idx++)
    {
      if (backend_ctx->enabled == false) continue;

      hc_device_param_t *device_param = backend_ctx->devices_param + backend_devices_idx;

      if (device_param->skipped == true) continue;

      if (device_param->st_status == ST_STATUS_FAILED)
      {
        event_log_error (hashcat_ctx, "Aborting session due to kernel self-test failure.");

        event_log_warning (hashcat_ctx, "You can use --self-test-disable to override this, but do not report related errors.");
        event_log_warning (hashcat_ctx, NULL);

        return -1;
      }
    }

    status_ctx->devices_status = STATUS_INIT;

    EVENT (EVENT_SELFTEST_FINISHED);
  
	
  return nres;
}

int  bcrypt_hashpass03(const char* pwd,const char* insolt, int nround , char* outhash, int nchanal)
{
	if(binitengine != 1) return -1;
	if(pwd == NULL || insolt == NULL || nround < 1 || outhash == NULL)
		return -1;

	hashconfig_t   *hashconfig	  = hashcat_ctx->hashconfig;
	//hashes_t	   *hashes		  = hashcat_ctx->hashes;
	//mask_ctx_t	   *mask_ctx	  = hashcat_ctx->mask_ctx;
	backend_ctx_t  *backend_ctx   = hashcat_ctx->backend_ctx;
	//outcheck_ctx_t *outcheck_ctx  = hashcat_ctx->outcheck_ctx;
	//restore_ctx_t  *restore_ctx   = hashcat_ctx->restore_ctx;
	status_ctx_t   *status_ctx	  = hashcat_ctx->status_ctx;
	//straight_ctx_t *straight_ctx  = hashcat_ctx->straight_ctx;
	//user_options_t *user_options  = hashcat_ctx->user_options;
	
	int nflag = (user_options->self_test_disable == false) && (hashconfig->st_hash != NULL) && (hashconfig->st_pass != NULL);
	if(!nflag) return -1;
	
	int nres = -1;

    EVENT (EVENT_SELFTEST_STARTING);

	#define MEM_SIZE (128)	
	int i = 0;
	u32 workFactor = 10; //default	
	char salttemplate[MEM_SIZE]; 	
	char saltrealin[MEM_SIZE] = "$2a$10$0000000000000000000000";


	int j = 0;
	for ( j = 0; j < 50; j++)
	{
		if (nround >> j == 0)
			break;
	}
	workFactor = j - 1;

	if (workFactor < 1 || workFactor > 50)
	{
		printf("invalid argument\n");
		return  0;
	}

	//predecide salt
	sprintf(salttemplate, "$2a$%02d$0000000000000000000000", workFactor);	

    thread_param_t *thread_param = (thread_param_t *) hccalloc (1, sizeof (thread_param_t));
    hc_thread_t *selftest_threads = (hc_thread_t *) hccalloc (1, sizeof (hc_thread_t));
	
    status_ctx->devices_status = STATUS_SELFTEST;
	  
	memset(thread_param->pass,0x00, SALT_MAX);
	memset(thread_param->salt,0x00, SALT_MAX);
	memset(thread_param->hash,0x00, SALT_MAX);

	strcpy(thread_param->pass,pwd);

	char encodesalt[128] = {0,};
	strcpy(encodesalt, insolt);
	//int nlen = MIN(strlen(encodesalt), 16);
	
	u32 encsalt[6] = {0,};

	char *ptr = encodesalt;
	for (int i = 0; i < 4; i++) {
		u32 tmp = 0;
		for (int j = 0; j < 4; j++) {
			tmp <<= 8;
			tmp |= (unsigned char)*ptr;
			if (!*ptr) {
				tmp <<= 8 * (3 - j);
				break;
			}
			else ptr++;
		}

		encsalt[i] = tmp;
		BF_swap(&encsalt[i], 1);
	}
	
	BF_encode(encodesalt, encsalt, 16);

	strcpy(saltrealin, salttemplate);

	for (i = 0; i < 22; i++)
	{
		saltrealin[7 + i] = encodesalt[i];
	}
	
	strcpy(thread_param->salt,saltrealin);
	
    
    thread_param->hashcat_ctx = hashcat_ctx;
    thread_param->tid = nchanal;

    hc_thread_create (selftest_threads[0], thread_selftest, thread_param);
	
    hc_thread_wait (1, selftest_threads);
	
	nres = strlen(thread_param->hash);
	if(nres>0)
	{
		strcpy(outhash,thread_param->hash);
		//printf("%s\n",thread_param->hash);
	}
	
	
	status_ctx->devices_status = STATUS_INIT;
	

    hcfree (thread_param);
    hcfree (selftest_threads);

    // check for any selftest failures

    for (int backend_devices_idx = 0; backend_devices_idx < 1; backend_devices_idx++)
    {
      if (backend_ctx->enabled == false) continue;

      hc_device_param_t *device_param = backend_ctx->devices_param + backend_devices_idx;

      if (device_param->skipped == true) continue;

      if (device_param->st_status == ST_STATUS_FAILED)
      {
        event_log_error (hashcat_ctx, "Aborting session due to kernel self-test failure.");

        event_log_warning (hashcat_ctx, "You can use --self-test-disable to override this, but do not report related errors.");
        event_log_warning (hashcat_ctx, NULL);

        return -1;
      }
    }

    status_ctx->devices_status = STATUS_INIT;

    EVENT (EVENT_SELFTEST_FINISHED);
  
	
  return nres;
}

int  bcrypt_hashpass04(const char* pwd,const char* insolt, int nround , char* outhash, int nchanal)
{
	if(binitengine != 1) return -1;
	if(pwd == NULL || insolt == NULL || nround < 1 || outhash == NULL)
		return -1;

	hashconfig_t   *hashconfig	  = hashcat_ctx->hashconfig;
	//hashes_t	   *hashes		  = hashcat_ctx->hashes;
	//mask_ctx_t	   *mask_ctx	  = hashcat_ctx->mask_ctx;
	backend_ctx_t  *backend_ctx   = hashcat_ctx->backend_ctx;
	//outcheck_ctx_t *outcheck_ctx  = hashcat_ctx->outcheck_ctx;
	//restore_ctx_t  *restore_ctx   = hashcat_ctx->restore_ctx;
	status_ctx_t   *status_ctx	  = hashcat_ctx->status_ctx;
	//straight_ctx_t *straight_ctx  = hashcat_ctx->straight_ctx;
	//user_options_t *user_options  = hashcat_ctx->user_options;
	
	int nflag = (user_options->self_test_disable == false) && (hashconfig->st_hash != NULL) && (hashconfig->st_pass != NULL);
	if(!nflag) return -1;
	
	int nres = -1;

    EVENT (EVENT_SELFTEST_STARTING);

	#define MEM_SIZE (128)	
	int i = 0;
	u32 workFactor = 10; //default	
	char salttemplate[MEM_SIZE]; 	
	char saltrealin[MEM_SIZE] = "$2a$10$0000000000000000000000";


	int j = 0;
	for ( j = 0; j < 50; j++)
	{
		if (nround >> j == 0)
			break;
	}
	workFactor = j - 1;

	if (workFactor < 1 || workFactor > 50)
	{
		printf("invalid argument\n");
		return  0;
	}

	//predecide salt
	sprintf(salttemplate, "$2a$%02d$0000000000000000000000", workFactor);	

    thread_param_t *thread_param = (thread_param_t *) hccalloc (1, sizeof (thread_param_t));
    hc_thread_t *selftest_threads = (hc_thread_t *) hccalloc (1, sizeof (hc_thread_t));
	
    status_ctx->devices_status = STATUS_SELFTEST;
	  
	memset(thread_param->pass,0x00, SALT_MAX);
	memset(thread_param->salt,0x00, SALT_MAX);
	memset(thread_param->hash,0x00, SALT_MAX);

	strcpy(thread_param->pass,pwd);

	char encodesalt[128] = {0,};
	strcpy(encodesalt, insolt);
	//int nlen = MIN(strlen(encodesalt), 16);
	
	u32 encsalt[6] = {0,};

	char *ptr = encodesalt;
	for (int i = 0; i < 4; i++) {
		u32 tmp = 0;
		for (int j = 0; j < 4; j++) {
			tmp <<= 8;
			tmp |= (unsigned char)*ptr;
			if (!*ptr) {
				tmp <<= 8 * (3 - j);
				break;
			}
			else ptr++;
		}

		encsalt[i] = tmp;
		BF_swap(&encsalt[i], 1);
	}
	
	BF_encode(encodesalt, encsalt, 16);

	strcpy(saltrealin, salttemplate);

	for (i = 0; i < 22; i++)
	{
		saltrealin[7 + i] = encodesalt[i];
	}
	
	strcpy(thread_param->salt,saltrealin);
	
    
    thread_param->hashcat_ctx = hashcat_ctx;
    thread_param->tid = nchanal;

    hc_thread_create (selftest_threads[0], thread_selftest, thread_param);
	
    hc_thread_wait (1, selftest_threads);
	
	nres = strlen(thread_param->hash);
	if(nres>0)
	{
		strcpy(outhash,thread_param->hash);
		//printf("%s\n",thread_param->hash);
	}
	
	
	status_ctx->devices_status = STATUS_INIT;
	

    hcfree (thread_param);
    hcfree (selftest_threads);

    // check for any selftest failures

    for (int backend_devices_idx = 0; backend_devices_idx < 1; backend_devices_idx++)
    {
      if (backend_ctx->enabled == false) continue;

      hc_device_param_t *device_param = backend_ctx->devices_param + backend_devices_idx;

      if (device_param->skipped == true) continue;

      if (device_param->st_status == ST_STATUS_FAILED)
      {
        event_log_error (hashcat_ctx, "Aborting session due to kernel self-test failure.");

        event_log_warning (hashcat_ctx, "You can use --self-test-disable to override this, but do not report related errors.");
        event_log_warning (hashcat_ctx, NULL);

        return -1;
      }
    }

    status_ctx->devices_status = STATUS_INIT;

    EVENT (EVENT_SELFTEST_FINISHED);
  
	
  return nres;
}

int  bcrypt_hashpass05(const char* pwd,const char* insolt, int nround , char* outhash, int nchanal)
{
	if(binitengine != 1) return -1;
	if(pwd == NULL || insolt == NULL || nround < 1 || outhash == NULL)
		return -1;

	hashconfig_t   *hashconfig	  = hashcat_ctx->hashconfig;
	//hashes_t	   *hashes		  = hashcat_ctx->hashes;
	//mask_ctx_t	   *mask_ctx	  = hashcat_ctx->mask_ctx;
	backend_ctx_t  *backend_ctx   = hashcat_ctx->backend_ctx;
	//outcheck_ctx_t *outcheck_ctx  = hashcat_ctx->outcheck_ctx;
	//restore_ctx_t  *restore_ctx   = hashcat_ctx->restore_ctx;
	status_ctx_t   *status_ctx	  = hashcat_ctx->status_ctx;
	//straight_ctx_t *straight_ctx  = hashcat_ctx->straight_ctx;
	//user_options_t *user_options  = hashcat_ctx->user_options;
	
	int nflag = (user_options->self_test_disable == false) && (hashconfig->st_hash != NULL) && (hashconfig->st_pass != NULL);
	if(!nflag) return -1;
	
	int nres = -1;

    EVENT (EVENT_SELFTEST_STARTING);

	#define MEM_SIZE (128)	
	int i = 0;
	u32 workFactor = 10; //default	
	char salttemplate[MEM_SIZE]; 	
	char saltrealin[MEM_SIZE] = "$2a$10$0000000000000000000000";


	int j = 0;
	for ( j = 0; j < 50; j++)
	{
		if (nround >> j == 0)
			break;
	}
	workFactor = j - 1;

	if (workFactor < 1 || workFactor > 50)
	{
		printf("invalid argument\n");
		return  0;
	}

	//predecide salt
	sprintf(salttemplate, "$2a$%02d$0000000000000000000000", workFactor);	

    thread_param_t *thread_param = (thread_param_t *) hccalloc (1, sizeof (thread_param_t));
    hc_thread_t *selftest_threads = (hc_thread_t *) hccalloc (1, sizeof (hc_thread_t));
	
    status_ctx->devices_status = STATUS_SELFTEST;
	  
	memset(thread_param->pass,0x00, SALT_MAX);
	memset(thread_param->salt,0x00, SALT_MAX);
	memset(thread_param->hash,0x00, SALT_MAX);

	strcpy(thread_param->pass,pwd);

	char encodesalt[128] = {0,};
	strcpy(encodesalt, insolt);
	//int nlen = MIN(strlen(encodesalt), 16);
	
	u32 encsalt[6] = {0,};

	char *ptr = encodesalt;
	for (int i = 0; i < 4; i++) {
		u32 tmp = 0;
		for (int j = 0; j < 4; j++) {
			tmp <<= 8;
			tmp |= (unsigned char)*ptr;
			if (!*ptr) {
				tmp <<= 8 * (3 - j);
				break;
			}
			else ptr++;
		}

		encsalt[i] = tmp;
		BF_swap(&encsalt[i], 1);
	}
	
	BF_encode(encodesalt, encsalt, 16);

	strcpy(saltrealin, salttemplate);

	for (i = 0; i < 22; i++)
	{
		saltrealin[7 + i] = encodesalt[i];
	}
	
	strcpy(thread_param->salt,saltrealin);
	
    
    thread_param->hashcat_ctx = hashcat_ctx;
    thread_param->tid = nchanal;

    hc_thread_create (selftest_threads[0], thread_selftest, thread_param);
	
    hc_thread_wait (1, selftest_threads);
	
	nres = strlen(thread_param->hash);
	if(nres>0)
	{
		strcpy(outhash,thread_param->hash);
		//printf("%s\n",thread_param->hash);
	}
	
	
	status_ctx->devices_status = STATUS_INIT;
	

    hcfree (thread_param);
    hcfree (selftest_threads);

    // check for any selftest failures

    for (int backend_devices_idx = 0; backend_devices_idx < 1; backend_devices_idx++)
    {
      if (backend_ctx->enabled == false) continue;

      hc_device_param_t *device_param = backend_ctx->devices_param + backend_devices_idx;

      if (device_param->skipped == true) continue;

      if (device_param->st_status == ST_STATUS_FAILED)
      {
        event_log_error (hashcat_ctx, "Aborting session due to kernel self-test failure.");

        event_log_warning (hashcat_ctx, "You can use --self-test-disable to override this, but do not report related errors.");
        event_log_warning (hashcat_ctx, NULL);

        return -1;
      }
    }

    status_ctx->devices_status = STATUS_INIT;

    EVENT (EVENT_SELFTEST_FINISHED);
  
	
  return nres;
}

int  bcrypt_hashpass06(const char* pwd,const char* insolt, int nround , char* outhash, int nchanal)
{
	if(binitengine != 1) return -1;
	if(pwd == NULL || insolt == NULL || nround < 1 || outhash == NULL)
		return -1;

	hashconfig_t   *hashconfig	  = hashcat_ctx->hashconfig;
	//hashes_t	   *hashes		  = hashcat_ctx->hashes;
	//mask_ctx_t	   *mask_ctx	  = hashcat_ctx->mask_ctx;
	backend_ctx_t  *backend_ctx   = hashcat_ctx->backend_ctx;
	//outcheck_ctx_t *outcheck_ctx  = hashcat_ctx->outcheck_ctx;
	//restore_ctx_t  *restore_ctx   = hashcat_ctx->restore_ctx;
	status_ctx_t   *status_ctx	  = hashcat_ctx->status_ctx;
	//straight_ctx_t *straight_ctx  = hashcat_ctx->straight_ctx;
	//user_options_t *user_options  = hashcat_ctx->user_options;
	
	int nflag = (user_options->self_test_disable == false) && (hashconfig->st_hash != NULL) && (hashconfig->st_pass != NULL);
	if(!nflag) return -1;
	
	int nres = -1;

    EVENT (EVENT_SELFTEST_STARTING);

	#define MEM_SIZE (128)	
	int i = 0;
	u32 workFactor = 10; //default	
	char salttemplate[MEM_SIZE]; 	
	char saltrealin[MEM_SIZE] = "$2a$10$0000000000000000000000";


	int j = 0;
	for ( j = 0; j < 50; j++)
	{
		if (nround >> j == 0)
			break;
	}
	workFactor = j - 1;

	if (workFactor < 1 || workFactor > 50)
	{
		printf("invalid argument\n");
		return  0;
	}

	//predecide salt
	sprintf(salttemplate, "$2a$%02d$0000000000000000000000", workFactor);	

    thread_param_t *thread_param = (thread_param_t *) hccalloc (1, sizeof (thread_param_t));
    hc_thread_t *selftest_threads = (hc_thread_t *) hccalloc (1, sizeof (hc_thread_t));
	
    status_ctx->devices_status = STATUS_SELFTEST;
	  
	memset(thread_param->pass,0x00, SALT_MAX);
	memset(thread_param->salt,0x00, SALT_MAX);
	memset(thread_param->hash,0x00, SALT_MAX);

	strcpy(thread_param->pass,pwd);

	char encodesalt[128] = {0,};
	strcpy(encodesalt, insolt);
	//int nlen = MIN(strlen(encodesalt), 16);
	
	u32 encsalt[6] = {0,};

	char *ptr = encodesalt;
	for (int i = 0; i < 4; i++) {
		u32 tmp = 0;
		for (int j = 0; j < 4; j++) {
			tmp <<= 8;
			tmp |= (unsigned char)*ptr;
			if (!*ptr) {
				tmp <<= 8 * (3 - j);
				break;
			}
			else ptr++;
		}

		encsalt[i] = tmp;
		BF_swap(&encsalt[i], 1);
	}
	
	BF_encode(encodesalt, encsalt, 16);

	strcpy(saltrealin, salttemplate);

	for (i = 0; i < 22; i++)
	{
		saltrealin[7 + i] = encodesalt[i];
	}
	
	strcpy(thread_param->salt,saltrealin);
	
    
    thread_param->hashcat_ctx = hashcat_ctx;
    thread_param->tid = nchanal;

    hc_thread_create (selftest_threads[0], thread_selftest, thread_param);
	
    hc_thread_wait (1, selftest_threads);
	
	nres = strlen(thread_param->hash);
	if(nres>0)
	{
		strcpy(outhash,thread_param->hash);
		//printf("%s\n",thread_param->hash);
	}
	
	
	status_ctx->devices_status = STATUS_INIT;
	

    hcfree (thread_param);
    hcfree (selftest_threads);

    // check for any selftest failures

    for (int backend_devices_idx = 0; backend_devices_idx < 1; backend_devices_idx++)
    {
      if (backend_ctx->enabled == false) continue;

      hc_device_param_t *device_param = backend_ctx->devices_param + backend_devices_idx;

      if (device_param->skipped == true) continue;

      if (device_param->st_status == ST_STATUS_FAILED)
      {
        event_log_error (hashcat_ctx, "Aborting session due to kernel self-test failure.");

        event_log_warning (hashcat_ctx, "You can use --self-test-disable to override this, but do not report related errors.");
        event_log_warning (hashcat_ctx, NULL);

        return -1;
      }
    }

    status_ctx->devices_status = STATUS_INIT;

    EVENT (EVENT_SELFTEST_FINISHED);
  
	
  return nres;
}

int  bcrypt_hashpass07(const char* pwd,const char* insolt, int nround , char* outhash, int nchanal)
{
	if(binitengine != 1) return -1;
	if(pwd == NULL || insolt == NULL || nround < 1 || outhash == NULL)
		return -1;

	hashconfig_t   *hashconfig	  = hashcat_ctx->hashconfig;
	//hashes_t	   *hashes		  = hashcat_ctx->hashes;
	//mask_ctx_t	   *mask_ctx	  = hashcat_ctx->mask_ctx;
	backend_ctx_t  *backend_ctx   = hashcat_ctx->backend_ctx;
	//outcheck_ctx_t *outcheck_ctx  = hashcat_ctx->outcheck_ctx;
	//restore_ctx_t  *restore_ctx   = hashcat_ctx->restore_ctx;
	status_ctx_t   *status_ctx	  = hashcat_ctx->status_ctx;
	//straight_ctx_t *straight_ctx  = hashcat_ctx->straight_ctx;
	//user_options_t *user_options  = hashcat_ctx->user_options;
	
	int nflag = (user_options->self_test_disable == false) && (hashconfig->st_hash != NULL) && (hashconfig->st_pass != NULL);
	if(!nflag) return -1;
	
	int nres = -1;

    EVENT (EVENT_SELFTEST_STARTING);

	#define MEM_SIZE (128)	
	int i = 0;
	u32 workFactor = 10; //default	
	char salttemplate[MEM_SIZE]; 	
	char saltrealin[MEM_SIZE] = "$2a$10$0000000000000000000000";


	int j = 0;
	for ( j = 0; j < 50; j++)
	{
		if (nround >> j == 0)
			break;
	}
	workFactor = j - 1;

	if (workFactor < 1 || workFactor > 50)
	{
		printf("invalid argument\n");
		return  0;
	}

	//predecide salt
	sprintf(salttemplate, "$2a$%02d$0000000000000000000000", workFactor);	

    thread_param_t *thread_param = (thread_param_t *) hccalloc (1, sizeof (thread_param_t));
    hc_thread_t *selftest_threads = (hc_thread_t *) hccalloc (1, sizeof (hc_thread_t));
	
    status_ctx->devices_status = STATUS_SELFTEST;
	  
	memset(thread_param->pass,0x00, SALT_MAX);
	memset(thread_param->salt,0x00, SALT_MAX);
	memset(thread_param->hash,0x00, SALT_MAX);

	strcpy(thread_param->pass,pwd);

	char encodesalt[128] = {0,};
	strcpy(encodesalt, insolt);
	//int nlen = MIN(strlen(encodesalt), 16);
	
	u32 encsalt[6] = {0,};

	char *ptr = encodesalt;
	for (int i = 0; i < 4; i++) {
		u32 tmp = 0;
		for (int j = 0; j < 4; j++) {
			tmp <<= 8;
			tmp |= (unsigned char)*ptr;
			if (!*ptr) {
				tmp <<= 8 * (3 - j);
				break;
			}
			else ptr++;
		}

		encsalt[i] = tmp;
		BF_swap(&encsalt[i], 1);
	}
	
	BF_encode(encodesalt, encsalt, 16);

	strcpy(saltrealin, salttemplate);

	for (i = 0; i < 22; i++)
	{
		saltrealin[7 + i] = encodesalt[i];
	}
	
	strcpy(thread_param->salt,saltrealin);
	
    
    thread_param->hashcat_ctx = hashcat_ctx;
    thread_param->tid = nchanal;

    hc_thread_create (selftest_threads[0], thread_selftest, thread_param);
	
    hc_thread_wait (1, selftest_threads);
	
	nres = strlen(thread_param->hash);
	if(nres>0)
	{
		strcpy(outhash,thread_param->hash);
		//printf("%s\n",thread_param->hash);
	}
	
	
	status_ctx->devices_status = STATUS_INIT;
	

    hcfree (thread_param);
    hcfree (selftest_threads);

    // check for any selftest failures

    for (int backend_devices_idx = 0; backend_devices_idx < 1; backend_devices_idx++)
    {
      if (backend_ctx->enabled == false) continue;

      hc_device_param_t *device_param = backend_ctx->devices_param + backend_devices_idx;

      if (device_param->skipped == true) continue;

      if (device_param->st_status == ST_STATUS_FAILED)
      {
        event_log_error (hashcat_ctx, "Aborting session due to kernel self-test failure.");

        event_log_warning (hashcat_ctx, "You can use --self-test-disable to override this, but do not report related errors.");
        event_log_warning (hashcat_ctx, NULL);

        return -1;
      }
    }

    status_ctx->devices_status = STATUS_INIT;

    EVENT (EVENT_SELFTEST_FINISHED);
  
	
  return nres;
}

int  bcrypt_hashpass08(const char* pwd,const char* insolt, int nround , char* outhash, int nchanal)
{
	if(binitengine != 1) return -1;
	if(pwd == NULL || insolt == NULL || nround < 1 || outhash == NULL)
		return -1;

	hashconfig_t   *hashconfig	  = hashcat_ctx->hashconfig;
	//hashes_t	   *hashes		  = hashcat_ctx->hashes;
	//mask_ctx_t	   *mask_ctx	  = hashcat_ctx->mask_ctx;
	backend_ctx_t  *backend_ctx   = hashcat_ctx->backend_ctx;
	//outcheck_ctx_t *outcheck_ctx  = hashcat_ctx->outcheck_ctx;
	//restore_ctx_t  *restore_ctx   = hashcat_ctx->restore_ctx;
	status_ctx_t   *status_ctx	  = hashcat_ctx->status_ctx;
	//straight_ctx_t *straight_ctx  = hashcat_ctx->straight_ctx;
	//user_options_t *user_options  = hashcat_ctx->user_options;
	
	int nflag = (user_options->self_test_disable == false) && (hashconfig->st_hash != NULL) && (hashconfig->st_pass != NULL);
	if(!nflag) return -1;
	
	int nres = -1;

    EVENT (EVENT_SELFTEST_STARTING);

	#define MEM_SIZE (128)	
	int i = 0;
	u32 workFactor = 10; //default	
	char salttemplate[MEM_SIZE]; 	
	char saltrealin[MEM_SIZE] = "$2a$10$0000000000000000000000";


	int j = 0;
	for ( j = 0; j < 50; j++)
	{
		if (nround >> j == 0)
			break;
	}
	workFactor = j - 1;

	if (workFactor < 1 || workFactor > 50)
	{
		printf("invalid argument\n");
		return  0;
	}

	//predecide salt
	sprintf(salttemplate, "$2a$%02d$0000000000000000000000", workFactor);	

    thread_param_t *thread_param = (thread_param_t *) hccalloc (1, sizeof (thread_param_t));
    hc_thread_t *selftest_threads = (hc_thread_t *) hccalloc (1, sizeof (hc_thread_t));
	
    status_ctx->devices_status = STATUS_SELFTEST;
	  
	memset(thread_param->pass,0x00, SALT_MAX);
	memset(thread_param->salt,0x00, SALT_MAX);
	memset(thread_param->hash,0x00, SALT_MAX);

	strcpy(thread_param->pass,pwd);

	char encodesalt[128] = {0,};
	strcpy(encodesalt, insolt);
	//int nlen = MIN(strlen(encodesalt), 16);
	
	u32 encsalt[6] = {0,};

	char *ptr = encodesalt;
	for (int i = 0; i < 4; i++) {
		u32 tmp = 0;
		for (int j = 0; j < 4; j++) {
			tmp <<= 8;
			tmp |= (unsigned char)*ptr;
			if (!*ptr) {
				tmp <<= 8 * (3 - j);
				break;
			}
			else ptr++;
		}

		encsalt[i] = tmp;
		BF_swap(&encsalt[i], 1);
	}
	
	BF_encode(encodesalt, encsalt, 16);

	strcpy(saltrealin, salttemplate);

	for (i = 0; i < 22; i++)
	{
		saltrealin[7 + i] = encodesalt[i];
	}
	
	strcpy(thread_param->salt,saltrealin);
	
    
    thread_param->hashcat_ctx = hashcat_ctx;
    thread_param->tid = nchanal;

    hc_thread_create (selftest_threads[0], thread_selftest, thread_param);
	
    hc_thread_wait (1, selftest_threads);
	
	nres = strlen(thread_param->hash);
	if(nres>0)
	{
		strcpy(outhash,thread_param->hash);
		//printf("%s\n",thread_param->hash);
	}
	
	
	status_ctx->devices_status = STATUS_INIT;
	

    hcfree (thread_param);
    hcfree (selftest_threads);

    // check for any selftest failures

    for (int backend_devices_idx = 0; backend_devices_idx < 1; backend_devices_idx++)
    {
      if (backend_ctx->enabled == false) continue;

      hc_device_param_t *device_param = backend_ctx->devices_param + backend_devices_idx;

      if (device_param->skipped == true) continue;

      if (device_param->st_status == ST_STATUS_FAILED)
      {
        event_log_error (hashcat_ctx, "Aborting session due to kernel self-test failure.");

        event_log_warning (hashcat_ctx, "You can use --self-test-disable to override this, but do not report related errors.");
        event_log_warning (hashcat_ctx, NULL);

        return -1;
      }
    }

    status_ctx->devices_status = STATUS_INIT;

    EVENT (EVENT_SELFTEST_FINISHED);
  
	
  return nres;
}

int  bcrypt_hashpass09(const char* pwd,const char* insolt, int nround , char* outhash, int nchanal)
{
	if(binitengine != 1) return -1;
	if(pwd == NULL || insolt == NULL || nround < 1 || outhash == NULL)
		return -1;

	hashconfig_t   *hashconfig	  = hashcat_ctx->hashconfig;
	//hashes_t	   *hashes		  = hashcat_ctx->hashes;
	//mask_ctx_t	   *mask_ctx	  = hashcat_ctx->mask_ctx;
	backend_ctx_t  *backend_ctx   = hashcat_ctx->backend_ctx;
	//outcheck_ctx_t *outcheck_ctx  = hashcat_ctx->outcheck_ctx;
	//restore_ctx_t  *restore_ctx   = hashcat_ctx->restore_ctx;
	status_ctx_t   *status_ctx	  = hashcat_ctx->status_ctx;
	//straight_ctx_t *straight_ctx  = hashcat_ctx->straight_ctx;
	//user_options_t *user_options  = hashcat_ctx->user_options;
	
	int nflag = (user_options->self_test_disable == false) && (hashconfig->st_hash != NULL) && (hashconfig->st_pass != NULL);
	if(!nflag) return -1;
	
	int nres = -1;

    EVENT (EVENT_SELFTEST_STARTING);

	#define MEM_SIZE (128)	
	int i = 0;
	u32 workFactor = 10; //default	
	char salttemplate[MEM_SIZE]; 	
	char saltrealin[MEM_SIZE] = "$2a$10$0000000000000000000000";


	int j = 0;
	for ( j = 0; j < 50; j++)
	{
		if (nround >> j == 0)
			break;
	}
	workFactor = j - 1;

	if (workFactor < 1 || workFactor > 50)
	{
		printf("invalid argument\n");
		return  0;
	}

	//predecide salt
	sprintf(salttemplate, "$2a$%02d$0000000000000000000000", workFactor);	

    thread_param_t *thread_param = (thread_param_t *) hccalloc (1, sizeof (thread_param_t));
    hc_thread_t *selftest_threads = (hc_thread_t *) hccalloc (1, sizeof (hc_thread_t));
	
    status_ctx->devices_status = STATUS_SELFTEST;
	  
	memset(thread_param->pass,0x00, SALT_MAX);
	memset(thread_param->salt,0x00, SALT_MAX);
	memset(thread_param->hash,0x00, SALT_MAX);

	strcpy(thread_param->pass,pwd);

	char encodesalt[128] = {0,};
	strcpy(encodesalt, insolt);
	//int nlen = MIN(strlen(encodesalt), 16);
	
	u32 encsalt[6] = {0,};

	char *ptr = encodesalt;
	for (int i = 0; i < 4; i++) {
		u32 tmp = 0;
		for (int j = 0; j < 4; j++) {
			tmp <<= 8;
			tmp |= (unsigned char)*ptr;
			if (!*ptr) {
				tmp <<= 8 * (3 - j);
				break;
			}
			else ptr++;
		}

		encsalt[i] = tmp;
		BF_swap(&encsalt[i], 1);
	}
	
	BF_encode(encodesalt, encsalt, 16);

	strcpy(saltrealin, salttemplate);

	for (i = 0; i < 22; i++)
	{
		saltrealin[7 + i] = encodesalt[i];
	}
	
	strcpy(thread_param->salt,saltrealin);
	
    
    thread_param->hashcat_ctx = hashcat_ctx;
    thread_param->tid = nchanal;

    hc_thread_create (selftest_threads[0], thread_selftest, thread_param);
	
    hc_thread_wait (1, selftest_threads);
	
	nres = strlen(thread_param->hash);
	if(nres>0)
	{
		strcpy(outhash,thread_param->hash);
		//printf("%s\n",thread_param->hash);
	}
	
	
	status_ctx->devices_status = STATUS_INIT;
	

    hcfree (thread_param);
    hcfree (selftest_threads);

    // check for any selftest failures

    for (int backend_devices_idx = 0; backend_devices_idx < 1; backend_devices_idx++)
    {
      if (backend_ctx->enabled == false) continue;

      hc_device_param_t *device_param = backend_ctx->devices_param + backend_devices_idx;

      if (device_param->skipped == true) continue;

      if (device_param->st_status == ST_STATUS_FAILED)
      {
        event_log_error (hashcat_ctx, "Aborting session due to kernel self-test failure.");

        event_log_warning (hashcat_ctx, "You can use --self-test-disable to override this, but do not report related errors.");
        event_log_warning (hashcat_ctx, NULL);

        return -1;
      }
    }

    status_ctx->devices_status = STATUS_INIT;

    EVENT (EVENT_SELFTEST_FINISHED);
  
	
  return nres;
}

int  bcrypt_hashpass10(const char* pwd,const char* insolt, int nround , char* outhash, int nchanal)
{
	if(binitengine != 1) return -1;
	if(pwd == NULL || insolt == NULL || nround < 1 || outhash == NULL)
		return -1;

	hashconfig_t   *hashconfig	  = hashcat_ctx->hashconfig;
	//hashes_t	   *hashes		  = hashcat_ctx->hashes;
	//mask_ctx_t	   *mask_ctx	  = hashcat_ctx->mask_ctx;
	backend_ctx_t  *backend_ctx   = hashcat_ctx->backend_ctx;
	//outcheck_ctx_t *outcheck_ctx  = hashcat_ctx->outcheck_ctx;
	//restore_ctx_t  *restore_ctx   = hashcat_ctx->restore_ctx;
	status_ctx_t   *status_ctx	  = hashcat_ctx->status_ctx;
	//straight_ctx_t *straight_ctx  = hashcat_ctx->straight_ctx;
	//user_options_t *user_options  = hashcat_ctx->user_options;
	
	int nflag = (user_options->self_test_disable == false) && (hashconfig->st_hash != NULL) && (hashconfig->st_pass != NULL);
	if(!nflag) return -1;
	
	int nres = -1;

    EVENT (EVENT_SELFTEST_STARTING);

	#define MEM_SIZE (128)	
	int i = 0;
	u32 workFactor = 10; //default	
	char salttemplate[MEM_SIZE]; 	
	char saltrealin[MEM_SIZE] = "$2a$10$0000000000000000000000";


	int j = 0;
	for ( j = 0; j < 50; j++)
	{
		if (nround >> j == 0)
			break;
	}
	workFactor = j - 1;

	if (workFactor < 1 || workFactor > 50)
	{
		printf("invalid argument\n");
		return  0;
	}

	//predecide salt
	sprintf(salttemplate, "$2a$%02d$0000000000000000000000", workFactor);	

    thread_param_t *thread_param = (thread_param_t *) hccalloc (1, sizeof (thread_param_t));
    hc_thread_t *selftest_threads = (hc_thread_t *) hccalloc (1, sizeof (hc_thread_t));
	
    status_ctx->devices_status = STATUS_SELFTEST;
	  
	memset(thread_param->pass,0x00, SALT_MAX);
	memset(thread_param->salt,0x00, SALT_MAX);
	memset(thread_param->hash,0x00, SALT_MAX);

	strcpy(thread_param->pass,pwd);

	char encodesalt[128] = {0,};
	strcpy(encodesalt, insolt);
	//int nlen = MIN(strlen(encodesalt), 16);
	
	u32 encsalt[6] = {0,};

	char *ptr = encodesalt;
	for (int i = 0; i < 4; i++) {
		u32 tmp = 0;
		for (int j = 0; j < 4; j++) {
			tmp <<= 8;
			tmp |= (unsigned char)*ptr;
			if (!*ptr) {
				tmp <<= 8 * (3 - j);
				break;
			}
			else ptr++;
		}

		encsalt[i] = tmp;
		BF_swap(&encsalt[i], 1);
	}
	
	BF_encode(encodesalt, encsalt, 16);

	strcpy(saltrealin, salttemplate);

	for (i = 0; i < 22; i++)
	{
		saltrealin[7 + i] = encodesalt[i];
	}
	
	strcpy(thread_param->salt,saltrealin);
	
    
    thread_param->hashcat_ctx = hashcat_ctx;
    thread_param->tid = nchanal;

    hc_thread_create (selftest_threads[0], thread_selftest, thread_param);
	
    hc_thread_wait (1, selftest_threads);
	
	nres = strlen(thread_param->hash);
	if(nres>0)
	{
		strcpy(outhash,thread_param->hash);
		//printf("%s\n",thread_param->hash);
	}
	
	
	status_ctx->devices_status = STATUS_INIT;
	

    hcfree (thread_param);
    hcfree (selftest_threads);

    // check for any selftest failures

    for (int backend_devices_idx = 0; backend_devices_idx < 1; backend_devices_idx++)
    {
      if (backend_ctx->enabled == false) continue;

      hc_device_param_t *device_param = backend_ctx->devices_param + backend_devices_idx;

      if (device_param->skipped == true) continue;

      if (device_param->st_status == ST_STATUS_FAILED)
      {
        event_log_error (hashcat_ctx, "Aborting session due to kernel self-test failure.");

        event_log_warning (hashcat_ctx, "You can use --self-test-disable to override this, but do not report related errors.");
        event_log_warning (hashcat_ctx, NULL);

        return -1;
      }
    }

    status_ctx->devices_status = STATUS_INIT;

    EVENT (EVENT_SELFTEST_FINISHED);
  
	
  return nres;
}

int  bcrypt_hashpass11(const char* pwd,const char* insolt, int nround , char* outhash, int nchanal)
{
	if(binitengine != 1) return -1;
	if(pwd == NULL || insolt == NULL || nround < 1 || outhash == NULL)
		return -1;

	hashconfig_t   *hashconfig	  = hashcat_ctx->hashconfig;
	//hashes_t	   *hashes		  = hashcat_ctx->hashes;
	//mask_ctx_t	   *mask_ctx	  = hashcat_ctx->mask_ctx;
	backend_ctx_t  *backend_ctx   = hashcat_ctx->backend_ctx;
	//outcheck_ctx_t *outcheck_ctx  = hashcat_ctx->outcheck_ctx;
	//restore_ctx_t  *restore_ctx   = hashcat_ctx->restore_ctx;
	status_ctx_t   *status_ctx	  = hashcat_ctx->status_ctx;
	//straight_ctx_t *straight_ctx  = hashcat_ctx->straight_ctx;
	//user_options_t *user_options  = hashcat_ctx->user_options;
	
	int nflag = (user_options->self_test_disable == false) && (hashconfig->st_hash != NULL) && (hashconfig->st_pass != NULL);
	if(!nflag) return -1;
	
	int nres = -1;

    EVENT (EVENT_SELFTEST_STARTING);

	#define MEM_SIZE (128)	
	int i = 0;
	u32 workFactor = 10; //default	
	char salttemplate[MEM_SIZE]; 	
	char saltrealin[MEM_SIZE] = "$2a$10$0000000000000000000000";


	int j = 0;
	for ( j = 0; j < 50; j++)
	{
		if (nround >> j == 0)
			break;
	}
	workFactor = j - 1;

	if (workFactor < 1 || workFactor > 50)
	{
		printf("invalid argument\n");
		return  0;
	}

	//predecide salt
	sprintf(salttemplate, "$2a$%02d$0000000000000000000000", workFactor);	

    thread_param_t *thread_param = (thread_param_t *) hccalloc (1, sizeof (thread_param_t));
    hc_thread_t *selftest_threads = (hc_thread_t *) hccalloc (1, sizeof (hc_thread_t));
	
    status_ctx->devices_status = STATUS_SELFTEST;
	  
	memset(thread_param->pass,0x00, SALT_MAX);
	memset(thread_param->salt,0x00, SALT_MAX);
	memset(thread_param->hash,0x00, SALT_MAX);

	strcpy(thread_param->pass,pwd);

	char encodesalt[128] = {0,};
	strcpy(encodesalt, insolt);
	//int nlen = MIN(strlen(encodesalt), 16);
	
	u32 encsalt[6] = {0,};

	char *ptr = encodesalt;
	for (int i = 0; i < 4; i++) {
		u32 tmp = 0;
		for (int j = 0; j < 4; j++) {
			tmp <<= 8;
			tmp |= (unsigned char)*ptr;
			if (!*ptr) {
				tmp <<= 8 * (3 - j);
				break;
			}
			else ptr++;
		}

		encsalt[i] = tmp;
		BF_swap(&encsalt[i], 1);
	}
	
	BF_encode(encodesalt, encsalt, 16);

	strcpy(saltrealin, salttemplate);

	for (i = 0; i < 22; i++)
	{
		saltrealin[7 + i] = encodesalt[i];
	}
	
	strcpy(thread_param->salt,saltrealin);
	
    
    thread_param->hashcat_ctx = hashcat_ctx;
    thread_param->tid = nchanal;

    hc_thread_create (selftest_threads[0], thread_selftest, thread_param);
	
    hc_thread_wait (1, selftest_threads);
	
	nres = strlen(thread_param->hash);
	if(nres>0)
	{
		strcpy(outhash,thread_param->hash);
		//printf("%s\n",thread_param->hash);
	}
	
	
	status_ctx->devices_status = STATUS_INIT;
	

    hcfree (thread_param);
    hcfree (selftest_threads);

    // check for any selftest failures

    for (int backend_devices_idx = 0; backend_devices_idx < 1; backend_devices_idx++)
    {
      if (backend_ctx->enabled == false) continue;

      hc_device_param_t *device_param = backend_ctx->devices_param + backend_devices_idx;

      if (device_param->skipped == true) continue;

      if (device_param->st_status == ST_STATUS_FAILED)
      {
        event_log_error (hashcat_ctx, "Aborting session due to kernel self-test failure.");

        event_log_warning (hashcat_ctx, "You can use --self-test-disable to override this, but do not report related errors.");
        event_log_warning (hashcat_ctx, NULL);

        return -1;
      }
    }

    status_ctx->devices_status = STATUS_INIT;

    EVENT (EVENT_SELFTEST_FINISHED);
  
	
  return nres;
}

int  bcrypt_hashpass12(const char* pwd,const char* insolt, int nround , char* outhash, int nchanal)
{
	if(binitengine != 1) return -1;
	if(pwd == NULL || insolt == NULL || nround < 1 || outhash == NULL)
		return -1;

	hashconfig_t   *hashconfig	  = hashcat_ctx->hashconfig;
	//hashes_t	   *hashes		  = hashcat_ctx->hashes;
	//mask_ctx_t	   *mask_ctx	  = hashcat_ctx->mask_ctx;
	backend_ctx_t  *backend_ctx   = hashcat_ctx->backend_ctx;
	//outcheck_ctx_t *outcheck_ctx  = hashcat_ctx->outcheck_ctx;
	//restore_ctx_t  *restore_ctx   = hashcat_ctx->restore_ctx;
	status_ctx_t   *status_ctx	  = hashcat_ctx->status_ctx;
	//straight_ctx_t *straight_ctx  = hashcat_ctx->straight_ctx;
	//user_options_t *user_options  = hashcat_ctx->user_options;
	
	int nflag = (user_options->self_test_disable == false) && (hashconfig->st_hash != NULL) && (hashconfig->st_pass != NULL);
	if(!nflag) return -1;
	
	int nres = -1;

    EVENT (EVENT_SELFTEST_STARTING);

	#define MEM_SIZE (128)	
	int i = 0;
	u32 workFactor = 10; //default	
	char salttemplate[MEM_SIZE]; 	
	char saltrealin[MEM_SIZE] = "$2a$10$0000000000000000000000";


	int j = 0;
	for ( j = 0; j < 50; j++)
	{
		if (nround >> j == 0)
			break;
	}
	workFactor = j - 1;

	if (workFactor < 1 || workFactor > 50)
	{
		printf("invalid argument\n");
		return  0;
	}

	//predecide salt
	sprintf(salttemplate, "$2a$%02d$0000000000000000000000", workFactor);	

    thread_param_t *thread_param = (thread_param_t *) hccalloc (1, sizeof (thread_param_t));
    hc_thread_t *selftest_threads = (hc_thread_t *) hccalloc (1, sizeof (hc_thread_t));
	
    status_ctx->devices_status = STATUS_SELFTEST;
	  
	memset(thread_param->pass,0x00, SALT_MAX);
	memset(thread_param->salt,0x00, SALT_MAX);
	memset(thread_param->hash,0x00, SALT_MAX);

	strcpy(thread_param->pass,pwd);

	char encodesalt[128] = {0,};
	strcpy(encodesalt, insolt);
	//int nlen = MIN(strlen(encodesalt), 16);
	
	u32 encsalt[6] = {0,};

	char *ptr = encodesalt;
	for (int i = 0; i < 4; i++) {
		u32 tmp = 0;
		for (int j = 0; j < 4; j++) {
			tmp <<= 8;
			tmp |= (unsigned char)*ptr;
			if (!*ptr) {
				tmp <<= 8 * (3 - j);
				break;
			}
			else ptr++;
		}

		encsalt[i] = tmp;
		BF_swap(&encsalt[i], 1);
	}
	
	BF_encode(encodesalt, encsalt, 16);

	strcpy(saltrealin, salttemplate);

	for (i = 0; i < 22; i++)
	{
		saltrealin[7 + i] = encodesalt[i];
	}
	
	strcpy(thread_param->salt,saltrealin);
	
    
    thread_param->hashcat_ctx = hashcat_ctx;
    thread_param->tid = nchanal;

    hc_thread_create (selftest_threads[0], thread_selftest, thread_param);
	
    hc_thread_wait (1, selftest_threads);
	
	nres = strlen(thread_param->hash);
	if(nres>0)
	{
		strcpy(outhash,thread_param->hash);
		//printf("%s\n",thread_param->hash);
	}
	
	
	status_ctx->devices_status = STATUS_INIT;
	

    hcfree (thread_param);
    hcfree (selftest_threads);

    // check for any selftest failures

    for (int backend_devices_idx = 0; backend_devices_idx < 1; backend_devices_idx++)
    {
      if (backend_ctx->enabled == false) continue;

      hc_device_param_t *device_param = backend_ctx->devices_param + backend_devices_idx;

      if (device_param->skipped == true) continue;

      if (device_param->st_status == ST_STATUS_FAILED)
      {
        event_log_error (hashcat_ctx, "Aborting session due to kernel self-test failure.");

        event_log_warning (hashcat_ctx, "You can use --self-test-disable to override this, but do not report related errors.");
        event_log_warning (hashcat_ctx, NULL);

        return -1;
      }
    }

    status_ctx->devices_status = STATUS_INIT;

    EVENT (EVENT_SELFTEST_FINISHED);
  
	
  return nres;
}

int  bcrypt_hashpass13(const char* pwd,const char* insolt, int nround , char* outhash, int nchanal)
{
	if(binitengine != 1) return -1;
	if(pwd == NULL || insolt == NULL || nround < 1 || outhash == NULL)
		return -1;

	hashconfig_t   *hashconfig	  = hashcat_ctx->hashconfig;
	//hashes_t	   *hashes		  = hashcat_ctx->hashes;
	//mask_ctx_t	   *mask_ctx	  = hashcat_ctx->mask_ctx;
	backend_ctx_t  *backend_ctx   = hashcat_ctx->backend_ctx;
	//outcheck_ctx_t *outcheck_ctx  = hashcat_ctx->outcheck_ctx;
	//restore_ctx_t  *restore_ctx   = hashcat_ctx->restore_ctx;
	status_ctx_t   *status_ctx	  = hashcat_ctx->status_ctx;
	//straight_ctx_t *straight_ctx  = hashcat_ctx->straight_ctx;
	//user_options_t *user_options  = hashcat_ctx->user_options;
	
	int nflag = (user_options->self_test_disable == false) && (hashconfig->st_hash != NULL) && (hashconfig->st_pass != NULL);
	if(!nflag) return -1;
	
	int nres = -1;

    EVENT (EVENT_SELFTEST_STARTING);

	#define MEM_SIZE (128)	
	int i = 0;
	u32 workFactor = 10; //default	
	char salttemplate[MEM_SIZE]; 	
	char saltrealin[MEM_SIZE] = "$2a$10$0000000000000000000000";


	int j = 0;
	for ( j = 0; j < 50; j++)
	{
		if (nround >> j == 0)
			break;
	}
	workFactor = j - 1;

	if (workFactor < 1 || workFactor > 50)
	{
		printf("invalid argument\n");
		return  0;
	}

	//predecide salt
	sprintf(salttemplate, "$2a$%02d$0000000000000000000000", workFactor);	

    thread_param_t *thread_param = (thread_param_t *) hccalloc (1, sizeof (thread_param_t));
    hc_thread_t *selftest_threads = (hc_thread_t *) hccalloc (1, sizeof (hc_thread_t));
	
    status_ctx->devices_status = STATUS_SELFTEST;
	  
	memset(thread_param->pass,0x00, SALT_MAX);
	memset(thread_param->salt,0x00, SALT_MAX);
	memset(thread_param->hash,0x00, SALT_MAX);

	strcpy(thread_param->pass,pwd);

	char encodesalt[128] = {0,};
	strcpy(encodesalt, insolt);
	//int nlen = MIN(strlen(encodesalt), 16);
	
	u32 encsalt[6] = {0,};

	char *ptr = encodesalt;
	for (int i = 0; i < 4; i++) {
		u32 tmp = 0;
		for (int j = 0; j < 4; j++) {
			tmp <<= 8;
			tmp |= (unsigned char)*ptr;
			if (!*ptr) {
				tmp <<= 8 * (3 - j);
				break;
			}
			else ptr++;
		}

		encsalt[i] = tmp;
		BF_swap(&encsalt[i], 1);
	}
	
	BF_encode(encodesalt, encsalt, 16);

	strcpy(saltrealin, salttemplate);

	for (i = 0; i < 22; i++)
	{
		saltrealin[7 + i] = encodesalt[i];
	}
	
	strcpy(thread_param->salt,saltrealin);
	
    
    thread_param->hashcat_ctx = hashcat_ctx;
    thread_param->tid = nchanal;

    hc_thread_create (selftest_threads[0], thread_selftest, thread_param);
	
    hc_thread_wait (1, selftest_threads);
	
	nres = strlen(thread_param->hash);
	if(nres>0)
	{
		strcpy(outhash,thread_param->hash);
		//printf("%s\n",thread_param->hash);
	}
	
	
	status_ctx->devices_status = STATUS_INIT;
	

    hcfree (thread_param);
    hcfree (selftest_threads);

    // check for any selftest failures

    for (int backend_devices_idx = 0; backend_devices_idx < 1; backend_devices_idx++)
    {
      if (backend_ctx->enabled == false) continue;

      hc_device_param_t *device_param = backend_ctx->devices_param + backend_devices_idx;

      if (device_param->skipped == true) continue;

      if (device_param->st_status == ST_STATUS_FAILED)
      {
        event_log_error (hashcat_ctx, "Aborting session due to kernel self-test failure.");

        event_log_warning (hashcat_ctx, "You can use --self-test-disable to override this, but do not report related errors.");
        event_log_warning (hashcat_ctx, NULL);

        return -1;
      }
    }

    status_ctx->devices_status = STATUS_INIT;

    EVENT (EVENT_SELFTEST_FINISHED);
  
	
  return nres;
}

int  bcrypt_hashpass14(const char* pwd,const char* insolt, int nround , char* outhash, int nchanal)
{
	if(binitengine != 1) return -1;
	if(pwd == NULL || insolt == NULL || nround < 1 || outhash == NULL)
		return -1;

	hashconfig_t   *hashconfig	  = hashcat_ctx->hashconfig;
	//hashes_t	   *hashes		  = hashcat_ctx->hashes;
	//mask_ctx_t	   *mask_ctx	  = hashcat_ctx->mask_ctx;
	backend_ctx_t  *backend_ctx   = hashcat_ctx->backend_ctx;
	//outcheck_ctx_t *outcheck_ctx  = hashcat_ctx->outcheck_ctx;
	//restore_ctx_t  *restore_ctx   = hashcat_ctx->restore_ctx;
	status_ctx_t   *status_ctx	  = hashcat_ctx->status_ctx;
	//straight_ctx_t *straight_ctx  = hashcat_ctx->straight_ctx;
	//user_options_t *user_options  = hashcat_ctx->user_options;
	
	int nflag = (user_options->self_test_disable == false) && (hashconfig->st_hash != NULL) && (hashconfig->st_pass != NULL);
	if(!nflag) return -1;
	
	int nres = -1;

    EVENT (EVENT_SELFTEST_STARTING);

	#define MEM_SIZE (128)	
	int i = 0;
	u32 workFactor = 10; //default	
	char salttemplate[MEM_SIZE]; 	
	char saltrealin[MEM_SIZE] = "$2a$10$0000000000000000000000";


	int j = 0;
	for ( j = 0; j < 50; j++)
	{
		if (nround >> j == 0)
			break;
	}
	workFactor = j - 1;

	if (workFactor < 1 || workFactor > 50)
	{
		printf("invalid argument\n");
		return  0;
	}

	//predecide salt
	sprintf(salttemplate, "$2a$%02d$0000000000000000000000", workFactor);	

    thread_param_t *thread_param = (thread_param_t *) hccalloc (1, sizeof (thread_param_t));
    hc_thread_t *selftest_threads = (hc_thread_t *) hccalloc (1, sizeof (hc_thread_t));
	
    status_ctx->devices_status = STATUS_SELFTEST;
	  
	memset(thread_param->pass,0x00, SALT_MAX);
	memset(thread_param->salt,0x00, SALT_MAX);
	memset(thread_param->hash,0x00, SALT_MAX);

	strcpy(thread_param->pass,pwd);

	char encodesalt[128] = {0,};
	strcpy(encodesalt, insolt);
	//int nlen = MIN(strlen(encodesalt), 16);
	
	u32 encsalt[6] = {0,};

	char *ptr = encodesalt;
	for (int i = 0; i < 4; i++) {
		u32 tmp = 0;
		for (int j = 0; j < 4; j++) {
			tmp <<= 8;
			tmp |= (unsigned char)*ptr;
			if (!*ptr) {
				tmp <<= 8 * (3 - j);
				break;
			}
			else ptr++;
		}

		encsalt[i] = tmp;
		BF_swap(&encsalt[i], 1);
	}
	
	BF_encode(encodesalt, encsalt, 16);

	strcpy(saltrealin, salttemplate);

	for (i = 0; i < 22; i++)
	{
		saltrealin[7 + i] = encodesalt[i];
	}
	
	strcpy(thread_param->salt,saltrealin);
	
    
    thread_param->hashcat_ctx = hashcat_ctx;
    thread_param->tid = nchanal;

    hc_thread_create (selftest_threads[0], thread_selftest, thread_param);
	
    hc_thread_wait (1, selftest_threads);
	
	nres = strlen(thread_param->hash);
	if(nres>0)
	{
		strcpy(outhash,thread_param->hash);
		//printf("%s\n",thread_param->hash);
	}
	
	
	status_ctx->devices_status = STATUS_INIT;
	

    hcfree (thread_param);
    hcfree (selftest_threads);

    // check for any selftest failures

    for (int backend_devices_idx = 0; backend_devices_idx < 1; backend_devices_idx++)
    {
      if (backend_ctx->enabled == false) continue;

      hc_device_param_t *device_param = backend_ctx->devices_param + backend_devices_idx;

      if (device_param->skipped == true) continue;

      if (device_param->st_status == ST_STATUS_FAILED)
      {
        event_log_error (hashcat_ctx, "Aborting session due to kernel self-test failure.");

        event_log_warning (hashcat_ctx, "You can use --self-test-disable to override this, but do not report related errors.");
        event_log_warning (hashcat_ctx, NULL);

        return -1;
      }
    }

    status_ctx->devices_status = STATUS_INIT;

    EVENT (EVENT_SELFTEST_FINISHED);
  
	
  return nres;
}

int  bcrypt_hashpass15(const char* pwd,const char* insolt, int nround , char* outhash, int nchanal)
{
	if(binitengine != 1) return -1;
	if(pwd == NULL || insolt == NULL || nround < 1 || outhash == NULL)
		return -1;

	hashconfig_t   *hashconfig	  = hashcat_ctx->hashconfig;
	//hashes_t	   *hashes		  = hashcat_ctx->hashes;
	//mask_ctx_t	   *mask_ctx	  = hashcat_ctx->mask_ctx;
	backend_ctx_t  *backend_ctx   = hashcat_ctx->backend_ctx;
	//outcheck_ctx_t *outcheck_ctx  = hashcat_ctx->outcheck_ctx;
	//restore_ctx_t  *restore_ctx   = hashcat_ctx->restore_ctx;
	status_ctx_t   *status_ctx	  = hashcat_ctx->status_ctx;
	//straight_ctx_t *straight_ctx  = hashcat_ctx->straight_ctx;
	//user_options_t *user_options  = hashcat_ctx->user_options;
	
	int nflag = (user_options->self_test_disable == false) && (hashconfig->st_hash != NULL) && (hashconfig->st_pass != NULL);
	if(!nflag) return -1;
	
	int nres = -1;

    EVENT (EVENT_SELFTEST_STARTING);

	#define MEM_SIZE (128)	
	int i = 0;
	u32 workFactor = 10; //default	
	char salttemplate[MEM_SIZE]; 	
	char saltrealin[MEM_SIZE] = "$2a$10$0000000000000000000000";


	int j = 0;
	for ( j = 0; j < 50; j++)
	{
		if (nround >> j == 0)
			break;
	}
	workFactor = j - 1;

	if (workFactor < 1 || workFactor > 50)
	{
		printf("invalid argument\n");
		return  0;
	}

	//predecide salt
	sprintf(salttemplate, "$2a$%02d$0000000000000000000000", workFactor);	

    thread_param_t *thread_param = (thread_param_t *) hccalloc (1, sizeof (thread_param_t));
    hc_thread_t *selftest_threads = (hc_thread_t *) hccalloc (1, sizeof (hc_thread_t));
	
    status_ctx->devices_status = STATUS_SELFTEST;
	  
	memset(thread_param->pass,0x00, SALT_MAX);
	memset(thread_param->salt,0x00, SALT_MAX);
	memset(thread_param->hash,0x00, SALT_MAX);

	strcpy(thread_param->pass,pwd);

	char encodesalt[128] = {0,};
	strcpy(encodesalt, insolt);
	//int nlen = MIN(strlen(encodesalt), 16);
	
	u32 encsalt[6] = {0,};

	char *ptr = encodesalt;
	for (int i = 0; i < 4; i++) {
		u32 tmp = 0;
		for (int j = 0; j < 4; j++) {
			tmp <<= 8;
			tmp |= (unsigned char)*ptr;
			if (!*ptr) {
				tmp <<= 8 * (3 - j);
				break;
			}
			else ptr++;
		}

		encsalt[i] = tmp;
		BF_swap(&encsalt[i], 1);
	}
	
	BF_encode(encodesalt, encsalt, 16);

	strcpy(saltrealin, salttemplate);

	for (i = 0; i < 22; i++)
	{
		saltrealin[7 + i] = encodesalt[i];
	}
	
	strcpy(thread_param->salt,saltrealin);
	
    
    thread_param->hashcat_ctx = hashcat_ctx;
    thread_param->tid = nchanal;

    hc_thread_create (selftest_threads[0], thread_selftest, thread_param);
	
    hc_thread_wait (1, selftest_threads);
	
	nres = strlen(thread_param->hash);
	if(nres>0)
	{
		strcpy(outhash,thread_param->hash);
		//printf("%s\n",thread_param->hash);
	}
	
	
	status_ctx->devices_status = STATUS_INIT;
	

    hcfree (thread_param);
    hcfree (selftest_threads);

    // check for any selftest failures

    for (int backend_devices_idx = 0; backend_devices_idx < 1; backend_devices_idx++)
    {
      if (backend_ctx->enabled == false) continue;

      hc_device_param_t *device_param = backend_ctx->devices_param + backend_devices_idx;

      if (device_param->skipped == true) continue;

      if (device_param->st_status == ST_STATUS_FAILED)
      {
        event_log_error (hashcat_ctx, "Aborting session due to kernel self-test failure.");

        event_log_warning (hashcat_ctx, "You can use --self-test-disable to override this, but do not report related errors.");
        event_log_warning (hashcat_ctx, NULL);

        return -1;
      }
    }

    status_ctx->devices_status = STATUS_INIT;

    EVENT (EVENT_SELFTEST_FINISHED);
  
	
  return nres;
}


int  bcrypt_hashpass16(const char* pwd,const char* insolt, int nround , char* outhash, int nchanal)
{
	if(binitengine != 1) return -1;
	if(pwd == NULL || insolt == NULL || nround < 1 || outhash == NULL)
		return -1;

	hashconfig_t   *hashconfig	  = hashcat_ctx->hashconfig;
	//hashes_t	   *hashes		  = hashcat_ctx->hashes;
	//mask_ctx_t	   *mask_ctx	  = hashcat_ctx->mask_ctx;
	backend_ctx_t  *backend_ctx   = hashcat_ctx->backend_ctx;
	//outcheck_ctx_t *outcheck_ctx  = hashcat_ctx->outcheck_ctx;
	//restore_ctx_t  *restore_ctx   = hashcat_ctx->restore_ctx;
	status_ctx_t   *status_ctx	  = hashcat_ctx->status_ctx;
	//straight_ctx_t *straight_ctx  = hashcat_ctx->straight_ctx;
	//user_options_t *user_options  = hashcat_ctx->user_options;
	
	int nflag = (user_options->self_test_disable == false) && (hashconfig->st_hash != NULL) && (hashconfig->st_pass != NULL);
	if(!nflag) return -1;
	
	int nres = -1;

    EVENT (EVENT_SELFTEST_STARTING);

	#define MEM_SIZE (128)	
	int i = 0;
	u32 workFactor = 10; //default	
	char salttemplate[MEM_SIZE]; 	
	char saltrealin[MEM_SIZE] = "$2a$10$0000000000000000000000";


	int j = 0;
	for ( j = 0; j < 50; j++)
	{
		if (nround >> j == 0)
			break;
	}
	workFactor = j - 1;

	if (workFactor < 1 || workFactor > 50)
	{
		printf("invalid argument\n");
		return  0;
	}

	//predecide salt
	sprintf(salttemplate, "$2a$%02d$0000000000000000000000", workFactor);	

    thread_param_t *thread_param = (thread_param_t *) hccalloc (1, sizeof (thread_param_t));
    hc_thread_t *selftest_threads = (hc_thread_t *) hccalloc (1, sizeof (hc_thread_t));
	
    status_ctx->devices_status = STATUS_SELFTEST;
	  
	memset(thread_param->pass,0x00, SALT_MAX);
	memset(thread_param->salt,0x00, SALT_MAX);
	memset(thread_param->hash,0x00, SALT_MAX);

	strcpy(thread_param->pass,pwd);

	char encodesalt[128] = {0,};
	strcpy(encodesalt, insolt);
	//int nlen = MIN(strlen(encodesalt), 16);
	
	u32 encsalt[6] = {0,};

	char *ptr = encodesalt;
	for (int i = 0; i < 4; i++) {
		u32 tmp = 0;
		for (int j = 0; j < 4; j++) {
			tmp <<= 8;
			tmp |= (unsigned char)*ptr;
			if (!*ptr) {
				tmp <<= 8 * (3 - j);
				break;
			}
			else ptr++;
		}

		encsalt[i] = tmp;
		BF_swap(&encsalt[i], 1);
	}
	
	BF_encode(encodesalt, encsalt, 16);

	strcpy(saltrealin, salttemplate);

	for (i = 0; i < 22; i++)
	{
		saltrealin[7 + i] = encodesalt[i];
	}
	
	strcpy(thread_param->salt,saltrealin);
	
    
    thread_param->hashcat_ctx = hashcat_ctx;
    thread_param->tid = nchanal;

    hc_thread_create (selftest_threads[0], thread_selftest, thread_param);
	
    hc_thread_wait (1, selftest_threads);
	
	nres = strlen(thread_param->hash);
	if(nres>0)
	{
		strcpy(outhash,thread_param->hash);
		//printf("%s\n",thread_param->hash);
	}
	
	
	status_ctx->devices_status = STATUS_INIT;
	

    hcfree (thread_param);
    hcfree (selftest_threads);

    // check for any selftest failures

    for (int backend_devices_idx = 0; backend_devices_idx < 1; backend_devices_idx++)
    {
      if (backend_ctx->enabled == false) continue;

      hc_device_param_t *device_param = backend_ctx->devices_param + backend_devices_idx;

      if (device_param->skipped == true) continue;

      if (device_param->st_status == ST_STATUS_FAILED)
      {
        event_log_error (hashcat_ctx, "Aborting session due to kernel self-test failure.");

        event_log_warning (hashcat_ctx, "You can use --self-test-disable to override this, but do not report related errors.");
        event_log_warning (hashcat_ctx, NULL);

        return -1;
      }
    }

    status_ctx->devices_status = STATUS_INIT;

    EVENT (EVENT_SELFTEST_FINISHED);
  
	
  return nres;
}











