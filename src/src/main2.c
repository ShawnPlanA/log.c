//   gcc main.c  log.c  -l pthread

#include <pthread.h>
#include "log.h"

pthread_mutex_t MUTEX_LOG;
FILE *fp_log = NULL;


void log_lock(bool lock, void* udata)
{
	pthread_mutex_t *LOCK = (pthread_mutex_t*)(udata);
	if (lock)
	{
		pthread_mutex_lock(LOCK);
		//printf("\nlock\n");
	}
	else
	{
		pthread_mutex_unlock(LOCK);
		//printf("unlock\n");
	}
}

int init_mylog()
{
	log_set_level(LOG_TRACE);
	log_set_quiet(0); // 是否开启 终端显示打印信息

	pthread_mutex_init(&MUTEX_LOG, NULL);
	log_set_lock(log_lock, &MUTEX_LOG);
	char *log_file = "./_xxx.log";

	fp_log = fopen(log_file, "ab");
	if(fp_log == NULL)
	{
		printf("ERR open=%s\n", log_file);
		return -1;
	}

	log_add_fp(fp_log, LOG_TRACE);
	return 0;
}

void exit_mylog()
{
	fclose(fp_log);
	pthread_mutex_destroy(&MUTEX_LOG);
}


int main(int argc, char *argv[])
{
	int ret = 0;

	ret = init_mylog();
	if(ret)
	{
		printf("ret == -1\n");
		return -1;
	}

	log_trace("log_trace");
	log_debug("log_debug");
	log_info("log_info");
	log_warn("log_warn");
	log_error("log_error");
	log_fatal("log_fatal");



	exit_mylog();
}
