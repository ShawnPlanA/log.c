/*
gcc main.c  log.c  -l pthread

ps -aux | grep a.out

kill -9 `pidof  a.out`
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>
#include "log.h"

pthread_mutex_t MUTEX_LOG;
FILE *fp_log = NULL;
static const char *pid_file = NULL;
char *config_file = NULL;
char g_log_file[] = "./luo.log";
char *log_file = g_log_file;
int background = 0;
int loglevel = LOG_TRACE;
static char  procname[128] = {0};

#define SW_VERSION_MAIN   1 // V1.0.5
#define SW_VERSION_SUB1   0
#define SW_VERSION_SUB2   5
#define SW_VERSION(a,b,c)   (((a) << 16) + ((b) << 8) + (c))
#define __TO_STR(R) #R
#define TO_STR(R) __TO_STR(R)
#define SW_VERSION_NUM  SW_VERSION(SW_VERSION_MAIN, SW_VERSION_SUB1, SW_VERSION_SUB2)

#define SW_VERSION_STR  "V"TO_STR(SW_VERSION_MAIN)"."TO_STR(SW_VERSION_SUB1)"."TO_STR(SW_VERSION_SUB2)
#define THIS_VERSION    SW_VERSION_STR " ("__DATE__" " __TIME__")"


#define ERR_EXIT(m) \
do { \
    perror(m);\
	printf("xxxxxxxxx\n");\
    exit(EXIT_FAILURE);\
}while (0);


#define ST_STR(sig) \
	case sig: \
		return #sig; \
		break;
const char *format_signal(unsigned int sig)
{
	switch (sig)
	{
#if 1
		ST_STR(SIGHUP)
		ST_STR(SIGINT)
		ST_STR(SIGQUIT)
		ST_STR(SIGILL)
		ST_STR(SIGTRAP)
		ST_STR(SIGABRT)
		//ST_STR(SIGIOT)
		ST_STR(SIGBUS)
		ST_STR(SIGFPE)
		ST_STR(SIGKILL)
		ST_STR(SIGUSR1)
		ST_STR(SIGSEGV)
		ST_STR(SIGUSR2)
		ST_STR(SIGPIPE)
		ST_STR(SIGALRM)
		ST_STR(SIGTERM)
		ST_STR(SIGSTKFLT)
		ST_STR(SIGCHLD)
		ST_STR(SIGCONT)
		ST_STR(SIGSTOP)
		ST_STR(SIGTSTP)
		ST_STR(SIGTTIN)
		ST_STR(SIGTTOU)
		ST_STR(SIGURG)
		ST_STR(SIGXCPU)
		ST_STR(SIGXFSZ)
		ST_STR(SIGVTALRM)
		ST_STR(SIGPROF)
		ST_STR(SIGWINCH)
		//ST_STR(SIGIO)
		ST_STR(SIGPOLL)
		ST_STR(SIGPWR)
		ST_STR(SIGSYS)
		//ST_STR(SIGUNUSED)
#else
		case SIGHUP:    return "SIGHUP";
		case SIGINT:    return "SIGINT";
		case SIGQUIT:   return "SIGQUIT";
		case SIGILL:    return "SIGTRAP";
		case SIGTRAP:   return "SIGILL";
		case SIGABRT:   return "SIGABRT";
		//case SIGIOT:    return "SIGIOT";
		case SIGBUS:    return "SIGBUS";
		case SIGFPE:    return "SIGFPE";
		case SIGKILL:   return "SIGKILL";
		case SIGUSR1:   return "SIGUSR1";
		case SIGSEGV:   return "SIGSEGV";
		case SIGUSR2:   return "SIGUSR2";
		case SIGPIPE:   return "SIGPIPE";
		case SIGALRM:   return "SIGALRM";
		case SIGTERM:   return "SIGTERM";
		case SIGSTKFLT: return "SIGSTKFLT";
		case SIGCHLD:   return "SIGCHLD";
		case SIGCONT:   return "SIGCONT";
		case SIGSTOP:   return "SIGSTOP";
		case SIGTSTP:   return "SIGTSTP";
		case SIGTTIN:   return "SIGTTIN";
		case SIGTTOU:   return "SIGTTOU";
		case SIGURG:    return "SIGURG";
		case SIGXCPU:   return "SIGXCPU";
		case SIGXFSZ:   return "SIGXFSZ";
		case SIGVTALRM: return "SIGVTALRM";
		case SIGPROF:   return "SIGPROF";
		case SIGWINCH:  return "SIGWINCH";
		//case SIGIO:     return "SIGIO";
		case SIGPOLL:   return "SIGPOLL";
		case SIGPWR:    return "SIGPWR";
		case SIGSYS:    return "SIGSYS";
		//case SIGUNUSED: return "SIGUNUSED";
#endif
	}
}

void handle_signal(int sig_no)
{
	log_info("got signal :%d\n", sig_no);
	log_info("SIGTERM:%d SIGHUP:%d SIGINT:%d SIGILL:%d SIGABRT:%d SIGKILL:%d SIGSEGV:%d SIGBUS:%d SIGUSR1 :%d SIGUSR2:%d\n",
		SIGTERM ,SIGHUP, SIGINT, SIGILL, SIGABRT, SIGKILL, SIGSEGV, SIGBUS, SIGUSR1, SIGUSR2);
	log_info("Catch signal = %s\n", format_signal(sig_no));
	switch(sig_no)
	{
		case SIGHUP:
		case SIGPIPE:
		case SIGUSR1:
		case SIGUSR2:
			log_info("ignore signal :%d\r\n", sig_no);
			return;
/*
		case SIGSEGV:
			dump_stack();
			break;
*/
		default:
			break;
	}

	signal(sig_no, SIG_DFL);
	//kill(getpid(), sig_no);
}

void sig_catch()
{
	signal(SIGPIPE, SIG_IGN); // 当服务器close一个socket连接时，若client端接着发数据。  若不想客户端退出可以把SIGPIPE设为SIG_IGN. 忽略
	signal(SIGHUP, SIG_IGN); // 挂起控制终端或进程. 忽略
	signal(SIGTRAP, SIG_IGN); // 跟踪的断点
	signal(SIGBUS, handle_signal);  //总线错误
	signal(SIGFPE, handle_signal); // 浮点异常
	signal(SIGILL, handle_signal);  // 非法指令
	//signal(SIGINT, handle_signal); // 来自键盘的中断,  Ctrl+C
	//signal(SIGTERM, handle_signal); // 进程终止 kill
	signal(SIGIOT, handle_signal); // 等价于SIGABRT, 异常结束
	signal(SIGQUIT, handle_signal); // 从键盘退出,  Ctrl+\
	signal(SIGSEGV, handle_signal); // 无效的内存引用
	signal(SIGSYS, handle_signal); // 坏的系统调用
	signal(SIGUSR1, handle_signal);
	signal(SIGUSR2, handle_signal);
}



static void parse_args(int argc, char *argv[])
{
	int i = 0;
	static char pid_name[50] = {0};

	argc--;
	i++;
	//printf("argc=%d\n", argc);

	while (argc)
	{
		//printf("i=%d, argc=%d, argv[%d]=%s  ", i, argc, i, argv[i]);
		/* Config file */
		if (!strcmp(argv[i], "-c"))
		{
			if (argc > 1) {
				config_file = argv[i+1];
				printf("[test] config_file=%s\n", config_file);
				argc--;
				i++;
			}
		}
		else if (!strcmp(argv[i], "-d"))  /* Log Level */
		{
			if (argc > 1) {
				int tmp_loglevel = strtoul(argv[i+1], NULL, 0);
				if(tmp_loglevel < 0 || tmp_loglevel > 5)
					loglevel = LOG_TRACE;
				else
					loglevel = tmp_loglevel;
				printf("[test] loglevel=%d\n", loglevel);
				argc--;
				i++;
				i++;
			}
			//printf("2222argc=%d\n", argc);
		}
		else if (!strcmp(argv[i], "-b")) /* Backgroud */
		{
			if (argc > 1) {
				snprintf(pid_name, sizeof(pid_name), "/var/run/%s.pid", argv[0]);
				pid_file = pid_name;
				printf("[test] pid_file=%s\n", pid_file);
				background = 1;
				argc--;
				i++;
			}
		}
		else if (!strcmp(argv[i], "-l")) /* Log File */
		{
			if (argc = 1) {
				log_file = argv[i+1];
				printf("[test] log_file=%s\n", log_file);
				argc--;
				i++;
			}
		}
		else if (!strcmp(argv[i], "-v"))
		{
			printf("Version: %d\n", SW_VERSION_NUM);
			exit(-1);
		}
		else if (!strcmp(argv[i], "-V"))
		{
			printf("Version: %s\n", THIS_VERSION);
			exit(-1);
		}
		else if (!strcmp(argv[i], "-h")) /* help */
		{
			printf("    -c  config_file \n");
			printf("    -d  debug_level \n");
			printf("    -l  log_file\n");
			printf("    -b  // backgroud \n");
			printf("    -h  // help\n");
			printf("    -v  // version_num \n");
			printf("    -V  // version_string \n");
			printf("eg： -b  -d 8  -l ./luo.log \n\n");
			exit(-1);
		}
		else
		{
			i++;
			argc--;
		}
		//printf("\nend_argc=%d, i=%d\n", argc, i);
	}
}



void creat_daemon(int nochdir, int noclose)
{
#if 0
	pid_t pid;
	struct sigaction sa;

	//调用umask将文件模式创建屏蔽字设置为0
	umask(0);

	//调用fork,父进程退出(exit)
	if ((pid = fork()) < 0) {
		perror("fork error:\n");
		return;
	}
	else if (pid != 0) {
		printf("pid1 != 0\n");
		exit(0);
	}

	//调用setsid函数返回一个新的Session id(也就是当前进程的id)
	setsid();
	sa.sa_handler = SIG_IGN;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;

	if (sigaction(SIGHUP, &sa, NULL) < 0)
		perror("sigaction error:");

	//再次fork一次，保证 daemon进程
	if ((pid = fork()) < 0) {
		perror("fork error:\n");
		return;
	}
	else if (pid != 0) {
		printf("pid2 != 0\n");
		exit(0);
	}

#else

	pid_t pid;

	pid = fork();
	if( pid == -1)
	{
		printf("exit [%s:%u]\n", __FUNCTION__, __LINE__);
		ERR_EXIT("fork error");
	}

	if(pid > 0 )
	{
		printf("APP_name=%s, father_pid=%d\n", procname, getpid());
		printf("father  exit [%s:%u]\n", __FUNCTION__, __LINE__);
		exit(EXIT_SUCCESS);
	}

	if(setsid() == -1) // 调用进程不能是进程首进程，也就是说要想setsid调用成功那么调用者就不能是进程组长。
	{
		printf("err setsid [%s:%u]\n", __FUNCTION__, __LINE__);
		ERR_EXIT("SETSID ERROR");
	}

	if(nochdir == 0)
		chdir("/");

	if(noclose == 0)
	{
		int i;
		for( i = 0; i < 3; ++i)
		{
			close(i);
			open("/dev/null", O_RDWR);
			dup(0);
			dup(0);
		}
		umask(0);
	}
#endif
}





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
	int ret = -1;
	log_set_level(loglevel);
	log_set_quiet(0); // 是否开启 终端显示打印信息

	pthread_mutex_init(&MUTEX_LOG, NULL);
	log_set_lock(log_lock, &MUTEX_LOG);

	fp_log = fopen(log_file, "ab");
	if(fp_log == NULL)
	{
		printf("ERR open=%s\n", log_file);
		goto end;
	}

	log_add_fp(fp_log, loglevel);
	ret = 0;

end:
	return ret;
}

void exit_mylog()
{
	fclose(fp_log);
	pthread_mutex_destroy(&MUTEX_LOG);
}


void get_procname()
{
	int i = 0, count = 0;
	char tmp[4096] = {0};

	if( !strcmp(procname, "") )
	{
		char *p = NULL;
		count = readlink("/proc/self/exe", tmp, sizeof(tmp));
		if(count < 0 || count > (int)sizeof(tmp))
		{
			fprintf(stderr, "Firewall: %s readlink error.\n", __FUNCTION__);
			return ;
		}
		tmp[count] = '\0';
		p = rindex(tmp, '/');
		p++;
		while(*p!=0)
		{
			procname[i++] = *p;
			p++;
		}
	}
}

int main(int argc, char *argv[])
{
	int ret = 0;
	parse_args(argc, argv);

	get_procname();
	if (background)
		creat_daemon(1, 1);

	sig_catch();

	ret = init_mylog();
	if(ret)
	{
		printf("ret == -1\n");
		return -1;
	}

	log_error("APP_name=%s, pid=%d", procname, getpid());

	log_trace("log_trace  1");
	log_debug("log_debug  2");
	log_info("log_info   3");
	log_warn("log_warn   4");
	log_error("log_error  4");
	log_fatal("log_fatal  6");

	while(1)
	{
		printf("while 1\n");
		sleep(1);
	}

	exit_mylog();
}
