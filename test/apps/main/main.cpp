/*
 * Copyright (C) 2016  Nexell Co., Ltd.
 *
 * Author: junghyun, kim <jhkim@nexell.co.kr>
 *
 * SPDX-License-Identifier:	GPL-2.0+
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "task.h"

#define	RET_FILE_NAME	"RESULT.txt"

typedef struct option_t {
	char file[256]  = { 0, };
	char retdir[256]  = { 0, };
	int log_buffsize = 16384;
	bool log_date = true;
	bool log_print = false;
	bool log_re_no = false;
	bool log_re_err = false;
	bool show_task = false;
	int task_active[256] = { 0, };
	int active_size = 0;
	int continue_stat = -1;
} OP_T;

typedef struct log_redirect_t {
	char file[256]  = { 0, };
	int fd = -1, logout, logerr;
	bool redirect_err = false;
} LOG_RE_T;

#if 0
#define	LOGMESG(l, t, format, ...) do { \
		fprintf(stdout, format, ##__VA_ARGS__); \
	} while (0)
#define	LOGDUMP(l, t)	do { } while (0)
#define	LOGDONE(l, t)	do { } while (0)
#else
#define	LOGMESG(l, t, format, ...) do { \
		l->Write(t, format, ##__VA_ARGS__); \
	} while (0)
#define	LOGDUMP(l, t)	 do { l->Dump(t); } while (0)
#define	LOGDONE(l, t)	 do { l->Done(t); } while (0)
#endif

#define COLOR_RED     "\x1b[31m"
#define COLOR_GREEN   "\x1b[32m"
#define COLOR_YELLOW  "\x1b[33m"
#define COLOR_BLUE    "\x1b[34m"
#define COLOR_MAGENTA "\x1b[35m"
#define COLOR_CYAN    "\x1b[36m"
#define COLOR_RESET   "\x1b[0m"

static int mkpath(const char *s, mode_t mode)
{
        char *q, *r = NULL, *path = NULL, *up = NULL;
        int ret = -1;

        if (strcmp(s, ".") == 0 || strcmp(s, "/") == 0)
                return 0;

        if (!(path = strdup(s)))
                return -errno;

        if (!(q = strdup(s)))
                goto out;

        if (!(r = (char *)dirname(q)))
                goto out;

        if (!(up = strdup(r)))
                goto out;

        if ((mkpath(up, mode) == -1) && (errno != EEXIST))
                goto out;

        if ((mkdir(path, mode) == -1) && (errno != EEXIST))
                ret = -1;
        else
                ret = 0;
out:
        if (up != NULL)
                free(up);

        free(q);
        free(path);

        return ret;
}

static LOG_RE_T *logo_new(const char *dir, const char *logfile,
			bool redirect_err)
{
	LOG_RE_T *log_t;
	char file[256];
	int fd, out = -1, err = -1, ret;

	if (!logfile)
		return NULL;

	if (dir && 0 != access(dir, W_OK)) {
		LogE("%s : %s\n", dir, strerror(errno));
		return NULL;
	}

	if (dir && strlen(dir)) {
		string s = dir;

		if (dir[strlen(dir)-1] != '/')
			s += '/';

		s += logfile;
		strcpy(file, s.c_str());
	} else {
		strcpy(file, logfile);
	}

	fd = open(file, O_RDWR | O_TRUNC | O_CREAT, 0644);
	if (fd < 0)
		return NULL;

	out = dup(STDOUT_FILENO);
	ret = dup2(fd, STDOUT_FILENO);
	if (ret < 0) {
		LogE("%s stdout dup2 %s !!!\n", file, strerror(errno));
		close(out), close(fd);
		return NULL;
	}

	if (!redirect_err)
		goto _end_redirect;

	err = dup(STDERR_FILENO);
	ret = dup2(fd, STDERR_FILENO);
	if (ret < 0) {
		LogE("%s stderr dup2 %s !!!\n", file, strerror(errno));
		close(err);
	}

_end_redirect:

	log_t = new LOG_RE_T;

	strcpy(log_t->file, file);
	log_t->fd = fd;
	log_t->logout = out;
	log_t->logerr = err;

	return log_t;
}

static void logo_del(LOG_RE_T *log_t)
{
	if (!log_t)
		return;

	if (log_t->fd < 0)
		return;

	dup2(log_t->logout, STDOUT_FILENO);
	if (log_t->redirect_err)
		dup2(log_t->logerr, STDOUT_FILENO);

	close(log_t->fd);
	close(log_t->logout);

	if (log_t->redirect_err)
		close(log_t->logerr);

	delete log_t;
}

static int task_command(const char *exec, bool syscmd)
{
	FILE *fp;
	char buf[16];
	size_t len;

	if (syscmd)
		return system(exec);

	fp = popen(exec, "r");
	if (!fp)
		return errno;

	len = fread((void*)buf, sizeof(char), sizeof(buf), fp);
	if (!len) {
		pclose(fp);
	        return errno;
	}
	pclose(fp);

	return strtol(buf, NULL, sizeof(buf));
}

static int task_execute(TASK_DESC_T *task)
{
	TaskManager *manager = task->manager;
	OP_T *op = static_cast<OP_T *>(manager->GetPrivData());
	char buf[16];
	string s;
	const char *c = task->path;
	TIMESTEMP_T *time = &task->time;
	long long ts = 0, td = 0;
	bool syscmd = false;
	bool success = true;
	int loop = 1, ret;
	LOG_RE_T * log_t = NULL;
	Logger *Log = manager->GetLogger();

	if (!task->exec)
		return -EINVAL;

	LOGMESG(Log, task, "------------------------------------------------------------------------\n");
	LOGMESG(Log, task, "ID       : [%d] %d \n", task->priority, task->id);
	LOGMESG(Log, task, "DESC     : %s\n", task->desc);
	LOGMESG(Log, task, "EXEC     : %s\n", task->exec);
	LOGMESG(Log, task, "THREAD   : %s\n", task->isthread ? "Y" : "N");
	LOGMESG(Log, task, "LOGFILE  : %s\n", task->logo);

	if (c) {
		s = c;
		if (c[strlen(c)-1] != '/')
			s += '/';
	}

	c = strtok((char *)task->cmd, " ");
	s += c;

	if (0 != access(s.c_str(), X_OK)) {
		task->retval = errno;
		goto _err_execute;
	}

	if (task->min == 0 && task->max == 0)
		syscmd = true;

	if (task->delay)
		msleep(task->delay);

	if (task->loop)
		loop = task->loop;

	if (manager->IsExitFail())
		goto _err_execute;

	/* Log redirect */
	if (!op->log_re_no)
		log_t = logo_new(manager->GetResultDir(),task->logo,
					op->log_re_err);

	for (int i = 0; i < loop; i++) {
		RUN_TIMESTAMP_US(ts);

		ret = task_command(task->exec, syscmd);

		task->retval = ret;
		task->count++;

		END_TIMESTAMP_US(ts, td);
		SET_TIME_STAT(time, td);

		if (ret < task->min || ret > task->max) {
			if (!manager->IsContinue()) {
				manager->ExitFail();
				break;
			}

			task->success = false;
			success = false;
		}

		if (success)
			task->success = true;

		/* ExitFail other task */
		if (manager->IsExitFail())
			break;

		if (task->sleep)
			msleep(task->sleep);
	}

	/* Close Log redirect */
	logo_del(log_t);

_err_execute:
	LOGMESG(Log, task, "ACT      : loop:%d/%d, delay:%d ms, sleep:%d ms\n",
		task->count, task->loop, task->delay, task->sleep);
	if (time->cnt)
		LOGMESG(Log, task, "TIME     : min:%2llu.%03llu ms, max:%2llu.%03llu ms, avr:%2llu.%03llu ms\n",
			time->min/1000, time->min%1000, time->max/1000, time->max%1000,
			(time->tot/time->cnt)/1000, (time->tot/time->cnt)%1000);

	if (task->success)
		LOGMESG(Log, task, COLOR_GREEN);
	else
		LOGMESG(Log, task, COLOR_RED);

	LOGMESG(Log, task, "RESULT   : [ID:%d, %d] %s, RET:%d [%d,%d] %s \n",
		task->id, task->priority,
		!task->count ? "NO RUN" : task->success ? "OK" : "FAIL",
		task->retval, task->min, task->max,
		task->success ? "" : strerror(task->retval));
	LOGMESG(Log, task, COLOR_RESET);
	LOGMESG(Log, task, "------------------------------------------------------------------------\n");
	LOGDUMP(Log, task); LOGDONE(Log, task);

	return task->success ? 0 : -1;
}

static void *thread_execute(void *data)
{
	TASK_DESC_T *task = static_cast<TASK_DESC_T *>(data);
	TaskManager *manager = task->manager;
	int pid, status;

	pid = fork();
	if (pid == 0) {
		int ret = task_execute(task);
		exit(ret);
	}

	while (1) {
		if (waitpid(pid, &status, WNOHANG))
			break;

		if (!manager->IsContinue() && manager->IsExitFail()) {
			kill(pid, SIGTERM);
			waitpid(pid, &status, 0);
			break;
		}
		msleep(100);
	}

	if (!status)
		task->success = true;

	if (!manager->IsContinue() && status)
		manager->ExitFail();

	pthread_exit(NULL);
}

static int run_execute(TaskManager *manager)
{
	OP_T *op = static_cast<OP_T *>(manager->GetPrivData());
	vector <pthread_t> handle;
	const char *retdir = manager->GetResultDir();
	char dir[256];

	if (strlen(op->retdir))
		retdir = op->retdir;

	/* create result directory */
	if (retdir) {
		if (op->log_date) {
  			time_t timer = time(NULL);
  			struct tm *t = localtime(&timer);

  			sprintf(dir, "%s/%d%02d%02d-%02d%02d",
  				retdir, t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
  				t->tm_hour, t->tm_min);
  			retdir = dir;
		}
		mkpath(retdir, 0755);
	}

	manager->SetResultDir(retdir);

	/* create Diagnostic Log */
	Logger *Log = new Logger(retdir, RET_FILE_NAME,
				op->log_buffsize, op->log_print);
	manager->SetLogger(Log);

	LOGMESG(Log, NULL, "========================================================================\n");
	LOGMESG(Log, NULL, "RETDIR   : %s\n", manager->GetResultDir());
	LOGMESG(Log, NULL, "CONTINUE : %s\n", manager->IsContinue() ? "Y" : "N");
	LOGMESG(Log, NULL, "========================================================================\n");
	LOGDUMP(Log, NULL); LOGDONE(Log, NULL);

	for (int i = 0 ; i < manager->GetTaskNum(); i++) {
		TASK_DESC_T *task = manager->TaskGet();

		if (op->active_size) {
			for (int n = 0; n < op->active_size; n++) {
				if (op->task_active[n] == task->priority) {
					task->active = true;
					break;
				}
			}

			if (!task->active)
				continue;
		}

		task->active = true;
		task->manager = manager;

		if (task->isthread) {
			pthread_t hnd;
			if (pthread_create(&hnd, NULL, thread_execute, task)) {
				LogE("%s : %s !!!\n",
					task->exec, strerror(errno));
				if (!manager->IsContinue())
					return -1;
			}
			handle.push_back(hnd);
			continue;
		}

		int ret = task_execute(task);

		if (ret || manager->IsExitFail())
			return -1;
	}

	for (auto ls = handle.begin(); ls != handle.end();) {
		pthread_t hnd = (*ls);

		pthread_join(hnd, NULL);
		ls = handle.erase(ls);
	}

 	if (manager->IsExitFail())
 		return -1;

	return 0;
}

static void print_help(const char *name, OP_T *op)
{
	LogI("\n");
	LogI("usage: options\n");
	LogI("\t-f : config file path\n");
	LogI("\t-r : set result directory, log is exist 'result/<date>', refer to '-d'\n");
	LogI("\t-d : skip date directory in result directory\n");
	LogI("\t-l : log buffer size for each task print log default[%d]\n", op->log_buffsize);
	LogI("\t-n : not redirect application's printf out\n");
	LogI("\t-p : enable diagnostic's message print immediately\n");
	LogI("\t-e : redirect application's 'STDERR' printf err\n");
	LogI("\t-i : show tasks in config file\n");
	LogI("\t-a : set active task numbers with priority ex> 1,2,3,...\n");
	LogI("\t-c : set application running status if 'y' continue, if 'n' stop when failed\n");
}

static OP_T *parse_options(int argc, char **argv)
{
	int opt;
	OP_T *op = new OP_T;

	while (-1 != (opt = getopt(argc, argv, "hf:r:nl:edpa:ic:"))) {
		switch(opt) {
       		case 'f':
       			strcpy(op->file, optarg);
       			break;
       		case 'r':
       			strcpy(op->retdir, optarg);
       			break;
       		case 'd':
       			op->log_date = false;
       			break;
       		case 'l':
       			op->log_buffsize = strtoul(optarg, NULL, 10);;
       			break;
       		case 'e':
       			op->log_re_err = true;
       			break;
       		case 'n':
       			op->log_re_no = true;
       			break;
       		case 'p':
       			op->log_print = true;
       			break;
       		case 'i':
       			op->show_task = true;
       			break;
       		case 'a':
       			{
			int size = 0;
       			char *s = optarg, *c = strtok(s, " ,.-");

			while (c != NULL) {
				int id = strtoul(c, NULL, 10);

				c = strtok(NULL, " ,.-");
				op->task_active[size++] = id;

				if (size > (int)ARRAY_SIZE(op->task_active)) {
					LogE("over task array size[%d] !!!\n",
						(int)ARRAY_SIZE(op->task_active));
					exit(EXIT_FAILURE);
				}
    			}
    			op->active_size = size;
    			}
    			break;
       		case 'c':
       			{
       			char *s = optarg;

       			if (!strcmp(s, "y"))
       				op->continue_stat = 1;

       			if (!strcmp(s, "n"))
       				op->continue_stat = 0;
       			}
       			break;

        	default:
        		print_help(argv[0], op);
        		exit(EXIT_FAILURE);
        		break;
	      	}
	}

	return op;
}

int main(int argc, char **argv)
{
	TaskManager *manager;
	Logger *Log;
	OP_T *op;
	bool ret;

	op = parse_options(argc, argv);
	if (!op)
		exit(EXIT_FAILURE);

	manager = new TaskManager;

	if (!manager->LoadTask(op->file))
		exit(EXIT_FAILURE);

	if (op->continue_stat != -1)
		manager->SetContinue(op->continue_stat ? true : false);

	if (op->show_task) {
		for (int i = 0 ; i < manager->GetTaskNum(); i++) {
			TASK_DESC_T *task = manager->TaskGet();

			LogI("------------------------------------------------------------------------\n");
			LogI("ID       : [%d] %d \n", task->priority, task->id);
			LogI("DESC     : %s\n", task->desc);
			LogI("EXEC     : %s\n", task->exec);
			LogI("THREAD   : %s\n", task->isthread ? "Y" : "N");
			LogI("ACT      : loop:%d/%d, delay:%d ms, sleep:%d ms\n",
				task->count, task->loop, task->delay, task->sleep);
			LogI("LOGFILE  : %s\n", task->logo);
		}
		return 0;
	}
	manager->SetPrivData(op);

	/*
	 * execute tasks
	 */
	run_execute(manager);

	Log = manager->GetLogger();
	ret = manager->IsSuccess();

	LOGMESG(Log, NULL, "========================================================================\n");
	if (ret)
		LOGMESG(Log, NULL, "\033[42m");
	else
		LOGMESG(Log, NULL, "\033[43m");

	LOGMESG(Log, NULL, "EXIT : %s, LOG: %s\n", ret ? "SUCCESS" : "FAIL", manager->GetResultDir());
	LOGMESG(Log, NULL, "\033[0m\r\n");
	LOGMESG(Log, NULL, "========================================================================\n");
	LOGDUMP(Log, NULL); LOGDONE(Log, NULL);

	return 0;
}
