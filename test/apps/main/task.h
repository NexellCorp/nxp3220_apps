/*
 * Copyright (C) 2016  Nexell Co., Ltd.
 *
 * Author: junghyun, kim <jhkim@nexell.co.kr>
 *
 * SPDX-License-Identifier:	GPL-2.0+
 */
#ifndef _TASK_CLASS_H_
#define _TASK_CLASS_H_

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>
#include <fcntl.h>
#include <pthread.h>
#include <vector>
#include <algorithm>
#include <json.h>
#include <libgen.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "util.h"

using namespace std;
class TaskManager;

#define KEY_ID_RESULT	"result"
#define KEY_ID_CONTINUE	"continue"
#define KEY_ID_SKIP	"skip"
#define KEY_ID_ID	"id"
#define KEY_ID_DESC	"descript"
#define KEY_ID_THREAD	"thread"
#define KEY_ID_PATH	"path"
#define KEY_ID_CMD	"command"
#define KEY_ID_ARGS	"args"
#define KEY_ID_RET	"return"
#define KEY_ID_DELAY	"delay"
#define KEY_ID_LOOP	"loop"
#define KEY_ID_SLEEP	"sleep"
#define KEY_ID_LOGO	"logofile"
#define	_KEY_(c)	(c)

typedef struct task_desc_t {
	const char *name;
	const char *retdir;
	const char *desc, *path, *cmd, *args, *logo;
	char exec[256] = { 0, };
	int id;
	bool isthread;
	int delay, loop, sleep;
	int min, max;
	int priority;
	int retval = 0;
	bool active = false;
	bool success = false;
	int count = 0;
	TIMESTEMP_T time = { 1000 * 1000, 0, 0, 0 };
	TaskManager *manager;
} TASK_DESC_T;

class TaskParser {
public:
	TaskParser(void) { };
	~TaskParser(void);

	bool LoadFile(const char *File);
	int GetTaskNum(void) const;
	bool ParseTask(TASK_DESC_T *Task, int Index);
	char *GetResultDir(void) const;
	bool IsContinue(void) const;

private:
	bool ParseKey(const char *Key,
			struct json_object *Jobj);

	const char *GetKeyValueStr(struct json_object *Jobj, const char *Key);
	const int   GetKeyValueInt(struct json_object *Jobj, const char *Key);
	const bool  GetKeyValueBool(struct json_object *Jobj, const char *Key);
	const int   GetKeyValueArray(
			struct json_object *Jobj, const char *Key, int Index);

	typedef struct key_obj_t {
		const char *name;
		struct json_object *obj;
		int priority;

		key_obj_t(const char *Name, struct json_object *Jobj) {
			name = Name, obj = Jobj;
			priority = 0;
		}
	} KEY_OBJ_T;

	static bool key_cmp(const KEY_OBJ_T *a, const KEY_OBJ_T *b) {
		string sa = a->name, sb = b->name;

		return stoi(sa) < stoi(sb);
	}

private:
	const char *m_File = NULL;
	const char *m_ResultDir = NULL;
	bool m_Continue = false;
	struct json_object *m_pJobj = NULL;
	vector <KEY_OBJ_T *> m_KeyList;
};

#define	__print__(format, ...) do { \
		fprintf(stdout, format, ##__VA_ARGS__); \
	} while (0)

#define	__logo_id__(t, i) do { \
		i = !t ? -1 : t->priority; \
	} while (0)

class Logger {
private:
	typedef struct log_desc_t {
		int id;
		char *buffer;
		int size;
		int offset;

		log_desc_t(
			int Id = 0,
			int Size = 0
			)
		{
			if (Size > 0) {
				id = Id;
				buffer = new char[Size];
				size = Size;
				offset = 0;
				memset(buffer, 0, size);
			}
		}
		~log_desc_t(void) {
			if (buffer)
				delete buffer;
		}
	} LOG_DESC_T;

public:
	Logger(const char *Dir, const char *File, size_t LogSize, bool Print);
	~Logger(void);

	int  Write(TASK_DESC_T *Task, const char *Format, ...);
	void Dump(TASK_DESC_T *Task);
	void Done(TASK_DESC_T *Task);

private:
	char m_File[256] = { 0, };
	int m_LogSize = 0;
	pthread_mutex_t *m_pLock = NULL;
	bool m_bPrint = false;
	vector <LOG_DESC_T *> m_BList;
};

class TaskManager {
public:
	TaskManager(void);
	~TaskManager(void);

	bool  LoadTask(const char *File);

	void  SetPrivData(void *Data);
	void *GetPrivData(void);

	char *GetResultDir(void) const;
	void SetResultDir(const char *RetDir);
	void SetContinue(bool Continue);
	bool IsContinue(void);

	int GetTaskNum(void);

	TASK_DESC_T *TaskGet(void);
	void TaskPut(void);

	void ExitFail(void);
	bool IsExitFail(void);
	bool IsSuccess(void);

public:
	void SetLogger(Logger *Log) { m_pLog = Log; }
	Logger *GetLogger(void) { return m_pLog; }

private:
	TaskParser * m_Parser = NULL;
	char m_ResultDir[256] = { 0, };
	bool m_ExitTask = false;
	void *m_pData = NULL;
	pthread_mutex_t *m_pLock = NULL;
	vector <TASK_DESC_T *> m_TaskList;
	int m_Tasks = 0;
	int m_RefCount = 0;
	Logger *m_pLog = NULL;
	bool m_Continue = false;
};
#endif
