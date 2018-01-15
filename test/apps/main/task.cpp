/*
 * Copyright (C) 2016  Nexell Co., Ltd.
 *
 * Author: junghyun, kim <jhkim@nexell.co.kr>
 *
 * SPDX-License-Identifier:	GPL-2.0+
 */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <list>

#include "util.h"
#include "task.h"

TaskParser::~TaskParser(void)
{
	/* release json object */
	if (m_pJobj)
		json_object_put(m_pJobj);

	for (auto k = m_KeyList.begin(); k != m_KeyList.end();) {
		delete (*k);
		k = m_KeyList.erase(k);

	}
}

const char *TaskParser::GetKeyValueStr(
			struct json_object *Jobj, const char *Key)
{
	assert(m_pJobj && Jobj);

	struct json_object *obj = json_object_object_get(Jobj, Key);
	if (!obj)
		return NULL;

	if (!json_object_is_type(obj, json_type_string)) {
		LogE("%s:%s: not string :%s\n",
			m_File, Key, json_object_to_json_string(obj));
		return NULL;
	}
	const char *c = json_object_get_string(obj);

	if (!strlen(c))
		return NULL;

	return c;
}

const int TaskParser::GetKeyValueInt(
			struct json_object *Jobj, const char *Key)
{
	assert(m_pJobj && Jobj);

	struct json_object *obj = json_object_object_get(Jobj, Key);
	if (!obj)
		return 0;

	if (!json_object_is_type(obj, json_type_int)) {
		LogE("%s:%s: not int :%s\n",
			m_File, Key, json_object_to_json_string(obj));
		return 0;
	}

	return json_object_get_int(obj);
}

const bool TaskParser::GetKeyValueBool(
			struct json_object *Jobj, const char *Key)
{
	assert(m_pJobj && Jobj);

	struct json_object *obj = json_object_object_get(Jobj, Key);

	if (!obj)
		return false;

	if (!json_object_is_type(obj, json_type_boolean)) {
		LogE("%s:%s: not bool :%s\n",
			m_File, Key, json_object_to_json_string(obj));
		return false;
	}

	return json_object_get_boolean(obj) ? true : false ;
}

const int TaskParser::GetKeyValueArray(
			struct json_object *Jobj, const char *Key, int Index)
{
	assert(m_pJobj && Jobj);

	struct json_object *obj = json_object_object_get(Jobj, Key);

	if (!obj)
		return 0;

	if (!json_object_is_type(obj, json_type_array)) {
		LogE("%s:%s: not array :%s\n",
			m_File, Key, json_object_to_json_string(obj));
		return 0;
	}

	int length = json_object_array_length(obj);

	if (Index > length - 1) {
		LogE("%s:%s: %d over arrays %d : %s\n",
			m_File, Key, Index, length,
			json_object_to_json_string(obj));
		return 0;
	}

	json_object *j = json_object_array_get_idx(obj, Index);

	if (!json_object_is_type(j, json_type_int)) {
		LogE("%s:%s: not int :%s\n",
			m_File, Key, json_object_to_json_string(obj));
		return 0;
	}

	return json_object_get_int(j);
}

bool TaskParser::LoadFile(const char *File)
{
	assert(!m_pJobj);

	struct json_object *jobj = json_object_from_file(File);

	if (!jobj) {
		LogE("json_tokener_parse for %s: %s\n",
			File, json_util_get_last_err());
		LogI("Check : cat %s | python -m json.tool\n", File);
		return false;
	}

	if (!json_object_to_json_string_ext(jobj,
		JSON_C_TO_STRING_SPACED | JSON_C_TO_STRING_PRETTY)) {
		LogE("json_object_to_json_string_ext for %s: %s\n",
			File, json_util_get_last_err());
		return false;
	}

        m_File = File, m_pJobj = jobj;

	/*
	LogD("jobj from str:%s [%d]\n---\n%s\n---\n",
		m_File, json_object_object_length(jobj),
		json_object_to_json_string_ext(jobj,
		JSON_C_TO_STRING_SPACED | JSON_C_TO_STRING_PRETTY));
	*/

	json_object_object_foreach(jobj, key, obj) {
		/*
		 * parse jsion object if ojbect type
		 */
		if (json_object_is_type(obj, json_type_object))
			ParseKey(key, obj);
		else if (!strcmp(key, KEY_ID_RESULT))
			m_ResultDir = json_object_get_string(obj);
		else if (!strcmp(key, KEY_ID_CONTINUE))
			m_Continue = json_object_get_boolean(obj);
	}

	/* sort with priority */
	sort(m_KeyList.begin(), m_KeyList.end(), key_cmp);

        return true;
}

char *TaskParser::GetResultDir(void) const
{
	return (char *)m_ResultDir;
}

bool TaskParser::IsContinue(void) const
{
	return m_Continue;
}

int TaskParser::GetTaskNum(void) const
{
	return m_KeyList.size();
}

bool TaskParser::ParseKey(const char *Key, struct json_object *Jobj)
{
	assert(Jobj);

	if (atoi(Key) == 0 && Key[0] != '0') {
		LogE("KEY: '%s' is not a number !!!\n", Key);
		return false;
	}

	if (!GetKeyValueStr(Jobj, _KEY_(KEY_ID_CMD)))
		return false;

	if (GetKeyValueBool(Jobj, _KEY_(KEY_ID_SKIP)))
		return false;

	KEY_OBJ_T *kobj = new KEY_OBJ_T(Key, Jobj);
	assert(kobj);

	kobj->obj = Jobj;
	kobj->priority = atoi(Key);

	m_KeyList.push_back(kobj);

	return true;
}

bool TaskParser::ParseTask(TASK_DESC_T *Task, int Index)
{
	assert(m_pJobj && Task);

	KEY_OBJ_T *kobj = m_KeyList[Index];
	struct json_object *jobj = kobj->obj;
	string s;
	const char *c;

	/*
 	 * parse task descripts
	 */
	Task->name = kobj->name;
	Task->retdir = m_ResultDir;
	Task->priority = kobj->priority;
	Task->id = GetKeyValueInt(jobj, _KEY_(KEY_ID_ID));
	Task->desc = GetKeyValueStr(jobj, _KEY_(KEY_ID_DESC));
	Task->isthread = GetKeyValueBool(jobj, _KEY_(KEY_ID_THREAD));
	Task->path = GetKeyValueStr(jobj, _KEY_(KEY_ID_PATH));
	Task->cmd = GetKeyValueStr(jobj, _KEY_(KEY_ID_CMD));
	Task->args = GetKeyValueStr(jobj, _KEY_(KEY_ID_ARGS));
	Task->delay = GetKeyValueInt(jobj, _KEY_(KEY_ID_DELAY));
	Task->loop = GetKeyValueInt(jobj, _KEY_(KEY_ID_LOOP));
	Task->sleep = GetKeyValueInt(jobj, _KEY_(KEY_ID_SLEEP));
	Task->logo = GetKeyValueStr(jobj, _KEY_(KEY_ID_LOGO));
	Task->min = GetKeyValueArray(jobj, _KEY_(KEY_ID_RET), 0);
	Task->max = GetKeyValueArray(jobj, _KEY_(KEY_ID_RET), 1);

	c = Task->path;
	if (c) {
		s = c;
		if (c[strlen(c)-1] != '/')
			s += '/';
	}

	s += Task->cmd;
	c = Task->args;
	if (c)
		s = s + ' ' + c;

	strcpy(Task->exec, s.c_str());

	if (Task->max < Task->min)
		Task->max = Task->min;

	LogD("[%s] %s \n", Task->name, Task->retdir);
	LogD("\tEXEC     : %s\n", Task->exec);
	LogD("\tid       : %d\n", Task->id);
	LogD("\tdescript : %s\n", Task->desc);
	LogD("\tthread   : %s\n", Task->isthread ? "yes" : "no");
	LogD("\tcontinue : %s\n", Task->nostop ? "yes" : "no");
	LogD("\tpath     : %s\n", Task->path);
	LogD("\tcommand  : %s\n", Task->cmd);
	LogD("\targs     : %s\n", Task->args);
	LogD("\treturn   : %d,%d\n", Task->min, Task->max);
	LogD("\tdelay    : %d\n", Task->delay);
	LogD("\tloop     : %d\n", Task->loop);
	LogD("\tsleep    : %d\n", Task->sleep);
	LogD("\tlogofile : %s\n", Task->logo);

	return true;
}

Logger::Logger(const char *Dir, const char *File, size_t LogSize, bool Print)
{
	string s = File;

	if (Dir && 0 != access(Dir, W_OK)) {
		fprintf(stderr, "ERROR %s : %s\n", Dir, strerror(errno));
		return;
	}

	if (Dir) {
		s = Dir;
		if (Dir[strlen(Dir)-1] != '/')
			s += '/';
		s += File;
	}

	/* create file */
	FILE *fp = fopen(s.c_str(), "wb+");
	if (!fp) {
		fprintf(stderr, "ERROR %s : %s\n", s.c_str(), strerror(errno));
		return;
	}
	fclose(fp);

	if (!LogSize)
		LogSize = 4096;

	m_LogSize = LogSize;
	m_bPrint = Print;
	strcpy(m_File, s.c_str());

	/*
	 * create shared mutex
	 * for mutex with fork process
	 */
	int prot = PROT_READ | PROT_WRITE;
    	int flags = MAP_SHARED | MAP_ANONYMOUS;

    	m_pLock = (pthread_mutex_t *)mmap(NULL,
    			sizeof(pthread_mutex_t), prot, flags, -1, 0);
    	assert(m_pLock);

    	pthread_mutexattr_t attr;
    	pthread_mutexattr_init(&attr);
    	pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
    	pthread_mutex_init(m_pLock, &attr);
}

Logger::~Logger(void)
{
	for (auto l = m_BList.begin(); l != m_BList.end();) {
		delete (*l);
		l = m_BList.erase(l);
	}
}

int Logger::Write(TASK_DESC_T *Task, const char *Format, ...)
{
	vector<LOG_DESC_T *>::iterator li;
	LOG_DESC_T *log = NULL;
	va_list args;
	char buf[2048];
	int len;
	int id;

	assert(m_LogSize && m_pLock);

	__logo_id__(Task, id);

	pthread_mutex_lock(m_pLock);

	for (li = m_BList.begin(); li != m_BList.end(); ++li) {
		log = (*li);
		if (id == log->id)
			break;
	}

	if (li == m_BList.end()) {
		log = new LOG_DESC_T(id, m_LogSize);
		m_BList.push_back(log);
	}

	va_start(args, Format);
	vsprintf(buf, Format, args);
	va_end(args);
	len = strlen(buf);

	if (log->size - (log->offset + len) < 0) {
		fprintf(stderr, "ERROR over buffer size %d require %d\n",
			log->size, log->offset + len);
		pthread_mutex_unlock(m_pLock);
		return -EINVAL;
	}

	if (m_bPrint)
		__print__("%s", buf);

	strcpy(log->buffer + log->offset, buf);
	log->offset += len;

	pthread_mutex_unlock(m_pLock);

	return len;
}

void Logger::Dump(TASK_DESC_T *Task)
{
	vector<LOG_DESC_T *>::iterator li;
	LOG_DESC_T *log;
	int id;

	assert(m_LogSize && m_pLock);

	__logo_id__(Task, id);

	for (li = m_BList.begin(); li != m_BList.end(); ++li) {
		log = (*li);
		if (id == log->id)
			break;
	}

	if (li == m_BList.end()) {
		fprintf(stderr, "No log buffer for %d\n", id);
		return;
	}

	pthread_mutex_lock(m_pLock);

	if (!m_bPrint)
		__print__("%s", log->buffer);

	pthread_mutex_unlock(m_pLock);
}

void Logger::Done(TASK_DESC_T *Task)
{
	vector<LOG_DESC_T *>::iterator li;
	LOG_DESC_T *log;
	FILE *fp;
	int id;

	assert(m_LogSize && m_pLock);

	__logo_id__(Task, id);

	for (li = m_BList.begin(); li != m_BList.end(); ++li) {
		log = (*li);
		if (id == log->id)
			break;
	}

	if (li == m_BList.end()) {
		fprintf(stderr, "No log buffer for %d\n", id);
		return;
	}

	pthread_mutex_lock(m_pLock);

	fp = fopen(m_File, "a+");
	if (!fp) {
		fprintf(stderr, "ERROR %s : %s\n", m_File, strerror(errno));
		pthread_mutex_unlock(m_pLock);
		return;
	}

	fwrite(log->buffer, 1, strlen(log->buffer), fp);
	fclose(fp);

	log->offset = 0;
	pthread_mutex_unlock(m_pLock);
}

TaskManager::TaskManager(void)
{
	/*
	 * create shared mutex
	 * for mutex with fork process
	 */
	int prot = PROT_READ | PROT_WRITE;
    	int flags = MAP_SHARED | MAP_ANONYMOUS;

    	m_pLock = (pthread_mutex_t *)mmap(NULL,
    			sizeof(pthread_mutex_t), prot, flags, -1, 0);
    	assert(m_pLock);

    	pthread_mutexattr_t attr;
    	pthread_mutexattr_init(&attr);
    	pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
    	pthread_mutex_init(m_pLock, &attr);
}

TaskManager::~TaskManager(void)
{
	/* release json object */
	if (m_Parser)
		delete m_Parser;

	for (auto t = m_TaskList.begin(); t != m_TaskList.end();) {
		delete (*t);
		t = m_TaskList.erase(t);
	}

	if (m_pLock)
		munmap(m_pLock, sizeof(pthread_mutex_t));
}

bool TaskManager::LoadTask(const char *File)
{
	assert(!m_Parser);
	TaskParser *parser = new TaskParser;

	if (!parser->LoadFile(File)) {
		delete parser;
		return false;
	}

	int size = parser->GetTaskNum();

	for (int i = 0; i < size; i++) {
		TASK_DESC_T *task = new TASK_DESC_T;
		bool ret = parser->ParseTask(task, i);

		assert(ret);
		m_TaskList.push_back(task);
	}

	strcpy(m_ResultDir, parser->GetResultDir());
	m_Continue = parser->IsContinue();
	m_Parser = parser;

	return true;
}

void TaskManager::SetPrivData(void *Data)
{
	m_pData = Data;
}

void *TaskManager::GetPrivData(void)
{
	return m_pData;
}

char *TaskManager::GetResultDir(void) const
{
	assert(m_Parser);

	return (char *)m_ResultDir;
}

void TaskManager::SetResultDir(const char *RetDir)
{
	assert(m_Parser);
	assert(RetDir);

	strcpy(m_ResultDir, RetDir);
}

bool TaskManager::IsContinue(void)
{
	assert(m_Parser);

	return m_Continue;
}

void TaskManager::SetContinue(bool Continue)
{
	assert(m_Parser);

	m_Continue = Continue;
}

int TaskManager::GetTaskNum(void)
{
	return m_TaskList.size();
}

TASK_DESC_T *TaskManager::TaskGet(void)
{
	assert(m_Parser);
	int size = m_TaskList.size();

	if (!size || m_RefCount > size - 1) {
		LogE("Invalid task refcount %d, avaliable 0~%d\n",
			m_RefCount, size - 1);
		return NULL;
	}

	TASK_DESC_T *task = m_TaskList[m_RefCount];

	pthread_mutex_lock(m_pLock);
	if (task)
		m_RefCount++;
	pthread_mutex_unlock(m_pLock);

	return task;
}

void TaskManager::TaskPut(void)
{
	assert(m_Parser);

	pthread_mutex_lock(m_pLock);

	m_RefCount--;
	if (m_RefCount < 0)
		m_RefCount = 0;

	pthread_mutex_unlock(m_pLock);
}

void TaskManager::ExitFail(void)
{
	pthread_mutex_lock(m_pLock);
	m_ExitTask = true;
	pthread_mutex_unlock(m_pLock);
}

bool TaskManager::IsExitFail(void)
{
	bool exit;

	pthread_mutex_lock(m_pLock);
	exit = m_ExitTask;
	pthread_mutex_unlock(m_pLock);

	return exit;
}

bool TaskManager::IsSuccess(void)
{
	for (auto t = m_TaskList.begin(); t != m_TaskList.end(); ++t) {
		TASK_DESC_T *task = (*t);

		if (task->active && !task->success)
			return false;
	}

	return true;
}
