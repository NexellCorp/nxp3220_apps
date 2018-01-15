/*
 * Copyright (C) 2016  Nexell Co., Ltd.
 *
 * Author: junghyun, kim <jhkim@nexell.co.kr>
 *
 * SPDX-License-Identifier:	GPL-2.0+
 */
#ifndef _UTIL_H_
#define _UTIL_H_

#include <stdio.h>
#include <errno.h>
#include <sys/time.h>

#if __cplusplus
extern "C" {
#endif

/**
 * util
 */
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

/**
 * times
 */
typedef struct time_stemp_t {
	long long min;
	long long max;
	long long tot;
	long long cnt;
} TIMESTEMP_T;

#define	msleep(m)	usleep(m*1000)

#define	RUN_TIMESTAMP_US(s) {		\
		struct timeval tv;	\
		gettimeofday(&tv, NULL);	\
		s = (tv.tv_sec*1000000) + (tv.tv_usec);	\
	}

#define	END_TIMESTAMP_US(s, d) { \
		struct timeval tv;	\
		gettimeofday(&tv, NULL);	\
		d = (tv.tv_sec*1000000) + (tv.tv_usec);	\
		d = d - s;	\
	}

#define	SET_TIME_STAT(t, d)	do { \
	if (t->min > d) t->min = d; \
	if (d > t->max) t->max = d; \
	t->cnt++, t->tot += d; \
	} while (0)

/**
 * debug
 */
#define	LogI(format, ...) do { \
		fprintf(stdout, format, ##__VA_ARGS__); \
	} while (0)
#define	LogE(format, ...) do { \
		fprintf(stderr, "ERROR: %s:%d: ", __func__, __LINE__); \
		fprintf(stderr, format, ##__VA_ARGS__); \
	} while (0)

#ifdef DEBUG
#define	LogD(msg...) do { \
		fprintf(stdout, msg); \
	} while (0)
#else
#define	LogD(m...)	do { } while (0)
#endif

#if __cplusplus
}
#endif
#endif /* _UTIL_H_ */

