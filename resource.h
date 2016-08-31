#pragma once
#include <stdbool.h>
#include <limits.h>
#include <pthread.h>
struct resource {
	char response[1024];
	char path[PATH_MAX];
	_Atomic int fd;
	size_t resp_len, cont_len;
	struct resource *next, *prev;
	pthread_rwlock_t rwlock;
};


