#pragma once
#include "hash.h"
#include <stddef.h>
#include "resource.h"
#include <pthread.h>
struct server {
	const char *name;
	int rootfd;
	_Atomic int open_files;
	struct hashtable resources;
	struct resource *lru;
	pthread_mutex_t lru_lock;
};

extern struct hashtable server_hash;
extern struct server default_server;

static inline struct server *server_lookup(const char *name)
{
	struct entry *e = hash_lookup(&server_hash, name);
	return e ? e->val : &default_server;
}

void vsrv_init(struct server *srv, const char *name, const char *root);
