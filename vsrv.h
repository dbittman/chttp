#pragma once
#include "hash.h"
#include <stddef.h>
struct server {
	char *name;
	int rootfd;
};

extern struct hashtable server_hash;
extern struct server default_server;

static inline struct server *server_lookup(const char *name)
{
	struct entry *e = hash_lookup(&server_hash, name);
	return e ? e->val : NULL;
}


