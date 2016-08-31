#include "hash.h"
#include "vsrv.h"
#include <fcntl.h>
#include <pthread.h>

struct server default_server;
struct hashtable server_hash;

void vsrv_init(struct server *srv, const char *name, const char *root)
{
	memset(srv, 0, sizeof(*srv));
	srv->name = name;
	srv->rootfd = open(root, O_RDONLY);
	hash_init(&srv->resources);
	pthread_mutex_init(&srv->lru_lock, NULL);
	hash_ingest(&server_hash, name, srv);
}

