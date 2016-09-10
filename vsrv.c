#include "hash.h"
#include "vsrv.h"
#include <fcntl.h>
#include <pthread.h>
#include <assert.h>
struct server default_server;
struct hashtable server_hash;
/* test:
 * GET / -> GET /index.html
 * GET /(?<foo>[a-z]+)/test -> GET /test/${foo}
 */
PCRE2_SPTR router = "(*MARK:0)^GET /$|(*MARK:1)^GET /(?<foo>[a-z]+)/test$";
/*
 * (*MARK:0)^GET /$
 * |
 * (*MARK:1)^GET /(?<foo>[a-z]+)/test$
 */
PCRE2_SPTR p0 = "^GET /$";
PCRE2_SPTR r0 = "GET /index.html";
PCRE2_SPTR p1 = "^GET /(?<foo>[a-z]+)/test$";
PCRE2_SPTR r1 = "GET /test/${foo}";


void vsrv_init(struct server *srv, const char *name, const char *root)
{
	memset(srv, 0, sizeof(*srv));
	srv->name = name;
	srv->rootfd = open(root, O_RDONLY);
	hash_init(&srv->resources);
	pthread_mutex_init(&srv->lru_lock, NULL);
	hash_ingest(&server_hash, name, srv);

	int errnum;
	PCRE2_SIZE erroff;
	srv->router = pcre2_compile(router, PCRE2_ZERO_TERMINATED, 0, &errnum, &erroff, NULL); /* TODO: handle errors */
	assert(srv->router);

	srv->routes = calloc(2, sizeof(pcre2_code *));
	srv->repl = calloc(2, sizeof(PCRE2_SPTR));

	srv->routes[0] = pcre2_compile(p0, PCRE2_ZERO_TERMINATED, 0, &errnum, &erroff, NULL);
	srv->routes[1] = pcre2_compile(p1, PCRE2_ZERO_TERMINATED, 0, &errnum, &erroff, NULL);

	assert(srv->routes[0]);
	assert(srv->routes[1]);

	srv->repl[0] = r0;
	srv->repl[1] = r1;
}

