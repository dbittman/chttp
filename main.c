#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <time.h>
#include <sys/time.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/sendfile.h>

#include "mime.h"
#include "futex.h"
#include "hash.h"
#include "vsrv.h"

/* github: http://github.com/dbittman/chttp */

char *default_server_root = "root";
unsigned num_threads = 128;

struct threaddata {
	int tid;
};

static inline unsigned long long rdtsc(void)
{
	unsigned hi, lo;
	__asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
	return ( (unsigned long long)lo)|(((unsigned long long)hi)<<32);
}

static _Atomic int *mailbox;

static _Atomic long last_mailbox = 0;

const char *mime_get(char *path)
{
	char *last_dot = strrchr(path, '.');
	if(last_dot) {
		char *ret = mime_lookup(last_dot + 1);
		return ret ? ret : "text/plain";
	}
	return "text/plain";
}

void handle_get(struct server *srv, int client, char *buf)
{
	char *path = buf + 5;
	char *space = strchr(path, ' ');
	if(space) {
		*space = '\0';
	}
	if(path[0] == '\0') {
		path = "index.html";
	}

	int fd = openat(srv->rootfd, path, O_RDONLY);
	if(fd == -1) {
		/* send err */
		const char *err_resp = "HTTP/1.1 404 Not Found\r\n\r\nGo Fish!";
		write(client, err_resp, strlen(err_resp));
	} else {
		struct stat sb;
		if(fstat(fd, &sb) == 0) {
			char response[1024];
			int len = snprintf(response, 1024,
					"HTTP/1.1 200 OK\r\n"
					"Server: chttp\r\n"
					"Content-Type: %s\r\n"
					"Content-Length: %ld\r\n"
					"\r\n",
					mime_get(path),
					sb.st_size);

			write(client, response, len);
			sendfile(client, fd, NULL, sb.st_size);
		} /* TODO: handle failure? */

	}
	close(fd);
}

void bad_request(int client)
{
	const char *err_resp = "HTTP/1.1 400 Bad Request\r\n\r\nBad Request!";
	write(client, err_resp, strlen(err_resp));
}

#define STACK_LEN 1024
const size_t page_size = 4096;
void thread_client(int client)
{
	ssize_t len, total = 0;
	ssize_t curlen = STACK_LEN;
	char _stackbuf[STACK_LEN];
	char *buf = _stackbuf;
	bool alloc = false;

	while((len = read(client, buf + total, curlen - total)) >= 0 || total == 0) {
		if(len == -1)
			continue;
		total += len;

		if(buf[total-1] == '\n' && buf[total-2] == '\r'
				&& buf[total-3] == '\n' && buf[total-4] == '\r') {
			break;
		}

		int flags = fcntl(client, F_GETFL);
		fcntl(client, F_SETFL, flags | O_NONBLOCK);
		if(alloc) {
			if(total >= curlen) {
				curlen *= 2;
				buf = realloc(buf, curlen);
			}
		} else {
			if(total >= STACK_LEN) {
				buf = malloc(page_size);
				memcpy(buf, _stackbuf, STACK_LEN);
				alloc = true;
				curlen = page_size;
			}
		}
	}
	if(len < 0 && errno != EAGAIN) {
		perror("thread_client failed");
		close(client);
		return;
	}
	
	char *host = strstr(buf, "Host: ");
	if(!host) {
		bad_request(client);
	} else {
		char *servername = host + 6;
		char *col = strchr(servername, ':');
		if(col) *col = 0;
		struct server *srv = server_lookup(servername);
		if(col) *col = ':';

		if(!strncmp(buf, "GET", 3)) {
			handle_get(srv, client, buf);
		} else {
			bad_request(client);
		}
	}

	close(client);
	if(alloc)
		free(buf);
}

#define PROFILE 0

/* TODO: make this configurable */
#define TIMEOUT 10000

void *thread_main(void *data)
{
#if PROFILE
	static unsigned long long mean = 0;
	static long _count = 0;
	static unsigned long long meanns = 0;
#endif
	struct threaddata *td = data;
	int mb = td->tid;
	int timeout = TIMEOUT;
	while(true) {
		int client = atomic_load(&mailbox[mb]);
		if(client != 0) {
#if PROFILE
			struct timespec start, end;
			clock_gettime(CLOCK_THREAD_CPUTIME_ID, &start);
			unsigned long long tsc = rdtsc();
#endif
			thread_client(client);
#if PROFILE
			unsigned long long tsc2 = rdtsc();
			clock_gettime(CLOCK_THREAD_CPUTIME_ID, &end);
			mean = ((mean * _count) + (tsc2 - tsc)) / (_count + 1);
			meanns = ((meanns * _count) + (end.tv_nsec - start.tv_nsec)) / (_count + 1);
			_count++;
			printf("%lld, %lld\n", tsc2 - tsc, mean);
			printf(":: %ld %lld\n", (end.tv_nsec - start.tv_nsec), meanns);
#endif

			atomic_store(&mailbox[mb], 0);
			atomic_store(&last_mailbox, mb);
		} else if(--timeout == 0) {
			timeout = TIMEOUT;
			futex((int *)&mailbox[mb], FUTEX_WAIT, 0, NULL, NULL, 0);
		}
	}
}

void handle_client(int client)
{
#if PROFILE
	static unsigned long mean;
	static unsigned long _count;
	unsigned long long tsc = rdtsc();
#endif
	int mb;
	while(true) {
		int expect = 0;
		mb = atomic_load(&last_mailbox) % num_threads;
		if(atomic_compare_exchange_strong(&mailbox[mb], &expect, client)) {
			futex((int *)&mailbox[mb], FUTEX_WAKE, 1, NULL, NULL, 0);
			break;
		}

		atomic_fetch_add(&last_mailbox, 1);
	}
#if PROFILE
	unsigned long long tsc2 = rdtsc();
	mean = ((mean * _count) + (tsc2 - tsc)) / (_count + 1);
	_count++;
	printf("enqueue %lld, %ld (to %d)\n", tsc2 - tsc, mean, mb);
#endif
}

void parse_cmd_opts(int argc, char **argv)
{
	int c;
	while((c = getopt(argc, argv, "t:")) != -1) {
		switch(c) {
			char *err;
			case 't':
				num_threads = strtol(optarg, &err, 10);
				if(*err == '\0') {
					if(num_threads <= 0) {
						num_threads = 128;
					}
					printf("%d\n", num_threads);
				} else {
					fprintf(stderr, "-t option requires an integer\n");
					exit(1);
				}
				break;
		}
	}
}

void handler(int sig)
{
	(void)sig;
	exit(1);
}
int main(int argc, char **argv)
{
	signal(SIGINT, handler);
	parse_cmd_opts(argc, argv);

	default_server.name = "[default]";
	default_server.rootfd = open(default_server_root, O_RDONLY);

	if(default_server.rootfd == -1) {
		perror("Failed to open server root");
		exit(1);
	}
	
	init_mime_database();
	hash_init(&server_hash);
	
	/* temporary test virtual servers */
	struct server joe;
	joe.name = "joe.org";
	joe.rootfd = open("joe", O_RDONLY);
	hash_ingest(&server_hash, joe.name, &joe);
	struct server bob;
	bob.name = "bob.com";
	bob.rootfd = open("bob", O_RDONLY);
	hash_ingest(&server_hash, bob.name, &bob);


	mailbox = calloc(num_threads, sizeof(int));
	pthread_t threads[num_threads];
	struct threaddata td[num_threads];

	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if(sock == -1) {
		perror("Failed to open socket");
		exit(1);
	}

	int enable = 1;
#ifdef SO_REUSEPORT
	if(setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &enable, sizeof(enable)) == -1) {
		perror("Failed to set socket options");
		exit(1);
	}
#endif

	if(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) == -1) {
		perror("Failed to set socket options");
		exit(1);
	}

	struct sockaddr_in bind_addr;
	bind_addr.sin_family = AF_INET;
	bind_addr.sin_port = htons(8080);
	inet_aton("0.0.0.0", &bind_addr.sin_addr);
	if(bind(sock, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) == -1) {
		perror("Failed to bind socket");
		exit(1);
	}

	if(listen(sock, 0) == -1) {
		perror("Failed to listen");
		exit(1);
	}

	struct rlimit lim;
	getrlimit(RLIMIT_NOFILE, &lim);
	if(lim.rlim_cur <= num_threads + 8) {
		fprintf(stderr, "warning - you have more threads than files. Probably not what you want.\n");
	}
	printf("Listening with %d threads, %ld files!\n", num_threads, lim.rlim_cur);

	for(unsigned i=0;i<num_threads;i++) {
		td[i].tid = i;
		pthread_create(&threads[i], NULL, thread_main, &td[i]);
	}

	struct sockaddr_in caddr;
	socklen_t caddr_len = sizeof(caddr);
	int client;
	while((client = accept(sock, (struct sockaddr *)&caddr, &caddr_len)) != -1) {
		handle_client(client);
	}

	perror("Accept failed");
	return 1;
}

