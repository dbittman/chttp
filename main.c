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
#include <linux/futex.h>
#include <sys/time.h>
#include <sys/syscall.h>
#include <fcntl.h>

struct entry {
	char *key;
	char *val;
	size_t vallen;
};

struct entry *hashtable;
size_t hashtablelen = 512;
size_t num_entries = 0;

void ingest(struct entry *table, size_t tablen, char *ext, char *mime);
/* http://cseweb.ucsd.edu/~kube/cls/100/Lectures/lec16/lec16-16.html */
size_t hashfn(const char *key, size_t tablen)
{
	long hashVal = 0;
	while (*key != '\0') {
		hashVal = (hashVal << 4) + *(key++);
		long g = hashVal & 0xF0000000L;
		if (g != 0) hashVal ^= g >> 24;
		hashVal &= ~g;
	}
	return hashVal % tablen;
}

void grow_hashtable(void)
{
	size_t newlen = hashtablelen * 2;
	struct entry *newtable = calloc(newlen, sizeof(struct entry));
	for(size_t i=0;i<hashtablelen;i++) {
		struct entry *ent = &hashtable[i];
		if(ent->key != NULL) {
			ingest(newtable, newlen, ent->key, ent->val);
			free(ent->key);
			free(ent->val);
		}
	}
	free(hashtable);
	hashtable = newtable;
	hashtablelen = newlen;
}

char *lookup(const char *key, size_t *len)
{
	size_t index = hashfn(key, hashtablelen);
	for(size_t i=0;i<hashtablelen;i++) {
		struct entry *ent = &hashtable[(index + i) % hashtablelen];
		if(ent->key && !strcmp(ent->key, key)) {
			*len = ent->vallen;
			return ent->val;
		}
	}
	return NULL;
}

/* TODO: better hashing */
void ingest(struct entry *table, size_t tablen, char *ext, char *mime)
{
	size_t index = hashfn(ext, tablen);
	for(size_t i=0;i<tablen;i++) {
		struct entry *ent = &table[(index + i) % tablen];

		if(ent->key == NULL) {
			ent->key = strdup(ext);
			ent->val = strdup(mime);
			ent->vallen = strlen(ent->val);
			return;
		}
	}
	fprintf(stderr, "Mime type hash table too small.\n");
	abort();
}

void init_mime_database(void)
{
	hashtable = calloc(hashtablelen, sizeof(struct entry));
	FILE *f = fopen("/etc/mime.types", "r");
	if(f == NULL) {
		perror("Failed to open mime database");
		exit(1);
	}

	char buffer[1024];
	while(fgets(buffer, 1024, f)) {
		if(buffer[0] == '#' || buffer[0] == '\n')
			continue;

		/* some mime types have multiple extensions */
		char *mime = strtok(buffer, " \t");
		char *extension;
		while((extension = strtok(NULL, " \t\n"))) {
			ingest(hashtable, hashtablelen, extension, mime);
			if((num_entries++ * 100) / hashtablelen > 25) {
				grow_hashtable();
			}
		}
	}
	printf("mime database initialized with %ld entries\n", num_entries);
}

char *server_root = "root";
int num_threads = 128;

int rootfd;

struct threaddata {
	int tid;
};

static _Atomic int *mailbox;

static int futex(int *uaddr, int futex_op, int val, const struct timespec *timeout, int *uaddr2, int val3)
{
    return syscall(SYS_futex, uaddr, futex_op, val, timeout, uaddr2, val3);
}

static _Atomic long last_mailbox = 0;

void write_content_type(int client, char *path)
{
	write(client, "Content-Type: ", 14);
	char *last_dot = strrchr(path, '.');
	if(last_dot) {
		size_t len;
		char *m = lookup(last_dot + 1, &len);
		write(client, m, len);
	} else {
		write(client, "text/plain", 10);
	}
	write(client, "\r\n", 2);
}

void handle_get(int client, char *buf)
{
	char *path = buf + 5;
	char *space = strchr(path, ' ');
	if(space) {
		*space = '\0';
	}
	if(path[0] == '\0') {
		path = "index.html";
	}

	int fd = openat(rootfd, path, O_RDONLY);
	if(fd == -1) {
		/* send err */
		const char *err_resp = "HTTP/1.1 404 Not Found\r\n\r\nGo Fish!";
		write(client, err_resp, strlen(err_resp));
	} else {
		char data[1024];
		ssize_t len;

		const char *resp = "HTTP/1.1 200 OK\r\nServer: chttp\r\n";
		write(client, resp, strlen(resp));
		write_content_type(client, path);
		write(client, "\r\n", 2);

		while((len = read(fd, data, 1024)) > 0) {
			if(write(client, data, len) == -1) {
				break;
			}
		}
	}
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

	while((len = read(client, buf, curlen - total)) >= 0 || total == 0) {
		if(len == -1)
			continue;
		int flags = fcntl(client, F_GETFL);
		fcntl(client, F_SETFL, flags | O_NONBLOCK);
		total += len;
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
	
	if(!strncmp(buf, "GET", 3)) {
		handle_get(client, buf);
	} else {
		const char *err_resp = "HTTP/1.1 400 Bad Request\r\n\r\nBad Request!";
		write(client, err_resp, strlen(err_resp));
	}


	close(client);
	if(alloc)
		free(buf);
}

void *thread_main(void *data)
{
	struct threaddata *td = data;
	int mb = td->tid;
	while(true) {
		int client = atomic_load(&mailbox[mb]);
		if(client != 0) {
			thread_client(client);

			atomic_store(&mailbox[mb], 0);
			atomic_store(&last_mailbox, mb);
		} else {
			if(futex((int *)&mailbox[mb], FUTEX_WAIT, 0, NULL, NULL, 0) == -1) {
				perror("futex");
			}
		}
	}
}

void handle_client(int client)
{
	while(true) {
		int expect = 0;
		int mb = atomic_load(&last_mailbox) % num_threads;
		if(atomic_compare_exchange_strong(&mailbox[mb], &expect, client)) {
			futex((int *)&mailbox[mb], FUTEX_WAKE, 1, NULL, NULL, 0);
			break;
		}

		atomic_fetch_add(&last_mailbox, 1);
	}
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

int main(int argc, char **argv)
{
	parse_cmd_opts(argc, argv);
	rootfd = open(server_root, O_RDONLY);
	if(rootfd == -1) {
		perror("Failed to open server root");
		exit(1);
	}
	
	init_mime_database();

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

	printf("Listening!\n");

	for(int i=0;i<num_threads;i++) {
		td[i].tid = i;
		pthread_create(&threads[i], NULL, thread_main, &td[i]);
	}

	struct sockaddr_in caddr;
	socklen_t caddr_len;
	int client;
	while((client = accept(sock, (struct sockaddr *)&caddr, &caddr_len)) != -1) {
		handle_client(client);
	}

	perror("Accept failed");
	return 1;
}

