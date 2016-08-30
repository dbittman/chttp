#pragma once
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
struct entry {
	char *key;
	void *val;
};

struct hashtable {
	struct entry *table;
	size_t count;
	size_t len;
};

static inline void hash_init(struct hashtable *h)
{
	h->len = 512;
	h->count = 0;
	h->table = calloc(h->len, sizeof(struct entry));
}

static inline void hash_ingest(struct hashtable *, char *ext, void *);
/* http://cseweb.ucsd.edu/~kube/cls/100/Lectures/lec16/lec16-16.html */
static inline size_t __hashfn(const char *key, size_t tablen)
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

static inline void grow_hashtable(struct hashtable *h)
{
	size_t newlen = h->len * 2;
	struct entry *newtable = calloc(newlen, sizeof(struct entry));
	struct hashtable nh;
	nh.table = newtable;
	nh.len = newlen;
	nh.count = 0;
	for(size_t i=0;i<h->len;i++) {
		struct entry *ent = &h->table[i];
		if(ent->key != NULL) {
			hash_ingest(&nh, ent->key, ent->val);
			free(ent->key);
		}
	}
	free(h->table);
	h->table = newtable;
	h->len = newlen;
}

static inline struct entry *hash_lookup(struct hashtable *h, const char *key)
{
	size_t index = __hashfn(key, h->len);
	for(size_t i=0;i<h->len;i++) {
		struct entry *ent = &h->table[(index + i) % h->len];
		if(ent->key && !strcmp(ent->key, key)) {
			return ent;
		}
	}
	return NULL;
}

static void hash_ingest(struct hashtable *h, char *key, void *val)
{
	size_t index = __hashfn(key, h->len);
	for(size_t i=0;i<h->len;i++) {
		struct entry *ent = &h->table[(index + i) % h->len];

		if(ent->key == NULL) {
			ent->key = strdup(key);
			ent->val = val;
			if((h->count++) * 100 / h->len > 25)
				grow_hashtable(h);
			return;
		}
	}
	fprintf(stderr, "Mime type hash table too small.\n");
	abort();
}

