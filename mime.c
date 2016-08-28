#include <stdlib.h>
#include <string.h>
#include <stdio.h>
struct entry {
	char *key;
	char *val;
	size_t vallen;
};

static struct entry *hashtable;
static size_t hashtablelen = 512;
static size_t num_entries = 0;

static void ingest(struct entry *table, size_t tablen, char *ext, char *mime);
/* http://cseweb.ucsd.edu/~kube/cls/100/Lectures/lec16/lec16-16.html */
static size_t hashfn(const char *key, size_t tablen)
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

static void grow_hashtable(void)
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

char *mime_lookup(const char *key, size_t *len)
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
static void ingest(struct entry *table, size_t tablen, char *ext, char *mime)
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
	fclose(f);
}


