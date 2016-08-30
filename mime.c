#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "hash.h"

static struct hashtable mime_table;
char *mime_lookup(const char *key)
{
	struct entry *e = hash_lookup(&mime_table, key);
	if(e) {
		return e->val;
	}
	return NULL;
}

void init_mime_database(void)
{
	hash_init(&mime_table);
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
			hash_ingest(&mime_table, extension, strdup(mime));
		}
	}
	printf("mime database initialized with %ld entries\n", mime_table.count);
	fclose(f);
}

