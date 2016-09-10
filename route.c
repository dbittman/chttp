#include <string.h>
#include "vsrv.h"
enum route_result route_request(struct server *srv, char *input, char *output, PCRE2_SIZE *outlen)
{
	/* METHOD URL HTTP/1.1 */
	char *mspace = strchr(input, ' ');
	if(!mspace)
		return ROUTE_ERROR;
	char *uspace = strchr(mspace+1, ' ');
	if(!uspace)
		return ROUTE_ERROR;
	*uspace = '\0';

	size_t input_len = strlen(input);
	pcre2_match_data *router_mdata = pcre2_match_data_create_from_pattern(srv->router, NULL);
	int re = pcre2_match(srv->router, (PCRE2_SPTR)input, input_len, 0, 0, router_mdata, NULL);
	
	if(re == -1) {
		pcre2_match_data_free(router_mdata);
		return ROUTE_NOMATCH;
	}

	//printf("%d %s: %s\n", re, input, pcre2_get_mark(router_mdata));

	char *mark_string = (char *)pcre2_get_mark(router_mdata);
	
	int rte = atoi(mark_string);
	//printf("route number %d\n", rte);
	
	pcre2_match_data *mdata = pcre2_match_data_create_from_pattern(srv->routes[rte], NULL);
	/* TODO: check return value */
	pcre2_substitute(srv->routes[rte], (const unsigned char *)input, input_len,
			0, 0, mdata, NULL,
			srv->repl[rte], strlen((const char *)srv->repl[rte]), (unsigned char *)output, outlen);
	
	/* TODO: remove leading /'s */
	pcre2_match_data_free(mdata);

	return ROUTE_MATCH;
}

