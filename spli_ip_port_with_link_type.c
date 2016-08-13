#include <string.h>
#include <stdio.h>
#include <stdlib.h>

int split_hostport(char *str, char **host, char **port)
{
	char *s = str;
	char *orig_str = str;/* Original string in case the port presence is incorrect. */
	char *host_end = NULL;/* Delay terminating the host in case the port presence is incorrect. */

	printf( "Splitting '%s' into...\n", str);
	*host = NULL;
	*port = NULL;

	*host = s;
	for (; *s; ++s) {
		if (*s == ':') {
			if (*port) {
				*port = NULL;
				break;
			} else {
				*port = s;
			}
		}
	}
	if (*port) {
		host_end = *port;
		++*port;
	}



	/* Can terminate the host string now if needed. */
	if (host_end) {
		*host_end = '\0';
	}
	printf( "...host '%s' and port '%s'.\n", *host, *port ? *port : "");
	return 1;
}


int main(int argc, char const *argv[])
{
	char *ipport = strdup("basic/192.168.5.22:6655");
	char *tmp, *ip, *port;

	tmp = strchr(ipport, '/');
	*tmp++ = '\0';
	split_hostport(tmp, &ip, &port);

	printf("ip: %s, port: %s\n", ip, port );

	return 0;
}

