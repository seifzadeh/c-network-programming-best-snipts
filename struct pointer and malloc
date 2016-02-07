#include <stdio.h>
#include <stdlib.h>

struct DataSend
{
	char *ip;
	int port;
};


int UseStruct(struct DataSend *dsend ) {
	printf("%s:%d \n", dsend->ip,dsend->port);
}

int main(int argc, char const *argv[])
{
	struct DataSend *dsend = malloc(sizeof(struct DataSend));

	dsend->ip = "192.168.50.30";
	dsend->port = 2563;

	UseStruct(dsend);

	return 0;
}