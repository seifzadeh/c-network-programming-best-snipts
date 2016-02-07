#include<stdio.h> //printf
#include<string.h> //memset
#include<stdlib.h> //for exit(0);
#include<sys/socket.h>
#include<errno.h> //For errno - the error number
#include<netdb.h> //hostent
#include<arpa/inet.h>
 
int hostname_to_ip(char *  , char *);
 
int main(int argc , char *argv[])
{
    if(argc <2)
    {
        printf("Please provide a hostname to resolve");
        exit(1);
    }
     
    char *hostname = argv[1];
    char ip[100];
     
    hostname_to_ip(hostname , ip);
    printf("%s resolved to %s" , hostname , ip);
     
    printf("\n");
     
}
/*
    Get ip from domain name
 */
 
int hostname_to_ip(char * hostname , char* ip)
{
    struct hostent *he;
    struct in_addr **addr_list;
    int i;
         
    if ( (he = gethostbyname( hostname ) ) == NULL) 
    {
        // get the host info
        herror("gethostbyname");
        return 1;
    }
 
    addr_list = (struct in_addr **) he->h_addr_list;
     
    for(i = 0; addr_list[i] != NULL; i++) 
    {
        //Return the first one;
        strcpy(ip , inet_ntoa(*addr_list[i]) );
        return 0;
    }
     
    return 1;
}






#include<stdio.h> //printf
#include<string.h> //memset
#include<stdlib.h> //for exit(0);
#include<sys/socket.h>
#include<errno.h> //For errno - the error number
#include<netdb.h> //hostent
#include<arpa/inet.h>
 
int hostname_to_ip(char *  , char *);
 
int main(int argc , char *argv[])
{
    if(argc <2)
    {
        printf("Please provide a hostname to resolve");
        exit(1);
    }
     
    char *hostname = argv[1];
    char ip[100];
     
    hostname_to_ip(hostname , ip);
    printf("%s resolved to %s" , hostname , ip);
     
    printf("\n");
     
}
/*
    Get ip from domain name
 */
 
int hostname_to_ip(char *hostname , char *ip)
{
    int sockfd;  
    struct addrinfo hints, *servinfo, *p;
    struct sockaddr_in *h;
    int rv;
 
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; // use AF_INET6 to force IPv6
    hints.ai_socktype = SOCK_STREAM;
 
    if ( (rv = getaddrinfo( hostname , "http" , &hints , &servinfo)) != 0) 
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }
 
    // loop through all the results and connect to the first we can
    for(p = servinfo; p != NULL; p = p->ai_next) 
    {
        h = (struct sockaddr_in *) p->ai_addr;
        strcpy(ip , inet_ntoa( h->sin_addr ) );
    }
     
    freeaddrinfo(servinfo); // all done with this structure
    return 0;
}