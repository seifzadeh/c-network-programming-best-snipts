/*
 * @brief
 * Whois client program
 * 
 * @details
 * This program shall fetch whois data for a IPv4 address.
 * 
 * @author Silver Moon ( m00n.silv3r@gmail.com )
 * */
 
#include<stdio.h> //scanf , printf
#include<string.h>    //strtok
#include<stdlib.h>    //realloc
#include<sys/socket.h>    //socket
#include<netinet/in.h> //sockaddr_in
#include<arpa/inet.h> //getsockname
#include<netdb.h> //hostent
#include<unistd.h>    //close
 
int main(int argc , char *argv[])
{
    char ip[100] , *data = NULL;
     
    printf("Enter ip address to whois : ");
    scanf("%s" , ip);
     
    get_whois(ip , &data);
    printf("\n\n");
    puts(data);
     
    free(data);
    return 0;
}
 
/**
    Get the whois content of an ip
    by selecting the correct server
*/
void get_whois(char *ip , char **data) 
{
    char *wch = NULL, *pch , *response = NULL;
     
    if(whois_query("whois.iana.org" , ip , &response))
    {
        printf("Whois query failed");
    }
     
    pch = strtok(response , "\n");
     
    while(pch != NULL)
    {
        //Check if whois line
        wch = strstr(pch , "whois.");
        if(wch != NULL)
        {
            break;
        }
 
        //Next line please
        pch = strtok(NULL , "\n");
    }
     
    if(wch != NULL)
    {
        printf("\nWhois server is : %s" , wch);
        whois_query(wch , ip , data);
    }
    else
    {
        *data = malloc(100);
        strcpy(*data , "No whois data");
    }
     
    return;
}
 
/*
 * Perform a whois query to a server and record the response
 * */
int whois_query(char *server , char *query , char **response)
{
    char ip[32] , message[100] , buffer[1500];
    int sock , read_size , total_size = 0;
    struct sockaddr_in dest;
      
    sock = socket(AF_INET , SOCK_STREAM , IPPROTO_TCP);
      
    //Prepare connection structures :)
    memset( &dest , 0 , sizeof(dest) );
    dest.sin_family = AF_INET;
      
    printf("\nResolving %s..." , server);
    if(hostname_to_ip(server , ip))
    {
        printf("Failed");
        return 1;
    }
    printf("%s" , ip);    
    dest.sin_addr.s_addr = inet_addr( ip );
    dest.sin_port = htons( 43 );
 
    //Now connect to remote server
    if(connect( sock , (const struct sockaddr*) &dest , sizeof(dest) ) < 0)
    {
        perror("connect failed");
    }
     
    //Now send some data or message
    printf("\nQuerying for ... %s ..." , query);
    sprintf(message , "%s\r\n" , query);
    if( send(sock , message , strlen(message) , 0) < 0)
    {
        perror("send failed");
    }
     
    //Now receive the response
    while( (read_size = recv(sock , buffer , sizeof(buffer) , 0) ) )
    {
        *response = realloc(*response , read_size + total_size);
        if(*response == NULL)
        {
            printf("realloc failed");
        }
        memcpy(*response + total_size , buffer , read_size);
        total_size += read_size;
    }
    printf("Done");
    fflush(stdout);
     
    *response = realloc(*response , total_size + 1);
    *(*response + total_size) = '\0';
     
    close(sock);
    return 0;
}
 
/*
 * @brief
 * Get the ip address of a given hostname
 * 
 * */
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
     
    return 0;
}