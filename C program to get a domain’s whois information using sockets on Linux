/*
 * @brief
 * Whois client program
 * 
 * @details
 * This program shall perform whois for a domain and get you the whois data of that domain
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
 
int get_whois_data(char * , char **);
int hostname_to_ip(char * , char *);
int whois_query(char * , char * , char **);
char *str_replace(char *search , char *replace , char *subject );
 
int main(int argc , char *argv[])
{
    char domain[100] , *data = NULL;
     
    printf("Enter domain name to whois : ");
    scanf("%s" , domain);
     
    get_whois_data(domain , &data);
     
    //puts(data);
    return 0;
}
 
/*
 * Get the whois data of a domain
 * */
int get_whois_data(char *domain , char **data)
{
    char ext[1024] , *pch , *response = NULL , *response_2 = NULL , *wch , *dt;
 
    //remove "http://" and "www."
    domain = str_replace("http://" , "" , domain);
    domain = str_replace("www." , "" , domain);
 
    //get the extension , com , org , edu
    dt = strdup(domain);
    if(dt == NULL)
    {
        printf("strdup failed");
    }
    pch = (char*)strtok(dt , ".");
    while(pch != NULL)
    {
        strcpy(ext , pch);
        pch = strtok(NULL , ".");
    }
     
    //This will tell the whois server for the particular TLD like com , org
    if(whois_query("whois.iana.org" , ext , &response))
    {
        printf("Whois query failed");
    }
     
    //Now analysze the response :)
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
 
     
     
    //Now we have the TLD whois server in wch , query again
    //This will provide minimal whois information along with the parent whois server of the specific domain :)
    free(response);
    //This should not be necessary , but segmentation fault without this , why ?
    response = NULL;
    if(wch != NULL)
    {
        printf("\nTLD Whois server is : %s" , wch);
        if(whois_query(wch , domain , &response))
        {
            printf("Whois query failed");
        }
    }
    else
    {
        printf("\nTLD whois server for %s not found" , ext);
        return 1;
    }
     
    response_2 = strdup(response);
 
    //Again search for a whois server in this response. :)
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
 
 
    /*
     * If a registrar whois server is found then query it
     * */
    if(wch)
    {
        //Now we have the registrar whois server , this has the direct full information of the particular domain
        //so lets query again
         
        printf("\nRegistrar Whois server is : %s" , wch);
         
        if(whois_query(wch , domain , &response))
        {
            printf("Whois query failed");
        }
         
        printf("\n%s" , response);
    }
     
    /*
     * otherwise echo the output from the previous whois result
     * */
    else
    {
        printf("%s" , response_2);
    }
    return 0;
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
 
/*
 * Search and replace a string with another string , in a string
 * */
char *str_replace(char *search , char *replace , char *subject)
{
    char  *p = NULL , *old = NULL , *new_subject = NULL ;
    int c = 0 , search_size;
     
    search_size = strlen(search);
     
    //Count how many occurences
    for(p = strstr(subject , search) ; p != NULL ; p = strstr(p + search_size , search))
    {
        c++;
    }
     
    //Final size
    c = ( strlen(replace) - search_size )*c + strlen(subject);
     
    //New subject with new size
    new_subject = malloc( c );
     
    //Set it to blank
    strcpy(new_subject , "");
     
    //The start position
    old = subject;
     
    for(p = strstr(subject , search) ; p != NULL ; p = strstr(p + search_size , search))
    {
        //move ahead and copy some text from original subject , from a certain position
        strncpy(new_subject + strlen(new_subject) , old , p - old);
         
        //move ahead and copy the replacement text
        strcpy(new_subject + strlen(new_subject) , replace);
         
        //The new start position after this search match
        old = p + search_size;
    }
     
    //Copy the part after the last search match
    strcpy(new_subject + strlen(new_subject) , old);
     
    return new_subject;
}