#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
 
enum { ARGV_CMD, ARGV_INTERFACE };
 
int s_getMacAddress(const char * dev, unsigned char * mac)
{
    int sock;
    struct ifreq ifr;
 
    memset(&ifr, 0x00, sizeof(ifr));
    strcpy(ifr.ifr_name, dev);
 
    int fd=socket(AF_UNIX, SOCK_DGRAM, 0);
 
    if((sock=socket(AF_UNIX, SOCK_DGRAM, 0))<0){
        perror("socket ");
        return 1;
    }
 
    if(ioctl(fd,SIOCGIFHWADDR,&ifr)<0){
        perror("ioctl ");
        return 1;
    }
 
    memcpy (mac, (void*)&ifr.ifr_hwaddr.sa_data, sizeof(ifr.ifr_hwaddr.sa_data));  
 
 
    //close(sock);
    return 0;
}
