#include<unistd.h>
#include<string.h>
#include<stdio.h>
#include<stdlib.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<sys/ioctl.h>
#include<netdb.h>
#include<netinet/in.h>
#include<netinet/ip.h>
#include<linux/if_ether.h> //ETH_P_ARP = 0x0806
#include<net/if.h>
#include<linux/if_packet.h>
#include<arpa/inet.h>

#define ARP_REQUEST 1
#define ARP_REPLY 2
#define ETH_HDRLEN 14
#define IP$_HDRLEN 20
#define ARP_HDRLEN 28

typedef struct _arp_hdr arp_hdr;
struct _arp_hdr{
	uint16_t htype;
	uint16_t ptype;
	uint8_t hlen;
	uint8_t plen;
	uint16_t opcode;
 	uint8_t sender_mac[6];
	uint8_t sender_ip[4];
	uint8_t target_mac[6];
	uint8_t target_ip[4];
};
int main(int argc, char* argv[])
{
	char *interface;
	int i, frame_len, sd, bytes;
	uint8_t src_ip[4], src_mac[6], dst_mac[6], ether_frame[IP_MAXPACKET];
	uint8_t des_ip[4];
	uint8_t gate_ip[4];
	struct sockaddr_in *ipv4;
	struct sockaddr_ll device;
	struct ifreq ifr;
	
	char ip[20];
	char mac[20];
	arp_hdr arphdr;
	/*des_ip[0]=192;
	des_ip[1]=168;
	des_ip[2]=190;
	des_ip[3]=133;*/


	if(argc!=4)
	{
		perror("Check argument! (./send_arp <interface> <sender ip> <target ip>)\n");
		exit(EXIT_FAILURE);
	}

	strcpy(interface, argv[1]);
	strcpy(des_ip, argv[2]);
	strcpy(gate_ip, argv[3]);

	if((sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW))<0){
		perror("socket() failed to get socket descriptor for using ioctl()");
		exit(EXIT_FAILURE);
	}

	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", interface);
	if(ioctl(sd, SIOCGIFADDR, &ifr)<0){
		perror("ioctl() failed to get source IP address\n");
		return(EXIT_FAILURE);
	}

	ipv4 = (struct sockaddr_in *)&ifr.ifr_addr;
	memcpy(src_ip, &ipv4->sin_addr, 4*sizeof(uint8_t));

	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name),"%s", interface);
	if(ioctl(sd, SIOCGIFHWADDR, &ifr)<0){
		perror("ioctl() failed to get source MAC address");
		return (EXIT_FAILURE);
	}

	close(sd);
	memcpy(src_mac, ifr.ifr_hwaddr.sa_data, 6 * sizeof(uint8_t));

	printf("MAC address for interface %s is ", interface);
	for(i=0; i<5; i++){
		printf("%02x:", src_mac[i]);
	}
	printf("%02x\n", src_mac[5]);

	printf("IP address is : ");
	for(i=0; i<3; i++){
		printf("%d.",src_ip[i]);
	}
	printf("%d\n", src_ip[3]);
	
	if((device.sll_ifindex = if_nametoindex(interface))==0){
		perror("if_nametoindex() failed to obtain interface index");
		exit(EXIT_FAILURE);
	}
	printf("Index for interface %s is %i\n", interface, device.sll_ifindex);
	
	
	memcpy(src_mac, "0xff", 6 * sizeof(uint8_t));
	memcpy(&arphdr.sender_ip, src_ip, 4 * sizeof(uint8_t));
	memcpy(&arphdr.target_ip, des_ip, 4 * sizeof(uint8_t));

	device.sll_family = AF_PACKET;
	memcpy(device.sll_addr, src_mac, 6 * sizeof(uint8_t));
	device.sll_halen = htons(6);

	arphdr.htype = htons(1);
	arphdr.ptype = htons(ETH_P_IP);
	arphdr.hlen=6;
	arphdr.plen=4;
	arphdr.opcode = htons(ARP_REQUEST);

	memcpy(&arphdr.sender_mac, src_mac, 6 * sizeof(uint8_t));

	memset(&arphdr.target_mac, 0, 6*sizeof(uint8_t));
	frame_len = 14 + ARP_HDRLEN;

	memcpy(ether_frame, dst_mac, 6 * sizeof(uint8_t));
	memcpy(ether_frame + 6, src_mac, 6 * sizeof(uint8_t));

	ether_frame[12] = ETH_P_ARP/256;
	ether_frame[13] = ETH_P_ARP%256;

	memcpy(ether_frame + ETH_HDRLEN, &arphdr, ARP_HDRLEN * sizeof(uint8_t));
	if((sd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL)))<0){
		perror("Socket() failed");
		exit(EXIT_FAILURE);
	}

	if((bytes=sendto(sd, ether_frame, frame_len, 0, (struct sockaddr *)&device, sizeof(device)))<=0){
		perror("sendto() failed");
		exit(EXIT_FAILURE);
	}
	close(sd);

	return 0;
}

