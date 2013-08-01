#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#if 0
#	include <linux/in.h>
#endif
#include <netinet/in.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/sockios.h>
#include <netpacket/packet.h>
#include <unistd.h>
#include <fcntl.h>

#ifdef linux
#	define	NEWSOCKET()	socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ARP))
#else
#	define	NEWSOCKET()	socket(SOL_SOCKET, SOCK_RAW, ETHERTYPE_REVARP)
#endif

#define MAC_ADDR_LEN 6
#define IP_ADDR_LEN 4
#define ARP_FRAME_TYPE 0x0806
#define ETHER_HW_TYPE 1
#define IP_PROTO_TYPE 0x0800
#define OP_ARP_REQUEST 1
#define SONOS_PREFIX_NUM 2

const unsigned char ether_broadcast_addr[] = {0xff,0xff,0xff,0xff,0xff,0xff};
const char* sonos_prefixes[] = {"\x00\x0e\x58", "\xb8\xe9\x37"};

char usage[] = {"Usage: send_arp <ifname>\n\nExamples:\n\tsend_arp eth0\n\tsend_arp eth1:1"};

void die(const char *);
void print_usage(const char *);
unsigned long get_ip_addr(char*);
unsigned long get_ip_mask(char*);
void get_hw_addr(u_char*, char*);
void send_arp(int sock, int ifindex, unsigned long dest, unsigned long my_ip, u_char* hwaddr);
void detect_sonos(int sock);
int get_interface_index(char* ifname);

int ioctl_sock;
int opt_d = 0;

int main(int argc, char** argv) {
	unsigned long my_ip, my_netmask, my_prefix, network_len, cur_ip;
	int my_index;
	struct sockaddr sa;
	int sock, insock;
	u_char hwaddr[MAC_ADDR_LEN];
	char *ifname, *ifsend, *cindex;
	char ch;

	if (argc < 2) {
		print_usage(usage);
	}

	while ((ch = getopt(argc, argv, "d")) != -1) {
		switch(ch) {
			case 'd':
				opt_d = 1;
				break;
			case '?':
			default:
				goto args;
		}
	}

args:	argc -= optind;
	argv += optind;

	if (opt_d && !argc) {
		print_usage(usage);
	}

	// Sockets
	sock = NEWSOCKET();
	insock = NEWSOCKET();
	ioctl_sock = NEWSOCKET();

	// Recv timeout
	struct timeval tv;
	tv.tv_sec = 0;
	tv.tv_usec = 1;
	setsockopt(insock, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(struct timeval));

	if ((sock < 0) || (ioctl_sock < 0)) {
		perror("Unable to create socket");

		exit(1);
	}

	if (!(ifname = strdup(*argv)) || !(ifsend = strdup(*argv)))
		die("Cannot duplicate interface name\n");

	/*
	 * For an alias interface we use its data but we send
	 * the actual packet on corresponding real interface
	 */
	if ((cindex = strchr(ifsend, ':')))
		*cindex = '\0';

	if (opt_d) {
		printf("Interface: %s\n", ifname);
	}

	sa.sa_family = AF_INET;
	strcpy(sa.sa_data, ifsend);

	get_hw_addr(hwaddr, ifname);
	my_ip = get_ip_addr(ifname);
	my_netmask = get_ip_mask(ifname);
	my_index = get_interface_index(ifname);
	my_prefix = my_ip & my_netmask;
	network_len = my_netmask ^ 0xffffffff;

	if (opt_d) {
		printf("Prefix: %lu\n", my_prefix);
		printf("Network length: %lu\n", network_len);
	}

	for (cur_ip = my_prefix + 1; cur_ip <= my_prefix + network_len; cur_ip++) {
		if (cur_ip == my_ip) continue; // Skip gratuitous ARP

		send_arp(sock, my_index, cur_ip, my_ip, hwaddr);

		detect_sonos(insock);
	}

	exit(0);
}

void detect_sonos(int sock) {
	unsigned char msg[65535];
	struct ether_arp *arp_frame = (struct ether_arp *)msg;
	int r, i;

	if ((r = recv(sock, msg, sizeof(msg), 0)) != -1) {
		if (r != -1) {
			// skip if it's not an ARP REPLY
        		if (ntohs(arp_frame->arp_op) != ARPOP_REPLY)
				return;

			struct in_addr addr2;
			memcpy(&addr2.s_addr, &arp_frame->arp_spa, 4);

			for (i = 0; i < SONOS_PREFIX_NUM; i++) {
				if (!memcmp(sonos_prefixes[i], arp_frame->arp_sha, 3)) {
					struct in_addr addr;
					memcpy(&addr.s_addr, &arp_frame->arp_spa, 4);

					printf("Sonos found at %s\n", inet_ntoa(addr));
				}
			}
		}
	}
}

void send_arp(int sock, int ifindex, unsigned long dest, unsigned long my_ip, u_char* hwaddr) {
	struct sockaddr_ll addr = {0};
	unsigned int rev_my_ip = htonl(my_ip);
	unsigned int rev_dest = htonl(dest);

	// Ethernet header
	addr.sll_family = AF_PACKET;
	addr.sll_ifindex = ifindex;
	addr.sll_halen = MAC_ADDR_LEN;
	addr.sll_protocol = htons(ETH_P_ARP);
	memcpy(addr.sll_addr, ether_broadcast_addr, ETHER_ADDR_LEN);

	// ARP packet
	struct ether_arp req;
	req.arp_hrd = htons(ARPHRD_ETHER);
	req.arp_pro = htons(ETH_P_IP);
	req.arp_hln = MAC_ADDR_LEN;
	req.arp_pln = sizeof(in_addr_t);
	req.arp_op = htons(ARPOP_REQUEST);
	memcpy(&req.arp_spa, &rev_my_ip, sizeof(req.arp_spa));
	memcpy(&req.arp_sha, hwaddr, ETHER_ADDR_LEN);
	memset(&req.arp_tha, 0xff, sizeof(req.arp_tha));
	memcpy(&req.arp_tpa, &rev_dest, sizeof(req.arp_tpa));

	if (sendto(sock, &req, sizeof(req), 0, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
		perror("Unable to send");
	}
}

void die(const char* str) {
	fprintf(stderr, "Error: %s\n", str);

	exit(1);
}

void print_usage(const char* usage) {
	fprintf(stderr, "%s\n", usage);

	exit(1);
}

unsigned long get_ip_addr(char* ifname) {
	struct ifreq ifr;
	struct sockaddr_in sin;
	unsigned long ip;

	strcpy(ifr.ifr_name, ifname);
	ifr.ifr_addr.sa_family = AF_INET;

	if (ioctl(ioctl_sock, SIOCGIFADDR, &ifr))
		die("Failed to get IP address for the interface");

	memcpy(&sin, &ifr.ifr_addr, sizeof(struct sockaddr_in));

	ip = ntohl(sin.sin_addr.s_addr);

	if (opt_d)
		printf("IP address: %lu\n", ip);

	return ip;
}

unsigned long get_ip_mask(char* ifname) {
	struct ifreq ifr;
	struct sockaddr_in sin;
	unsigned long ip;

	strcpy(ifr.ifr_name, ifname);
	ifr.ifr_addr.sa_family = AF_INET;

	if (ioctl(ioctl_sock, SIOCGIFNETMASK, &ifr))
		die("Failed to get network mask for the interface");

	memcpy(&sin, &ifr.ifr_addr, sizeof(struct sockaddr_in));

	ip = ntohl(sin.sin_addr.s_addr);

	if (opt_d)
		printf("Network mask: %lu\n", ip);

	return ip;
}

void get_hw_addr(u_char* buf, char* ifname) {
	struct ifreq ifr;

	strcpy(ifr.ifr_name, ifname);

	if (ioctl(ioctl_sock, SIOCGIFHWADDR, &ifr))
		die("Failed to get MAC address for the interface");

	memcpy(buf, ifr.ifr_hwaddr.sa_data, 8);

	if (opt_d)
		printf("MAC address: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n", *(buf), *(buf+1), *(buf+2), *(buf+3),*(buf+4), *(buf+5));
}

int get_interface_index(char* ifname) {
	struct ifreq ifr;

	strcpy(ifr.ifr_name, ifname);

	if (ioctl(ioctl_sock, SIOCGIFINDEX, &ifr))
		die("Failed to get interface index");

	if (opt_d)
		printf("Interface index: %d\n", ifr.ifr_ifindex);

	return ifr.ifr_ifindex;
}

