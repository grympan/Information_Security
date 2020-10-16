#define WIN32
#define WPCAP
#define HAVE_REMOTE
#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include "pcap.h"

struct pseudo_header {
	unsigned int source_address;
	unsigned int dest_address;
	unsigned char placeholder;
	unsigned char protocol;
	unsigned short tcp_length;
};

struct ip_hdr {
	unsigned char ip_header_len : 4;
	unsigned char ip_version : 4;
	unsigned char ip_tos;
	unsigned short ip_total_length;
	unsigned short ip_id;
	unsigned char ip_frag_offset : 5;
	unsigned char ip_more_fragment : 1;
	unsigned char ip_dont_fragment : 1;
	unsigned char ip_reserved_zero : 1;
	unsigned char ip_frag_offset1;
	unsigned char ip_ttl;
	unsigned char ip_protocol;
	unsigned short ip_checksum;
	unsigned int ip_srcaddr;
	unsigned int ip_destaddr;
};

struct tcp_hdr {
	unsigned short source_port;
	unsigned short dest_port;
	unsigned int sequence;
	unsigned int acknowledge;
	unsigned char ns : 1;
	unsigned char reserved_part1 : 3;
	unsigned char data_offset : 4;
	unsigned char fin : 1;
	unsigned char syn : 1;
	unsigned char rst : 1;
	unsigned char psh : 1;
	unsigned char ack : 1;
	unsigned char urg : 1;
	unsigned char ecn : 1;
	unsigned char cwr : 1;
	unsigned short window;
	unsigned short checksum;
	unsigned short urgent_pointer;
};

unsigned short in_checksum(unsigned short* ptr, int nbytes) {
	register long sum;
	unsigned short oddbyte;
	register short answer;

	sum = 0;
	while (nbytes > 1) {
		sum += *ptr++;
		nbytes -= 2;
	}

	if (nbytes == 1) {
		oddbyte = 0;
		*((u_char*)&oddbyte) = *(u_char*)ptr;
		sum += oddbyte;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum = sum + (sum >> 16);
	answer = (SHORT)~sum;

	return(answer);
}

void print_raw_packet(const unsigned char* pkt_data, int caplen) {
	printf("\n== 1) Raw byte stream of the packet ===\n");
	int i;
	for (i = 0; i < caplen; i++) {
		printf("%02x", pkt_data[i]);
		if (i % 2 == 1) printf(" ");
		if ((i + 1) % 16 == 0) printf("\n");
	}
	printf("\n=======================================");
}

int main() {
	pcap_if_t* alldevs = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];

	// find all network adapters
	if (pcap_findalldevs(&alldevs, errbuf) == -1) {
		printf("dev find failed\n");
		return -1;
	}

	if (alldevs == NULL) {
		printf("no devs found\n");
		return -1;
	}

	// print them
	pcap_if_t* d; int i;
	for (d = alldevs, i = 0; d != NULL; d = d->next) {
		printf("%d-th dev: %s ", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	int inum;
	printf("enter the interface number: ");
	scanf("%d", &inum);
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++); //jump to the inum-th dev

	// open
	pcap_t* fp;
	if ((fp = pcap_open_live(d->name,	// name of the device
		65536,							// capture size
		1,								// promiscuous mode
		20,								// read timeout
		errbuf
		)) == NULL) {
		printf("pacp open failed\n");
		pcap_freealldevs(alldevs);
		return -1;
	}
	printf("pcap open successful\n");

	struct bpf_program fcode;
	if (pcap_compile(fp,								// pcap handle
		&fcode,											// compiled rule
		(char*)("host 165.246.38.157 and port 34567"),	// filtering rule
		1,												// optimize
		NULL) < 0) {
		printf("pcap compiled failed\n");
		pcap_freealldevs(alldevs);
		return -1;
	}	// Now we have filter rule in fcode. Apply it to the interface, fp.

	if (pcap_setfilter(fp, &fcode) < 0) {
		printf("pcap setfilter failed\n");
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("filter setting successful\n");

	pcap_freealldevs(alldevs);							// we don't need this anymore
	struct pcap_pkthdr* header;
	const unsigned char* pkt_data;

	int res;
	while ((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0) {	// 1 if success
		if (res == 0) continue;									// 0 if time-out
		print_raw_packet(pkt_data, header->caplen);
		printf("\nnow breaking this loop\n");
		break;
	}

	// ¨è copy them into another buffer: pkt_data=>packet
	const unsigned char* packet = (unsigned char*)malloc(65535);
	packet = pkt_data;

	printf("\nkill server and the client. run the original sniffer.\n");
	printf("rerun the serverand hit 9 when ready\n");
	int x;
	scanf("%d", &x);

	int p;
	for (p = 1; p <= 65535; p ++) {
		struct ip_hdr* ih = (struct ip_hdr*)(packet + 14);
		struct tcp_hdr* th = (struct tcp_hdr*)(packet + 14 + 20);

		th->dest_port = htons(p);			// destnation port º¯°æ (1~65535)

		int tcp_len = th->data_offset * 4;

		// ¨é set ip_checksum and tcp_checksum to zero
		ih->ip_checksum = 0;
		th->checksum = 0;

		struct pseudo_header psh;
		inet_pton(AF_INET, "(MY IP ADDRESS)", &(psh.source_address));
		inet_pton(AF_INET, "165.246.38.157", &(psh.dest_address));
		psh.placeholder = 0;
		psh.protocol = 6;
		psh.tcp_length = htons(tcp_len);

		unsigned char* seudo;
		seudo = (unsigned char*)malloc(sizeof(struct pseudo_header) + tcp_len);
		memcpy(seudo, &psh, sizeof(struct pseudo_header));
		memcpy(seudo + sizeof(struct pseudo_header), th, tcp_len);

		// ¨ê, ¨ë recompute ip_checksum, tcp_checksum
		ih->ip_checksum = in_checksum((unsigned short*)ih, 20);
		th->checksum = in_checksum((unsigned short*)seudo,
			sizeof(struct pseudo_header) + tcp_len);

		printf("send SYN packet to port %d\n", p);
		if (pcap_sendpacket(fp, packet, 14 + 20 + tcp_len) != 0) {
			printf("err in packet send : %s\n", pcap_geterr(fp));
		}
	}

	return 0;
}