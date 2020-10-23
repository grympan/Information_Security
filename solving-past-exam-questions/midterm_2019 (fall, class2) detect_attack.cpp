#define WIN32
#define WPCAP
#define HAVE_REMOTE
#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include "pcap.h"
#include <string.h>

struct ether_addr {
	unsigned char ether_addr_octet[6];
};

struct ether_header {
	struct ether_addr ether_dhost;
	struct ether_addr ether_shost;
	unsigned short ether_type;		// 0x0800 for IP
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

struct tcp_data {
	char data_buf[10000];
};

bool IsAttack(const unsigned char* pkt_data, int total_len);
bool IsFromServer(const unsigned char* pkt_data);

void print_raw_packet(const unsigned char* pkt_data, int caplen);
void print_ether_header(const unsigned char* pkt_data);
void print_ip_header(const unsigned char* pkt_data);
void print_tcp_header(const unsigned char* pkt_data);
void print_data(const unsigned char* pkt_data, int caplen);

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
	if (pcap_compile(fp,					// pcap handle
		&fcode,							// compiled rule
		(char*)("host 165.246.38.157"),	// filtering rule
		1,								// optimize
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

	pcap_freealldevs(alldevs);			// we don't need this anymore
	struct pcap_pkthdr* header;
	const unsigned char* pkt_data;
	int res;
	while ((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0) {	// 1 if success
		if (res == 0) continue;									// 0 if time-out

		if (IsAttack(pkt_data, header->caplen) == true && IsFromServer(pkt_data) == true) {
			printf("\n★★★★ abc attack detected ★★★★★\n");
			printf("★★★★ Check below data stream ★★★\n");
			print_raw_packet(pkt_data, header->caplen);
		//	print_ether_header(pkt_data);
		//	print_ip_header(pkt_data);
		//	print_tcp_header(pkt_data);
			print_data(pkt_data, header->caplen);
		}
	}

	return 0;
}

// tcp data에 "abc" 문자열이 있는지 확인하는 함수
bool IsAttack(const unsigned char* pkt_data, int total_len) {
	struct tcp_hdr* th = (struct tcp_hdr*)(pkt_data + 14 + 20);
	int th_len = th->data_offset * 4;				// tcp header 길이
	int except_data_len = 14 + 20 + th_len;			// tcp data를 제외한 패킷 길이 
	struct tcp_data* td = (struct tcp_data*)(pkt_data + except_data_len);

	if (except_data_len < total_len) {				// tcp data가 있는 경우에만 검사 수행
		if (strstr(td->data_buf, "abc") == NULL)	// "abc"가 발견되지 않으면
			return false;							// false

		else
			return true;							// 발견된 경우 true
	}
	return false;
}

// source ip가 서버의 ip인지 확인하는 함수
bool IsFromServer(const unsigned char* pkt_data) {
	struct ip_hdr* ih = (struct ip_hdr*)(pkt_data + 14);
	
	unsigned int src_all = ih->ip_srcaddr;			// 4bytes ip address 통째
	unsigned int src_part[4];						// 1bytes씩 나눈 배열

	for (int i = 0; i < 4; i++) {					// 10진수로 변환하여 배열에 차례로 저장
		src_part[i] = src_all % 256;
		src_all /= 256;
	}

	if ((src_part[0] == 165) && (src_part[1] == 246) && (src_part[2] == 38) && (src_part[3] == 157) == true)
		return true;								// 서버 ip가 맞으면 true

	else
		return false;
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

void print_ether_header(const unsigned char* pkt_data) {
	struct ether_header* eh = (struct ether_header*)pkt_data;
	printf("\n== 2) Ethernet_header =================\n");

	printf("Destinaiton_MAC : ");
	for (int i = 0; i < 6; i++)
		printf("%02x ", eh->ether_dhost.ether_addr_octet[i]);
	printf("\n");

	printf("Source_MAC : ");
	for (int i = 0; i < 6; i++)
		printf("%02x ", eh->ether_shost.ether_addr_octet[i]);
	printf("\n");

	printf("Type : %04x\n", ntohs(eh->ether_type));
	printf("=======================================");
}

void print_ip_header(const unsigned char* pkt_data) {
	struct ip_hdr* ih = (struct ip_hdr*)(pkt_data + 14);
	printf("\n== 3) IP_header =======================\n");

	printf("Version : %x\n", ih->ip_version);
	printf("Header_length : %d\n", ih->ip_header_len);
	printf("TOS : %02x\n", ih->ip_tos);
	printf("Total_length : %d\n", ntohs(ih->ip_total_length));

	printf("Identification : %d\n", ntohs(ih->ip_id));
	printf("Reserved_zero : %x\n", ih->ip_reserved_zero);
	printf("Don't_fragment : %x\n", ih->ip_dont_fragment);
	printf("More_fragment : %x\n", ih->ip_more_fragment);
	printf("Fragment_offset : %x\n", ih->ip_frag_offset);
	printf("Fragment_offset1 : %x\n", ih->ip_frag_offset1);

	printf("TTL : %d\n", ih->ip_ttl);
	printf("Protocol : %02x\n", ih->ip_protocol);
	printf("Header_checksum : %04x\n", ntohs(ih->ip_checksum));

	printf("Source_IP : %08x\n", ntohl(ih->ip_srcaddr));
	printf("Destination_IP : %08x\n", ntohl(ih->ip_destaddr));
	printf("=======================================");
}

void print_tcp_header(const unsigned char* pkt_data) {
	struct tcp_hdr* th = (struct tcp_hdr*)(pkt_data + 14 + 20);
	int th_len = th->data_offset * 4;
	int except_data_len = 14 + 20 + th_len;

	printf("\n== 4) TCP_header ======================\n");

	printf("Source_port : %d\n", ntohs(th->source_port));
	printf("Destination_port : %d\n", ntohs(th->dest_port));

	printf("Sequence_number : %d\n", ntohl(th->sequence));

	printf("Acknowledgement_number : %d\n", ntohl(th->acknowledge));

	printf("Header_length : %d\n", th->data_offset);
	printf("Reserved : %x\n", th->reserved_part1);
	printf("Nonce : %x\n", th->ns);
	printf("CWR : %x\n", th->cwr);
	printf("ECN : %x\n", th->ecn);
	printf("URG : %x\n", th->urg);
	printf("ACK : %x\n", th->ack);
	printf("PSH : %x\n", th->psh);
	printf("RST : %x\n", th->rst);
	printf("SYN : %x\n", th->syn);
	printf("FIN : %x\n", th->fin);
	printf("Window_size : %d\n", ntohs(th->window));

	printf("Checksum : %04x\n", ntohs(th->checksum));
	printf("Urgent_point : %04x\n", ntohs(th->urgent_pointer));

	if (th_len > 20) {
		int i;
		printf("TCP option :\n");
		for (i = 54; i < except_data_len; i++) {
			printf("%02x", pkt_data[i]);
			if (i % 2 == 1) printf(" ");
			if ((i + 11) % 16 == 0) printf("\n");
		}
		printf("\n");
	}
	printf("=======================================");
}

void print_data(const unsigned char* pkt_data, int caplen) {
	struct tcp_hdr* th = (struct tcp_hdr*)(pkt_data + 14 + 20);
	int th_len = th->data_offset * 4;
	int except_data_len = 14 + 20 + th_len;

	if (caplen > except_data_len) {
		printf("\n== 5) TCP Data ========================\n");
		int i;
		for (i = 54; i < caplen; i++) {
			printf("%c", pkt_data[i]);
			if ((i + 11) % 16 == 0) printf("\n");
		}
		printf("\n=======================================\n\n\n");
	}

	else
		printf("\n\n\n");
}
