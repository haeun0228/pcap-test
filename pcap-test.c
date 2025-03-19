#include "pch.h"

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

struct payload{
    uint8_t payload[20];
}__attribute__ ((__packed__));


void print_ether(uint8_t* mac){
    for(int i=0;i<ETHER_ADDR_LEN;i++){
        if(i!=0){
            printf(":");
        }
        printf("%02X",mac[i]);
    }
    printf("\n");
}

void print_ip(uint8_t* ip){
    for(int i=0;i<IP_LEN;i++){
        if(i!=0){
            printf(".");
        }
        printf("%d",ip[i]);
    }
    printf("\n");
}

void print_payload(uint8_t* payload){
    for(int i=0;i<sizeof(struct payload);i++){
        printf("%02X ", payload[i]);
    }
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

        // ethernet header
        struct ethHdr* ethernet = (struct ethHdr *)packet;
        // check if protocol is ipv4 (ether tyype = 0x0800)
        if(ntohs(ethernet->ether_type) != 0x0800) continue;

        // ip header
        struct ipHdr* ip = (struct ipHdr *)(packet + sizeof(struct ethHdr));
        // check if protocol is tcp (ip protocol = 0x06)
        if(ip->protocol != 0x06) continue;
        size_t ip_len = (ip->IHL)*4;

        // tcp header, payload
        struct tcpHdr* tcp = (struct tcpHdr *)(packet + sizeof(struct ethHdr) + ip_len);
        size_t tcp_len = (tcp->data_offset)*4;
        struct payload* payload = (struct payload*)(packet + sizeof(struct ethHdr) + ip_len + tcp_len);

        printf("\n--------------------\n");
        printf("Ethernet\nSource Mac: ");
        print_ether(ethernet->smac);
        printf("Destination Mac: ");
        print_ether(ethernet->dmac);

        printf("\nIP\nSource IP: ");
        print_ip(ip->sip);
        printf("Destination IP: ");
        print_ip(ip->dip);

        printf("\nTCP\nSource Port: %d\n",ntohs(tcp->sport));
        printf("Destination Port: %d\n",ntohs(tcp->dport));
        printf("\npayload: ");
        print_payload(payload->payload);

    }
	pcap_close(pcap);
}
