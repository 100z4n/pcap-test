#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <libnet.h>

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

void print_mac_address(u_int8_t *mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2],
           mac[3], mac[4], mac[5]);
}

void print_ip_address(u_int32_t ip) {
    printf("%d.%d.%d.%d",
           (ip & 0xFF),
           (ip >> 8) & 0xFF,
           (ip >> 16) & 0xFF,
           (ip >> 24) & 0xFF);
}

void handle_packet(const u_char* packet) {
    struct libnet_ethernet_hdr *eth_hdr = (struct libnet_ethernet_hdr *)packet;
    if (ntohs(eth_hdr->ether_type) != ETHERTYPE_IP) {
        
        return;
    }

    struct libnet_ipv4_hdr *ip_hdr = (struct libnet_ipv4_hdr *)(packet + sizeof(struct libnet_ethernet_hdr));
    if (ip_hdr->ip_p != IPPROTO_TCP) {
        return;
    }

    struct libnet_tcp_hdr *tcp_hdr = (struct libnet_tcp_hdr *)((u_char *)ip_hdr + (ip_hdr->ip_hl * 4));

    printf("Src MAC: ");
    print_mac_address(eth_hdr->ether_shost);
    printf(" -> Dst MAC: ");
    print_mac_address(eth_hdr->ether_dhost);
    printf("\n");

    printf("Src IP: ");
    print_ip_address(ip_hdr->ip_src.s_addr);
    printf(" -> Dst IP: ");
    print_ip_address(ip_hdr->ip_dst.s_addr);
    printf("\n");

    printf("Src Port: %d -> Dst Port: %d\n", ntohs(tcp_hdr->th_sport), ntohs(tcp_hdr->th_dport));

    const u_char *payload = (const u_char *)(tcp_hdr + 1);
    int payload_len = ntohs(ip_hdr->ip_len) - (ip_hdr->ip_hl * 4) - (tcp_hdr->th_off * 4);
    if (payload_len > 0) {
        int print_len = payload_len > 20 ? 20 : payload_len;
        printf("Payload (first %d bytes): ", print_len);
        for (int i = 0; i < print_len; i++) {
            printf("%02x ", payload[i]);
        }
        printf("\n");
    }
    printf("\n");
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
        printf("%u bytes captured\n", header->caplen);
        handle_packet(packet);
    }

    pcap_close(pcap);
    return 0;
}

