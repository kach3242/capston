#include <stdint.h>

struct eth_header{
    uint8_t dmac[6];  //0~5
    uint8_t smac[6];  //6~11
    uint16_t eth_type;
};

#pragma pack(push, 1)
struct arp_header{
    uint16_t hw_type;
    uint16_t protocol;
    uint8_t hw_add_len;
    uint8_t proto_add_len;
    uint16_t opcode;
    uint8_t smac[6];   //23~27
    uint32_t sip;      //28~31
    uint8_t dmac[6];   //32~37
    uint32_t dip;      //38~41
};
#pragma pack(pop)

struct ip_header{
    uint8_t ipv4_len;
    uint8_t tos;
    uint16_t packet_len;
    uint16_t id;
    uint16_t flag;
    uint8_t ttl;
    uint8_t pid;
    uint16_t checksum;
    uint32_t sip;
    uint32_t dip;
};

struct tcp_header{
    uint16_t sport;
    uint16_t dport;
    uint32_t seqnum;
    uint32_t acknum;
    uint8_t hlen;
    uint8_t flag;
    uint16_t wsize;
    uint16_t checksum;
    uint16_t urg_pointer;
};

struct udp_header{
    uint16_t sport;
    uint16_t dport;
    uint16_t length;
    uint16_t checksum;
};

struct dhcp_header{
    uint8_t opcode;
    uint8_t htype;
    uint8_t h_add_len;
    uint8_t hops;
    uint32_t transid;
    uint16_t secs;
    uint16_t flags;
    uint32_t cip;
    uint32_t yip;
    uint32_t sip;
    uint32_t gip;
    uint8_t cmac[6];
    uint8_t padd[10];
    uint8_t hostname[64];
    uint8_t boot_file[128];
    uint32_t mcookie;
};

unsigned char* request(unsigned char *smac, uint32_t *sip, uint32_t *dip);
int dhcp(char *argv);
