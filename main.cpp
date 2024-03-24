#include <cstdio>
#include <pcap.h>

#include <stdio.h>

#include "arp_spoof.h"

#pragma pack(push, 1)

#pragma pack(pop)


void usage() {
    printf("syntax: send-arp-test <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[]) {
    if (argc < 4 && argc%2 != 0) {
        usage();
        return -1;
    }
    int i;
    char* dev = argv[1];
    for(i=1;i<(argc/2);i++){
    arp_spoof(getMymac(dev),getMyip(dev),argv[i*2],argv[i*2+1],dev);
    }


}
