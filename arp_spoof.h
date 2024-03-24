#ifndef ARP_SPOOF_H
#define ARP_SPOOF_H

#endif // ARP_SPOOF_H

#include "mac.h"
#include "ip.h"
#include "ethhdr.h"
#include "arphdr.h"

struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};


uint8_t* getMymac(char* interface);
char* getMyip(char* interface);
void arp_spoof(uint8_t* My_mac,char* My_ip,char* Sender_ip,char* Target_ip,char* dev);
