#ifndef ARP_SPOOF_H
#define ARP_SPOOF_H

#include <pcap.h>
#include <iostream>

void arp_spoof_detector(const u_char* data, const struct pcap_pkthdr* header);
static std::string mac_to_str(const u_char* mac);
static std::string ip_to_str(const u_char* ip);

#endif