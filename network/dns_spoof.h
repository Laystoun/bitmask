#ifndef DNS_SPOOF_H
#define DNS_SPOOF_H

#define UDP_HEADER_BYTE 0x11
#define ETH_MIN_SIZE 0x0e

#include <pcap.h>
#include <map>

typedef std::map<uint16_t, uint32_t> dns_map;
void dns_spoof_detector(const u_char* packet, const struct pcap_pkthdr* header);

#endif
