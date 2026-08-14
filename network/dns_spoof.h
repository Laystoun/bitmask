#ifndef DNS_SPOOF_H
#define DNS_SPOOF_H

#define UDP_HEADER_BYTE 0x11
#define ETH_MIN_SIZE 0x0e

#include <pcap.h>
#include <map>
#include <string>
#include <chrono>

#include "../shell/shell.h"

struct dns_record {
    uint32_t ip;
    std::chrono::steady_clock::time_point timestamp;
};

typedef std::map<std::pair<uint16_t, std::string>, dns_record> dns_map;
void dns_spoof_detector(const u_char* packet, const struct pcap_pkthdr* header, NetworkEntry* network_entry);
std::string parse_domain(const u_char* dns, const u_char* ptr);

#endif
