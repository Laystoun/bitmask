#include "dns_spoof.h"

#include <iostream>

dns_map dns_table;

void dns_spoof_detector(const u_char* packet, const struct pcap_pkthdr* header) {
    if (header->caplen < ETH_MIN_SIZE + 20 + 8) return;
    const u_char* ipv4 = packet + 14;
    if (*(ipv4 + 9) != UDP_HEADER_BYTE) return;
    int ip_len = (*(ipv4) & 0x0f) * 4;
    
    const u_char* udp = ipv4 + ip_len;
    const u_char* dns = udp + 8;

    uint16_t src = (udp[0] << 8) | udp[1];
    uint16_t dst = (udp[2] << 8) | udp[3];
    bool is_dns = (src==53 || dst==53) ? true : false; if (!is_dns) return;
    bool is_response = ((dns[2] & 0x80) != 0) ? true:false; if (!is_response) return;
    uint16_t trans_id = (dns[0] << 8) | dns[1];
    const u_char* ptr = dns + 12;
    
    while (*ptr != 0x00) ptr += *ptr + 1;
    ptr += 5;

    while (*ptr != 0x00) ptr += *ptr + 1;
    ptr += 11;
    
    uint32_t ip = ((ptr[0] << 24) | (ptr[1] << 16) | (ptr[2] << 8) | ptr[3]);
    if (dns_table.find(trans_id) == dns_table.end()) dns_table[trans_id] = ip;
    else if (dns_table[trans_id] != ip) {
            std::cout << "[DANGER] DNS SPOOF DETECTED\n"
                   << "IP: " << ip << std::endl
                   << "TRANSACTION ID: " << trans_id << std::endl;
        }
}