#include <iostream>
#include <chrono>

#include "dns_spoof.h"
#include "../shell/shell.h"

#define COMPRESSION_POINTER 0xC0 // 11000000

dns_map dns_table;

std::string parse_domain(const u_char* dns, const u_char* ptr){
    std::string domain;

    while(*ptr != 0x00){
        if((*ptr & 0xC0)==COMPRESSION_POINTER){
            uint16_t offset=((*ptr & 0x3F) << 8) | *(ptr+1);
            ptr=dns+offset;
            continue;
        }
        uint8_t len=*ptr; ptr++;
        if(!domain.empty())domain+=".";
        for(int i=0;i<len;i++){
            domain+=(char)*ptr;
            ptr++;
        }
    }
    return domain;
}

void cleanup() {
    auto now = std::chrono::steady_clock::now();
    for (auto it = dns_table.begin(); it != dns_table.end();) {
        auto age = std::chrono::duration_cast<std::chrono::seconds>(
            now - it->second.timestamp).count();
        if (age > 10)
            it = dns_table.erase(it);
        else
            ++it;
    }
}

void dns_spoof_detector(const u_char* packet, const struct pcap_pkthdr* header, NetworkEntry* network_entry) {
    if (header->caplen < ETH_MIN_SIZE + 20 + 8) return;
    const u_char* ipv4 = packet + 14;
    if (*(ipv4 + 9) != UDP_HEADER_BYTE) return;
    int ip_len = (*(ipv4) & 0x0f) * 4;

    const u_char* udp = ipv4 + ip_len;
    const u_char* dns = udp + 8;

    uint16_t src = (udp[0] << 8) | udp[1];
    uint16_t dst = (udp[2] << 8) | udp[3];
    bool is_dns=(src==53||dst==53)?true:false;if (!is_dns) return;
    bool is_response = ((dns[2] & 0x80) != 0) ? true:false; if (!is_response) return;
    uint16_t trans_id = (dns[0] << 8) | dns[1];
    std::string domain=parse_domain(dns, dns+12);
    
    if(network_entry->network_flags.verbose) std::cout << "Domain: " << domain << "\n";
    const u_char* ptr = dns + 12;  // Jump to Answer
    while(*ptr != 0x00) {
        if((*ptr & 0xC0)==COMPRESSION_POINTER) {ptr += 2; break;}
        ptr += *ptr + 1;
    }
    if ((*ptr & 0xC0) != 0xC0) ptr++;
    ptr += 4; // TYPE + CLASS
    // Answer
    if ((*ptr & 0xC0) == 0xC0) ptr += 2; // compression pointer
    else { while (*ptr != 0x00) ptr += *ptr + 1; ptr++; }
    ptr += 8; // TYPE + CLASS + TTL
    ptr += 2; // RDLENGTH
    uint32_t ip = ((ptr[0] << 24) | (ptr[1] << 16) | (ptr[2] << 8) | ptr[3]);
    auto key=std::make_pair(trans_id,domain); cleanup();
    if (dns_table.find(key) == dns_table.end()) {
        dns_record record;
        record.ip = ip;
        record.timestamp = std::chrono::steady_clock::now();
        dns_table[key] = record;
    }
    else if (dns_table[key].ip != ip) {
            std::cout << "[DANGER] DNS SPOOF DETECTED\n"
                << "Domain: " << domain << "\n"
                << "Expected IP: " << ((dns_table[key].ip >> 24) & 0xFF) << "."
                                   << ((dns_table[key].ip >> 16) & 0xFF) << "."
                                   << ((dns_table[key].ip >> 8)  & 0xFF) << "."
                                   << (dns_table[key].ip & 0xFF) << "\n"
                << "Got IP: "      << ((ip >> 24) & 0xFF) << "."
                                   << ((ip >> 16) & 0xFF) << "."
                                   << ((ip >> 8)  & 0xFF) << "."
                                   << (ip & 0xFF) << "\n"
                << "Transaction ID: " << trans_id << std::endl;

            if (network_entry->network_start_type == NetworkStartType::EMERGENCY) {
                
                // Implementing disconnection from the internet
                
                std::cout << "Internet connection was reset..." << "\n";
            }
        }
}