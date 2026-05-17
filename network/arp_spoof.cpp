#include "arp_spoof.h"
#include "core.h"

static std::string mac_to_str(const u_char* mac) {
    char buf[18];
    sprintf(buf,
        "%02X:%02X:%02X:%02X:%02X:%02X",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    );
    return buf;
}
static std::string ip_to_str(const u_char* ip) {
    char buf[16];
    sprintf(buf,
        "%d.%d.%d.%d",
        ip[0], ip[1], ip[2], ip[3]
    );
    return buf;
}

void spoof_detector(const u_char* data) {
    const u_char* arp = data + 14;
    const u_char* sender_mac = arp + 8;
    const u_char* sender_ip = arp + 14;
    
    std::string ip = ip_to_str(sender_ip);
    std::string mac = mac_to_str(sender_mac);

    std::cout << "[ARP] " << ip << " -> " << mac << std::endl;
    
    if (arp_table.find(ip) == arp_table.end()) {
        arp_table[ip] = mac;
        std::cout << "[+] " << ip << "->" << mac << std::endl;
    } else if (arp_table[ip] != mac) {
        std::cout << "[WARNING!] ARP SPOOFING ATTEMPT!\n"
                  << "IP: " << ip << std::endl
                  << "OLD MAC: " << arp_table[ip] << std::endl
                  << "NEW MAC: " << mac << std::endl;
        arp_table[ip] = mac;
    }
}