#ifndef CORE_H
#define CORE_H

#include <pcap.h>
#include <iostream>
#include <vector>
#include <map>

typedef std::vector<pcap_if_t*>::iterator pcap_iterator;

static std::map<std::string, std::string> arp_table;

struct core {
    pcap_if_t* alldevs;
    char error_buff[PCAP_ERRBUF_SIZE];
    
    std::vector<pcap_if_t*> devices;
    pcap_if_t* master_device;
    core() {
        if (pcap_findalldevs(&alldevs, error_buff) == -1)
            throw std::runtime_error("Network error: " + std::string(error_buff));

        for (pcap_if_t* d = alldevs; d != nullptr; d = d->next) {
            devices.push_back(d);    
        }
        device_ch();
        capture();
    }

    void device_ch() { 
        int count = 1;
        for (pcap_iterator it = devices.begin(); it != devices.end(); ++it) {
            std::cout << count << ". " << ((*it)->description ? (*it)->description : (*it)->name) << std::endl;
            count += 1;
        }
        std::cout << "\nSelect a device for traffic capture (Enter for Auto) #: ";
        
        std::string choise;
        std::getline(std::cin, choise);
        
        try {
            bool is_empty = false;
            if (choise.empty()) is_empty=true;
            
            if (is_empty) {
                master_device = devices.at(0);
                std::cout << "[INFO] "
                          << "Auto-selected: "
                          << (master_device->description ? master_device->description : master_device->name) << std::endl;
                return;
            }
            
            int ch_int = std::stoi(choise);
            master_device = devices.at(ch_int - 1);
        } catch (const std::invalid_argument& ex) {
            std::cerr << "[ERROR] Invalid argument " << choise << std::endl;
            exit(1);
        } catch (const std::out_of_range& ex) {
            std::cerr << "[ERROR] Overflow: " << choise << std::endl;
            exit(1);
        }
    }

    void capture() {
        char error_buff[PCAP_ERRBUF_SIZE];

        pcap_t* descriptor = pcap_open_live(
            master_device->name,
            65536,
            1,
            1000,
            error_buff
        );

        if (descriptor == nullptr) {
            std::cerr << "[ERROR] Cannot open device: " << error_buff << std::endl;
            return;
        }

        pcap_loop(descriptor, -1, pcap_handler, nullptr);
    }

    static void pcap_handler(u_char *user, const struct pcap_pkthdr* header, const u_char* data) {
        if (header->caplen < 42) return;

        if (data[12] != 0x08 || data[13] != 0x06) return;

        const u_char* arp = data + 14;

        const u_char* sender_mac = arp + 8;
        const u_char* sender_ip = arp + 14;

        std::string ip = ip_to_str(sender_ip);
        std::string mac = mac_to_str(sender_mac);

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

    ~core() {
        pcap_freealldevs(alldevs);
    }
};


#endif