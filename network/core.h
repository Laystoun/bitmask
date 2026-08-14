#ifndef CORE_H
#define CORE_H

#define PACKET_HEADER_SIZE 0x0E
#define ARP_PROTOCOL_12 0x08
#define ARP_PROTOCOL_13 0x06
#define IPV4_1 0x008
#define IPV4_2 0x00

#include <pcap.h>
#include <iostream>
#include <vector>
#include <map>
#include <cstring>

#include "arp_spoof.h"
#include "dns_spoof.h"
#include "../shell/shell.h"

typedef std::vector<pcap_if_t*>::iterator pcap_iterator;

static std::map<std::string, std::string> arp_table;

struct NetworkCore {
    pcap_if_t* alldevs;
    char error_buff[PCAP_ERRBUF_SIZE];
    
    std::vector<pcap_if_t*> devices;
    pcap_if_t* master_device;

    NetworkCore(NetworkEntry entry) {
        std::cout.setf(std::ios::unitbuf); // disable bufferized
        if (pcap_findalldevs(&alldevs, error_buff) == -1)
            throw std::runtime_error("Network error: " + std::string(error_buff));

        for (pcap_if_t* d = alldevs; d != nullptr; d = d->next) {
            devices.push_back(d);
        }
        device_ch();
        capture(entry);
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
                for (pcap_iterator it = devices.begin(); it != devices.end(); ++it) {
                    if ((*it)->addresses != nullptr) {
                        char errbuf[PCAP_ERRBUF_SIZE];
                        
                        pcap_t* openl = pcap_open_live(
                            (*it)->name,
                            65536,
                            PCAP_OPENFLAG_PROMISCUOUS,
                            1000,
                            errbuf
                        );

                        if (openl != nullptr) {
                            master_device = *it;
                            pcap_close(openl);
                            break;
                        }
                    }
                }
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

    void capture(NetworkEntry& network_entry) {
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
        std::cout << "Start...\nIf something happens, we will let you know." << "\n";
        pcap_loop(descriptor, -1, pcap_handler, reinterpret_cast<unsigned char*>(&network_entry));
    }

    static void pcap_handler(u_char *user, const struct pcap_pkthdr* header, const u_char* data) {
        NetworkEntry* network_entry = reinterpret_cast<NetworkEntry*>(user);
        
        u_char ETH_HEADER_1 = data[12];
        u_char ETH_HEADER_2 = data[13];
        
        if (ETH_HEADER_1 == ARP_PROTOCOL_12 && ETH_HEADER_2 == ARP_PROTOCOL_13 &&
            network_entry->network_protocol == NetworkProtocolListen::ARP)
        {
            arp_spoof_detector(data, header);
        }
        
        // DNS Block
        if (ETH_HEADER_1 == IPV4_1 && ETH_HEADER_2 == IPV4_2 &&
            network_entry->network_protocol == NetworkProtocolListen::DNS)
        {
            if (header->caplen >= 23) {
                dns_spoof_detector(data, header, network_entry);
            } 
        }
    }

    ~NetworkCore() {
        pcap_freealldevs(alldevs);
    }
};


#endif