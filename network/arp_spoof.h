#ifndef ARP_SPOOF_H
#define ARP_SPOOF_H

#include <pcap.h>
#include <iostream>

void spoof_detector(const u_char* data);
static std::string mac_to_str(const u_char* mac);
static std::string ip_to_str(const u_char* ip);

#endif