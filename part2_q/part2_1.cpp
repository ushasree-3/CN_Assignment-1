#include <pcap.h>
#include <iostream>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <fstream>  // For file operations

// Function to check if an IP is in the private address range
bool is_private_ip(const std::string &ip) {
    uint32_t ip_int;
    inet_pton(AF_INET, ip.c_str(), &ip_int);

    if ((ip_int & 0xFF000000) == 0x0A000000) return true;
    if ((ip_int & 0xFFF00000) == 0xAC100000) return true;
    if ((ip_int & 0xFFFF0000) == 0xC0A80000) return true;

    return false;
}

// Function to handle DNS requests
void process_dns_packet(const unsigned char *packet) {
    struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
    struct udphdr *udp_header = (struct udphdr *)((unsigned char *)ip_header + (ip_header->ip_hl << 2));
}

// Function to handle packets captured
void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    struct ether_header *eth_header = (struct ether_header *)packet;
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));

        if (ip_header->ip_p == IPPROTO_TCP) {
            struct in_addr src_ip = ip_header->ip_src;
            struct in_addr dest_ip = ip_header->ip_dst;

            char src_ip_str[INET_ADDRSTRLEN];
            char dest_ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &src_ip, src_ip_str, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &dest_ip, dest_ip_str, INET_ADDRSTRLEN);

            std::ofstream file("private_ips.txt", std::ios::app);
            if (is_private_ip(dest_ip_str)) {
                // Write the private IP address to the file
                file << "Private IP Address: " << dest_ip_str << std::endl;
            }
            file.close();
        }

        // Check for DNS packets
        if (ip_header->ip_p == IPPROTO_UDP) {
            process_dns_packet(packet);
        }
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf); 

    if (handle == nullptr) {
        std::cerr << "Error opening device: " << errbuf << std::endl;
        return 1;
    }

    if (pcap_loop(handle, 0, packet_handler, nullptr) < 0) {
        std::cerr << "Error capturing packets: " << pcap_geterr(handle) << std::endl;
        return 1;
    }

    pcap_close(handle);

    return 0;
}