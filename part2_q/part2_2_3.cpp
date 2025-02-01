#include <pcap.h>
#include <iostream>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <cstring>
#include <string>
#include <regex>

using namespace std;

// Function to print IP address
void print_ip(struct in_addr ip) {
    cout << inet_ntoa(ip) << endl;
}

// Function to check if an IP is private
bool is_private_ip(const string &ip) {
    // Check for private IP ranges
    return (ip.find("10.") == 0) || (ip.find("172.") == 0 && stoi(ip.substr(4, 1)) >= 16 && stoi(ip.substr(4, 1)) <= 31) || (ip.find("192.168.") == 0);
}

// Function to handle packet capture
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ip* ip_header = (struct ip*)(packet + 14); // Skip Ethernet header (14 bytes)

    // Print the source and destination IPs
    string src_ip = inet_ntoa(ip_header->ip_src);
    string dst_ip = inet_ntoa(ip_header->ip_dst);

    if (ip_header->ip_p == IPPROTO_TCP) {
        struct tcphdr* tcp_header = (struct tcphdr*)(packet + 14 + (ip_header->ip_hl << 2));

        // 1. Check if it is DNS traffic (phishing page, port 53)
        if (ntohs(tcp_header->th_dport) == 53 || ntohs(tcp_header->th_sport) == 53) {
            // DNS Query: Attacker's IP might be identified here
            struct udphdr* udp_header = (struct udphdr*)(packet + 14 + (ip_header->ip_hl << 2));
            if (udp_header->uh_dport == htons(53)) {
                cout << "DNS Query Detected! Attacker's IP: ";
                print_ip(ip_header->ip_dst);  // Destination IP is likely the attacker
                if (is_private_ip(dst_ip)) {
                    cout << "This is a Private IP address." << endl;
                } else {
                    cout << "This is a Public IP address." << endl;
                }
            }
        }

        // 2. Check for HTTP POST (to capture victim's username at secure-bank)
        if (ntohs(tcp_header->th_dport) == 80 || ntohs(tcp_header->th_sport) == 80) {
            const u_char *http_data = packet + 14 + (ip_header->ip_hl << 2) + (tcp_header->th_off << 2);
            string http_message((char*)http_data);

            // Look for HTTP POST method
            if (http_message.find("POST") != string::npos) {
                size_t start = http_message.find("username="); // Look for username
                if (start != string::npos) {
                    start += 9; // Skip "username=" part
                    size_t end = http_message.find("&", start); // Find the end of the username
                    string username = http_message.substr(start, end - start);
                    cout << "Possible Username at secure-bank: " << username << endl;
                }
            }
        }

        // 3. Check for SMTP traffic (to get info on attacker sending email)
        if (ntohs(tcp_header->th_dport) == 25 || ntohs(tcp_header->th_dport) == 587 || ntohs(tcp_header->th_dport) == 465) {
            const u_char *smtp_data = packet + 14 + (ip_header->ip_hl << 2) + (tcp_header->th_off << 2);
            string smtp_message((char*)smtp_data);

            // Look for SMTP MAIL FROM and RCPT TO commands
            if (smtp_message.find("MAIL FROM:") != string::npos) {
                size_t start = smtp_message.find("MAIL FROM:") + 10;
                size_t end = smtp_message.find("\r\n", start);
                string sender_email = smtp_message.substr(start, end - start);
                cout << "Sender (MAIL FROM): " << sender_email << endl;
            }

            if (smtp_message.find("RCPT TO:") != string::npos) {
                size_t start = smtp_message.find("RCPT TO:") + 8;
                size_t end = smtp_message.find("\r\n", start);
                string recipient_email = smtp_message.substr(start, end - start);
                cout << "Recipient (RCPT TO): " << recipient_email << endl;
            }

            // 4. Capture the email body
            if (smtp_message.find("DATA") != string::npos) {
                size_t start = smtp_message.find("DATA") + 4;
                size_t end = smtp_message.find("\r\n.\r\n", start);
                if (end != string::npos) {
                    string email_body = smtp_message.substr(start, end - start);
                    cout << "Email Body: " << email_body << endl;
                }
            }
        }
    }
}

// Main function
int main(int argc, char *argv[]) {
    if (argc != 2) {
        cout << "Usage: " << argv[0] << " <interface>" << endl;
        return 1;
    }

    // Open the network device for sniffing
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        cerr << "Error opening device: " << errbuf << endl;
        return 1;
    }

    // Start capturing packets
    cout << "Starting packet capture..." << endl;
    pcap_loop(handle, 0, packet_handler, nullptr);

    pcap_close(handle);
    return 0;
}