#include <iostream>
#include <pcap.h>
#include <vector>
#include <map>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <climits>
#include <csignal>
#include <fstream>
#include <sys/stat.h>

using namespace std;

// Structure to store network packet statistics
struct NetworkStats {
    int packetCount = 0; // Total number of captured packets
    long long totalData = 0; // Total data transferred in bytes
    int smallestPacket = INT_MAX; // Smallest packet size seen
    int largestPacket = 0; // Largest packet size seen
    vector<int> packetSizeList; // List of all packet sizes
    map<int, int> packetSizeHistogram; // Histogram: Packet size -> frequency
    map<string, long long> trafficFlows; // Data transferred per flow (source-destination pair)
    map<string, int> sourceIPCount; // Count of packets per source IP
    map<string, int> destinationIPCount; // Count of packets per destination IP
};

volatile sig_atomic_t captureStop = 0;
pcap_t *captureHandle = nullptr;

// Signal handler for Ctrl+C to stop packet capture
void signalHandler(int signum) {
    captureStop = 1;
    if (captureHandle) {
        pcap_breakloop(captureHandle);
    }
}

// Callback function for processing incoming packets
void processPacket(u_char *userData, const struct pcap_pkthdr *packetHeader, const u_char *packet) {
    NetworkStats *stats = (NetworkStats *)userData;
    
    int packetSize = packetHeader->len;
    stats->packetCount++;
    stats->totalData += packetSize;
    stats->smallestPacket = min(stats->smallestPacket, packetSize);
    stats->largestPacket = max(stats->largestPacket, packetSize);
    stats->packetSizeList.push_back(packetSize);
    stats->packetSizeHistogram[packetSize]++;

    // Extract IP header (assuming Ethernet frame, offset 14 bytes)
    struct ip *ipHeader = (struct ip *)(packet + 14);
    char sourceIP[INET_ADDRSTRLEN], destIP[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ipHeader->ip_src, sourceIP, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &ipHeader->ip_dst, destIP, INET_ADDRSTRLEN);

    // Extract TCP header (IP header length is variable, so calculate offset dynamically)
    struct tcphdr *tcpHeader = (struct tcphdr *)(packet + 14 + (ipHeader->ip_hl << 2));
    uint16_t sourcePort = ntohs(tcpHeader->th_sport);
    uint16_t destPort = ntohs(tcpHeader->th_dport);

    // Format flow as "SourceIP:Port -> DestIP:Port"
    string flowKey = string(sourceIP) + ":" + to_string(sourcePort) + " -> " + string(destIP) + ":" + to_string(destPort);

    // Update packet flow statistics
    stats->trafficFlows[flowKey] += packetSize;
    stats->sourceIPCount[sourceIP]++;
    stats->destinationIPCount[destIP]++;

    if (captureStop) {
        pcap_breakloop(captureHandle);
    }
}

// Function to create results directory if it doesn't exist
void createResultsDirectory() {
    struct stat info;
    if (stat("results", &info) != 0) {
        if (mkdir("results", 0777) != 0) {
            cerr << "Error creating results directory!" << endl;
            exit(1);
        }
    }
}

// Function to save collected network metrics to text files in the "results" folder
void saveStatistics(NetworkStats &stats) {
    // Create results directory
    createResultsDirectory();

    // Save summary statistics
    ofstream summaryFile("results/1_1.txt");
    double avgPacketSize = (stats.packetCount > 0) ? (double)stats.totalData / stats.packetCount : 0;

    summaryFile << "Total Packets: " << stats.packetCount << endl;
    summaryFile << "Total Data Transferred: " << stats.totalData << " bytes" << endl;
    summaryFile << "Min Packet Size: " << stats.smallestPacket << " bytes" << endl;
    summaryFile << "Max Packet Size: " << stats.largestPacket << " bytes" << endl;
    summaryFile << "Avg Packet Size: " << avgPacketSize << " bytes" << endl;
    summaryFile.close();

    // Save packet size distribution (histogram)
    ofstream histogramFile("results/packet_size_histogram.txt");
    for (auto &[size, freq] : stats.packetSizeHistogram) {
        histogramFile << size << " " << freq << endl;
    }
    histogramFile.close();

    // Save per-flow data transfer statistics
    ofstream flowDataFile("results/1_2.txt");
    for (auto &flow : stats.trafficFlows) {
        flowDataFile << flow.first << " -> " << flow.second << " bytes transferred" << endl;
    }
    flowDataFile.close();

    // Save per-IP flow statistics
    ofstream ipStatsFile("results/1_3.txt");
    ipStatsFile << "Source IP Flow Counts:" << endl;
    for (auto &flow : stats.sourceIPCount) {
        ipStatsFile << flow.first << " : " << flow.second << " flows" << endl;
    }

    ipStatsFile << "\nDestination IP Flow Counts:" << endl;
    for (auto &flow : stats.destinationIPCount) {
        ipStatsFile << flow.first << " : " << flow.second << " flows" << endl;
    }
    ipStatsFile.close();
    
    // Find the source-destination pair with the most data transferred
    string maxFlowPair;
    long long maxData = 0;
    for (auto &flow : stats.trafficFlows) {
        if (flow.second > maxData) {
            maxData = flow.second;
            maxFlowPair = flow.first;
        }
    }

    // Save the max flow information to a file
    ofstream maxFlowFile("results/1_3_max_flow.txt");
    if (maxFlowFile.is_open()) {
        maxFlowFile << "Max Flow: " << maxFlowPair << endl;
        maxFlowFile << "Data Transferred: " << maxData << " bytes" << endl;
        maxFlowFile.close();
    } else {
        cerr << "Error opening max flow file!" << endl;
    }
}

int main() {
    char errorBuffer[PCAP_ERRBUF_SIZE];

    // Find available network interfaces
    pcap_if_t *allDevices, *selectedDevice;
    if (pcap_findalldevs(&allDevices, errorBuffer) == -1) {
        cerr << "Error finding network interfaces: " << errorBuffer << endl;
        return 1;
    }

    selectedDevice = allDevices;
    if (!selectedDevice) {
        cerr << "No network interfaces found!" << endl;
        return 1;
    }
    cout << "Using device: " << selectedDevice->name << endl;

    // Open selected network interface for live packet capture
    captureHandle = pcap_open_live(selectedDevice->name, BUFSIZ, 1, 1000, errorBuffer);
    if (!captureHandle) {
        cerr << "Error opening device: " << errorBuffer << endl;
        return 1;
    }

    pcap_freealldevs(allDevices);
    signal(SIGINT, signalHandler);

    NetworkStats stats;
    cout << "Listening for packets... Press Ctrl+C to stop.\n";

    // Start capturing packets
    pcap_loop(captureHandle, 0, processPacket, (u_char *)&stats);

    pcap_close(captureHandle);

    // Save collected statistics to files in the results directory
    saveStatistics(stats);

    cout << "\nCapture complete.\n";
    cout << "Metrics and statistics saved to respective files in the 'results' folder." << endl;

    return 0;
}
