# CS331 Computer Networks Assignment 1

## Overview

This assignment involves implementing a raw packet sniffer to analyze and compute various network traffic metrics from a captured packet file (`6.pcap`). Additionally, the program replays the captured traffic using `tcpreplay` and generates relevant insights through metrics and visualizations.

## Team Members

- **22110221** - Repalle Bhanu Roshini
- **22110272** - Thumma Ushasree
  
## Prerequisites

### Operating System: 
- Linux (WSL/Ubuntu preferred)

### Dependencies:
- `g++` (for compiling C++ code)
- `libpcap-dev` (for packet capturing)
- `tcpreplay` (for replaying network traffic)
- `python3`, `matplotlib` (for visualization)

### To install dependencies, run:

```bash
sudo apt update && sudo apt install g++ libpcap-dev tcpreplay python3 python3-matplotlib
```

## Folder Structure

```bash
|-- part1_q/
    |-- results/
        |-- 1_1.txt                     # Metrics output file
        |-- 1_2.txt                     # Flow data output file
        |-- 1_3_max_flow.txt            # Max flow data output file
        |-- packet_size_histogram.png   # Packet size histogram
        |-- packet_sizes_distribution.csv   # Distribution of packet sizes
        |-- 6.pcap                       # Selected PCAP file
        |-- histogram_data.csv           # Histogram data in CSV format
    |-- histogram_gen.py                # Script to generate histogram of packet sizes
    |-- raw_packet_sniffer.cpp          # Packet Sniffer Implementation
|--part2_q/
  |--part2_1.cpp
  |--part2_2_3.cpp
|-- 6-22110272_22110221.pdf #report
|-- README.md                          # This file

```
## PCAP File

The required PCAP file (`6.pcap`) has been omitted from this repository due to its large size. Please download the `6.pcap` file from the provided source and place it in the `part1` and `part2` folder to run the packet sniffer and complete the assignment.

## Compilation and Execution for part1

### In One Terminal

#### Compile the Packet Sniffer

```bash
g++ -o raw_packet_sniffer raw_packet_sniffer.cpp -lpcap
```
#### Run the Packet Sniffer
```bash
sudo ./raw_packet_sniffer
```
### In Another Terminal
#### Replay Captured Packets
```bash

sudo tcpreplay -i eth0 --topspeed 6.pcap
```
(Replace eth0 with your active network interface)

### Stop the Sniffer
Once the packet replay output is displayed, press Ctrl + C in the first terminal to stop the sniffer.

### Check Generated Output Files

After stopping the sniffer, the following output files will be created:

- **1_1.txt** - Contains total packets, total data transferred, min/max/avg packet size.
- **1_2.txt** - Contains source-destination pair statistics.
- **1_3.txt** - Contains per-IP flow statistics.
- **1_3_max_data.txt** - Contains source-destination pair with maximum data transfer.

### Generate Histogram
Run the following command in WSL:

```bash
python3 histogram_gen.py
```
This script generates a histogram of packet sizes from the captured data.

## Compilation and Execution for part2_q1

### In One Terminal

#### Compile the Packet Sniffer

```bash
g++ -o part2_1 part2_1.cpp -lpcap
```
#### Run the Packet Sniffer
```bash
sudo ./part2_1 eth0
```
### In Another Terminal
#### Replay Captured Packets
```bash

sudo tcpreplay -i eth0 --topspeed 6.pcap
```
(Replace eth0 with your active network interface)

### Stop the Sniffer
Once the packet replay output is displayed, press Ctrl + C in the first terminal to stop the sniffer.

## Compilation and Execution for part2_q2 & part2_q3

### In One Terminal

#### Compile the Packet Sniffer

```bash
g++ -o part2_2_3 part2_2_3.cpp -lpcap
```
#### Run the Packet Sniffer
```bash
sudo ./part2_2_3 eth0
```
### In Another Terminal
#### Replay Captured Packets
```bash

sudo tcpreplay -i eth0 --topspeed 6.pcap
```
(Replace eth0 with your active network interface)

### Stop the Sniffer
Once the packet replay output is displayed, press Ctrl + C in the first terminal to stop the sniffer.
