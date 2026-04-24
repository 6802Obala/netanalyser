// =============================================================================
//  capture.h – Packet capture using libpcap
// =============================================================================
#pragma once

#include <string>
#include <functional>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>

// ── Packet structure ──────────────────────────────────────────────────────────
struct Packet {
    std::string timestamp;
    std::string src_ip;
    std::string dst_ip;
    std::string protocol;   // TCP / UDP / ICMP / ARP / OTHER
    int         src_port  = 0;
    int         dst_port  = 0;
    int         length    = 0;
    std::string flags;      // TCP flags: SYN, ACK, FIN, RST...
    std::string info;       // Extra info (DNS query, ARP type, etc.)
    bool        suspicious = false;
    std::string alert;      // Alert message if suspicious
};

// ── Capture class ─────────────────────────────────────────────────────────────
class Capture {
public:
    Capture(const std::string& iface,
            const std::string& filter,
            int count,
            volatile bool* running);
    ~Capture();

    // Start capture; calls callback for each packet
    void start(std::function<void(Packet&)> callback);

    // Auto-detect the default network interface
    static std::string auto_detect_interface();

private:
    std::string  iface_;
    std::string  filter_;
    int          count_;
    volatile bool* running_;
    pcap_t*      handle_ = nullptr;

    static Packet parse_packet(const struct pcap_pkthdr* header,
                               const u_char* data);
    static std::string get_timestamp(const struct timeval& ts);
    static std::string tcp_flags(const struct tcphdr* tcp);
};
