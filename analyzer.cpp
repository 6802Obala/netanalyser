// =============================================================================
//  analyzer.cpp – Threat detection logic
// =============================================================================
#include "analyzer.h"

#define PORT_SCAN_THRESHOLD 15   // unique ports from one IP = suspicious

void Analyzer::analyze(Packet& pkt) {
    stats_.total++;

    // Count by protocol
    if      (pkt.protocol == "TCP")   stats_.tcp++;
    else if (pkt.protocol == "UDP")   stats_.udp++;
    else if (pkt.protocol == "ICMP")  stats_.icmp++;
    else if (pkt.protocol == "ARP")   stats_.arp++;
    else                              stats_.other++;

    // Top talkers
    if (!pkt.src_ip.empty())
        stats_.top_talkers[pkt.src_ip]++;

    // Threat detection
    detect_port_scan(pkt);
    detect_icmp_flood(pkt);

    if (pkt.suspicious) stats_.alerts++;
}

// ── Port scan detection ───────────────────────────────────────────────────────
void Analyzer::detect_port_scan(Packet& pkt) {
    if (pkt.protocol != "TCP" && pkt.protocol != "UDP") return;
    if (pkt.src_ip.empty() || pkt.dst_port == 0) return;

    port_tracker_[pkt.src_ip][pkt.dst_port]++;
    int unique_ports = port_tracker_[pkt.src_ip].size();

    stats_.port_scan_map[pkt.src_ip] = unique_ports;

    if (unique_ports >= PORT_SCAN_THRESHOLD) {
        pkt.suspicious = true;
        pkt.alert = "⚠ PORT SCAN detected from " + pkt.src_ip +
                    " (" + std::to_string(unique_ports) + " unique ports)";
    }
}

// ── ICMP flood detection ──────────────────────────────────────────────────────
void Analyzer::detect_icmp_flood(Packet& pkt) {
    if (pkt.protocol != "ICMP") return;

    static std::map<std::string, int> icmp_count;
    icmp_count[pkt.src_ip]++;

    if (icmp_count[pkt.src_ip] > 50) {
        pkt.suspicious = true;
        pkt.alert = "⚠ ICMP FLOOD detected from " + pkt.src_ip;
    }
}
