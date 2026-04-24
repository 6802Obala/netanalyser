// =============================================================================
//  analyzer.h – Protocol analysis and threat detection
// =============================================================================
#pragma once
#include "capture.h"
#include <map>
#include <string>

struct Stats {
    int total   = 0;
    int tcp     = 0;
    int udp     = 0;
    int icmp    = 0;
    int arp     = 0;
    int other   = 0;
    int alerts  = 0;
    std::map<std::string, int> top_talkers;   // src_ip → packet count
    std::map<std::string, int> port_scan_map; // src_ip → unique dst_port count
};

class Analyzer {
public:
    void analyze(Packet& pkt);
    const Stats& get_stats() const { return stats_; }
    int get_total() const { return stats_.total; }

private:
    Stats stats_;
    std::map<std::string, std::map<int,int>> port_tracker_; // ip → {port → count}

    void detect_port_scan(Packet& pkt);
    void detect_icmp_flood(Packet& pkt);
};
