// =============================================================================
//  capture.cpp – libpcap capture implementation
// =============================================================================
#include "capture.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <cstring>

// ── Constructor / Destructor ──────────────────────────────────────────────────
Capture::Capture(const std::string& iface,
                 const std::string& filter,
                 int count,
                 volatile bool* running)
    : iface_(iface), filter_(filter), count_(count), running_(running) {}

Capture::~Capture() {
    if (handle_) pcap_close(handle_);
}

// ── Auto-detect interface ─────────────────────────────────────────────────────
std::string Capture::auto_detect_interface() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) == -1 || alldevs == nullptr)
        return "";
    std::string iface = alldevs->name;
    pcap_freealldevs(alldevs);
    return iface;
}

// ── Timestamp helper ──────────────────────────────────────────────────────────
std::string Capture::get_timestamp(const struct timeval& ts) {
    char buf[32];
    time_t t = ts.tv_sec;
    struct tm* tm_info = localtime(&t);
    strftime(buf, sizeof(buf), "%H:%M:%S", tm_info);
    std::ostringstream oss;
    oss << buf << "." << std::setw(3) << std::setfill('0') << (ts.tv_usec / 1000);
    return oss.str();
}

// ── TCP flags helper ──────────────────────────────────────────────────────────
std::string Capture::tcp_flags(const struct tcphdr* tcp) {
    std::string flags = "";
    if (tcp->syn) flags += "SYN ";
    if (tcp->ack) flags += "ACK ";
    if (tcp->fin) flags += "FIN ";
    if (tcp->rst) flags += "RST ";
    if (tcp->psh) flags += "PSH ";
    if (tcp->urg) flags += "URG ";
    if (!flags.empty()) flags.pop_back();
    return flags;
}

// ── Parse a raw packet ────────────────────────────────────────────────────────
Packet Capture::parse_packet(const struct pcap_pkthdr* header,
                              const u_char* data) {
    Packet pkt;
    pkt.timestamp = get_timestamp(header->ts);
    pkt.length    = header->len;

    const struct ether_header* eth = (struct ether_header*)data;
    uint16_t ether_type = ntohs(eth->ether_type);

    // ── ARP ──────────────────────────────────────────────────
    if (ether_type == ETHERTYPE_ARP) {
        pkt.protocol = "ARP";
        pkt.src_ip   = "ARP Request/Reply";
        pkt.info     = "ARP packet";
        return pkt;
    }

    // ── IPv4 ─────────────────────────────────────────────────
    if (ether_type != ETHERTYPE_IP) {
        pkt.protocol = "OTHER";
        return pkt;
    }

    const struct ip* ip_hdr = (struct ip*)(data + sizeof(struct ether_header));
    pkt.src_ip = inet_ntoa(ip_hdr->ip_src);
    pkt.dst_ip = inet_ntoa(ip_hdr->ip_dst);

    int ip_hdr_len = ip_hdr->ip_hl * 4;
    const u_char* transport = data + sizeof(struct ether_header) + ip_hdr_len;

    switch (ip_hdr->ip_p) {

        case IPPROTO_TCP: {
            pkt.protocol = "TCP";
            const struct tcphdr* tcp = (struct tcphdr*)transport;
            pkt.src_port = ntohs(tcp->source);
            pkt.dst_port = ntohs(tcp->dest);
            pkt.flags    = tcp_flags(tcp);

            // Common service names
            if      (pkt.dst_port == 80  || pkt.src_port == 80)  pkt.info = "HTTP";
            else if (pkt.dst_port == 443 || pkt.src_port == 443) pkt.info = "HTTPS";
            else if (pkt.dst_port == 22  || pkt.src_port == 22)  pkt.info = "SSH";
            else if (pkt.dst_port == 21  || pkt.src_port == 21)  pkt.info = "FTP";
            else if (pkt.dst_port == 25  || pkt.src_port == 25)  pkt.info = "SMTP";
            break;
        }

        case IPPROTO_UDP: {
            pkt.protocol = "UDP";
            const struct udphdr* udp = (struct udphdr*)transport;
            pkt.src_port = ntohs(udp->source);
            pkt.dst_port = ntohs(udp->dest);
            if (pkt.dst_port == 53 || pkt.src_port == 53) pkt.info = "DNS";
            else if (pkt.dst_port == 67 || pkt.dst_port == 68) pkt.info = "DHCP";
            break;
        }

        case IPPROTO_ICMP:
            pkt.protocol = "ICMP";
            pkt.info     = "Ping / Traceroute";
            break;

        default:
            pkt.protocol = "OTHER";
            break;
    }

    return pkt;
}

// ── Main capture loop ─────────────────────────────────────────────────────────
void Capture::start(std::function<void(Packet&)> callback) {
    char errbuf[PCAP_ERRBUF_SIZE];

    handle_ = pcap_open_live(iface_.c_str(), 65535, 1, 1000, errbuf);
    if (!handle_) {
        std::cerr << "  [ERROR] Cannot open interface: " << errbuf << "\n";
        std::cerr << "  Try running with sudo.\n";
        return;
    }

    // Apply BPF filter if provided
    if (!filter_.empty()) {
        struct bpf_program fp;
        if (pcap_compile(handle_, &fp, filter_.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1 ||
            pcap_setfilter(handle_, &fp) == -1) {
            std::cerr << "  [ERROR] Bad filter: " << pcap_geterr(handle_) << "\n";
            return;
        }
        pcap_freecode(&fp);
    }

    int captured = 0;
    struct pcap_pkthdr* header;
    const u_char* data;

    while (*running_) {
        int ret = pcap_next_ex(handle_, &header, &data);
        if (ret == 0)  continue;   // timeout, try again
        if (ret == -1) break;      // error

        Packet pkt = parse_packet(header, data);
        callback(pkt);

        if (count_ > 0 && ++captured >= count_) break;
    }
}
