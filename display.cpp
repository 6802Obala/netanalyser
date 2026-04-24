// =============================================================================
//  display.cpp – Coloured terminal output
// =============================================================================
#include "display.h"
#include <iostream>
#include <iomanip>

// ANSI colours
#define RESET   "\033[0m"
#define BOLD    "\033[1m"
#define RED     "\033[0;31m"
#define GREEN   "\033[0;32m"
#define YELLOW  "\033[0;33m"
#define CYAN    "\033[0;36m"
#define BLUE    "\033[0;34m"
#define MAGENTA "\033[0;35m"
#define WHITE   "\033[1;37m"
#define BG_DARK "\033[48;5;235m"

void Display::print_banner() {
    std::cout << "\n"
              << BG_DARK << WHITE << BOLD
              << "  ╔══════════════════════════════════════════════════════╗\n"
              << "  ║        🔍  NETWORK ANALYZER  –  C++ / libpcap       ║\n"
              << "  ║        Author : Marc Kambou Kengnang                ║\n"
              << "  ║        HTW Berlin – Computer Engineering             ║\n"
              << "  ╚══════════════════════════════════════════════════════╝\n"
              << RESET << "\n";
}

void Display::separator() {
    std::cout << BLUE
              << "  ──────────────────────────────────────────────────────\n"
              << RESET;
}

void Display::print_info(const std::string& msg) {
    std::cout << "  " << CYAN << "[*] " << RESET << msg << "\n";
}

void Display::print_packet(const Packet& pkt) {
    // Colour by protocol
    std::string color;
    if      (pkt.protocol == "TCP")  color = GREEN;
    else if (pkt.protocol == "UDP")  color = CYAN;
    else if (pkt.protocol == "ICMP") color = YELLOW;
    else if (pkt.protocol == "ARP")  color = MAGENTA;
    else                             color = WHITE;

    // Alert overrides colour
    if (pkt.suspicious) color = RED;

    std::cout << "  "
              << BLUE  << pkt.timestamp << RESET << "  "
              << color << BOLD << std::setw(5) << pkt.protocol << RESET << "  "
              << std::setw(15) << pkt.src_ip;

    if (pkt.src_port > 0)
        std::cout << ":" << std::setw(5) << pkt.src_port;
    else
        std::cout << "       ";

    std::cout << "  →  " << std::setw(15) << pkt.dst_ip;

    if (pkt.dst_port > 0)
        std::cout << ":" << std::setw(5) << pkt.dst_port;
    else
        std::cout << "       ";

    std::cout << "  " << std::setw(4) << pkt.length << "B";

    if (!pkt.info.empty())
        std::cout << "  " << CYAN << pkt.info << RESET;

    if (!pkt.flags.empty())
        std::cout << "  [" << pkt.flags << "]";

    std::cout << "\n";

    // Print alert on next line
    if (pkt.suspicious && !pkt.alert.empty())
        std::cout << "  " << RED << BOLD << pkt.alert << RESET << "\n";
}

void Display::print_stats(const Stats& stats) {
    separator();
    std::cout << BOLD << WHITE << "  STATISTICS\n" << RESET;
    std::cout << "  Total packets : " << WHITE << stats.total  << RESET << "\n"
              << "  TCP           : " << GREEN  << stats.tcp   << RESET << "\n"
              << "  UDP           : " << CYAN   << stats.udp   << RESET << "\n"
              << "  ICMP          : " << YELLOW << stats.icmp  << RESET << "\n"
              << "  ARP           : " << MAGENTA<< stats.arp   << RESET << "\n"
              << "  Other         : "           << stats.other << "\n"
              << "  Alerts        : " << RED << BOLD << stats.alerts << RESET << "\n";

    // Top 5 talkers
    if (!stats.top_talkers.empty()) {
        std::cout << "\n  " << BOLD << "TOP TALKERS\n" << RESET;
        int shown = 0;
        // Simple sort: find max 5 times
        auto tmp = stats.top_talkers;
        while (shown < 5 && !tmp.empty()) {
            auto max_it = tmp.begin();
            for (auto it = tmp.begin(); it != tmp.end(); ++it)
                if (it->second > max_it->second) max_it = it;
            std::cout << "  " << std::setw(16) << max_it->first
                      << "  →  " << max_it->second << " packets\n";
            tmp.erase(max_it);
            shown++;
        }
    }

    // Port scan suspects
    if (!stats.port_scan_map.empty()) {
        for (auto& [ip, ports] : stats.port_scan_map) {
            if (ports >= 15)
                std::cout << "  " << RED << BOLD
                          << "⚠ Port scan suspect: " << ip
                          << " (" << ports << " ports)" << RESET << "\n";
        }
    }

    separator();
}
