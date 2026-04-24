// =============================================================================
//  main.cpp – Network Analysis Tool
//  Author  : Marc Kambou Kengnang
//  Description : Real-time network packet capture and analysis using libpcap.
//                Detects protocols, suspicious behaviour and generates reports.
// =============================================================================

#include "capture.h"
#include "analyzer.h"
#include "display.h"
#include "logger.h"
#include <iostream>
#include <csignal>
#include <cstring>

// ── Global flag for clean shutdown ───────────────────────────────────────────
volatile bool running = true;

void signal_handler(int sig) {
    (void)sig;
    running = false;
}

// ── Usage ─────────────────────────────────────────────────────────────────────
void print_usage(const char* prog) {
    std::cout << "\n  Usage: sudo " << prog << " [OPTIONS]\n\n"
              << "  Options:\n"
              << "    -i <interface>   Network interface (default: auto-detect)\n"
              << "    -f <filter>      BPF filter (e.g. \"tcp\", \"udp port 53\")\n"
              << "    -o <file.pcap>   Save capture to .pcap file\n"
              << "    -c <count>       Stop after N packets (default: unlimited)\n"
              << "    -h               Show this help\n\n"
              << "  Examples:\n"
              << "    sudo ./netanalyzer -i eth0\n"
              << "    sudo ./netanalyzer -i eth0 -f \"tcp\" -o capture.pcap\n"
              << "    sudo ./netanalyzer -i eth0 -c 100\n\n";
}

// ── Entry point ───────────────────────────────────────────────────────────────
int main(int argc, char* argv[]) {

    // Default config
    std::string interface = "";
    std::string filter    = "";
    std::string outfile   = "";
    int         count     = 0;   // 0 = unlimited

    // Parse arguments
    for (int i = 1; i < argc; i++) {
        if      (strcmp(argv[i], "-i") == 0 && i+1 < argc) interface = argv[++i];
        else if (strcmp(argv[i], "-f") == 0 && i+1 < argc) filter    = argv[++i];
        else if (strcmp(argv[i], "-o") == 0 && i+1 < argc) outfile   = argv[++i];
        else if (strcmp(argv[i], "-c") == 0 && i+1 < argc) count     = std::stoi(argv[++i]);
        else if (strcmp(argv[i], "-h") == 0) { print_usage(argv[0]); return 0; }
        else { std::cerr << "  Unknown option: " << argv[i] << "\n"; print_usage(argv[0]); return 1; }
    }

    // Signal handling for clean exit (Ctrl+C)
    signal(SIGINT,  signal_handler);
    signal(SIGTERM, signal_handler);

    // Auto-detect interface if not specified
    if (interface.empty()) {
        interface = Capture::auto_detect_interface();
        if (interface.empty()) {
            std::cerr << "  [ERROR] No network interface found. Use -i <interface>\n";
            return 1;
        }
    }

    Display::print_banner();
    Display::print_info("Interface : " + interface);
    if (!filter.empty())  Display::print_info("Filter    : " + filter);
    if (!outfile.empty()) Display::print_info("Output    : " + outfile);
    Display::separator();

    // Initialise modules
    Logger   logger(outfile);
    Analyzer analyzer;
    Capture  capture(interface, filter, count, &running);

    // Start capture loop
    capture.start([&](Packet& pkt) {
        analyzer.analyze(pkt);
        Display::print_packet(pkt);
        logger.log(pkt);

        // Print stats every 50 packets
        if (analyzer.get_total() % 50 == 0 && analyzer.get_total() > 0)
            Display::print_stats(analyzer.get_stats());
    });

    // Final summary
    Display::separator();
    Display::print_stats(analyzer.get_stats());
    Display::print_info("Capture stopped. Total packets: " +
                        std::to_string(analyzer.get_total()));
    if (!outfile.empty())
        Display::print_info("Saved to: " + outfile);

    return 0;
}
