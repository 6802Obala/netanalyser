// =============================================================================
//  display.h / display.cpp – Terminal output with colours
// =============================================================================
#pragma once
#include "capture.h"
#include "analyzer.h"
#include <string>

class Display {
public:
    static void print_banner();
    static void print_info(const std::string& msg);
    static void separator();
    static void print_packet(const Packet& pkt);
    static void print_stats(const Stats& stats);
};
