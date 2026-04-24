// =============================================================================
//  logger.cpp
// =============================================================================
#include "logger.h"
#include <iostream>

Logger::Logger(const std::string& filename) {
    if (filename.empty()) return;
    file_.open(filename, std::ios::out | std::ios::trunc);
    if (file_.is_open()) {
        active_ = true;
        file_ << "timestamp,protocol,src_ip,src_port,dst_ip,dst_port,length,flags,info,alert\n";
        std::cout << "  [LOG] Writing to: " << filename << "\n";
    } else {
        std::cerr << "  [WARN] Cannot open log file: " << filename << "\n";
    }
}

Logger::~Logger() {
    if (file_.is_open()) file_.close();
}

void Logger::log(const Packet& pkt) {
    if (!active_) return;
    file_ << pkt.timestamp   << ","
          << pkt.protocol    << ","
          << pkt.src_ip      << ","
          << pkt.src_port    << ","
          << pkt.dst_ip      << ","
          << pkt.dst_port    << ","
          << pkt.length      << ","
          << pkt.flags       << ","
          << pkt.info        << ","
          << pkt.alert       << "\n";
    file_.flush();
}
