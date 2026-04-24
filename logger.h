// =============================================================================
//  logger.h / logger.cpp – Log packets to file
// =============================================================================
#pragma once
#include "capture.h"
#include <fstream>
#include <string>

class Logger {
public:
    explicit Logger(const std::string& filename);
    ~Logger();
    void log(const Packet& pkt);

private:
    std::ofstream file_;
    bool          active_ = false;
};
