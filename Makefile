# =============================================================================
#  Makefile – Network Analyzer
# =============================================================================

CXX      = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2
LIBS     = -lpcap
TARGET   = netanalyzer
SRCS     = main.cpp capture.cpp analyzer.cpp display.cpp logger.cpp

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRCS) $(LIBS)
	@echo "  ✅  Build successful → ./$(TARGET)"

clean:
	rm -f $(TARGET)

.PHONY: all clean
