CXX      ?= c++
CXXFLAGS ?= -O2 -g
CXXFLAGS += -std=c++17 -Wall -Wextra -Wpedantic -Isrc
LDLIBS   += -lpcap

BUILD_DIR := build
SNIFFER   := $(BUILD_DIR)/npcap_sniffer
TESTS     := $(BUILD_DIR)/ethernet_tests

.PHONY: all test clean

all: $(SNIFFER) $(TESTS)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(SNIFFER): src/main.cpp src/capture.cpp src/capture.h src/ethernet.cpp src/ethernet.h | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -o $@ src/main.cpp src/capture.cpp src/ethernet.cpp $(LDLIBS)

$(TESTS): tests/ethernet_tests.cpp src/ethernet.cpp src/ethernet.h | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -o $@ tests/ethernet_tests.cpp src/ethernet.cpp

test: $(TESTS)
	./$(TESTS)

clean:
	rm -rf $(BUILD_DIR)
