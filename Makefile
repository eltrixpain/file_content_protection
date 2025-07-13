# Makefile for fileguard

CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2

TARGET = fileguard
SRCS = main.cpp

$(TARGET): $(SRCS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRCS)

clean:
	rm -f $(TARGET)
