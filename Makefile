CXX = g++
CXXFLAGS = -std=c++17 -Wall -O2
INCLUDE_DIR = include
TARGET = fileguard

SRC_FILES = \
	main.cpp \
	src/CoreEngine/CoreEngine.cpp \
	src/Logger/Logger.cpp \
	src/ConfigManager/ConfigManager.cpp \
	src/RuleEvaluator/RuleEvaluator.cpp

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC_FILES)
	$(CXX) $(CXXFLAGS) -I$(INCLUDE_DIR) -o $@ $^

clean:
	rm -f $(TARGET)
