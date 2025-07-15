CXX = g++
CXXFLAGS = -std=c++17 -Wall -O2
INCLUDE_DIR = include

SRC_FILES = \
	main.cpp \
	src/CoreEngine/CoreEngine.cpp \
	src/Logger/Logger.cpp\
	src/RegexConfigManager/RegexConfigManager.cpp

all: fileguard

fileguard:
	$(CXX) $(CXXFLAGS) -I$(INCLUDE_DIR) -o fileguard $(SRC_FILES)

clean:
	rm -f fileguard
