CXX = g++
CXXFLAGS = -std=c++17 -Wall -O2
INCLUDE_DIR = include

SRC_FILES = \
    main.cpp \
    src/CoreEngine/CoreEngine.cpp \
    src/Logger/Logger.cpp \
    src/ConfigManager/ConfigManager.cpp \
    src/RuleEvaluator/RuleEvaluator.cpp \
    src/ContentParser/ContentParser.cpp

LIBS = `pkg-config --cflags --libs poppler-cpp`

all: fileguard

fileguard:
	$(CXX) $(CXXFLAGS) -I$(INCLUDE_DIR) -o fileguard $(SRC_FILES) $(LIBS)

clean:
	rm -f fileguard
