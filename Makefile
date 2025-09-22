CXX = g++
CXXFLAGS = -std=c++17 -Wall -O2
INCLUDE_DIR = include

SRC_FILES = \
    main.cpp \
    src/CoreEngine/CoreEngine.cpp \
    src/Logger/Logger.cpp \
    src/ConfigManager/ConfigManager.cpp \
    src/RuleEvaluator/RuleEvaluator.cpp \
    src/ContentParser/ContentParser.cpp \
    src/Requirements/Requirements.cpp \
    src/CacheManager/CacheManager.cpp

LIBS = `pkg-config --cflags --libs poppler-cpp` -lsqlite3

all: fileguard

fileguard:
	$(CXX) $(CXXFLAGS) -I$(INCLUDE_DIR) -o fileguard $(SRC_FILES) $(LIBS)

# --- cache policies ---
lru: CXXFLAGS += -DLRU
lru: clean fileguard

lfu: CXXFLAGS += -DLFU
lfu: clean fileguard

lfu_size: CXXFLAGS += -DLFU_SIZE
lfu_size: clean fileguard

# --- debug build ---
debug: CXXFLAGS += -DDEBUG -g -DLRU
debug: clean fileguard

clean:
	rm -f fileguard
