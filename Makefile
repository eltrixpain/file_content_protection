CXX = g++
CXXFLAGS = -std=c++17 -Wall -O2 -DLFU_SIZE
INCLUDE_DIR = include

SRC_FILES = \
    main.cpp \
    src/CoreEngine/CoreEngine.cpp \
    src/CoreEngine/CoreEngineStatistic.cpp \
    src/CoreEngine/CoreEngineSimulation.cpp \
    src/CoreEngine/StatisticStoreIO.cpp \
    src/Logger/Logger.cpp \
    src/ConfigManager/ConfigManager.cpp \
    src/RuleEvaluator/RuleEvaluator.cpp \
    src/ContentParser/ContentParser.cpp \
    src/Requirements/Requirements.cpp \
    src/CacheL1/CacheL1.cpp \
    src/CacheL2/CacheL2.cpp \
    src/AsyncScanQueue/AsyncScanQueue.cpp

LIBS = `pkg-config --cflags --libs poppler-cpp` -lsqlite3 -pthread

all: fileguard

fileguard: clean
	$(CXX) $(CXXFLAGS) -I$(INCLUDE_DIR) -o fileguard $(SRC_FILES) $(LIBS)


# --- cache policies ---
lru: CXXFLAGS = -std=c++17 -Wall -O2 -DLRU -DDEBUG_CACHE
lru: clean fileguard

lfu: CXXFLAGS = -std=c++17 -Wall -O2 -DLFU -DDEBUG_CACHE
lfu: clean fileguard

lfu_size: CXXFLAGS += -DDEBUG_CACHE
lfu_size: clean fileguard

# --- debug build ---
debug: CXXFLAGS += -DDEBUG -g 
debug: fileguard


clean:
	rm -f fileguard
