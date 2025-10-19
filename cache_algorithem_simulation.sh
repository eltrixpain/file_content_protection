make
mv fileguard fileguard_lfu_size

make lfu
mv fileguard fileguard_lfu

make lru
mv fileguard fileguard_lru


#sudo env FILEGUARD_CACHE=cache/lru.sqlite      ./fileguard_lru
#sudo env FILEGUARD_CACHE=cache/lfu.sqlite      ./fileguard_lfu
#sudo env FILEGUARD_CACHE=cache/lfu_size.sqlite ./fileguard_lfu_size

