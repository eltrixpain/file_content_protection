#!/bin/bash
mkdir -p ../../test_folder
NUM_FILES=200

for i in $(seq 1 $NUM_FILES); do
  SIZE=$(( (RANDOM % 500) + 1 ))

  base64 /dev/urandom | head -c ${SIZE}K > ../../test_folder/test2_${i}.txt
done

echo "All file successfully created"
