#!/bin/bash
mkdir -p ../../test_folder
NUM_FILES=300

for i in $(seq 1 $NUM_FILES); do
  SIZE=$(( (RANDOM % 5000) + 1 ))

  base64 /dev/urandom | head -c ${SIZE}K > ../../test_folder/test_${i}.txt
done

echo "All file successfully created"
