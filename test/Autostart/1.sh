#!/bin/bash

while read -r line
do
  params="$params $line"
done</home/ye/procfs_test/procfs_test.conf
$(insmod /home/ye/procfs_test/procfs_test.ko $params)
