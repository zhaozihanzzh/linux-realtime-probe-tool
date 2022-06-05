#!/bin/bash

$(rmmod procfs_test)
while read -r line
do
  params="$params $line"
done</home/ye/procfs_test/1.conf
$(insmod /home/ye/procfs_test/procfs_test.ko $params)
