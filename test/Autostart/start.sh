#!/bin/bash

while read -r line
do
  params="$params $line"
done</etc/realtime_probe/realtime_probe.conf
$(modprobe realtime_probe $params)
