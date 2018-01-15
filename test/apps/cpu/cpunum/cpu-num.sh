#!/bin/sh

# get cpu core numbers
echo `grep processor /proc/cpuinfo | wc -l`
