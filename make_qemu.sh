#!/bin/bash

cd build
make all -j 9 CONFIG_NEWDEV=y
sudo make install
cd ..
