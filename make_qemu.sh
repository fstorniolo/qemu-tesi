#!/bin/bash

cd build
make -j $(nproc)
sudo make install
cd ..
