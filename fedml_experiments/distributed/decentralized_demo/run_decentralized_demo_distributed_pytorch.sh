#!/usr/bin/env bash

#hostname > mpi_host_file

mpirun -np 7  python3 ./main_decentralized.py \
  --client_number 6 \
  --comm_round 3
