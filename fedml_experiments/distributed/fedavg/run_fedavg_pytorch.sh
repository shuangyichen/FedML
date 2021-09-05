#!/usr/bin/env bash

CLIENT_NUM=$1
WORKER_NUM=$2
MODEL=$3
DISTRIBUTION=$4
ROUND=$5
EPOCH=$6
BATCH_SIZE=$7
LR=$8
DATASET=$9
DATA_DIR=${10}
CLIENT_OPTIMIZER=${11}
CI=${12}
ROBUST=${13}
COMPRESSION=${14}
COMPRESSION_RATE=${15}
COMPRESSION_ALPHA=${16}

PROCESS_NUM=`expr $CLIENT_NUM + 1`
echo $PROCESS_NUM

hostname > mpi_host_file

mpirun -np $PROCESS_NUM python3 ./main_fedavg.py \
  --model $MODEL \
  --dataset $DATASET \
  --data_dir $DATA_DIR \
  --partition_method $DISTRIBUTION  \
  --client_num_in_total $CLIENT_NUM \
  --client_num_per_round $WORKER_NUM \
  --comm_round $ROUND \
  --epochs $EPOCH \
  --client_optimizer $CLIENT_OPTIMIZER \
  --batch_size $BATCH_SIZE \
  --lr $LR \
  --ci $CI \
  --robust $ROBUST \
  --compression $COMPRESSION \
  --compression_rate $COMPRESSION_RATE \
  --compression_alpha $COMPRESSION_ALPHA
