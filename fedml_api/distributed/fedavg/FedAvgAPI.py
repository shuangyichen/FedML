from mpi4py import MPI
#from .GoWrappers import *
from .FedAVGAggregator import FedAVGAggregator
from .FedAVGTrainer import FedAVGTrainer
from .FedAvgClientManager import FedAVGClientManager
from .FedAvgServerManager import FedAVGServerManager
from ...standalone.fedavg.my_model_trainer_classification import MyModelTrainer as MyModelTrainerCLS
from ...standalone.fedavg.my_model_trainer_nwp import MyModelTrainer as MyModelTrainerNWP
from ...standalone.fedavg.my_model_trainer_tag_prediction import MyModelTrainer as MyModelTrainerTAG


def FedML_init():
    comm = MPI.COMM_WORLD
    process_id = comm.Get_rank()
    worker_number = comm.Get_size()
    return comm, process_id, worker_number


def FedML_FedAvg_distributed(process_id, worker_number, device, comm, model, param_num, train_data_num, train_data_global, test_data_global,
        train_data_local_num_dict, train_data_local_dict, test_data_local_dict, args,robust=False,log_degree=13, log_scale=40, resiliency=0, model_trainer=None, preprocessed_sampling_lists=None):
    if process_id == 0:
        init_server(args, device, comm, process_id, worker_number, model, param_num, train_data_num, train_data_global,
                    test_data_global, train_data_local_dict, test_data_local_dict, train_data_local_num_dict,
                    model_trainer,robust, log_degree, log_scale,resiliency, preprocessed_sampling_lists)
    else:
        init_client(args, device, comm, process_id, worker_number, model, param_num, train_data_num, train_data_local_num_dict,
                    train_data_local_dict, test_data_local_dict, robust,log_degree, log_scale, resiliency, model_trainer)


def init_server(args, device, comm, rank, size, model, param_num, train_data_num, train_data_global, test_data_global,
                train_data_local_dict, test_data_local_dict, train_data_local_num_dict, model_trainer, robust, log_degree, log_scale, resiliency, preprocessed_sampling_lists=None):
    if model_trainer is None:
        if args.dataset == "stackoverflow_lr":
            model_trainer = MyModelTrainerTAG(model)
        elif args.dataset in ["fed_shakespeare", "stackoverflow_nwp"]:
            model_trainer = MyModelTrainerNWP(model)
        else: # default model trainer is for classification problem
            model_trainer = MyModelTrainerCLS(model)

    model_trainer.set_id(-1)
    worker_num = size - 1

    backend = args.backend

    aggregator = FedAVGAggregator(train_data_global, test_data_global, train_data_num,
                                  train_data_local_dict, test_data_local_dict, train_data_local_num_dict,
                                  worker_num, device, args, model_trainer)



    server_manager = FedAVGServerManager(worker_num,log_degree, log_scale,resiliency,robust,args, aggregator,param_num, comm, rank, size,backend)
    server_manager.run()




def init_client(args, device, comm, process_id, size, model, param_num, train_data_num, train_data_local_num_dict,
                train_data_local_dict, test_data_local_dict, robust,log_degree, log_scale, resiliency, model_trainer=None):
    client_index = process_id - 1
    if model_trainer is None:
        if args.dataset == "stackoverflow_lr":
            model_trainer = MyModelTrainerTAG(model)
        elif args.dataset in ["fed_shakespeare", "stackoverflow_nwp"]:
            model_trainer = MyModelTrainerNWP(model)
        else: # default model trainer is for classification problem
            model_trainer = MyModelTrainerCLS(model)

    worker_num = size - 1
    model_trainer.set_id(client_index)
    backend = args.backend
    trainer = FedAVGTrainer(client_index, train_data_local_dict, train_data_local_num_dict, test_data_local_dict,
                            train_data_num, device, args, model_trainer)

    client_manager = FedAVGClientManager(trainer,worker_num,robust, log_degree, log_scale, resiliency,param_num, args,comm, process_id, size, args.backend)
    if not robust:
        client_manager.send_pk_to_server()
    else:
        client_manager.send_SS()
    client_manager.run()

