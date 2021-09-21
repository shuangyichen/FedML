import logging
import os, signal
import sys

from .message_define import MyMessage
from .utils import random_matrix, transform_tensor_to_list, post_complete_message_to_sweep_process

sys.path.insert(0, os.path.abspath(os.path.join(os.getcwd(), "../../../")))
sys.path.insert(0, os.path.abspath(os.path.join(os.getcwd(), "../../../../FedML")))
try:
    from fedml_core.distributed.communication.message import Message
    from fedml_core.distributed.server.server_manager import ServerManager
except ImportError:
    from FedML.fedml_core.distributed.communication.message import Message
    from FedML.fedml_core.distributed.server.server_manager import ServerManager
from .GoWrappers import *
import numpy as np
import torch
import time

class FedAVGServerManager(ServerManager):
    def __init__(self,worker_num,log_degree, log_scale,resiliency,robust, args,aggregator,params_count ,comm=None,rank=0, size=0,backend="MPI"):
        super().__init__(args, comm, rank, size, backend)
        self.aggregator = aggregator
        self.round_num = args.comm_round
        self.resiliency = resiliency
        self.round_idx = 0
        self.worker_num = worker_num
        self.k = args.client_num_per_round
        self.log_degree = log_degree
        self.log_scale = log_scale
        self.flag_client_uploaded_dict = dict()
        self.CollectivePublicKey = [None]*self.worker_num#dict()
        self.CollectivePublicKeyStr = [None]*self.worker_num
        self.params_count = 200000
        self.model_weights = np.zeros((1,self.params_count))
        self.liveness_status = dict()
        self.count_times = 0
        self.robust = robust
        self.if_check_client_status = True
        self.compression = args.compression
        self.rate = args.compression_rate
        self.alpha = args.compression_alpha
        self.samples = int(self.params_count / self.rate)

        for idx in range(self.worker_num):
            self.flag_client_uploaded_dict[idx] = False

    def run(self):
        super().run()

    def send_message_sync_model_to_client(self, receive_id, global_model_params, client_index):
        #logging.info("send_message_sync_model_to_client. receive_id = %d" % receive_id)
        message = Message(MyMessage.MSG_TYPE_S2C_SYNC_MODEL_TO_CLIENT, self.get_sender_id(), receive_id)
        message.add_params(MyMessage.MSG_ARG_KEY_MODEL_PARAMS, global_model_params)
        message.add_params(MyMessage.MSG_ARG_KEY_CLIENT_INDEX, str(client_index))
        self.send_message(message)

    def send_init_msg(self):
        # sampling clients
        client_indexes = self.aggregator.client_sampling(self.round_idx, self.args.client_num_in_total,
                                                         self.worker_num)
        global_model_params = self.aggregator.get_global_model_params()
        if self.args.is_mobile == 1:
            global_model_params = transform_tensor_to_list(global_model_params)
        self.init_time = time.time()
        for process_id in range(1, self.size):
            self.send_message_init_config(process_id, global_model_params, client_indexes[process_id - 1])


    def register_message_receive_handlers(self):
        #self.register_message_receive_handler(MyMessage.MSG_TYPE_C2S_SEND_SS_TO_SERVER,self.handle_message_SS_from_client)
        self.register_message_receive_handler(MyMessage.MSG_TYPE_C2S_SEND_CPK_TO_SERVER,self.handle_message_CPK_from_client)
    #MSG_TYPE_C2S_PHASE1_DONE
        self.register_message_receive_handler(MyMessage.MSG_TYPE_C2S_PHASE1_DONE,self.handle_message_phase1_flag_from_client)
        self.register_message_receive_handler(MyMessage.MSG_TYPE_C2S_SEND_ENC_MODEL_TO_SERVER,self.handle_message_receive_enc_model_from_client)
        self.register_message_receive_handler(MyMessage.MSG_TYPE_C2S_SEND_LIVENESS_STATUS,self.handle_message_receive_liveness_status_from_client)
        self.register_message_receive_handler(MyMessage.MSG_TYPE_C2S_PCKS_SHARE,self.handle_message_receive_pcks_share)

    def handle_message_receive_pcks_share(self,msg_params):
        sender_id = msg_params.get(MyMessage.MSG_ARG_KEY_SENDER)
        #print("receive pcks shair from client",sender_id)
        pcks_share = msg_params.get(MyMessage.MSG_ARG_KEY_PCKS_SHARE)
        self.aggregator.add_pcks_share(sender_id-1, pcks_share)
        p_all_received = self.aggregator.check_whether_pcks_all_receive(self.client_chosen)
        if p_all_received:
            pcks_share_list = []
            for pcks_share in self.aggregator.pcks_share_list:
                if pcks_share is not None:
                    pcks_share_list += pcks_share
            res = decrypt(','.join(self.client_chosen),self.tsk,pcks_share_list,self.aggr_enc_model_list,self.log_degree,self.log_scale,self.samples,self.worker_num)
            res1 = res.tolist()
            #model_weights = self.model_weights.tolist()

            res1 = res1[0]

            #print("res",len(res))
            for i,r in enumerate(res1):
                #print(res1[i])
                res1[i] = res1[i]/pow(10,6)
                #print(res1[i])
            print("decrypted res,",res1[0:10])
            print("decrypted res,",res1[len(res1)-10:])
            print("cost time:", time.time()-self.init_time)

            '''
            res2 = np.array(res1).reshape(-1, 1)/self.worker_num

            if self.compression == 1:
                phi = random_matrix(self.alpha/2/self.samples, self.samples, self.params_count, seed = self.round_idx)
                res2 = phi.transpose().dot(res2)
            #print("res", res[0:5])
            model_params = self.aggregator.get_global_model_params()

            self.shape = {}
            idx = 0
            for k in model_params.keys():
                #print("idx")
                shape = model_params[k].shape
                count = torch.numel(model_params[k])
                model_params[k] = torch.from_numpy(res2[idx:idx + count])
                model_params[k] = torch.reshape(model_params[k],shape)
                idx += count

            self.aggregator.set_global_model_params(model_params)
            self.aggregator.test_on_server_for_all_clients(self.round_idx)
            '''
            # start the next round
            self.init_time = time.time()
            self.round_idx += 1
            client_indexes = self.aggregator.client_sampling(self.round_idx, self.args.client_num_in_total,
                                                                 self.worker_num)
            self.if_check_client_status = True
            self.aggregator.reset_pcks_dict()
            model_params = 1
            for receiver_id in range(1, self.size):

                self.send_message_sync_model_to_client(receiver_id, model_params,
                                                       client_indexes[receiver_id - 1])


    def handle_message_receive_liveness_status_from_client(self,msg_params):
        sender_id = msg_params.get(MyMessage.MSG_ARG_KEY_SENDER)
        #print("receive liveness status announcement from client",sender_id)
        liveness_status = msg_params.get(MyMessage.MSG_ARG_KEY_LIVENESS_STATUS)
        if self.if_check_client_status:
            self.liveness_status[sender_id-1] = liveness_status
            self.flag_client_uploaded_dict[sender_id-1] = True
            partial_received, self.client_chosen = self.check_whether_partial_receive()

            if partial_received:
                self.if_check_client_status = False
                if self.robust:
                    tpk,tsk= genTPK(self.log_degree,self.log_scale)
                    self.tsk = tsk.tolist()
                    client_chosen_list = ','.join(self.client_chosen)
                    res = genDecryptionCoefficients(client_chosen_list)
                    DecryptionCoefficients = res.decode()
                    DCoeff = DecryptionCoefficients.split('\n')[0]
                    DCoeff = DCoeff.split(',')
                    for i in range(len(self.client_chosen)):
                        Decryption_info = DCoeff[i].split(':')
                        receive_id = int(Decryption_info[0])
                        decryption_coeffi = int(Decryption_info[1])
                        self.send_decryption_info(receive_id,1,decryption_coeffi,tpk.tolist())
                else:
                    tpk,tsk= genTPK(self.log_degree,self.log_scale)
                    self.tsk = tsk.tolist()


                    for key in self.liveness_status.keys():
                        if self.liveness_status[key] ==1:
                            self.send_decryption_info(key+1,1,0,tpk.tolist())

    def handle_message_receive_enc_model_from_client(self,msg_params):
        sender_id = msg_params.get(MyMessage.MSG_ARG_KEY_SENDER)
        #print("receive enc_model from client",sender_id)
        enc_model_params = msg_params.get(MyMessage.MSG_ARG_KEY_ENCRYPTED_MODEL_PARAMS)
        local_sample_number = msg_params.get(MyMessage.MSG_ARG_KEY_NUM_SAMPLES)
        #self.aggregator.add_local_trained_result(sender_id - 1, enc_model_params, local_sample_number)
        self.aggregator.add_enc_model_params(sender_id - 1, enc_model_params, local_sample_number)
        #print(self.aggregator.flag_client_model_uploaded_dict)
        b_all_received = self.aggregator.check_whether_all_receive()
        if b_all_received:
            encModelList = []
            for i,model in enumerate(self.aggregator.enc_model_list):
                encModelList += model
            aggr_enc_model_list = aggregateEncrypted(encModelList,self.worker_num,self.log_degree,self.log_scale,self.samples)
            self.aggr_enc_model_list = aggr_enc_model_list.tolist()
            lenth = len(self.aggr_enc_model_list)
            #print("self.aggr_enc_model_list",self.aggr_enc_model_list[lenth-10:lenth])

            #client_indexes = self.aggregator.client_sampling(self.round_idx, self.args.client_num_in_total,
             #                                                    self.args.client_num_per_round)

            for receiver_id in range(1, self.size):
                self.send_message_aggregated_encrypted_model_to_client(receiver_id, self.aggr_enc_model_list)




    def send_decryption_info(self,receive_id,decryptionParticipation,decryptionCoefficients,tpk):
        #logging.info("send_message_decryption_info_to_client. receive_id = %d" % receive_id)

        message = Message(MyMessage.MSG_TYPE_S2C_SEND_DECRYPTION_INFO, self.get_sender_id(), receive_id)
        message.add_params(MyMessage.MSG_ARG_KEY_DECRYPTION_PARTICIPATION,decryptionParticipation)
        message.add_params(MyMessage.MSG_ARG_KEY_DECRYPTION_COEFFI,decryptionCoefficients)
        message.add_params(MyMessage.MSG_ARG_KEY_TPK,tpk)
        self.send_message(message)

    def send_message_aggregated_encrypted_model_to_client(self, receive_id, aggr_enc_model_params):
        #logging.info("send_message_sync_model_to_client. receive_id = %d" % receive_id)
        message = Message(MyMessage.MSG_TYPE_S2C_SEND_AGGR_ENCRYPTED_MODEL, self.get_sender_id(), receive_id)
        message.add_params(MyMessage.MSG_ARG_KEY_ENCRYPTED_MODEL_PARAMS, aggr_enc_model_params)
        #message.add_params(MyMessage.MSG_ARG_KEY_CLIENT_INDEX, str(client_index))
        self.send_message(message)


    def handle_message_phase1_flag_from_client(self,msg_params):
        sender_id = msg_params.get(MyMessage.MSG_ARG_KEY_SENDER)
        self.flag_client_uploaded_dict[sender_id-1] = True
        b_all_received = self.check_whether_all_receive()
        if b_all_received:
            self.send_init_msg()


    def handle_message_CPK_from_client(self,msg_params):
        sender_id = msg_params.get(MyMessage.MSG_ARG_KEY_SENDER)
        #print("receive cpk from client",sender_id)
        CPK = msg_params.get(MyMessage.MSG_ARG_KEY_CPK)
        self.CollectivePublicKey[sender_id-1] = CPK
        #self.CollectivePublicKeyStr[sender_id-1] = msg_params.get(MyMessage.MSG_ARG_KEY_CPK_STR).decode()
        self.flag_client_uploaded_dict[sender_id-1] = True
        all_received = self.check_whether_all_receive()
        if all_received:
            CPKconcate = []
            for i,pk in enumerate(self.CollectivePublicKey):
                #print("pk share",pk[0:5])
                CPKconcate += pk
            #CPKListStr = ','.join(self.CollectivePublicKeyStr)
            res = genCollectivePK(CPKconcate,self.worker_num,self.log_degree,self.log_scale)
            res = res.tolist()
            self.send_pk_to_client(res)


    def send_pk_to_client(self,pk):
        for client_idx in range(self.worker_num):
            #logging.info("send_message_public_key_to_client. receive_id = %d" % (client_idx+1))
            message = Message(MyMessage.MSG_TYPE_S2C_PUBLIC_KEY_TO_CLIENT, 0, client_idx+1)
            message.add_params(MyMessage.MSG_ARG_KEY_PUBLIC_KEY, pk)
            #message.add_params(MyMessage.MSG_ARG_KEY_CLIENT_INDEX, str(client_index+1))
            self.send_message(message)

    def send_message_init_config(self, receive_id, global_model_params, client_index):
        message = Message(MyMessage.MSG_TYPE_S2C_INIT_CONFIG, self.get_sender_id(), receive_id)
        message.add_params(MyMessage.MSG_ARG_KEY_MODEL_PARAMS, global_model_params)
        message.add_params(MyMessage.MSG_ARG_KEY_CLIENT_INDEX, str(client_index))
        self.send_message(message)

    def check_whether_partial_receive(self):
        status_already_received = 0
        client_chosen = []
        for idx in range(self.worker_num):
            if self.flag_client_uploaded_dict[idx]:
                status_already_received += 1
                client_chosen.append(str(idx+1))
        if status_already_received==self.k:
            for idx in range(self.worker_num):
                self.flag_client_uploaded_dict[idx] = False
            self.if_check_client_status  = False
            return True,client_chosen
        else:
            return False,client_chosen




    def check_whether_all_receive(self):
        for idx in range(self.worker_num):
            if not self.flag_client_uploaded_dict[idx]:
                return False
        for idx in range(self.worker_num):
            self.flag_client_uploaded_dict[idx] = False
        return True
