import logging
import os, signal
import sys

from .message_define import MyMessage
from .utils import random_matrix, transform_tensor_to_list, post_complete_message_to_sweep_process, transform_dict_list,transform_list_to_tensor

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
import random

class FedAVGServerManager(ServerManager):
    def __init__(self,worker_num,log_degree, log_scale,resiliency,robust, args,aggregator,params_count = 50000,comm=None,rank=0, size=0,backend="MPI"):
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
        self.flag_client_ss_uploaded_dict = dict()
        self.CollectivePublicKey = [None]*self.worker_num#dict()
        self.SS = [None]*self.worker_num
        self.CollectivePublicKeyStr = [None]*self.worker_num
        self.params_count = params_count
        self.model_weights = np.zeros((1,self.params_count))
        self.liveness_status = dict()
        self.count_times = 0
        self.robust = robust
        self.if_check_client_status = True
        self.compression = args.compression
        self.rate = args.compression_rate
        self.alpha = args.compression_alpha
        self.samples = int(self.params_count / self.rate)
        self.aggregate = np.zeros((self.params_count,1))
        self.client_list=[]
        self.cur_round = 0
        self.pause_learning = False
        for idx in range(self.worker_num):
            self.flag_client_uploaded_dict[idx] = False
            self.flag_client_ss_uploaded_dict[idx] = False

    def run(self):
        super().run()

    def send_message_sync_model_to_client(self, receive_id, global_model_params, client_index):
        #logging.info("send_message_sync_model_to_client. receive_id = %d" % receive_id)
        message = Message(MyMessage.MSG_TYPE_S2C_SYNC_MODEL_TO_CLIENT, self.get_sender_id(), receive_id)
        message.add_params(MyMessage.MSG_ARG_KEY_MODEL_PARAMS, global_model_params)
        message.add_params(MyMessage.MSG_ARG_KEY_CLIENT_INDEX, str(client_index))
        message.add_params(MyMessage.MSG_ARG_KEY_CLIENT_ROUND,self.cur_round)
        self.send_message(message)

    def send_init_msg(self):
        # sampling clients
        client_indexes = self.aggregator.client_sampling(self.round_idx, self.args.client_num_in_total,
                                                         self.worker_num)
        global_model_params = self.aggregator.get_global_model_params()
        #if self.args.is_mobile == 1:
        global_model_params = transform_tensor_to_list(global_model_params)
        self.init_time = time.time()
        #for process_id in range(1, self.size):
        for i,process_id in enumerate(self.client_list):
            if i<self.k:
                self.send_message_init_config(process_id, global_model_params, client_indexes[process_id - 1])
        self.client_list = self.client_list[0:self.k]
        self.client_list.sort()
        self.client_chosen =[]
        for client in self.client_list:
            self.client_chosen.append(str(client))
        print("Clients participated in current iterarion: ",self.client_chosen)

    def register_message_receive_handlers(self):
        self.register_message_receive_handler(MyMessage.MSG_TYPE_C2S_SEND_SS_TO_SERVER,self.handle_message_SS_from_client)
        self.register_message_receive_handler(MyMessage.MSG_TYPE_C2S_SEND_CPK_TO_SERVER,self.handle_message_CPK_from_client)
    #MSG_TYPE_C2S_PHASE1_DONE
        self.register_message_receive_handler(MyMessage.MSG_TYPE_C2S_PHASE1_DONE,self.handle_message_phase1_flag_from_client)
        self.register_message_receive_handler(MyMessage.MSG_TYPE_C2S_SEND_ENC_MODEL_TO_SERVER,self.handle_message_receive_enc_model_from_client)
        self.register_message_receive_handler(MyMessage.MSG_TYPE_C2S_SEND_LIVENESS_STATUS,self.handle_message_receive_liveness_status_from_client)
        self.register_message_receive_handler(MyMessage.MSG_TYPE_C2S_PCKS_SHARE,self.handle_message_receive_pcks_share)
        self.register_message_receive_handler(MyMessage.MSG_TYPE_C2S_SEND_ROUND_LIVE,self.handle_message_round_live)
        self.register_message_receive_handler(MyMessage.MSG_TYPE_C2S_SEND_JOIN_REQUEST,self.handle_message_join_request)
        self.register_message_receive_handler(MyMessage.MSG_TYPE_C2S_SEND_NEW_SHARE_TO_SERVER, self.handle_message_new_share)
        self.register_message_receive_handler(MyMessage.MSG_TYPE_C2S_OFFICIAL_JOIN,self.handle_message_new_user_official_join)

    def handle_message_new_user_official_join(self, msg_params):
        sender_id = msg_params.get(MyMessage.MSG_ARG_KEY_SENDER)
        if sender_id ==self.worker_num +1:
            self.update_system_info()
            client_list = [i for i in range(1,self.size)]
            random.shuffle(client_list)
            self.init_time = time.time()
            #print(client_list)
            for receiver_id in client_list:
                self.send_message_round_done_to_client(receiver_id)

    def update_system_info(self):
        self.size += 1
        self.worker_num = self.worker_num +1
        self.CollectivePublicKey = [None]*self.worker_num#dict()
        self.CollectivePublicKeyStr = [None]*self.worker_num
        self.client_chosen =[]
        self.aggregator.worker_num += 1
        self.aggregator.reset_dict()
        self.pause_learning = False
        self.if_check_client_status = True
        for idx in range(self.worker_num):
            self.flag_client_uploaded_dict[idx] = False


    def handle_message_new_share(self,msg_params):
        sender_id = msg_params.get(MyMessage.MSG_ARG_KEY_SENDER)
        print("Client ", sender_id, "send new share")
        ss = msg_params.get(MyMessage.MSG_ARG_KEY_SS)
        self.aggregator.add_ss(sender_id-1, ss)
        p_all_received = self.aggregator.check_whether_new_share_all_receive(self.client_chosen)
        #self.aggregator.add_ss(sender_id-1, ss)
        if p_all_received:
            ss_list = []
            for share in self.aggregator.ss_list:
                if share is not None:
                    ss_list += share
            newSK = genSKforNewUser(self.k, self.log_degree, ss_list)
            newSK = newSK.tolist()
            self.send_new_SK_to_new_user(newSK,self.pk, self.worker_num+1)

    def send_new_SK_to_new_user(self,newSK,pk, receive_id):
        message = Message(MyMessage.MSG_TYPE_S2C_NEW_SK, self.get_sender_id(), receive_id)
        message.add_params(MyMessage.MSG_ARG_NEW_SK, newSK)
        message.add_params(MyMessage.MSG_ARG_KEY_PUBLIC_KEY, pk)
        self.send_message(message)



    def handle_message_join_request(self,msg_params):
        self.pause_learning = True
        if self.client_chosen==[]:
            client_sampling = random.choice(range(1,self.worker_num))
            self.client_chosen = [str(i) for i in client_sampling]
        print("Clients participated in the construction of sk for new user joining", self.client_chosen)
        client_chosen_list = ','.join(self.client_chosen)
        res = genDecryptionCoefficients(client_chosen_list)
        DecryptionCoefficients = res.decode()
        DCoeff = DecryptionCoefficients.split('\n')[0]
        DCoeff = DCoeff.split(',')
        receiver =[]
        R_coeffi = []
        for i in range(len(self.client_chosen)):
            Reconstruction_info = DCoeff[i].split(':')
            receive_id = int(Reconstruction_info[0])
            coeffi = int(Reconstruction_info[1])
            receiver.append(receive_id)
            R_coeffi.append(coeffi)
        for idx in receiver:
            self.send_reconstruction_info(idx,1,R_coeffi)

    def send_reconstruction_info(self,receive_id,decryptionParticipation,decryptionCoefficients):
        message = Message(MyMessage.MSG_TYPE_S2C_SEND_RECONSTRUCTION_INFO, self.get_sender_id(), receive_id)
        #message.add_params(MyMessage.MSG_ARG_KEY_DECRYPTION_PARTICIPATION,decryptionParticipation)
        message.add_params(MyMessage.MSG_ARG_KEY_DECRYPTION_COEFFI,decryptionCoefficients)
        #message.add_params(MyMessage.MSG_ARG_KEY_TPK,tpk)
        self.send_message(message)


    def handle_message_SS_from_client(self,msg_params):
        sender_id = msg_params.get(MyMessage.MSG_ARG_KEY_SENDER)
        #print("receive ss from client",sender_id)
        SS = msg_params.get(MyMessage.MSG_ARG_KEY_SS)
        self.SS[sender_id-1] = SS
        #self.CollectivePublicKeyStr[sender_id-1] = msg_params.get(MyMessage.MSG_ARG_KEY_CPK_STR).decode()
        self.flag_client_ss_uploaded_dict[sender_id-1] = True
        all_received = self.check_whether_ss_all_receive()
        if all_received:
            SSconcat = []
            for i,ss in enumerate(self.SS):
                #print("pk share",pk[0:5])
                SSconcat += ss
            #print("length of ssconcat", len(SSconcat))
            ss_for_users = genShamirsharesforUser(SSconcat, self.worker_num,self.log_degree)
            ss_for_users = ss_for_users.reshape(self.worker_num, -1)
            for idx in range(self.worker_num):
                self.send_sk_to_client(idx+1, ss_for_users[idx].tolist())



    def handle_message_round_live(self,msg_params):
        if not self.pause_learning:
            sender_id = msg_params.get(MyMessage.MSG_ARG_KEY_SENDER)
            #print("Receive liveness from client", sender_id)
            #print(self.if_check_client_status)
            if self.if_check_client_status:
                self.liveness_status[sender_id-1] = 1
                self.flag_client_uploaded_dict[sender_id-1] = True
                b_received, self.client_chosen = self.check_whether_partial_receive()
                #print(b_received)
                #print(self.client_chosen)
                if b_received:
                    #self.if_check_client_status = False
                    #if self.worker_num==3:
                    #    self.client_chosen[1]='3'
                    print("Clients participated in current iterarion: ",self.client_chosen)
                    #print(self.args.client_num_in_total)
                    client_indexes = self.aggregator.client_sampling(self.round_idx, self.args.client_num_in_total,
                                                                    self.worker_num)
                    model_params = self.aggregator.get_global_model_params()
                    model_params = transform_tensor_to_list(model_params)
                    print("Iteration:",self.cur_round)
                    for idx in self.client_chosen:
                        self.send_message_sync_model_to_client(int(idx), model_params,
                                                        client_indexes[int(idx)- 1])

    def handle_message_receive_pcks_share(self,msg_params):
        if not self.pause_learning:
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
            #decrypted = np.array(res1).reshape(-1, 1)
            #difference = decrypted -self.aggregate
            #print("difference",sum(difference))
                for i,r in enumerate(res1):
                #print(res1[i])
                    res1[i] = res1[i]/pow(10,3)
                #print(res1[i])
            #difference =
            #print("decrypted res,",res1[0:10])
                #print("decrypted res,",res1[len(res1)-10:])
                print("cost time:", time.time()-self.init_time)

                model_params = self.aggregator.get_global_model_params()
                old_weights = transform_dict_list(transform_list_to_tensor(model_params))
                old_weights = old_weights.reshape((-1,1))
                res2 = np.array(res1).reshape(-1, 1)/self.worker_num

                if self.compression == 1:
                    phi = random_matrix(self.alpha/2/self.samples, self.samples, self.params_count, seed = self.round_idx)
                    res2 = phi.transpose().dot(res2)
                    res2 = old_weights - res2
            #elif self.compression == 0:


            #else:
            #    res2 = np.array(res1).reshape(-1, 1)/self.worker_num
            #print("res", res[0:5])
            #model_params = self.aggregator.get_global_model_params()

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

            # start the next round
                self.init_time = time.time()
                self.round_idx += 1
                client_indexes = self.aggregator.client_sampling(self.round_idx, self.args.client_num_in_total,
                                                                 self.worker_num)
                self.if_check_client_status = True
                self.aggregator.reset_dict()
                self.aggregate = np.zeros((self.params_count,1))
                self.cur_round+=1
            #model_params = np.zeros((1,self.params_count))
                client_list = [i for i in range(1,self.size)]
                random.shuffle(client_list)
                #print(client_list)
                for receiver_id in client_list:
                    self.send_message_round_done_to_client(receiver_id)


    def handle_message_receive_liveness_status_from_client(self,msg_params):
        if not self.pause_learning:

            sender_id = msg_params.get(MyMessage.MSG_ARG_KEY_SENDER)
        #print("receive liveness status announcement from client",sender_id)
            liveness_status = msg_params.get(MyMessage.MSG_ARG_KEY_LIVENESS_STATUS)
            self.aggregator.flag_client_liveness_uploaded_dict[sender_id-1] = True
            check_liveness = self.aggregator.check_whether_liveness_all_receive(self.client_chosen)
            if check_liveness:
            #self.liveness_status[sender_id-1] = liveness_status
            #self.flag_client_uploaded_dict[sender_id-1] = True
            #partial_received, self.client_chosen = self.check_whether_partial_receive()

            #if partial_received:
            #self.if_check_client_status = False
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
        if not self.pause_learning:
            sender_id = msg_params.get(MyMessage.MSG_ARG_KEY_SENDER)
        #print("receive enc_model from client",sender_id)
            enc_model_params = msg_params.get(MyMessage.MSG_ARG_KEY_ENCRYPTED_MODEL_PARAMS)
            local_sample_number = msg_params.get(MyMessage.MSG_ARG_KEY_NUM_SAMPLES)
            self.aggregator.add_enc_model_params(sender_id - 1, enc_model_params, local_sample_number)
            check_enc_model_all_reveived = self.aggregator.check_whether_enc_all_receive(self.client_chosen)
        #if self.if_check_client_status:
        #    self.liveness_status[sender_id-1] = 1
        #    self.flag_client_uploaded_dict[sender_id-1] = True
        #    b_received, self.client_chosen = self.check_whether_partial_receive()
            if check_enc_model_all_reveived:
            #print("Clients participated in current iterarion: ",self.client_chosen)
                encModelList = []
                for i,model in enumerate(self.aggregator.enc_model_list):
                    if model!=None:
                        encModelList += model
                aggr_enc_model_list = aggregateEncrypted(encModelList,self.k,self.log_degree,self.log_scale,self.samples)
                self.aggr_enc_model_list = aggr_enc_model_list.tolist()
                for idx in self.client_chosen:
                    self.send_message_aggregated_encrypted_model_to_client(int(idx), self.aggr_enc_model_list)
            #lenth = len(self.aggr_enc_model_list)
            #print("self.aggr_enc_model_list",self.aggr_enc_model_list[lenth-10:lenth])

            #client_indexes = self.aggregator.client_sampling(self.round_idx, self.args.client_num_in_total,
             #                                                    self.args.client_num_per_round)

            #for receiver_id in range(1, self.size):
            #    self.send_message_aggregated_encrypted_model_to_client(receiver_id, self.aggr_enc_model_list)




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
        self.client_list.append(sender_id)
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
            self.pk = res.tolist()
            self.send_pk_to_client(self.pk)


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

    def send_message_round_done_to_client(self,receive_id):
        message = Message(MyMessage.MSG_TYPE_S2C_ROUND_DONE, self.get_sender_id(), receive_id)
        self.send_message(message)


    def send_sk_to_client(self,receive_id,ss):
        message = Message(MyMessage.MSG_TYPE_S2C_SK, self.get_sender_id(), receive_id)
        message.add_params(MyMessage.MSG_ARG_KEY_SS, ss)
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

    def check_whether_ss_all_receive(self):
        for idx in range(self.worker_num):
            if not self.flag_client_ss_uploaded_dict[idx]:
                return False
        for idx in range(self.worker_num):
            self.flag_client_ss_uploaded_dict[idx] = False
        return True
