import logging
import os
import sys
import time
sys.path.insert(0, os.path.abspath(os.path.join(os.getcwd(), "../../../")))
sys.path.insert(0, os.path.abspath(os.path.join(os.getcwd(), "../../../../FedML")))

try:
    from fedml_core.distributed.client.client_manager import ClientManager
    from fedml_core.distributed.communication.message import Message
except ImportError:
    from FedML.fedml_core.distributed.client.client_manager import ClientManager
    from FedML.fedml_core.distributed.communication.message import Message
from .message_define import MyMessage
from .utils import random_matrix,transform_dict_list, transform_list_to_tensor, post_complete_message_to_sweep_process
from .GoWrappers import *
import numpy as np

class FedAVGClientManager(ClientManager):
    def __init__(self,trainer,worker_num,robust,log_degree, log_scale, resiliency,params_count,args, comm, rank, size, backend="MPI"):
        super().__init__(args, comm, rank, size, backend)
        self.worker_num = worker_num
        self.num_rounds = args.comm_round
        self.robust = robust
        self.status = 1
        if not self.robust:
            self.status = 1

        self.k = args.client_num_per_round

        self.log_degree = log_degree
        self.log_scale = log_scale
        self.resiliency = resiliency
        self.trainer = trainer
        self.params_count = params_count
        #print("params_count",params_count)
        self.shamirshare_list = []
        self.SSstr = None
        self.collective_shamirshare = [None]*self.worker_num
        self.flag_shamirshare_uploaded_dict = dict()
        for idx in range(self.worker_num):
            self.flag_shamirshare_uploaded_dict[idx] = False
        self.compression = args.compression
        self.rate = args.compression_rate
        if self.compression == 0:
            self.rate = 1.0
        self.samples = int(self.params_count / self.rate)
        self.error = np.zeros((self.params_count,1))
        self.alpha = args.compression_alpha
        self.beta = 1 / self.alpha / (self.rate + 1 + 1 / self.alpha)

    def register_message_receive_handlers(self):
        self.register_message_receive_handler(MyMessage.MSG_TYPE_S2C_PUBLIC_KEY_TO_CLIENT,self.handle_message_public_key_from_server)
        self.register_message_receive_handler(MyMessage.MSG_TYPE_S2C_INIT_CONFIG,self.handle_message_init)
        self.register_message_receive_handler(MyMessage.MSG_TYPE_S2C_SEND_AGGR_ENCRYPTED_MODEL,self.handle_message_enc_aggregated_model_from_server)
        self.register_message_receive_handler(MyMessage.MSG_TYPE_S2C_SEND_DECRYPTION_INFO,self.handle_message_decryption_info_from_server)
        self.register_message_receive_handler(MyMessage.MSG_TYPE_S2C_SYNC_MODEL_TO_CLIENT,self.handle_message_receive_model_from_server)
        self.register_message_receive_handler(MyMessage.MSG_TYPE_C2C_SEND_PROCESSED_SS,self.handle_message_shamirshares)


    def run(self):
        super().run()

    def handle_message_shamirshares(self,msg_params):
        sender_id = msg_params.get(MyMessage.MSG_ARG_KEY_SENDER)
        #logging.info("handle_message_client %d receive_ss_from_client %d."% (self.get_sender_id(),sender_id))
        shamirshares = msg_params.get(MyMessage.MSG_ARG_KEY_SS)

        self.flag_shamirshare_uploaded_dict[sender_id-1] = True
        self.collective_shamirshare[sender_id-1] = shamirshares
        all_received = self.check_whether_all_receive()
        self.shamirshare_list.append(shamirshares)
        if all_received:
            shamirshare_list = []
            for ss in self.collective_shamirshare:
                shamirshare_list += ss
            SS = genShamirShareString_robust(shamirshare_list, self.worker_num, self.k, self.log_degree,self.log_scale)
            self.SS = SS.tolist()
            self.send_message_CPK_to_server(0,self.CPK)

    #def handle_message_receive_model_from_server(self):
    def handle_message_receive_model_from_server(self, msg_params):
        print("receive syn model", self.get_sender_id())
        model_params = msg_params.get(MyMessage.MSG_ARG_KEY_MODEL_PARAMS)
        client_index = msg_params.get(MyMessage.MSG_ARG_KEY_CLIENT_INDEX)
        #self.old_weights = transform_dict_list(model_params)
        if self.args.is_mobile == 1:
            model_params = transform_list_to_tensor(model_params)
        self.old_weights = transform_dict_list(model_params)
        self.trainer.update_model(model_params)
        self.trainer.update_dataset(int(client_index))
        #self.trainer.update_dataset(0)
        #w = transform_dict_list(model_params)

        self.round_idx += 1
        self.__train()
        if self.round_idx == self.num_rounds - 1:
        #    post_complete_message_to_sweep_process(self.args)
            self.finish()

    def handle_message_init(self, msg_params):
        global_model_params = msg_params.get(MyMessage.MSG_ARG_KEY_MODEL_PARAMS)
        client_index = msg_params.get(MyMessage.MSG_ARG_KEY_CLIENT_INDEX)
        #self.old_weights = transform_dict_list(transform_list_to_tensor(global_model_params))
        #print("model param", global_model_params)
        if self.args.is_mobile == 1:
            global_model_params = transform_list_to_tensor(global_model_params)
        self.old_weights = transform_dict_list(global_model_params)
        self.trainer.update_model(global_model_params)
        self.trainer.update_dataset(int(client_index))
        self.round_idx = 0
        self.__train()

    def check_whether_all_receive(self):
        for idx in range(self.worker_num):
            if not self.flag_shamirshare_uploaded_dict[idx]:
                return False
        for idx in range(self.worker_num):
            self.flag_shamirshare_uploaded_dict[idx] = False
        return True

    def __train(self):
        logging.info("#######training########### round_id = %d" % self.round_idx)
        comp_init = time.time()
        weights, local_sample_num = self.trainer.train(self.round_idx)
        print("Computation time", time.time()-comp_init)
        #weights = np.ones((self.params_count,1))
        #print("non-encryped weights last 10", weights[self.params_count-10:self.params_count])
        #if self.get_sender_id()%2==0:
        #    weights = -1*22*np.ones((self.params_count,1), dtype=np.int)
        #else:
        #    weights = -1*10*np.ones((self.params_count,1), dtype=np.int)
        #weights = np.random.randint(-1*pow(10,4),pow(10,4),size = self.params_count)
        '''
        pweights = weights*pow(10,3)
        pweights = np.round(pweights)
        pweights = np.array(pweights, dtype = np.int)
        #print("weights", weights[0:10])
        #print("weights", weights[self.params_count-10:])
        pweights = np.clip(pweights,-1*pow(10,3),pow(10,3))
        '''
        weights = weights.reshape(-1,1)
        gradients = self.old_weights - weights
        error_compensated = gradients + self.error
        if self.compression==1:
            phi = random_matrix(self.alpha/2/self.samples, self.samples,self.params_count,seed = self.round_idx)
            compressed = self.beta * phi.dot(error_compensated)
            recov = phi.transpose().dot(compressed)
            self.error = error_compensated - recov
        else:
            compressed = weights

        compressed = compressed*pow(10,3)
        compressed = np.round(compressed)
        compressed = np.array(compressed, dtype = np.int)
        compressed = np.clip(compressed,-1*pow(10,3),pow(10,3))
        enc_weights, self.numPieces= self.encrypt(compressed.reshape((-1,1)))

        self.send_model_to_server(0, enc_weights.tolist(), local_sample_num)

    def handle_message_decryption_info_from_server(self,msg_params):
        decryptionParticipation = msg_params.get(MyMessage.MSG_ARG_KEY_DECRYPTION_PARTICIPATION)
        decryptionCoefficients = msg_params.get(MyMessage.MSG_ARG_KEY_DECRYPTION_COEFFI)
        if decryptionParticipation == 1:
            tpk = msg_params.get(MyMessage.MSG_ARG_KEY_TPK)
            PCKSShare = genPCKSShare(self.enc_aggregated_model,tpk,self.SS,self.worker_num, decryptionCoefficients, self.samples, self.robust, self.log_degree, self.log_scale,self.numPieces)
            self.send_PCKS_share_to_server(PCKSShare.tolist())


    def handle_message_public_key_from_server(self,msg_params):
        print("phase 1",time.time()-self.phase1init)
        self.pk = msg_params.get(MyMessage.MSG_ARG_KEY_PUBLIC_KEY)
        self.send_message_phase1_done_to_server()

    def send_message_phase1_done_to_server(self):
        message = Message(MyMessage.MSG_TYPE_C2S_PHASE1_DONE, self.get_sender_id(), 0)
        message.add_params(MyMessage.MSG_ARG_KEY_PHASE1_FLAG, "1")

        self.send_message(message)




    def send_PCKS_share_to_server(self,PCKS_shair):
        message = Message(MyMessage.MSG_TYPE_C2S_PCKS_SHARE, self.get_sender_id(), 0)
        message.add_params(MyMessage.MSG_ARG_KEY_PCKS_SHARE, PCKS_shair)
        self.send_message(message)


    def handle_message_enc_aggregated_model_from_server(self,msg_params):
        #client_index = msg_params.get(MyMessage.MSG_ARG_KEY_CLIENT_INDEX)
        self.enc_aggregated_model = msg_params.get(MyMessage.MSG_ARG_KEY_ENCRYPTED_MODEL_PARAMS)
        print("client receive model:",self.get_sender_id())
        self.announce_liveness_status()

    def announce_liveness_status(self):
        message = Message(MyMessage.MSG_TYPE_C2S_SEND_LIVENESS_STATUS, self.get_sender_id(), 0)
        message.add_params(MyMessage.MSG_ARG_KEY_LIVENESS_STATUS,self.status)
        self.send_message(message)



    def send_SS(self):
        self.phase1init = time.time()
        ShamirShares, CPK = genShamirShares(self.worker_num,self.k, self.log_degree,self.log_scale, self.resiliency)
        self.CPK = CPK.tolist()
        ShamirShares = ShamirShares.reshape(self.worker_num,-1)
        for partyCntr in range(self.worker_num):
            if partyCntr+1 == self.get_sender_id():
                self.flag_shamirshare_uploaded_dict[partyCntr] = True
                self.collective_shamirshare[partyCntr] = ShamirShares[partyCntr].tolist()
            else:
                self.send_message_ShamirShares(partyCntr+1,ShamirShares[partyCntr].tolist())

    def send_pk_to_server(self):
        self.phase1init = time.time()
        #CPK = genCollectiveKeyShare_not_robust(self.worker_num,self.log_degree,self.log_scale, self.resiliency)
        CPK, SS = genCollectiveKeyShare_not_robust(self.worker_num,self.k,self.log_degree,self.log_scale, self.resiliency)
        self.SS = SS.tolist()
        self.send_message_CPK_to_server(0,CPK.tolist())


    def send_message_ShamirShares(self, receive_id, ShamirShares):
        message = Message(MyMessage.MSG_TYPE_C2C_SEND_PROCESSED_SS, self.get_sender_id(), receive_id)
        message.add_params(MyMessage.MSG_ARG_KEY_SS, ShamirShares)
        self.send_message(message)

    def send_message_CPK_to_server(self, receive_id, CPK):
        #logging.info("send_message_CPK_to_server. receive_id = %d" % receive_id)
        message = Message(MyMessage.MSG_TYPE_C2S_SEND_CPK_TO_SERVER, self.get_sender_id(), receive_id)
        message.add_params(MyMessage.MSG_ARG_KEY_CPK, CPK)
        #message.add_params(MyMessage.MSG_ARG_KEY_CPK_STR, CPKstr)
        self.send_message(message)

    def send_model_to_server(self, receive_id, weights, local_sample_num):
        message = Message(MyMessage.MSG_TYPE_C2S_SEND_ENC_MODEL_TO_SERVER, self.get_sender_id(), receive_id)
        message.add_params(MyMessage.MSG_ARG_KEY_ENCRYPTED_MODEL_PARAMS, weights)
        #message.add_params(MyMessage.MSG_ARG_KEY_MODEL_PARAMS, pure_weights)
        message.add_params(MyMessage.MSG_ARG_KEY_NUM_SAMPLES, local_sample_num)
        #message.add_params(MyMessage.MSG_ARG_KEY_MODEL_PARAMS, pure_weights)
        self.send_message(message)

    def encrypt(self,weights):
        ct = encrypt(weights.reshape(-1), self.pk, self.SS, self.robust,self.log_degree, self.log_scale, self.resiliency, self.worker_num)
        return ct
