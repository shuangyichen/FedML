import logging
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.getcwd(), "../../../")))
sys.path.insert(0, os.path.abspath(os.path.join(os.getcwd(), "../../../../FedML")))

try:
    from fedml_core.distributed.client.client_manager import ClientManager
    from fedml_core.distributed.communication.message import Message
except ImportError:
    from FedML.fedml_core.distributed.client.client_manager import ClientManager
    from FedML.fedml_core.distributed.communication.message import Message
from .message_define import MyMessage
from .utils import transform_list_to_tensor, post_complete_message_to_sweep_process
from .GoWrappers import *


class FedAVGClientInit(ClientManager):
    def __init__(self,trainer,worker_num,robust,log_degree, log_scale, resiliency,params_count,args, comm, rank, size, backend="MPI"):
        super().__init__(args, comm, rank, size, backend)
        self.worker_num = worker_num
        self.robust = robust
        self.status = 1
        if not self.robust:
            self.status = 1
        self.log_degree = log_degree
        self.log_scale = log_scale
        self.resiliency = resiliency
        self.trainer = trainer
        self.params_count = params_count

    def register_message_receive_handlers(self):
        self.register_message_receive_handler(MyMessage.MSG_TYPE_S2C_PUBLIC_KEY_TO_CLIENT,self.handle_message_public_key_from_server)
        self.register_message_receive_handler(MyMessage.MSG_TYPE_S2C_INIT_CONFIG,self.handle_message_init)
        self.register_message_receive_handler(MyMessage.MSG_TYPE_S2C_SEND_AGGR_ENCRYPTED_MODEL,self.handle_message_enc_aggregated_model_from_server)
        self.register_message_receive_handler(MyMessage.MSG_TYPE_S2C_SEND_DECRYPTION_INFO,self.handle_message_decryption_info_from_server)


    def run(self):
        super().run()


    def handle_message_init(self, msg_params):
        global_model_params = msg_params.get(MyMessage.MSG_ARG_KEY_MODEL_PARAMS)
        client_index = msg_params.get(MyMessage.MSG_ARG_KEY_CLIENT_INDEX)

        if self.args.is_mobile == 1:
            global_model_params = transform_list_to_tensor(global_model_params)

        self.trainer.update_model(global_model_params)
        self.trainer.update_dataset(int(client_index))
        self.round_idx = 0
        self.__train()


    #def start_training(self):
    #    self.round_idx = 0
    #    self.__train()

    def __train(self):
        logging.info("#######training########### round_id = %d" % self.round_idx)
        weights, local_sample_num = self.trainer.train(self.round_idx)
        print(weights)
        enc_weights = self.encrypt(weights.reshape(-1))
        print("enc done")
        self.send_model_to_server(0, enc_weights, local_sample_num)

    def handle_message_decryption_info_from_server(self,msg_params):
        decryptionParticipation = msg_params.get(MyMessage.MSG_ARG_KEY_DECRYPTION_PARTICIPATION)
        decryptionCoefficients = msg_params.get(MyMessage.MSG_ARG_KEY_DECRYPTION_COEFFI)
        if decryptionParticipation == 1:
            print("get decryption info")
            tpk = msg_params.get(MyMessage.MSG_ARG_KEY_TPK)
            PCKSShair = genPCKSShair(self.enc_aggregated_model,tpk,self.SSstr, decryptionCoefficients, self.params_count, self.robust, self.log_degree, self.log_scale)
            self.send_PCKS_shair_to_server(PCKSShair)


    def handle_message_public_key_from_server(self,msg_params):
        print("receive public key.")
        self.pk = msg_params.get(MyMessage.MSG_ARG_KEY_PUBLIC_KEY)
        self.send_message_phase1_done_to_server()
        #client_index = msg_params.get(MyMessage.MSG_ARG_KEY_CLIENT_INDEX)
    def send_message_phase1_done_to_server(self):
        message = Message(MyMessage.MSG_TYPE_C2S_PHASE1_DONE, self.get_sender_id(), 0)
        message.add_params(MyMessage.MSG_ARG_KEY_PHASE1_FLAG, "1")

        self.send_message(message)




    def send_PCKS_shair_to_server(self,PCKS_shair):
        message = Message(MyMessage.MSG_TYPE_C2S_PCKS_SHAIR, self.get_sender_id(), 0)
        message.add_params(MyMessage.MSG_ARG_KEY_PCKS_SHAIR, PCKS_shair)
        self.send_message(message)


    def handle_message_enc_aggregated_model_from_server(self,msg_params):
        client_index = msg_params.get(MyMessage.MSG_ARG_KEY_CLIENT_INDEX)
        self.enc_aggregated_model = msg_params.get(MyMessage.MSG_ARG_KEY_ENCRYPTED_MODEL_PARAMS)

        self.announce_liveness_status()

    def announce_liveness_status(self):
        message = Message(MyMessage.MSG_TYPE_C2S_SEND_LIVENESS_STATUS, self.get_sender_id(), 0)
        message.add_params(MyMessage.MSG_ARG_KEY_LIVENESS_STATUS,self.status)
        self.send_message(message)



    def send_SS(self):
        ShamirShares = genShamirShares(self.worker_num,self.robust,self.log_degree,self.log_scale, self.resiliency)
        self.send_message_ShamirShares_to_server(0,ShamirShares)
    def send_pk_to_server(self):

        CPK, self.SSstr= genCollectiveKeyShair_not_robust(self.worker_num,self.robust,self.log_degree,self.log_scale, self.resiliency)

        #self.SSstr = SSstr
        self.send_message_CPK_to_server(0,CPK)


    def send_message_ShamirShares_to_server(self, receive_id, ShamirShares):
        logging.info("send_message_ShamirShares_to_client. receive_id = %d" % receive_id)
        print(self.get_sender_id())
        message = Message(MyMessage.MSG_TYPE_C2S_SEND_SS_TO_SERVER, self.get_sender_id(), receive_id)
        message.add_params(MyMessage.MSG_ARG_KEY_SS, ShamirShares)
        #message.add_params(MyMessage.MSG_ARG_KEY_Sender, ShamirShares)
        self.send_message(message)

    def send_message_CPK_to_server(self, receive_id, CPK):
        logging.info("send_message_CPK_to_server. receive_id = %d" % receive_id)
        message = Message(MyMessage.MSG_TYPE_C2S_SEND_CPK_TO_SERVER, self.get_sender_id(), receive_id)
        message.add_params(MyMessage.MSG_ARG_KEY_CPK, CPK)
        #message.add_params(MyMessage.MSG_ARG_KEY_Sender, ShamirShares)
        self.send_message(message)
        #print("send done")

    def send_model_to_server(self, receive_id, weights, local_sample_num):
        message = Message(MyMessage.MSG_TYPE_C2S_SEND_ENC_MODEL_TO_SERVER, self.get_sender_id(), receive_id)
        message.add_params(MyMessage.MSG_ARG_KEY_ENCRYPTED_MODEL_PARAMS, weights)
        message.add_params(MyMessage.MSG_ARG_KEY_NUM_SAMPLES, local_sample_num)
        self.send_message(message)

    def encrypt(self,weights):
        ct = encrypt(weights.reshape(-1), self.pk, self.SSstr, self.robust,self.log_degree, self.log_scale, self.resiliency)
        return ct
