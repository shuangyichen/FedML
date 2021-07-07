import logging
import os, signal
import sys

from .message_define import MyMessage
from .utils import transform_tensor_to_list, post_complete_message_to_sweep_process

sys.path.insert(0, os.path.abspath(os.path.join(os.getcwd(), "../../../")))
sys.path.insert(0, os.path.abspath(os.path.join(os.getcwd(), "../../../../FedML")))
try:
    from fedml_core.distributed.communication.message import Message
    from fedml_core.distributed.server.server_manager import ServerManager
except ImportError:
    from FedML.fedml_core.distributed.communication.message import Message
    from FedML.fedml_core.distributed.server.server_manager import ServerManager
from .GoWrappers import *

class FedAVGServerInit(ServerManager):
    def __init__(self,worker_num,log_degree, log_scale,args,aggregator,params_count = 7850,comm=None,rank=0, size=0,backend="MPI"):
        super().__init__(args, comm, rank, size, backend)
        self.aggregator = aggregator
        self.round_num = args.comm_round
        self.round_idx = 0
        self.worker_num = worker_num
        self.log_degree = log_degree
        #print(self.log_degree)
        self.log_scale = log_scale
        #print("log_scale",self.log_scale)
        self.flag_client_uploaded_dict = dict()
        self.CollectivePublicKey = dict()
        self.params_count = params_count
        for idx in range(self.worker_num):
            self.flag_client_uploaded_dict[idx] = False

    def run(self):
        super().run()


    def send_init_msg(self):
        # sampling clients
        client_indexes = self.aggregator.client_sampling(self.round_idx, self.args.client_num_in_total,
                                                         self.args.client_num_per_round)
        global_model_params = self.aggregator.get_global_model_params()
        if self.args.is_mobile == 1:
            global_model_params = transform_tensor_to_list(global_model_params)
        for process_id in range(1, self.size):
            self.send_message_init_config(process_id, global_model_params, client_indexes[process_id - 1])


    def register_message_receive_handlers(self):
        self.register_message_receive_handler(MyMessage.MSG_TYPE_C2S_SEND_SS_TO_SERVER,self.handle_message_SS_from_client)
        self.register_message_receive_handler(MyMessage.MSG_TYPE_C2S_SEND_CPK_TO_SERVER,self.handle_message_CPK_from_client)
    #MSG_TYPE_C2S_PHASE1_DONE
        self.register_message_receive_handler(MyMessage.MSG_TYPE_C2S_PHASE1_DONE,self.handle_message_phase1_flag_from_client)
        self.register_message_receive_handler(MyMessage.MSG_TYPE_C2S_SEND_ENC_MODEL_TO_SERVER,self.handle_message_receive_enc_model_from_client)
        self.register_message_receive_handler(MyMessage.MSG_TYPE_C2S_SEND_LIVENESS_STATUS,self.handle_message_receive_liveness_status_from_client)
        self.register_message_receive_handler(MyMessage.MSG_TYPE_C2S_PCKS_SHAIR,self.handle_message_receive_pcks_shair)

    def handle_message_receive_pcks_shair(self,msg_params):
        sender_id = msg_params.get(MyMessage.MSG_ARG_KEY_SENDER)
        print("receive pcks shair from client",sender_id)
        pcks_share = msg_params.get(MyMessage.MSG_ARG_KEY_PCKS_SHAIR)
        self.aggregator.add_pcks_share(sender_id-1, pcks_share)
        b_all_received = self.aggregator.check_whether_all_receive()
        if b_all_received:
            res = decrypt(self.tsk,','.join(self.aggregator.pcks_share_list),self.aggr_enc_model_list,self.log_degree,self.log_scale,self.params_count,self.worker_num)
            print("decrypt")

    def handle_message_receive_liveness_status_from_client(self,msg_params):
        sender_id = msg_params.get(MyMessage.MSG_ARG_KEY_SENDER)
        print("receive liveness status announcement from client",sender_id)
        liveness_status = msg_params.get(MyMessage.MSG_ARG_KEY_LIVENESS_STATUS)
        if liveness_status ==1:
            #tpk = genTPK(self.log_degree,self.log_scale)
            self.send_decryption_info(sender_id,1,0)

    def handle_message_receive_enc_model_from_client(self,msg_params):
        sender_id = msg_params.get(MyMessage.MSG_ARG_KEY_SENDER)
        print("receive enc_model from client",sender_id)
        enc_model_params = msg_params.get(MyMessage.MSG_ARG_KEY_ENCRYPTED_MODEL_PARAMS)
        local_sample_number = msg_params.get(MyMessage.MSG_ARG_KEY_NUM_SAMPLES)
        #self.aggregator.add_local_trained_result(sender_id - 1, enc_model_params, local_sample_number)
        self.aggregator.add_enc_model_params(sender_id - 1, enc_model_params, local_sample_number)
        b_all_received = self.aggregator.check_whether_all_receive()
        #print(self.aggregator.flag_client_model_uploaded_dict)
        if b_all_received:
            self.aggr_enc_model_list = aggregateEncrypted(','.join(self.aggregator.enc_model_list),self.worker_num,self.log_degree,self.log_scale,self.params_count)
            client_indexes = self.aggregator.client_sampling(self.round_idx, self.args.client_num_in_total,
                                                                 self.args.client_num_per_round)

            for receiver_id in range(1, self.size):
                self.send_message_aggregated_encrypted_model_to_client(receiver_id, self.aggr_enc_model_list,
                                                       client_indexes[receiver_id - 1])




    def send_decryption_info(self,receive_id,decryptionParticipation,decryptionCoefficients):
        logging.info("send_message_decryption_info_to_client. receive_id = %d" % receive_id)

        message = Message(MyMessage.MSG_TYPE_S2C_SEND_DECRYPTION_INFO, self.get_sender_id(), receive_id)
        message.add_params(MyMessage.MSG_ARG_KEY_DECRYPTION_PARTICIPATION,decryptionParticipation)
        message.add_params(MyMessage.MSG_ARG_KEY_DECRYPTION_COEFFI,decryptionCoefficients)
        if decryptionParticipation==1:
            tpk,self.tsk= genTPK(self.log_degree,self.log_scale)
            message.add_params(MyMessage.MSG_ARG_KEY_TPK,tpk)
        self.send_message(message)

    def send_message_aggregated_encrypted_model_to_client(self, receive_id, aggr_enc_model_params, client_index):
        logging.info("send_message_sync_model_to_client. receive_id = %d" % receive_id)
        message = Message(MyMessage.MSG_TYPE_S2C_SEND_AGGR_ENCRYPTED_MODEL, self.get_sender_id(), receive_id)
        message.add_params(MyMessage.MSG_ARG_KEY_ENCRYPTED_MODEL_PARAMS, aggr_enc_model_params)
        message.add_params(MyMessage.MSG_ARG_KEY_CLIENT_INDEX, str(client_index))
        self.send_message(message)


    def handle_message_phase1_flag_from_client(self,msg_params):

        self.send_init_msg()



    def handle_message_SS_from_client(self,msg_params):
        sender_id = msg_params.get(MyMessage.MSG_ARG_KEY_SENDER)
        ShamirShares = msg_params.get(MyMessage.MSG_ARG_KEY_SS)
        self.flag_client_uploaded_dict[sender_id-1] = True
        all_received = self.check_whether_all_receive()
        if all_received:
            print("recerve SS")

    def handle_message_CPK_from_client(self,msg_params):
        sender_id = msg_params.get(MyMessage.MSG_ARG_KEY_SENDER)
        print("receive cpk from client",sender_id)
        CPK = msg_params.get(MyMessage.MSG_ARG_KEY_CPK)
        self.CollectivePublicKey[sender_id-1] = CPK
        self.flag_client_uploaded_dict[sender_id-1] = True
        all_received = self.check_whether_all_receive()
        if all_received:
            collective_puclic_key = [None]*len(self.CollectivePublicKey)
            #print("length of cpk", len(collective_puclic_key))
            for i,key in enumerate(self.CollectivePublicKey.keys()):
                #print(key)
                collective_puclic_key[key] = self.CollectivePublicKey[key].decode()
            s = ','
            cpk = s.join(collective_puclic_key)
            res = genCollectivePK(cpk,self.worker_num,self.log_degree,self.log_scale)
            self.send_pk_to_client(res)


    def send_pk_to_client(self,pk):
        for client_idx in range(self.worker_num):
            logging.info("send_message_public_key_to_client. receive_id = %d" % (client_idx+1))
            message = Message(MyMessage.MSG_TYPE_S2C_PUBLIC_KEY_TO_CLIENT, 0, client_idx+1)
            message.add_params(MyMessage.MSG_ARG_KEY_PUBLIC_KEY, pk)
            #message.add_params(MyMessage.MSG_ARG_KEY_CLIENT_INDEX, str(client_index+1))
            self.send_message(message)

    def send_message_init_config(self, receive_id, global_model_params, client_index):
        message = Message(MyMessage.MSG_TYPE_S2C_INIT_CONFIG, self.get_sender_id(), receive_id)
        message.add_params(MyMessage.MSG_ARG_KEY_MODEL_PARAMS, global_model_params)
        message.add_params(MyMessage.MSG_ARG_KEY_CLIENT_INDEX, str(client_index))
        self.send_message(message)


    def check_whether_all_receive(self):
        for idx in range(self.worker_num):
            if not self.flag_client_uploaded_dict[idx]:
                return False
        for idx in range(self.worker_num):
            self.flag_client_uploaded_dict[idx] = False
        return True
