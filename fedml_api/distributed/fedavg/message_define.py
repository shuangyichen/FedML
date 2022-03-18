class MyMessage(object):
    """
        message type definition
    """

    # server to client
    MSG_TYPE_S2C_INIT_CONFIG = 1
    MSG_TYPE_S2C_SYNC_MODEL_TO_CLIENT = 2
    MSG_TYPE_S2C_SEND_AGGR_ENCRYPTED_MODEL = 5
    MSG_TYPE_S2C_PUBLIC_KEY_TO_CLIENT = 9
    MSG_TYPE_S2C_SEND_DECRYPTION_INFO = 12
    MSG_TYPE_S2C_ROUND_DONE = 14
    # client to server
    MSG_TYPE_C2S_SEND_MODEL_TO_SERVER = 3
    MSG_TYPE_C2S_SEND_STATS_TO_SERVER = 4
    MSG_TYPE_C2S_SEND_ENC_MODEL_TO_SERVER = 6
    MSG_TYPE_C2S_SEND_SS_TO_SERVER = 7
    MSG_TYPE_C2S_SEND_CPK_TO_SERVER = 8
    MSG_TYPE_C2S_PHASE1_DONE = 10
    MSG_TYPE_C2S_SEND_LIVENESS_STATUS = 11
    MSG_TYPE_C2S_PCKS_SHARE = 12
    MSG_TYPE_C2S_SEND_ROUND_LIVE = 15
    # client to client
    MSG_TYPE_C2C_SEND_PROCESSED_SS = 13


    MSG_ARG_KEY_TYPE = "msg_type"
    MSG_ARG_KEY_SENDER = "sender"
    MSG_ARG_KEY_RECEIVER = "receiver"

    """
        message payload keywords definition
    """
    MSG_ARG_KEY_NUM_SAMPLES = "num_samples"
    MSG_ARG_KEY_MODEL_PARAMS = "model_params"
    MSG_ARG_KEY_CLIENT_INDEX = "client_idx"
    MSG_ARG_KEY_ENCRYPTED_MODEL_PARAMS = "enc_model_params"
    MSG_ARG_KEY_SS = "ShamirShares"
    MSG_ARG_KEY_CPK = "collective_public_key"
    MSG_ARG_KEY_CPK_STR = "collective_public_key_str"
    MSG_ARG_KEY_PUBLIC_KEY = "public_key"
    MSG_ARG_KEY_PHASE1_FLAG = "whether phase 1 done"
    MSG_ARG_KEY_LIVENESS_STATUS = "liveness status"
    MSG_ARG_KEY_TPK = "target public key"
    MSG_ARG_KEY_DECRYPTION_PARTICIPATION = "decryption participation"
    MSG_ARG_KEY_DECRYPTION_COEFFI = "decryption coeff"
    MSG_ARG_KEY_PCKS_SHARE = "pcks shair"
    MSG_ARG_KEY_CLIENT_ROUND = "train round"

    MSG_ARG_KEY_TRAIN_CORRECT = "train_correct"
    MSG_ARG_KEY_TRAIN_ERROR = "train_error"
    MSG_ARG_KEY_TRAIN_NUM = "train_num_sample"

    MSG_ARG_KEY_TEST_CORRECT = "test_correct"
    MSG_ARG_KEY_TEST_ERROR = "test_error"
    MSG_ARG_KEY_TEST_NUM = "test_num_sample"


