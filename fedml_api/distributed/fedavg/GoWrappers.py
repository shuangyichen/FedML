from ctypes import *

# loading the shared libraries
lib = CDLL("./../../../fedml_api/distributed/fedavg/Encryption/func.so")

# defining the required conversion
def convertToGoSlice(npArray):
    #print("goslice length", len(npArray))
    data = (c_double * len(npArray))(0)
    for i in range(len(npArray)):
        data[i] = float(npArray[i])
    return GoSlice(data, len(data), len(data))

def convertListToGoSlice(listofstr):
    data = (c_char_p * len(listofstr))(0)
    for i in range(len(listofstr)):
        data[i] = listofstr[i]
    return GoSliceList(data, len(data), len(data))


class GoString(Structure):
    _fields_ = [("p", c_char_p), ("n", c_longlong)]

class GoSlice(Structure):
    _fields_ = [("data", POINTER(c_double)), ("len", c_longlong), ("cap", c_longlong)]

class GoSliceList(Structure):
    _fields_ = [("data", POINTER(c_char_p)), ("len", c_longlong), ("cap", c_longlong)]


class genCollectiveKeyShair_not_robust_return(Structure):
    _fields_ = [("r0", c_char_p), ("r1", c_char_p)]

class genTPK_return(Structure):
    _fields_ = [("r0", c_char_p), ("r1", c_char_p)]

class genShamirShares_return(Structure):
    _fields_ = [("r0", c_char_p), ("r1", c_char_p)]

lib.encryptMsg.argtypes = [GoSlice, GoString, GoString, c_ubyte, c_ulonglong, c_double, c_double]
lib.encryptMsg.restype = c_char_p
lib.aggregateEncrypted.argtypes = [GoString,c_ubyte,c_ulonglong, c_double, c_longlong]
lib.aggregateEncrypted.restype = c_char_p
lib.genShamirShares.argtypes = [c_longlong,c_ubyte, c_ulonglong, c_double, c_double]
lib.genShamirShares.restype = genShamirShares_return
lib.genCollectiveKeyShair_not_robust.argtypes = [c_longlong,c_ubyte, c_ulonglong, c_double, c_double]
lib.genCollectiveKeyShair_not_robust.restype = genCollectiveKeyShair_not_robust_return
lib.genCollectivePK.argtypes = [GoString,c_ubyte, c_ulonglong, c_double]
lib.genCollectivePK.restype = c_char_p
lib.genTPK.argtypes = [c_ulonglong, c_double]
lib.genTPK.restype = genTPK_return
lib.genPCKSShare.argtypes = [GoString, GoString, GoString, c_ulonglong, c_ulonglong,c_ubyte,c_ulonglong, c_double]
lib.genPCKSShare.restype = c_char_p
lib.decrypt.argtypes = [GoString, GoString, GoString, c_ulonglong, c_double, c_ulonglong, c_longlong ]
lib.decrypt.restype = c_char_p
lib.genShamirShareString_robust.argtypes = [GoString, c_longlong, c_ulonglong, c_double]
lib.genShamirShareString_robust.restype = c_char_p
lib.genDecryptionCoefficients.argtype = GoString
lib.genDecryptionCoefficients.restype = c_char_p

def genDecryptionCoefficients(client_chosen_list):
    client_chosen_list = client_chosen_list.encode()
    res = lib.genDecryptionCoefficients(GoString(client_chosen_list,len(client_chosen_list)))
    return res

def genShamirShareString_robust(shamirShare, numPeers, logDegree, scale):
    shamirShare = shamirShare.encode()
    res = lib.genShamirShareString_robust(GoString(shamirShare,len(shamirShare)), numPeers, logDegree, 2.**scale)
    return res

def decrypt(tsk,pcksShareString, encResultStr, logDegree, scale, inputLength, numPeers):
    pcksShareString = pcksShareString.encode()
    res = lib.decrypt(GoString(tsk,len(tsk)),GoString(pcksShareString,len(pcksShareString)), GoString(encResultStr,len(encResultStr)), logDegree, 2.**scale, inputLength, numPeers)
    res = res.decode()
    res = str.split(res, " ")[0:-1]
    res = [float(res_elem) for res_elem in res]
    #print(res)
    return res

def genPCKSShair(enc_aggr_model,TPK,shamir_share_str,decryptionCoefficient, inputLength, robust, logDegree, scale):
    PCKSShare = lib.genPCKSShare(GoString(enc_aggr_model,len(enc_aggr_model)),GoString(TPK,len(TPK)),GoString(shamir_share_str,len(shamir_share_str)),decryptionCoefficient,inputLength,robust,logDegree,2.**scale)

    return PCKSShare

def genTPK(log_degree,log_scale):
    out = lib.genTPK(log_degree,2.**log_scale)
    return out.r0, out.r1


def encrypt(inputs,public_key, shamir_share,robust, log_degree, log_scale, resiliency):
    cInput = convertToGoSlice(inputs)
    encMsg = lib.encryptMsg(cInput,GoString(public_key,len(public_key)),GoString(shamir_share,len(shamir_share)),robust, log_degree, 2.**log_scale, resiliency)
    return encMsg



def aggregateEncrypted(enc_model_list,worker_num,log_degree,log_scale,input_length):

    enc_models = enc_model_list.encode()
    res = lib.aggregateEncrypted(GoString(enc_models,len(enc_models)),worker_num,log_degree,2.**log_scale,input_length)
    return res



def genShamirShares(worker_num,robust, log_degree, log_scale,resilliency):

    res = lib.genShamirShares(worker_num,robust, log_degree,2.**log_scale,resilliency)
    return res.r0, res.r1

def genCollectiveKeyShair_not_robust(worker_num,robust, log_degree, log_scale,resilliency):

    out = lib.genCollectiveKeyShair_not_robust(worker_num,robust, log_degree,2.**log_scale,resilliency)
    return out.r0, out.r1
def genCollectivePK(CPK, worker_num,log_degree, log_scale):
    CPK = CPK.encode()
    res = lib.genCollectivePK(GoString(CPK,len(CPK)), worker_num,log_degree,2.**log_scale)
    return res
