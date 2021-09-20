from ctypes import *
from numpy.ctypeslib import ndpointer
import numpy as np
# loading the shared libraries
lib = CDLL("./../../../fedml_api/distributed/fedavg/Encryption/func1.so")
import time
# defining the required conversion
def convertToGoSlice(npArray):
    #print("goslice length", len(npArray))
    data = (c_double * len(npArray))(0)
    for i in range(len(npArray)):
        data[i] = float(npArray[i])
    return GoSlice(data, len(data), len(data))

def uint64convertToGoSlice(npArray):
    #print("goslice length", len(npArray))
    data = (c_ulonglong * len(npArray))(0)
    for i in range(len(npArray)):
        data[i] = npArray[i][0]
    return GoSliceuint64(data, len(data), len(data))

def int64convertToGoSlice(npArray):
    #print("goslice length", len(npArray))
    data = (c_longlong * len(npArray))(0)
    for i in range(len(npArray)):
        data[i] = npArray[i]
    return GoSliceint64(data, len(data), len(data))

def uint64convertToGoSlice_(npArray):
    #print("goslice length", len(npArray))
    data = (c_ulonglong * len(npArray))(0)
    for i in range(len(npArray)):
        data[i] = npArray[i]
    return GoSliceuint64(data, len(data), len(data))

class GoSliceint64(Structure):
    _fields_ = [("data", POINTER(c_longlong)), ("len", c_longlong), ("cap", c_longlong)]

class GoSliceuint64(Structure):
    _fields_ = [("data", POINTER(c_ulonglong)), ("len", c_longlong), ("cap", c_longlong)]

class GoString(Structure):
    _fields_ = [("p", c_char_p), ("n", c_longlong)]

class GoSlice(Structure):
    _fields_ = [("data", POINTER(c_double)), ("len", c_longlong), ("cap", c_longlong)]

class genCollectivePK_return(Structure):
    _fields_ = [("r0", POINTER(c_ulonglong))]
#class genCollectiveKeyShare_not_robust_return(Structure):
#    _fields_ = [("r0", ndpointer(dtype = c_ulonglong, shape = (16384,1))), ("r1", ndpointer(dtype = c_ulonglong, shape = (16384,1)))]
class genCollectiveKeyShare_not_robust_return(Structure):
    _fields_ = [("r0", POINTER(c_ulonglong)), ("r1", POINTER(c_ulonglong))]
    #_fields_ = [("r0", POINTER(c_ulonglong)), ("r1", POINTER(c_ulonglong)),("r2",c_char_p),("r3",c_char_p)]

class genTPK_return(Structure):
    _fields_ = [("r0", POINTER(c_ulonglong)), ("r1", POINTER(c_ulonglong))]

class genShamirShares_return(Structure):
    _fields_ = [("r0", POINTER(c_ulonglong)), ("r1", POINTER(c_ulonglong))]

class encryptMsg_return(Structure):
    _fields_ = [("r0", POINTER(c_ulonglong)), ("r1",c_longlong)]

class aggregateEncrypted_return(Structure):
    _fields_ = [("r0", POINTER(c_ulonglong)), ("r1",c_longlong)]

lib.encryptMsg.argtypes = [GoSliceint64, GoSliceuint64, GoSliceuint64, c_ubyte, c_ulonglong, c_double, c_double, c_longlong]
lib.encryptMsg.restype = encryptMsg_return#POINTER(c_ulonglong)
lib.aggregateEncrypted.argtypes = [GoSliceuint64,c_ubyte,c_ulonglong, c_double, c_longlong]
lib.aggregateEncrypted.restype =  aggregateEncrypted_return#POINTER(c_ulonglong)
lib.genShamirShares.argtypes = [c_longlong, c_longlong, c_ulonglong, c_double, c_double]
lib.genShamirShares.restype = genShamirShares_return
lib.genCollectiveKeyShare_not_robust.argtypes = [c_longlong,c_longlong, c_ulonglong, c_double, c_double]
lib.genCollectiveKeyShare_not_robust.restype = genCollectiveKeyShare_not_robust_return
#lib.genCollectiveKeyShare_not_robust.restype = c_uint64
#lib.genCollectiveKeyShare_not_robust.restype = ndpointer(dtype = c_ulonglong, shape = (16384,1))
lib.genCollectivePK.argtypes = [GoSliceuint64,c_ubyte, c_ulonglong, c_double]
lib.genCollectivePK.restype = POINTER(c_ulonglong)#genCollectivePK_return#POINTER(c_ulonglong)
lib.genTPK.argtypes = [c_ulonglong, c_double]
lib.genTPK.restype = genTPK_return
lib.genPCKSShare.argtypes = [GoSliceuint64, GoSliceuint64, GoSliceuint64, c_longlong,c_ulonglong, c_ulonglong,c_ubyte,c_ulonglong, c_double]
lib.genPCKSShare.restype = POINTER(c_ulonglong)
lib.decrypt.argtypes = [GoString, GoSliceuint64, GoSliceuint64, GoSliceuint64, c_ulonglong, c_double, c_ulonglong, c_longlong ]
lib.decrypt.restype = POINTER(c_longlong)
lib.genShamirShareString_robust.argtypes = [GoSliceuint64, c_longlong, c_longlong, c_ulonglong, c_double]
lib.genShamirShareString_robust.restype = POINTER(c_ulonglong)
lib.genDecryptionCoefficients.argtype = GoString
lib.genDecryptionCoefficients.restype = c_char_p

def genDecryptionCoefficients(client_chosen_list):
    client_chosen_list = client_chosen_list.encode()
    res = lib.genDecryptionCoefficients(GoString(client_chosen_list,len(client_chosen_list)))
    return res

def genShamirShareString_robust(shamirShare, numPeers, k,logDegree, scale):
    res = lib.genShamirShareString_robust(uint64convertToGoSlice_(shamirShare), numPeers, k, logDegree, 2.**scale)
    return np.ctypeslib.as_array(res,shape = (16384,1))

def decrypt(client_chosen,tsk,pcksShare, encResult, logDegree, scale, inputLength, numPeers):
    init = time.time()
    client_chosen = client_chosen.encode()
    res = lib.decrypt(GoString(client_chosen,len(client_chosen)),uint64convertToGoSlice(tsk),uint64convertToGoSlice(pcksShare), uint64convertToGoSlice(encResult), logDegree, 2.**scale, inputLength, numPeers)
    print("decryption time", time.time()-init)
    output = np.ctypeslib.as_array(res,shape = (1,inputLength))
    return output
def genPCKSShare(enc_aggr_model,TPK,shamir_share,worker_num,decryptionCoefficient, inputLength, robust, logDegree, scale, numPieces):
    #print("gowrappers shamirshare",shamir_share[0:10])
    init = time.time()
    PCKSShare = lib.genPCKSShare(uint64convertToGoSlice(enc_aggr_model),uint64convertToGoSlice(TPK),uint64convertToGoSlice(shamir_share),worker_num, decryptionCoefficient,inputLength,robust,logDegree,2.**scale)
    print("gen PCKSShare time",time.time()-init)
    #print("pcks numpieces",numPieces)
    return np.ctypeslib.as_array(PCKSShare,shape = (16384*numPieces,1))

def genTPK(log_degree,log_scale):
    out = lib.genTPK(log_degree,2.**log_scale)
    return np.ctypeslib.as_array(out.r0,shape = (32768,1)) ,np.ctypeslib.as_array(out.r1,shape = (16384,1))


def encrypt(inputs,public_key, shamir_share,robust, log_degree, log_scale, resiliency, worker_num):
    cInput = int64convertToGoSlice(inputs)
    pk = uint64convertToGoSlice(public_key)
    ss = uint64convertToGoSlice(shamir_share)
    init = time.time()
    res = lib.encryptMsg(cInput, pk, ss,robust, log_degree, 2.**log_scale, resiliency, worker_num)
    print("encryption time", time.time()-init)
    numPieces = res.r1
    #print("numPieces",numPieces)
    return np.ctypeslib.as_array(res.r0,shape = (16384*numPieces,1)),numPieces



def aggregateEncrypted(enc_model_list,worker_num,log_degree,log_scale,input_length):
    res = lib.aggregateEncrypted(uint64convertToGoSlice(enc_model_list),worker_num,log_degree,2.**log_scale,input_length)
    numPieces = res.r1
    return np.ctypeslib.as_array(res.r0,shape = (16384*numPieces,1))



def genShamirShares(worker_num, k, log_degree, log_scale,resilliency):

    res = lib.genShamirShares(worker_num, k, log_degree,2.**log_scale,resilliency)
    return np.ctypeslib.as_array(res.r0,shape = (16384*worker_num,1)), np.ctypeslib.as_array(res.r1,shape = (16384,1))

def genCollectiveKeyShare_not_robust(worker_num,k, log_degree, log_scale,resilliency):
    out = lib.genCollectiveKeyShare_not_robust(worker_num,k, log_degree,2.**log_scale,resilliency)
    out1 = np.ctypeslib.as_array(out.r0,shape = (16384,1))
    out2 = np.ctypeslib.as_array(out.r1,shape = (16384,1))
    return out1, out2

def genCollectivePK(CPK, worker_num,log_degree, log_scale):
    #CPKstr = CPKstr.encode()
    Input = uint64convertToGoSlice(CPK)
    res = lib.genCollectivePK(Input, worker_num,log_degree,2.**log_scale)
    publickey = np.ctypeslib.as_array(res,shape = (16384*2,1))
    return publickey
