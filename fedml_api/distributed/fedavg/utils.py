import os

import torch
import numpy as np
from scipy.sparse import csr_matrix

def transform_list_to_tensor(model_params_list):
    for k in model_params_list.keys():
        model_params_list[k] = torch.from_numpy(np.asarray(model_params_list[k])).float()
    return model_params_list


def transform_tensor_to_list(model_params):
    for k in model_params.keys():
        model_params[k] = model_params[k].detach().numpy().tolist()
    return model_params

def transform_dict_list(model_params):
    res = []
    seq = []
    for i,k in enumerate(model_params.keys()):
        #print("k",k)
        model_param = model_params[k].detach().numpy()
        #print(model_param.shape)
        res.append(np.reshape(model_param,(-1,1)))
        #seq.append('res[%d]' % i)
        #print(model_param.shape)
        #res.append(model_params[k].detach().numpy())
        if i==1:
            model_params_concat = np.concatenate((res[0],res[1]),axis=0)
        elif i>1:
            model_params_concat = np.concatenate((model_params_concat,res[i]),axis=0)
        #res.append(model_params[k].detach().numpy())
    return model_params_concat#np.concatenate(,axis=0)


def post_complete_message_to_sweep_process(args):
    pipe_path = "./tmp/fedml"
    if not os.path.exists(pipe_path):
        os.mkfifo(pipe_path)
    pipe_fd = os.open(pipe_path, os.O_WRONLY)

    with os.fdopen(pipe_fd, 'w') as pipe:
        pipe.write("training is finished! \n%s\n" % (str(args)))


def random_matrix(p,s,w,seed):
    np.random.seed(seed)
    counts = np.int(np.random.normal(loc=s*w*p*2, scale=np.sqrt(s * w * 2 * p * (1 - 2 * p)), size=(1)))
    rows = np.random.uniform(low=0,high=s,size=(counts)).astype(int)
    cols = np.random.uniform(low=0,high=w,size=(counts)).astype(int)
    vals = np.random.binomial(n=1,p=0.5,size=(counts))*2-1
    SparseTensor = csr_matrix((vals, (rows,cols)), shape=(s,w)).toarray()
    np.random.shuffle(SparseTensor)
    return SparseTensor
