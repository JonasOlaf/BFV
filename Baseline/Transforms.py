import numpy as np
import torch
import torch.nn as nn
import os
import pickle
import bisect
from os import remove
from os.path import getsize

class Model(nn.Module):
    def __init__(self, input_size, layers):
        # Should it include a dropout layer?
        super().__init__()
        self.output_size = layers[-1]
        layerlist = []

        for layer in layers[:-1]:
            layerlist.append(nn.Linear(input_size, layer))
            layerlist.append(nn.ReLU(inplace=True))
            input_size = layer

        # Do last layer without activation
        layerlist.append(nn.Linear(input_size, layers[-1]))

        self.fc = nn.Sequential(*layerlist)

    def forward(self, x):
        x = self.fc(x)
        return x

    def get_output_size(self):
        return self.output_size


def transform_model(db: list, model_path: str):
    assert model_path in ['model_64', 'model_96', 'model_128', 'model_160', 'model_512']
    if model_path == 'model_64':
        layers_in = list(np.linspace(512, 64, 4, dtype=int))
    elif model_path == 'model_96':
        layers_in = list(np.linspace(512, 96, 4, dtype=int))
    elif model_path == 'model_128':
        layers_in = list(np.linspace(512, 128, 4, dtype=int))
    elif model_path == 'model_160':
        layers_in = list(np.linspace(512, 160, 4, dtype=int))
    elif model_path == 'model_512':
        return db
    model = Model(512, layers_in[1:])
    model.load_state_dict(torch.load('models/'+model_path))
    if isinstance(db, list):  # db is a full DB, and not a single remove_single_sample_persons
        ndb = []
        with torch.no_grad():
            for person in db:
                plist = []
                for sample in person:
                    # convert a sample to tensor, take through model, back to
                    # numpy, append to plist.
                    plist.append(model(torch.FloatTensor(sample)).numpy())
                ndb.append(plist)
        return ndb
    else:  # received single sample
        return


def transform_references_model(references: list, model_path: str):
    if model_path == 'model':
        layers = [512, 256, 128, 64]
    elif model_path == 'model_96':
        layers = [512, 373, 234, 96]
    elif model_path == 'model_128':
        layers = [512, 384, 256, 128]
    model = Model(layers[0], layers[1:])
    model.load_state_dict(torch.load(model_path))
    ndb = []
    with torch.no_grad():
        for sample in references:
            ndb.append(model(torch.FloatTensor(sample)).numpy())
    return ndb


def transform_to_int(db, n:int):
    #transform DB into n integers
    udb, _ = unroll_db(db)
    translate = []
    for i in range(len(udb[0])):
        translate.append([])
        L = [sample[i] for sample in udb]
        L.sort()
        for j in range(1,n):
            translate[i].append(L[int(len(udb)/n*j)])

    newdb = []
    for subject in db: # should be len(translate)
        person = []
        for sample in subject:
            intsample = []
            for i, value in enumerate(sample):
                intsample.append(bisect.bisect_left(translate[i], value))
            person.append(intsample)
        newdb.append(person)
    return newdb, translate


def get_db(filename: str):
    folder = '/Users/jonasolafsson/Documents/speciale/biometrics.nosync/serialized_data/'
    file = folder + filename + ".pkl"
    open_file = open(file, "rb")
    loaded_list = pickle.load(open_file)
    open_file.close()
    return loaded_list

def get_size(variable, format='str'):
    # Serializes a variable to disk, and returns the size of it.
    filename = 'TEMPmeasure_size.pkl'
    open_file = open(filename, 'wb')
    pickle.dump(variable, open_file)
    open_file.close()
    size = getsize(filename)
    remove(filename)
    if format == 'str':
        return format_size(size)
    else:
        return size


def format_size(size: int):
    # To print string of bytes to kB and MB
    if size < 1000:
        return f'{size} bytes'
    elif size < 10**6:
        return f'{round(size/(10**3),2)} kB'
    else:
        return f'{round(size/(10**6),2)} MB'
