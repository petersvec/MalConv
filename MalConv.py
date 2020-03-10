from keras.models import Model
from keras.layers import Dense, Embedding, Conv1D, multiply, GlobalMaxPool1D, Input, Activation
from keras.callbacks import ModelCheckpoint, EarlyStopping
from keras.preprocessing.sequence import pad_sequences

import os
import argparse
import yaml
import pandas
import random
import numpy

training_data = []
training_labels = []
testing_data = []
testing_labels = []

batch_size = 64
epochs = 10
max_length = 2000000

parser = argparse.ArgumentParser(description = 'MalConv deep neural network')
parser.add_argument('--train', action = 'store_true')

'''
    Creates MalConv model
    max_input_length -> maximal input length of binary 
'''
def create_model(max_input_length = 2000000):
    print("Creating MalConv model.")

    input = Input(shape = (max_input_length,))
    embedding = Embedding(input_dim = 256, output_dim = 8)(input)
    convolution_1 = Conv1D(kernel_size = 500, filters = 128, strides = 500, padding = 'same')(embedding)
    convolution_2 = Conv1D(kernel_size = 500, filters = 128, strides = 500, padding = 'same')(embedding)
    activation_1 = Activation('sigmoid', name = 'sigmoid')(convolution_2)
    mul = multiply([convolution_1, activation_1])
    activation_2 = Activation('relu', name = 'relu')(mul)
    pooling = GlobalMaxPool1D()(activation_2)
    dense = Dense(64)(pooling)
    output = Dense(1, activation = 'sigmoid')(dense)

    return Model(input, output)

'''
    Generates random data for testing
'''
def generate_random_data(count, data_path, label_path):
    labels = {}

    for i in range(count):
        file_size = random.randint(1024, 2000000)
        file_content = os.urandom(file_size)
        file_name = file_content[0:10].hex()

        with open(data_path + file_name, 'wb') as f:
            f.write(file_content)

        labels[file_name] = random.randint(0, 1)

    with open(label_path, 'w') as f:
        for file_name in labels:
            f.write(data_path + file_name + ',' + str(labels[file_name]) + '\n')

'''
    Splits data between training and testing set
    data -> paths to malware samples
    labes -> malicious/benign labels
    ratio -> defining amount of data to be used as a testing set
'''
def train_test_split(data, labels, ratio):
    pass

'''
    Loads configuration file
'''
def load_config(path):
    config = yaml.load(open(path, 'r'))

    #training_data_path = config['training_data_path']
    #training_label_path = config['training_label_path']

    # TODO: maybe some optimization is needed

    #for item in pandas.read_csv(training_label_path, header = None).values:
    #    training_data.append(numpy.fromfile(training_data_path + item[0], dtype = numpy.ubyte))
    #    training_labels.append(item[1])

    #testing_data_path = config['testing_data_path']
    #testing_label_path = config['testing_label_path']

    #for item in pandas.read_csv(testing_label_path, header = None).values:
    #    testing_data.append(numpy.fromfile(testing_data_path + item[0], dtype = numpy.ubyte))
    #    testing_labels.append(item[1])

    global batch_size, epochs, max_length

    batch_size = config['batch_size']
    epochs = config['epochs']
    max_length = config['max_length']
    test_ratio = config['test_ratio']

    data_path = config['data_path']
    full_data = pandas.read_csv(data_path, header = None)

    data = full_data[0].values
    labels = full_data[1].values


'''
    Pads the input sequences to max length
    input -> input sequences
'''
def input_padding(input):
    sequence = pad_sequences(input, maxlen = max_length, padding = 'post', truncating = 'post')
    return sequence

'''
    Generates one batch of training/testing data
'''
def generate_batch(data, labels):
    # TODO: add shuffle

    for i in range(0, len(labels), batch_size):
        batch_data = input_padding(data[i:batch_size])
        batch_labels =  labels[i:batch_size]
        yield (batch_data, batch_labels)

'''
    Trains the model
    model -> model to train
'''
def training(model):
    early_stopping = EarlyStopping(monitor = 'val_acc', patience = 5)
    model_checkpoint = ModelCheckpoint(filepath = 'malconv.h5', monitor = 'val_acc', save_best_only = True, save_weights_only = False)

    model.fit_generator(
        generator = generate_batch(training_data, training_labels),
        steps_per_epoch = len(training_data) // batch_size,
        epochs = epochs,
        verbose = 2,
        callbacks = [early_stopping, model_checkpoint],
        validation_data = generate_batch(testing_data, testing_labels),
        validation_steps = len(testing_data) // batch_size)


if __name__ == '__main__':
    args = parser.parse_args()

    #generate_random_data(200, 'data\\', 'labels.csv')

    load_config('config.yaml')

    #if args.train:
    #    model = create_model(max_length)
    #    model.compile(loss = 'binary_crossentropy', optimizer = 'adam', metrics = ['accuracy'])
    #    training(model)