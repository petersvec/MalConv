from keras.models import Model
from keras.layers import Dense, Embedding, Conv1D, multiply, GlobalMaxPool1D, Input, Activation
from keras.callbacks import ModelCheckpoint, EarlyStopping
from keras.preprocessing.sequence import pad_sequences
from sklearn.metrics import confusion_matrix

import os
import argparse
import yaml
import pandas
import random
import numpy
import tensorflow
import warnings

training_data = []
training_labels = []
testing_data = []
testing_labels = []

batch_size = 64
epochs = 10
max_length = 2000000

warnings.filterwarnings("ignore")

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
    output = Dense(1, activation = 'softmax')(dense)

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
    idx = numpy.arange(len(data))
    numpy.random.shuffle(idx)

    split = int(len(data) * ratio)

    train_data, test_data = data[idx[split:]], data[idx[:split]]
    train_label, test_label = labels[idx[split:]], labels[idx[:split]]

    return train_data, test_data, train_label, test_label

'''
    Loads configuration file
'''
def load_config(path):
    config = yaml.load(open(path, 'r'))

    global batch_size, epochs, max_length, training_data, testing_data, training_labels, testing_labels

    batch_size = config['batch_size']
    epochs = config['epochs']
    max_length = config['max_length']
    test_ratio = config['test_ratio']

    data_path = config['data_path']
    full_data = pandas.read_csv(data_path, header = None)

    data = full_data[0].values
    labels = full_data[1].values

    training_data, testing_data, training_labels, testing_labels = train_test_split(data, labels, test_ratio)

'''
    Pads the input sequences to max length
    input -> input sequences
'''
def input_padding(input):
    sequence = pad_sequences(input, maxlen = max_length, padding = 'post', truncating = 'post')
    return sequence

'''
    Processes executable samples
    data -> malware samples paths
'''
def process(data):
    samples = []

    for file in data:
        with open(file, 'rb') as f:
            samples.append(f.read())

    samples = [[byte for byte in doc] for doc in samples]
    original_lengths = [len(doc) for doc in samples]

    return input_padding(samples), original_lengths

'''
    Continuously generates batches of training/testing data
'''
def generate_batch(data, labels, shuffle):
    idx = numpy.arange(len(data))

    if shuffle:
        numpy.random.shuffle(idx)

    batches = [idx[range(batch_size * i, min(len(data), batch_size * (i + 1)))] for i in range(len(data) // batch_size + 1)]

    while True:
        for i in batches:
            x = process(data[i])[0]
            y = labels[i]
            yield (x, y)

'''
    Trains the model
    model -> model to train
'''
def training(model):
    early_stopping = EarlyStopping(monitor = 'val_acc', patience = 5)
    model_checkpoint = ModelCheckpoint(filepath = 'malconv.h5', monitor = 'val_acc', save_best_only = True, save_weights_only = False)

    model.fit_generator(
        generator = generate_batch(training_data, training_labels, shuffle = True),
        steps_per_epoch = (len(training_data) // batch_size) + 1,
        epochs = epochs,
        verbose = 2,
        callbacks = [early_stopping, model_checkpoint],
        validation_data = generate_batch(testing_data, testing_labels, shuffle = True),
        validation_steps = (len(testing_data) // batch_size) + 1)

    predictions = model.predict_generator(generate_batch(testing_data, testing_labels, False), (len(testing_data) // batch_size) + 1)
    predictions = numpy.argmax(predictions, axis = 1)

    print("Confusion matrix:")
    print(confusion_matrix(testing_labels, predictions))

if __name__ == '__main__':
    args = parser.parse_args()

    #generate_random_data(200, 'data\\', 'labels.csv')

    load_config('config.yaml')

    if args.train:
        model = create_model(max_length)
        model.compile(loss = 'binary_crossentropy', optimizer = 'adam', metrics = ['accuracy'])
        training(model)