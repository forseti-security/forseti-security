# Copyright 2017 The Forseti Security Authors. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Code skeleton for the Machine Learning module.

TODO: Add the architecture for model.

"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import numpy as np
import tensorflow as tf
import tensorflow.keras as keras
import tensorflow.keras.layers as layers
import tensorflow.keras.Model as Model


def autoencoder_model(input_shape):
  """
  The model function which computes the embedding.

  This is based on the implementation mentioned here:
  https://arxiv.org/pdf/1511.06335.pdf

  """
  input_layer = layers.Input(shape=input_shape)
  encoder_1 = layers.Dense(500, act='relu', name="encoder_1")(input_layer)
  encoder_2 = layers.Dense(500, act='relu', name="encoder_2")(encoder_1)
  encoder_3 = layers.Dense(2000, act='relu', name="encoder_3")(encoder_2)
  encoder_4 = layers.Dense(10, act='relu', name="encoder_4")(encoder_3)

  hidden = layers.Dense(10, act='relu', name="hidden")(encoder_4)

  decoder_1 = layers.Dense(10, act='relu', name="decoder_1")(hidden)
  decoder_2 = layers.Dense(2000, act='relu', name="decoder_2")(decoder_1)
  decoder_3 = layers.Dense(500, act='relu', name="decoder_3")(decoder_2)
  decoder_4 = layers.Dense(500, act='relu', name="decoder_4")(decoder_3)

  output_layer = layers.Dense(input_shape, name="output_layer")(decoder_4)
  model = Model(inputs=input_layer, outputs=output_layer)

  return model


def embedding_model(model):
  """
  Returns the Trained model which gives the embeddings as the output.

  """
  intermediate_model = model(
      inputs=[model.input],
      outputs=[model.get_layer("hidden").output])

  return intermediate_model

def get_embeddings(model, input):
  """
   Given an input , this returns the learnt embedding for it.

  """

  return model.predict(input)
