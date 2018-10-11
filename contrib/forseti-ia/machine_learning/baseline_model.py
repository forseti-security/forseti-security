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
import pandas as pd
from google.cloud import bigquery as bq
from google.cloud.bigquery import Client
from sklearn import datasets
from sklearn.ensemble import RandomForestRegressor
from sklearn.model_selection import train_test_split
from sklearn import metrics


def rf(train_features, train_labels):
  """
  Returns the random forest model.

  """
  # Instantiate model with 1000 decision trees
  rf = RandomForestRegressor(n_estimators = 1000, random_state = 42)
  
  # Train the model on training data
  model = rf.fit(train_features, train_labels)
  
  return model

def data_prep(data):
    """
    Returns engineered data from raw data. Features and Labels has been returned as two separate dataframes.
    """
    data['direction'] = data['direction'].astype('category').cat.codes
    data['action'] = data['action'].astype('category').cat.codes
    data['disabled'] = data['disabled'].astype('category').cat.codes
    data['ip_protocol'] = data['ip_protocol'].replace('i','icmp')
    data['ip_protocol'] = data['ip_protocol'].replace('u','udp')
    data['ip_protocol'] = data['ip_protocol'].replace('t','tcp')
    data['ports'] = data['ports'].replace('[','')
    data['ports'] = data['ports'].replace(']','')
    data = data.loc[data['ip_protocol'].isin(['icmp','tcp','udp'])]
    data['ip_protocol'] = data['ip_protocol'].astype('category').cat.codes
    data['ports'] = data['ports'].astype('category').cat.codes

    # Splitting Features and labels
    labels = data['action']
    
    # drop the labels from the features
    features = data.drop(['action', 'ip_addr','identifier','int64_field_0'], axis = 1)
    
    return features, labels

if __name__ == '__main__':
  
    bigquery_client = bq.Client()
    data = bigquery_client.query("""
    select * from `forseti-ia.forseti_ml.sample_data`""").to_dataframe()
    
    # Data split for training and testing
    X,Y = data_prep(data)    
    train_features, test_features, train_labels, test_labels = train_test_split(X, Y, test_size = 0.25, random_state = 42)

    # Train model_selection
    model = rf(train_features, train_labels)
    
    # predeiction from RF
    predictions = model.predict(test_features)
    print("Accuracy:",metrics.accuracy_score(test_labels, predictions.round()))

    # Feature importance
    feature_importances = pd.DataFrame(model.feature_importances_,index = train_features.columns, columns=['importance']).sort_values('importance',ascending=False)
    print(feature_importances)
