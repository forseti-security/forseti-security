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

import pandas as pd
#from google.cloud import bigquery
import ipaddress

def dataToBQ(dataset_id,table_id,filename):

    # filename = '/path/to/file.csv'
    # dataset_id = 'my_dataset'
    # table_id = 'my_table'

    client = bigquery.Client()
    dataset_ref = client.dataset(dataset_id)
    table_ref = dataset_ref.table(table_id)
    job_config = bigquery.LoadJobConfig()
    job_config.source_format = bigquery.SourceFormat.CSV
    job_config.skip_leading_rows = 1
    job_config.autodetect = True

    with open(filename, 'rb') as source_file:
        job = client.load_table_from_file(
            source_file,
            table_ref,
            location='US',  # Must match the destination dataset location.
            job_config=job_config)  # API request

    job.result()  # Waits for table load to complete.

    print('Loaded {} rows into {}:{}.'.format(
        job.output_rows, dataset_id, table_id))

def ip_extraction_list(x):

    """Pre process ip data.
    
    Args:
        ip address (string): An ip address with subnet as a string.

    Returns:
        list: List of all the ip_addresses in that range.
        integer: Length of the list (means count of ip_addresses in the range)
    """
    l = []
    sub_net = ipaddress.ip_network(x)
    for subnet in sub_net:
        l.append(subnet)
    print(len(l))

    return l, len(l)


def pre_process_firewall_data(resource_data_json,
                              selected_features):
    """Pre process resource data.

    Args:
        resource_data_json (list): A list of resource data in json format.
        selected_features (list): A list of selected features, if the
            list is empty, we will include all the features.

    Returns:
        DataFrame: DataFrame table with all the resource_data.
    """

    df = pd.DataFrame(resource_data_json)

    existing_columns = df.columns

    new_columns = list(set(existing_columns).intersection(selected_features))
    df['creation_timestamp'] = df['creation_timestamp'].astype('category').cat.codes
    df['direction'] = df['direction'].astype('category').cat.codes
    df['action'] = df['action'].astype('category').cat.codes
    df['disabled'] = df['disabled'].astype('category').cat.codes
    df['ip_protocol'] = df['ip_protocol'].astype('category').cat.codes
    df['ports'] = df['ports'].astype('category').cat.codes
    df['source_ip_addr'] = df['source_ip_addr'].astype('category').cat.codes
    df['dest_ip_addr'] = df['dest_ip_addr'].astype('category').cat.codes
    df['service_account'] = df['service_account'].astype('category').cat.codes
    df['tag'] = df['tag'].astype('category').cat.codes
    df['full_name'] = df['full_name'].astype('category').cat.codes
    df['ip_protocol'] = df['ip_protocol'].astype('category').cat.codes
    df['network'] = df['network'].astype('category').cat.codes

    df = df[new_columns]

    return df


if __name__ == '__main__':
    import json
    from os import sys, path
    import sys
    sys.path.append(path.dirname(path.dirname(path.abspath(__file__))))

    from resources.firewall_rule import FirewallRule

    with open('../sample_datasets/dataset_firewall.json') as firewall_dataset:
        firewall_rules = json.load(firewall_dataset)

        flattened_firewall_rules = FirewallRule.flatten_firewall_rules(firewall_rules)

        flattened_firewall_rules_dict = [i.to_dict() for i in flattened_firewall_rules]

        dataset_id = "forseti"
        table_id = "forseti_fw_rules"


        import machine_learning.model as model

        df_filtered = pre_process_firewall_data(
            flattened_firewall_rules_dict,
            ['creation_timestamp',
             'source_ip_addr',
             'dest_ip_addr',
             'service_account',
             'tag',
             'full_name',
             'action',
             'ip_protocol',
             'ports',
             'direction',
             'disabled',
             'network'])
        print(df_filtered.iloc[0])

        reduced_data = model.dimensionality_reduce(df_filtered, 2)

        model.visualize_2d(reduced_data, ['pca1', 'pca2'])

        m = model.k_means(reduced_data, 3, max_iter=100, seed=0)

        print (m)
