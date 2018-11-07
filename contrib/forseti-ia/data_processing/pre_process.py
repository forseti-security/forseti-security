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
import ipaddress
from google.cloud import bigquery

def dataToBQ(dataset_id,table_id,filename):

    # filename = '/path/to/file.csv'
    # dataset_id = 'my_dataset'
    # table_id = 'my_table'

    #client = bigquery.Client.from_service_account_json(
    #    "forseti_pycharm.json")
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
    #return l, len(l)
    return len(l)


def ip_extraction(x):
    """Pre process ip data.

    Args:
        ip address (string): An ip address with subnet as a string.

    Returns:
        ip: IP extracted from the network.
        supernet: Supernet Ip network form the available ip network.
    """
    l = []
    ip_add = ipaddress.IPv4Interface(x)
    ip_supernet = ipaddress.ip_network(u'192.0.2.0/23').supernet()
    return ip_add.ip, ip_supernet


def pre_process_firewall_data(resource_data_json):
    """Pre process resource data.

    Args:
        resource_data_json (list): A list of resource data in json format.
        selected_features (list): A list of selected features, if the
            list is empty, we will include all the features.

    Returns:
        DataFrame: DataFrame table with all the resource_data.
    """

    def subnet_count(ip_addr):
        """Covert ip address."""
        if ip_addr and '/' in ip_addr:
            _, subnet = ip_addr.split('/')
            return 10 * (32 - int(subnet))
        return -1

    df = pd.DataFrame(resource_data_json)

    df['creation_timestamp'] = df['creation_timestamp'].astype('category').cat.codes
    df['direction'] = df['direction'].astype('category').cat.codes
    df['action'] = df['action'].astype('category').cat.codes
    df['disabled'] = df['disabled'].astype('category').cat.codes
    df['ip_protocol'] = df['ip_protocol'].astype('category').cat.codes
    df['ports'] = df['ports'].astype('category').cat.codes

    df['source_subnet_count'] = df['source_ip_addr'].apply(subnet_count)
    source_ips = df['source_ip_addr'].str.split('/', expand=True)[0].str.split('.', expand=True)
    df['source_ip_offset_1'] = source_ips[0] if len(source_ips.columns) > 1 else ''
    df['source_ip_offset_1'] = df['source_ip_offset_1'].astype('category').cat.codes
    df['source_ip_offset_2'] = source_ips[1] if len(source_ips.columns) > 1 else ''
    df['source_ip_offset_2'] = df['source_ip_offset_2'].astype('category').cat.codes
    df['source_ip_offset_3'] = source_ips[2] if len(source_ips.columns) > 1 else ''
    df['source_ip_offset_3'] = df['source_ip_offset_3'].astype('category').cat.codes
    df['source_ip_offset_4'] = source_ips[3] if len(source_ips.columns) > 1 else ''
    df['source_ip_offset_4'] = df['source_ip_offset_4'].astype('category').cat.codes

    df['dest_subnet_count'] = df['dest_ip_addr'].apply(subnet_count)
    dest_ips = df['dest_ip_addr'].str.replace('/', '').str.split('.', expand = True)
    df['dest_ip_offset_1'] = dest_ips[0] if len(dest_ips.columns) > 1 else ''
    df['dest_ip_offset_1'] = df['dest_ip_offset_1'].astype('category').cat.codes
    df['dest_ip_offset_2'] = dest_ips[1] if len(dest_ips.columns) > 1 else ''
    df['dest_ip_offset_2'] = df['dest_ip_offset_2'].astype('category').cat.codes
    df['dest_ip_offset_3'] = dest_ips[2] if len(dest_ips.columns) > 1 else ''
    df['dest_ip_offset_3'] = df['dest_ip_offset_3'].astype('category').cat.codes
    df['dest_ip_offset_4'] = dest_ips[3] if len(dest_ips.columns) > 1 else ''
    df['dest_ip_offset_4'] = df['dest_ip_offset_4'].astype('category').cat.codes

    df = df.drop(columns=['source_ip_addr', 'dest_ip_addr', 'org_id'])

    #df['org_id'] = df['org_id'].astype('category').cat.codes
    #df['source_ip_addr'] = df['source_ip_addr'].astype('category').cat.codes
    #df['dest_ip_addr'] = df['dest_ip_addr'].astype('category').cat.codes

    df['service_account'] = df['service_account'].astype('category').cat.codes
    df['tag'] = df['tag'].astype('category').cat.codes
    df['full_name'] = df['full_name'].astype('category').cat.codes
    df['ip_protocol'] = df['ip_protocol'].astype('category').cat.codes
    df['network'] = df['network'].astype('category').cat.codes

    return df


if __name__ == '__main__':

    #print(ipaddress.ip_network(u'192.168.1.128/30').supernet(prefixlen_diff=2))
    #print(ip_extraction(u'192.168.1.128/30'))
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
            flattened_firewall_rules_dict)
        print(df_filtered.iloc[0])

        reduced_data = model.dimensionality_reduce(df_filtered, 2)

        df_filtered['source_ip_addr_exp'] = ""
        df_filtered['source_ips_count'] = ""
        
        df_filtered['dest_ip_addr_exp'] = ""
        df_filtered['dest_ips_count'] = ""
        
        #df_filtered[['source_ip_addr_exp','source_ips_count']] = df_filtered['source_ip_addr'].apply(lambda x: pd.Series([ip_extraction_list(x)[0],ip_extraction_list(x)[1]]))
        #df_filtered[['dest_ip_addr_exp','dest_ips_count']] = df_filtered['dest_ip_addr'].apply(lambda x: pd.Series([ip_extraction_list(x)[0],ip_extraction_list(x)[1]]))

        df_filtered['source_ips_count'] = df_filtered['source_ip_addr'].apply(lambda x: ip_extraction_list(x))
        df_filtered['dest_ips_count'] = df_filtered['dest_ip_addr'].apply(lambda x: ip_extraction_list(x))
        
        df_filtered[['source_ip','source_ip_supernet']] = df_filtered['source_ip_addr'].apply(lambda x: pd.Series([ip_extraction(x)[0],ip_extraction(x)[1]]))
        df_filtered[['dest_ip','dest_ip_supernet']] = df_filtered['dest_ip_addr'].apply(lambda x: pd.Series([ip_extraction(x)[0],ip_extraction(x)[1]]))
        
        df_filtered['source_ip'] = df_filtered['source_ip_addr'].apply(lambda x: ip_extraction(x))
        df_filtered['dest_ip'] = df_filtered['dest_ip_addr'].apply(lambda x: ip_extraction(x))

        df_filtered.to_csv(filename, sep='\t', encoding='utf-8')
        
        dataset_id = "forseti"
        table_id = "forseti_fw_rules_1"

        dataToBQ(dataset_id,table_id,filename)
