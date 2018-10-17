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

        df_filtered = pre_process_firewall_data(
            flattened_firewall_rules_dict,
            ['creation_timestamp',
             'source_ip_addr',
             'dest_ip_addr',
             'service_account',
             'tag',
             'org_id',
             'full_name',
             'action',
             'ip_protocol',
             'ports',
             'direction',
             'disabled',
             'network'])
        print df_filtered.iloc[0]
