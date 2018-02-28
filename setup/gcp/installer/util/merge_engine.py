# Copyright 2017 The Forseti Security Authors. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Merge engine."""


def merge_object(merge_from, merge_to,
                 fields_to_ignore=None, field_identifiers=None):
    """Merge objects (dictionary/list of dictionaries).

    Note: merge_to will be modified during the merge process.

    High level overview:
    If you have 2 dictionaries, A and B.
    A = {a: a_val, a1: a1_val}, B = {a: a_val_prime, a2: a2_val}
    And by doing merge_object(A, B)
    You will get A = {a: a_va1_prime, a1: a1_val, a2: a2_val}
    You are able to selectively ignore some of the fields,
    e.g. merge_object(A, B, fields_to_ignore=['a', 'a2'])
    This will prevent field 'a' from getting modified during the merge
    process and will also prevent field 'a2' from merging into the
    base_obect (A). The result of this would be A = {a: a_val, a1: a1_val}
    Note that B, the target object will not be modified.

    If you have 2 lists of dictionaries, A and B
    A = [{id: a0, val: a0_val}, {id: a1, val: a1_val}]
    B = [{id: a0, val: a0_val_prime}, {id: b, val: b_val}]
    And by doing merge_object(A, B)
    You will get
    A = [{id: a0, val: a0_val}, {id: a1, val: a1_val},
    {id: a0, val: a0_val_prime}, {id: b, val: b_val}]
    It didn't merge based on 'id' as you expect it to do because
    we haven't specified an identifier for the list of dictionaries yet so
    the function is not able to identify them based on the field 'id'.
    We can do so by passing in field_identifiers,
    e.g. merge(A, B, field_identifiers={'default_identifier': 'id'})
    and by doing so, you will get A = [{id: a0, val: a0_val_prime},
    {id: a1, val: a1_val}, {id: b, val: b_val}] as expected.

    You are able to merge nested lists/dictionaries, the way can you define
    field_identifiers to handle this situation is to utilize the key of
    the key, value pairs inside the dictionary.
    E.g. if you have two dictionaries that look like the following:

    {
        rules:
            - id: 'rule_id'
              description: 'rule_description'
            - id: 'rule_id1'
              description: 'rule_description1'
            - id: 'rule_id2'
              description: 'rule_description2'
    }

    {
        rules:
            - id: 'rule_id1'
              description: 'rule_description1_prime'
            - id: 'rule_id2'
              description: 'rule_description2_prime'
            - id: 'rule_id3'
              description: 'rule_description3_prime'
    }

    And you would like the field 'id' to act as the identifier during the
    merge process, you need to define the field_identifiers like this
    field_identifiers=['rules': 'id'], which is same as saying 'rules' is a
    list of dictionaries, and the identifier of those dictionaries is 'id'.

    You can also define multiple identifiers for one field, the function
    will look for the one that is inside the dictionary object and use that
    as the identifier.

    E.g.
    field_identifiers=['rules': ['id', 'name']] works for both
    {
        rules:
            - id: 'rule_id1'
              description: 'rule_description1_prime'
    }
    and
    {
        rules:
            - name: 'rule_id1'
              description: 'rule_description1_prime'
    }

    Args:
        merge_from (object): Object merging from.
        merge_to (object): Object merging to.
        fields_to_ignore (list): Fields to ignore (keep in base_dict).
        field_identifiers (dict): Identifiers for fields.

    Raises:
          FormatNotSupported: Format not supported.
    """
    class FormatNotSupported(Exception):
        """Format not supported exception."""
        pass

    # Init default values for fields_to_ignore and field_identifiers
    # if they don't already exists.
    if fields_to_ignore is None:
        fields_to_ignore = []
    if field_identifiers is None:
        field_identifiers = {}

    if isinstance(merge_to, list) and isinstance(merge_from, list):
        identifier = field_identifiers.get('default_identifier')
        merge_dict_list(merge_from, merge_to, identifier,
                        fields_to_ignore, field_identifiers)
    elif isinstance(merge_to, dict) and isinstance(merge_from, dict):
        merge_dict(merge_from, merge_to, fields_to_ignore, field_identifiers)
    else:
        raise FormatNotSupported(
            'Merging {} and {} is not supported'.format(
                type(merge_to), type(merge_from)))


def merge_dict(merge_from_dict, merge_to_dict,
               fields_to_ignore, field_identifiers):
    """Merge target_dict into base_dict.

    Note: merge_to_dict will be modified during the merge process.

    Args:
        merge_from_dict (dict): Dictionary merging from.
        merge_to_dict (dict): Dictionary merging to.
        fields_to_ignore (list): Fields to ignore (keep in base_dict).
        field_identifiers (dict): Identifiers for fields.
    """

    for key, val in merge_to_dict.iteritems():
        if key in merge_from_dict:
            # If merge_from_dict has the same key, we check if the value is
            # an instance of dictionary. If it is we merge recursively and
            # if it's not, we do a simple replace if the key is not in
            # fields_to_ignore.
            if key in fields_to_ignore:
                continue
            if isinstance(val, dict):
                merge_dict(merge_from_dict.get(key), val,
                           fields_to_ignore, field_identifiers)
            elif isinstance(val, list) and val and isinstance(val[0], dict):
                # If the list has at least one item, we check for the type
                # of the first item, if it's a dictionary, we invoke
                # merge_dict_list.
                identifier = field_identifiers.get(key)
                if isinstance(identifier, list):
                    identifier = _select_identifier(identifier, val[0])
                merge_dict_list(merge_from_dict.get(key), val, identifier,
                                fields_to_ignore, field_identifiers)
            else:
                merge_to_dict[key] = merge_from_dict.get(key)

    for key, val in merge_from_dict.iteritems():
        if key not in merge_to_dict and key not in fields_to_ignore:
            # If this is a key we have only in target but not in base, we add
            # it to the base_dict.
            merge_to_dict[key] = val


def _select_identifier(identifiers, dict_to_identify):
    """Select the right field identifier.

    Args:
        identifiers (list): List of identifiers.
        dict_to_identify (dict): Dictionary to identify.

    Returns:
        str: Identifier.
    """

    for identifier in identifiers:
        if identifier in dict_to_identify:
            return identifier
    return ''


def merge_dict_list(merge_from_dicts, merge_to_dicts, identifier,
                    fields_to_ignore, field_identifiers):
    """Merge target_dict_list into base_dict_list.

    Note: merge_to_dict_list will be modified during the merge process.

    Args:
        merge_from_dicts (list): Base dictionary.
        merge_to_dicts (list): Target dictionary.
        identifier (str): Current field identifier.
        fields_to_ignore (list): Fields to ignore (keep in base_dict).
        field_identifiers (dict): Identifiers for fields.
    """

    contains_identifier = False

    if merge_to_dicts:
        # If merge_to_dict_list is not empty, check if the dictionary object
        # inside contains the identifier.
        contains_identifier = identifier in merge_to_dicts[0]
    if merge_from_dicts:
        # If merge_from_dict_list is not empty, check if the dictionary object
        # inside contains the identifier.
        contains_identifier = contains_identifier and (
            identifier in merge_from_dicts[0])

    if not identifier or not contains_identifier:
        # Doesn't have an identifier, replace the new list with the old list.
        del merge_to_dicts[:]
        merge_to_dicts.extend(merge_from_dicts)
        return

    # Sort both merge_from_dict_list and merge_to_dict_list by the identifier.
    merge_to_dicts.sort(key=lambda k: k[identifier])
    merge_from_dicts.sort(key=lambda k: k[identifier])

    # Merge them.
    merge_to_counter = 0
    merge_from_counter = 0
    max_items = len(merge_to_dicts) + len(merge_from_dicts)
    for _ in range(0, max_items):
        cur_merge_to_dict = (
            None if len(merge_to_dicts) <= merge_to_counter
            else merge_to_dicts[merge_to_counter])
        cur_merge_from_dict = (
            None if len(merge_from_dicts) <= merge_from_counter
            else merge_from_dicts[merge_from_counter])
        if merge_from_counter >= len(merge_from_dicts):
            break
        elif (merge_to_counter >= len(merge_to_dicts) or
              cur_merge_to_dict[identifier] > cur_merge_from_dict[identifier]):
            # cur_target_object only exists in merge_from_dict_list,
            # add it to merge_to_dict_list, increment target_counter.
            merge_to_dicts.append(cur_merge_from_dict)
            merge_from_counter += 1
        elif cur_merge_to_dict[identifier] < cur_merge_from_dict[identifier]:
            # cur_base_dict object only exists in merge_to_dict_list,
            # increment base_counter.
            merge_to_counter += 1
        else:
            # They have the same identifier, merge them,
            # increment both counters.
            merge_dict(cur_merge_from_dict, cur_merge_to_dict,
                       fields_to_ignore, field_identifiers)
            merge_to_counter += 1
            merge_from_counter += 1
