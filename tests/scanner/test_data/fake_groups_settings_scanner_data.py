# Copyright 2018 The Forseti Security Authors. All rights reserved.
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
"""Groups Settings data to be used in the unit tests."""

import json

SETTINGS_1 = {
	'group_name': 'group/settings1@testing.com',
	'settings': json.dumps({
		 "allowExternalMembers": "true","whoCanViewMembership": "ALL_IN_DOMAIN_CAN_VIEW", 
		 "email": "settings1@testing.com","whoCanLeaveGroup": "ALL_MEMBERS_CAN_LEAVE", 
		 "whoCanAdd": "ALL_MANAGERS_CAN_ADD", "whoCanJoin": "INVITED_CAN_JOIN",  
		 "whoCanInvite": "ALL_MANAGERS_CAN_INVITE", "type": "SETTINGS", 
		"whoCanViewGroup": "ALL_IN_DOMAIN_CAN_VIEW", })
}


SETTINGS_2 = {
	'group_name': 'group/settings2@testing.com',
	'settings': json.dumps({
		 "allowExternalMembers": "true","whoCanViewMembership": "ALL_IN_DOMAIN_CAN_VIEW", 
		 "email": "settings2@testing.com","whoCanLeaveGroup": "ALL_MEMBERS_CAN_LEAVE", 
		 "whoCanAdd": "ALL_MANAGERS_CAN_ADD", "whoCanJoin": "ALL_IN_DOMAIN_CAN_JOIN",  
		 "whoCanInvite": "ALL_MANAGERS_CAN_INVITE", "type": "SETTINGS", 
		"whoCanViewGroup": "ALL_IN_DOMAIN_CAN_VIEW", })
}

SETTINGS_3 = {
	'group_name': 'group/non_wildcard@test.com',
	'settings': json.dumps({
		 "allowExternalMembers": "true","whoCanViewMembership": "ALL_IN_DOMAIN_CAN_VIEW", 
		 "email": "non_wildcard@test.com","whoCanLeaveGroup": "ALL_MEMBERS_CAN_LEAVE", 
		 "whoCanAdd": "ALL_MANAGERS_CAN_ADD", "whoCanJoin": "ALL_IN_DOMAIN_CAN_JOIN",  
		 "whoCanInvite": "ALL_MANAGERS_CAN_INVITE", "type": "SETTINGS", 
		"whoCanViewGroup": "ALL_IN_DOMAIN_CAN_VIEW", })
}

SETTINGS_4 = {
	'group_name': 'group/non_wildcard2@test.com',
	'settings': json.dumps({
		 "allowExternalMembers": "true","whoCanViewMembership": "ALL_IN_DOMAIN_CAN_VIEW", 
		 "email": "non_wildcard2@test.com","whoCanLeaveGroup": "ALL_MEMBERS_CAN_LEAVE", 
		 "whoCanAdd": "ALL_MANAGERS_CAN_ADD", "whoCanJoin": "ALL_IN_DOMAIN_CAN_JOIN",  
		 "whoCanInvite": "ALL_MANAGERS_CAN_INVITE", "type": "SETTINGS", 
		"whoCanViewGroup": "ANYONE_CAN_VIEW", })
}

SETTINGS_5 = {
	'group_name': 'group/settings5@testing.com',
	'settings': json.dumps({
		 "allowExternalMembers": "true","whoCanViewMembership": "ALL_IN_DOMAIN_CAN_VIEW", 
		 "email": "settings5@testing.com","whoCanLeaveGroup": "NONE_CAN_LEAVE", 
		 "whoCanAdd": "ALL_MANAGERS_CAN_ADD", "whoCanJoin": "ALL_IN_DOMAIN_CAN_JOIN",  
		 "whoCanInvite": "ALL_MANAGERS_CAN_INVITE", "type": "SETTINGS", 
		"whoCanViewGroup": "ANYONE_CAN_VIEW", })
}

SETTINGS = [SETTINGS_1, SETTINGS_2, SETTINGS_3, SETTINGS_4, SETTINGS_5]
