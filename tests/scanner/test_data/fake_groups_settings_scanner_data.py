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

