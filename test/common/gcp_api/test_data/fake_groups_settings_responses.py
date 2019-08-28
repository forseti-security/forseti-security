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

"""Test data for Group Settings GCP api responses."""

FAKE_EMAIL = 'groups_settings@foo.testing'
FAKE_DESCRIPTION = 'value used in test case'

GET_GROUPS_SETTINGS_RESPONSE = """
{
  "allowExternalMembers": "True", 
  "whoCanEnterFreeFormTags": "NONE", 
  "whoCanMarkDuplicate": "NONE", 
  "whoCanJoin": "ALL_IN_DOMAIN_CAN_JOIN", 
  "whoCanModifyTagsAndCategories": "OWNERS_AND_MANAGERS", 
  "whoCanMarkNoResponseNeeded": "NONE", 
  "whoCanUnmarkFavoriteReplyOnAnyTopic": "NONE", 
  "primaryLanguage": "en", 
  "whoCanMarkFavoriteReplyOnOwnTopic": "NONE", 
  "whoCanViewMembership": "ALL_IN_DOMAIN_CAN_VIEW", 
  "favoriteRepliesOnTop": "false",
  "whoCanMarkFavoriteReplyOnAnyTopic": "NONE", 
  "includeCustomFooter": "false",
  "defaultMessageDenyNotificationText": "",
  "includeInGlobalAddressList": "True",
  "archiveOnly": "false",
  "isArchived": "True",
  "membersCanPostAsTheGroup": "false",
  "allowWebPosting": "True",
  "email": "groups_settings@foo.testing",
  "whoCanAssignTopics": "NONE",
  "sendMessageDenyNotification": "false",
  "description": "value used in test case",
  "whoCanUnassignTopic": "NONE",
  "replyTo": "REPLY_TO_IGNORE",
  "customReplyTo": "",
  "messageModerationLevel": "MODERATE_NONE",
  "whoCanContactOwner": "ALL_IN_DOMAIN_CAN_CONTACT",
  "messageDisplayFont": "DEFAULT_FONT",
  "whoCanLeaveGroup": "ALL_MEMBERS_CAN_LEAVE",
  "whoCanAdd": "ALL_MANAGERS_CAN_ADD",
  "whoCanPostMessage": "ALL_IN_DOMAIN_CAN_POST",
  "whoCanTakeTopics": "NONE",
  "name": "Test Name",
  "kind": "groupsSettings",
  "whoCanInvite": "ALL_MANAGERS_CAN_INVITE",
  "spamModerationLevel": "MODERATE",
  "whoCanAddReferences": "ALL_MEMBERS",
  "whoCanViewGroup": "ALL_IN_DOMAIN_CAN_VIEW",
  "showInGroupDirectory": "True",
  "maxMessageBytes": 26214400,
  "customFooterText": "",
  "allowGoogleCommunication": "True"
}
"""

UNAUTHORIZED = """
{
 "error": {
  "errors": [
   {
    "domain": "global",
    "reason": "forbidden",
    "message": "Not Authorized to access this resource/api"
   }
  ],
  "code": 403,
  "message": "Not Authorized to access this resource/api"
 }
}
"""
