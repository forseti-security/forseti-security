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

FAKE_EMAIL = "test_email@gmail.com"

GET_GROUP_SETTINGS_RESPONSE = """
{
  u'allowExternalMembers': u'true', 
  u'whoCanEnterFreeFormTags': u'NONE', 
  u'whoCanMarkDuplicate': u'NONE', 
  u'whoCanJoin': u'ALL_IN_DOMAIN_CAN_JOIN', 
  u'whoCanModifyTagsAndCategories': u'OWNERS_AND_MANAGERS', 
  u'whoCanMarkNoResponseNeeded': u'NONE', 
  u'whoCanUnmarkFavoriteReplyOnAnyTopic': u'NONE', 
  u'primaryLanguage': u'en', 
  u'whoCanMarkFavoriteReplyOnOwnTopic': u'NONE', 
  u'whoCanViewMembership': u'ALL_IN_DOMAIN_CAN_VIEW', 
  u'favoriteRepliesOnTop': u'false',
  u'whoCanMarkFavoriteReplyOnAnyTopic': u'NONE', 
  u'includeCustomFooter': u'false',
  u'defaultMessageDenyNotificationText': u'',
  u'includeInGlobalAddressList': u'true',
  u'archiveOnly': u'false',
  u'isArchived': u'true',
  u'membersCanPostAsTheGroup': u'false',
  u'allowWebPosting': u'true',
  u'email': u'my_account@gmail.com',
  u'whoCanAssignTopics': u'NONE',
  u'sendMessageDenyNotification': u'false',
  u'description': u'',
  u'whoCanUnassignTopic': u'NONE',
  u'replyTo': u'REPLY_TO_IGNORE',
  u'customReplyTo': u'',
  u'messageModerationLevel': u'MODERATE_NONE',
  u'whoCanContactOwner': u'ALL_IN_DOMAIN_CAN_CONTACT',
  u'messageDisplayFont': u'DEFAULT_FONT',
  u'whoCanLeaveGroup': u'ALL_MEMBERS_CAN_LEAVE',
  u'whoCanAdd': u'ALL_MANAGERS_CAN_ADD',
  u'whoCanPostMessage': u'ALL_IN_DOMAIN_CAN_POST',
  u'whoCanTakeTopics': u'NONE',
  u'name': u'Data Scientists',
  u'kind': u'groupsSettings#groups',
  u'whoCanInvite': u'ALL_MANAGERS_CAN_INVITE',
  u'spamModerationLevel': u'MODERATE',
  u'whoCanAddReferences': u'ALL_MEMBERS',
  u'whoCanViewGroup': u'ALL_IN_DOMAIN_CAN_VIEW',
  u'showInGroupDirectory': u'true',
  u'maxMessageBytes': 26214400,
  u'customFooterText': u'',
  u'allowGoogleCommunication': u'true'}
"""