import utils
# import pdb

# run_command = utils.run_command
# #
# return_code, out, _ = run_command(
#     ['git', 'describe', '--tags', '--exact-match'],
#     number_of_retry=0,
#     suppress_output=True)
#
#
#     segments = curr_tag.split('.')
#     if len(segments) != 3:
#         return curr_tag
#     # patch_query = (".").join(segments[:2]) + ".{[0-9],[0-9][0,9]}" #make query of everything up to and excluding the patch
#     patch_query = (".").join(segments[:2]) + "[0-9][0-9]"
#     if segments[2][1].isdigit(): #add everything after the patch number to query
#         patch_query += segments[2][2:]
#         latest_version = (curr_tag, int(segments[2][1][:2]))
#     else:
#         patch_query += segments[2][1:]
#         latest_version = (curr_tag, int(segments[2][1][:1]))
#
#     return_code, out, _ = run_command( #run query for matches and find latest version
#         ['git', 'tag', '-l', tag_query],
#         number_of_retry=0,
#         suppress_output=False)
#     matches = out.split("\n")[:-1]
#     for match in matches:
#         patch = match.split(".")[2][:2]
#         if len(patch) > 1 and not patch[1].isdigit():
#             patch = patch[0]
#         if int(patch) > latest_version[1]:
#             latest_version = (match, int(patch))
#
#     return latest_version[0]

#try to get opti


# tag_query = "v1.0.{[0-9],[0-9][0,9]}" #needs to denote end of line  if nothing

# tag_query = "v1.1.{[0-9],[0-9][0,9]}" #needs to denote end of line  if nothing


#
# tag_query = "v1.1.{[0-9],[0-9][0-9]}" #needs to denote end of line  if nothing
#
# latest_version = ("v1.0.1", 1) #delete
# return_code, out, _ = run_command(
#     ['git', 'tag', '-l', tag_query],
#     number_of_retry=0,
#     suppress_output=False)
# matches = out.split("\n")[:-1]
# for match in matches:
#     pdb.set_trace()
#     patch = match.split(".")[2][:2]
#     if len(patch) > 1 and not patch[1].isdigit():
#         patch = patch[0]
#     if int(patch) > latest_version[1]:
#         latest_version = (match, int(patch))
#
#
# pdb.set_trace()

version = utils.get_forseti_version()
pdb.set_trace()

#TODO
#handle v1.0

# strs = ["v1.1.10", "v1.1.1", "v1.0.3-pre"]
# if len(segments) != 3:
#     return curr_tag
#
#
#
#
# if 3rd segment len <
#
# query accordingly, split the 3rd segment, slice it length 2, and get max on that

