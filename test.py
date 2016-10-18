from acl.acl import ACL
import json
import pprint

perm_fo = open('./foobar.json', 'r')
perm_obj = json.load(perm_fo)

pprint.pprint(perm_obj)
ACL.ValidateDACLSchema(perm_obj)
pprint.pprint(perm_obj)
