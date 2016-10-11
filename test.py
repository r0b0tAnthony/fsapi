from user.user import user
from acl.aclschema import aclSchema
import json
import pprint
newUser = user('anthony', ['createProject', 'deleteProject', ])
print newUser.getPermissions()

newUser2 = user('tommy', ['deleteProject'], 'fhs8j2jahnvs')
print newUser2.getPermissions()
if newUser2.getPermission('createProject'):
    print 'Can CreateProject'
else:
    print 'Cant CreateProject'

perm_fo = open('./foobar.json', 'r')
perm_obj = json.load(perm_fo)

schema = aclSchema('schema01', perm_obj)
for key, value in schema.getDACL().iteritems():
    pprint.pprint(key)
    acl = value['acl']
    pprint.pprint(acl.getACL())
pprint.pprint(schema.getExpandedDACL())
