from user.user import user
from acl.aclschema import aclSchema
from project.project import project
import json
import pprint
import posixpath
newUser = user('anthony', ['createProject', 'deleteProject'], None, 13393583401)
print newUser.getPermissions()

newUser2 = user('tommy', ['deleteProject'], 'fhs8j2jahnvs', 35097091740270)
print newUser2.getPermissions()
if newUser2.getPermission('createProject'):
    print 'Can CreateProject'
else:
    print 'Cant CreateProject'

perm_fo = open('./foobar.json', 'r')
perm_obj = json.load(perm_fo)

schema = aclSchema('schema01', perm_obj, 45823058208)
for key, value in schema.getDACL().iteritems():
    pprint.pprint(key)
    acl = value['acl']
    pprint.pprint(acl.getACL())
pprint.pprint(schema.getExpandedDACL())

newProject = project('Project02',
    {'linux': '/mnt/JOBS/16002_MR_ROBOT', 'darwin': '/volumes/JOBS/16002_MR_ROBOT', 'windows': "\\\\server01\\JOBS\\16002_MR_ROBOT"},
    [newUser, newUser2],
    schema
)
pprint.pprint(newProject.getExpandedSchema())
