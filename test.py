from resources import models
from resources.acl import ACL
import json
import pprint
from pymodm import connect
from bson.objectid import ObjectId
import datetime

perm_fo = open('./foobar.json', 'r')
perm_obj = json.load(perm_fo)
'''
pprint.pprint(perm_obj)
ACL.ValidateDACLSchema(perm_obj)
pprint.pprint(perm_obj)
expanded_schema = {}
ACL.GetExpandedDACL(perm_obj, expanded_schema)
pprint.pprint(expanded_schema)
'''

connect("mongodb://localhost:27017/fsapi", alias='fsapi-app')
user1 = models.User(username = 'eaaj', password = 'fksh9ks8', permissions = ['createProject'])
user1.save()
user2 = models.User(username = '5fjdjdj', password = 'jf9n38fjsja', permissions = ['deleteProject', 'deleteUser'])
user2.save()
schema = models.Schema(title ='Moo', schema = perm_obj, modified=datetime.datetime.now()).save()
expanded_schema = {}
ACL.GetExpandedDACL(schema.schema, expanded_schema)
schema.expanded_schema = expanded_schema
schema.save()

project = models.Project(title = 'tvshow', paths = {'windows': 'C:\\Meow\\Woof', 'linux': '/foo/bar', 'darwin': '/Volumes/foo/bar'}, users = [user1.to_son(), user2.to_son()], acl_schema = ObjectId()).save()
expanded_project = ACL.GetProjectSchema(schema.expanded_schema, project.paths)
project.acl_expanded = expanded_project
print project._id
project.save()
print project._id
print 'Expanded'
pprint.pprint(project.acl_expanded)
