from resources import models
from acl.acl import ACL
import json
import pprint
from pymodm import connect
from user.user import UserModel
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

project = models.Project(title = 'tvshow', paths = {'windows': 'C:\\Meow\\Woof'}, users = ['fsjfjs921929', '9jf92jfjslf'], acl_schema = ObjectId(), acl_expanded = {'woof': 'meow'}).save()
print project._id
pprint.pprint(project.paths)

schema = models.Schema(title ='Moo', schema = perm_obj, expanded_schema={'woof': 'meow'}, modified=datetime.datetime.now()).save()
