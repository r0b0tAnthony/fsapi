from pymongo.write_concern import WriteConcern
from pymodm import MongoModel, fields

import re

def ValidateUsername(value):
    if ' ' in value:
        raise ValueError('Username can not contain spaces')

def ValidatePermissions(value):
    permissions = [
        'createUser',
        'deleteUser',
        'createProject',
        'deleteProject',
        'createFile',
        'setACL',
        'createACLSchema',
        'deleteACLSchema'
    ]

    diff = list(set(value) - set(permissions))

    if len(diff) > 0:
        raise ValueError("Invalid permissions specified: %s" % diff)

class UserModel(MongoModel):
    username = fields.CharField(min_length = 3, validators = [ValidateUsername])
    permissions = fields.ListField(validators = [ValidatePermissions])
    password = fields.CharField(min_length = 8)

    class Meta:
        connection_alias = 'fsapi-app'
