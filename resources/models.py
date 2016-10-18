import re
from acl import ACL
from pymongo.write_concern import WriteConcern
from pymodm import MongoModel, fields
import posixpath

def ValidateName(value):
    if ' ' in value:
        raise ValueError('Name can not contain spaces')

def ValidateUserPermissions(value):
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
        raise ValueError("Invalid user permissions specified: %s" % diff)

def ValidateProjectPaths(value):
    try:
        value['windows'] = posixpath.normpath(paths['windows'].replace('\\', '/'))
    except KeyError:
        raise ('Project path property requires windows property.')

class Schema(MongoModel):
    title = fields.CharField(min_length = 3, validators=[ValidateName])
    schema = fields.DictField(validators=[])
    expanded_schema = fields.DictField()
    modified = fields.DateTimeField()

    class Meta:
        connection_alias = 'fsapi-app'

class User(MongoModel):
    username = fields.CharField(min_length = 3, validators = [ValidateName])
    permissions = fields.ListField(validators = [ValidateUserPermissions])
    password = fields.CharField(min_length = 8)

    class Meta:
        connection_alias = 'fsapi-app'

class Project(MongoModel):
    title = fields.CharField(min_length=3, validators=[ValidateName])
    users = fields.ListField()
    acl_schema = fields.ReferenceField(Schema)
    paths = fields.DictField(validators=[ValidateProjectPaths])
    acl_expanded = fields.DictField()

    class Meta:
        connection_alias = 'fsapi-app'
