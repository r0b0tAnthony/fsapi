import re
from acl import ACL
from pymongo.write_concern import WriteConcern
from pymodm import MongoModel, fields
from pymodm import errors as pymodm_errors
import posixpath
import pprint
import base64

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
        raise pymodm_errors.ValidationError("Invalid user permissions specified: %s" % diff)

def ValidateProjectPaths(paths):
    try:
        paths['linux'] = posixpath.abspath(paths['linux'])
    except KeyError:
        raise pymodm_errors.ValidationError('Project paths property is missing linux propety.')

    try:
        paths['darwin'] = posixpath.abspath(paths['darwin'])
    except KeyError:
        raise pymodm_errors.ValidationError('Project paths property is missing darwin property.')

    try:
        paths['windows'] = posixpath.normpath(paths['windows'].replace('\\', '/'))
    except KeyError:
        raise pymodm_errors.ValidationError('Project paths property is missing windows property.')

class Schema(MongoModel):
    title = fields.CharField(min_length = 3, validators=[ValidateName], required = True)
    schema = fields.DictField(required = True, validators=[ACL.ValidateDACLSchema])
    expanded_schema = fields.DictField()
    modified = fields.DateTimeField(required = True)

    class Meta:
        connection_alias = 'fsapi-app'

class User(MongoModel):
    username = fields.CharField(min_length = 3, validators = [ValidateName], required = True)
    permissions = fields.ListField(validators = [ValidateUserPermissions], required = True)
    password = fields.CharField(min_length = 8, required = True)
    auth_b64 = fields.CharField(min_length = 11)

    class Meta:
        connection_alias = 'fsapi-app'

    def clean(self):
        auth = base64.b64encode("%s:%s" % (self.username, self.password))
        if self.auth_b64 != auth:
            raise pymodm_errors.ValidationError('auth_b64 must be a base64 encoded string of username:password.')

class Project(MongoModel):
    title = fields.CharField(min_length=3, validators=[ValidateName], required = True)
    users = fields.ReferenceField(User, required = True)
    acl_schema = fields.ReferenceField(Schema, required = True)
    paths = fields.DictField(validators=[ValidateProjectPaths], required = True)
    acl_expanded = fields.DictField()

    class Meta:
        connection_alias = 'fsapi-app'
