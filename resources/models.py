import re
from fs import ACL
from pymongo.write_concern import WriteConcern
from pymongo import errors as pymongo_errors
from pymodm import MongoModel, fields, context_managers
from pymodm import errors as pymodm_errors
import datetime
import posixpath
import ntpath
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
        if not posixpath.isabs(paths['linux']):
            raise pymodm_errors.ValidationError('Linux path must be absolute')
        else:
            paths['linux'] = posixpath.normpath(paths['linux'])
    except KeyError:
        raise pymodm_errors.ValidationError('Project paths property is missing linux propety.')

    try:
        if not posixpath.isabs(paths['darwin']):
            raise pymodm_errors.ValidationError('Darwin path must be absolute')
        else:
            paths['darwin']= posixpath.normpath(paths['darwin'])
    except KeyError:
        raise pymodm_errors.ValidationError('Project paths property is missing darwin property.')

    try:
        if not ntpath.isabs(paths['windows']):
            raise pymodm_errors.ValidationError('Windows path must be absolute')
        else:
            paths['windows'] = paths['windows'].replace('\\', '/')
    except KeyError:
        raise pymodm_errors.ValidationError('Project paths property is missing windows property.')


class Schema(MongoModel):
    name = fields.CharField(min_length = 3, validators=[ValidateName], required = True)
    schema = fields.DictField(required = True, validators=[ACL.ValidateDACLSchema])
    expanded_schema = fields.DictField()
    modified = fields.DateTimeField(required = True, default = datetime.datetime.now())

    ValidationError = pymodm_errors.ValidationError
    DuplicateKeyError = pymongo_errors.DuplicateKeyError

    class Meta:
        connection_alias = 'fsapi-app'

    def clean(self):
        self.expanded_schema = {}
        ACL.GetExpandedDACL(self.schema, self.expanded_schema)

    def to_dict(self):
        return {
                "name": self.name,
                "schema": self.schema,
                "modified": self.modified.isoformat(),
                "_id": str(self._id)
        }

class User(MongoModel):
    username = fields.CharField(min_length = 3, validators = [ValidateName], required = True, unique = True)
    permissions = fields.ListField(validators = [ValidateUserPermissions], required = True)
    password = fields.CharField(min_length = 8, required = True)
    auth_b64 = fields.CharField(min_length = 11, required = True, unique = True)
    valid_permissions = [
        'createUser',
        'deleteUser',
        'createProject',
        'deleteProject',
        'createFile',
        'setACL',
        'createACLSchema',
        'deleteACLSchema'
    ]
    ValidationError = pymodm_errors.ValidationError
    DuplicateKeyError = pymongo_errors.DuplicateKeyError
    class Meta:
        connection_alias = 'fsapi-app'

    def clean(self):
        auth = User.GetAuthBase64(self.username, self.password)
        if self.auth_b64 != auth:
            raise pymodm_errors.ValidationError('auth_b64 must be a base64 encoded string of username:password.')
    @staticmethod
    def GetAuthBase64(username, password):
        return base64.b64encode("%s:%s" % (username, password))

    def to_dict(self):
        return {
            'username': self.username,
            'permissions': self.permissions,
            '_id': str(self._id)
        }

class Project(MongoModel):
    name = fields.CharField(min_length=3, validators=[ValidateName], required = True)
    users = fields.ListField(fields.ReferenceField(User, on_delete = fields.ReferenceField.PULL), required = True)
    acl_schema = fields.ReferenceField(Schema, required = True, on_delete = fields.ReferenceField.DENY)
    paths = fields.DictField(validators=[ValidateProjectPaths], required = True)
    acl_expanded = fields.DictField()
    acl_expanded_depth = fields.DictField()

    ValidationError = pymodm_errors.ValidationError
    DuplicateKeyError = pymongo_errors.DuplicateKeyError

    class Meta:
        connection_alias = 'fsapi-app'

    def clean(self):
        self.acl_expanded = ACL.GetProjectSchema(self.acl_schema.expanded_schema, self.paths)
        self.acl_expanded_depth = ACL.GetProjectSchemaDepth(self.acl_expanded)

    def to_dict(self):
        user_ids = []
        for x in range(len(self.users)):
            user_ids.append(str(self.users[x]._id))
        return {
            'id': str(self._id),
            'name': self.name,
            'users': user_ids,
            'acl_schema': str(self.acl_schema._id),
            'paths': self.paths,
            'acl_expanded': self.acl_expanded
        }
