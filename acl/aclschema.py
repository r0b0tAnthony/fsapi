import re
from . import acl
import pprint
import posixpath as path

class aclSchema:
    def __init__(self, name, dacl, schema_id = None):
        self.setName(name)
        self.schema = {}
        self.setDACL(dacl, self.schema)
        self.expanded_schema = {}
        self.setExpandedDACL(self.schema, self.expanded_schema)
        if schema_id is not None:
            self.setId(schema_id)

    def setName(self, name):
        if len(name) > 3:
            if re.match(r'^[\w]+$', name):
                self.name = name
            else:
                print "'%s'" % name
                raise ValueError('ACLSchema name must contain only alphanumeric, underscores, or dashes.')
        else:
            raise ValueError('ACLSchema name must be more than 3 characters.')

    def getName(self):
        return self.name

    def setId(self, schema_id):
        if schema_id > 0:
            self.id = schema_id

    def getId(self):
        return self.id

    def setDACL(self, dacl, schema):
        for key in dacl:
            currentacl = dacl[key]
            schema[key] = {}
            schema[key]['acl'] = acl.ACL(currentacl['type'], currentacl['owner'], currentacl['acl'])
            try:
                if len(currentacl['children']) > 0:
                    schema[key]['children'] = {}
                    self.setDACL(currentacl['children'], schema[key]['children'])
            except KeyError as e:
                if 'children' in str(e):
                    pass
                else:
                    raise e
    def getDACL(self):
        return self.schema

    def setExpandedDACL(self, dacl, schema, acl_path = None):
        for key in dacl:
            current = dacl[key]['acl']
            pprint.pprint(current.getOwner())
            expanded_acl = current.getExpandedACL()
            if len(expanded_acl) < 1:
                continue

            expanded = {
                'owner': current.getOwner()['id'],
                'type': current.getType(),
                'ignore_inheritance': current.getIgnoreInherit(),
                'skip': current.getSkip(),
                'acl': current.getExpandedACL()
            }
            if key == '__DEFAULT__':
                regex_key = '[a-zA-Z0-9_\-\.]+'
            else:
                regex_key = key

            if acl_path is not None:
                path_key = path.join(acl_path, key)
                schema[path_key] = expanded
            else:
                schema[key] = expanded

            try:
                self.setExpandedDACL(dacl[key]['children'], schema, key)
            except KeyError as e:
                if 'children' in str(e):
                    pass
                else:
                    raise e

    def getExpandedDACL(self):
        return self.expanded_schema
