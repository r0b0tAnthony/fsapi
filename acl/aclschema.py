import re
from . import acl
import pprint
class aclSchema:
    def __init__(self, name, dacl):
        self.setName(name)
        self.schema = {}
        self.setDACL(dacl, self.schema)
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

    def setDACL(self, dacl, schema):
        for key in dacl:
            print key
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
