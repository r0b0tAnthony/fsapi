import re
import posixpath
class project :
    def __init__(self, name, paths, users, aclschema, project_id = None, expanded_schema = None):
        self.setName(name)
        self.setPaths(paths)
        self.setUsers(users)
        self.setACLSchema(aclschema)
        if project_id != None:
            self.setId(project_id)
        if expanded_schema != None:
            self.setExpandedSchema(expanded_schema)

    def setName(self, name):
        if len(name) > 3:
            if re.match(r'^\w+$', name):
                self.name = name
            else:
                raise ValueError('Project name can only contain alphanumeric and underscore characters.')
        else:
            raise ValueError('Project name must be more than 3 characters long.')

    def getName(self):
        return self.name

    def setPaths(self, paths):
        try:
            paths['linux'] = posixpath.abspath(paths['linux'])
        except KeyError:
            raise KeyError('Project paths property is missing linux propety.')

        try:
            paths['darwin'] = posixpath.abspath(paths['darwin'])
        except KeyError:
            raise KeyError('Project paths property is missing darwin property.')

        try:
            paths['windows'] = posixpath.normpath(paths['windows'].replace('\\', '/'))
        except KeyError:
            raise KeyError('Project paths property is missing windows property.')

        self.paths = paths

    def getPaths(self):
        return self.paths

    def setUsers(self, users):
        self.users = []
        for x in range(len(users)):
            user = users[x]
            self.users.append({'name': user.getUsername(), 'id': user.getId()})

    def getUsers(self):
        return self.users

    def setACLSchema(self, aclschema_obj):
        self.aclschema = {'name': aclschema_obj.getName(), 'id': aclschema_obj.getId()}
        self.setExpandedSchema(aclschema_obj.getExpandedDACL())

    def getACLSchema(self):
        return ACLSchema

    def setExpandedSchema(self, expanded):
        self.expanded_schema = {}
        for platform in self.paths:
            self.expanded_schema[platform] = {}
            for key in expanded:
                schema = expanded[key]
                path_key = posixpath.join(self.paths[platform], key)
                expanded_key = "^%s$" % path_key
                self.expanded_schema[platform][expanded_key] = schema

    def getExpandedSchema(self):
        return self.expanded_schema
