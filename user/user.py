import re

class user:
    permission_bits = {
        'createUser': 1,
        'deleteUser': 2,
        'createProject': 4,
        'deleteProject': 8,
        'createFile': 16,
        'setACL': 32,
        'createACLSchema': 64,
        'deleteACLSchema': 128
    }

    def __init__(self, username, permissions, password = None, idnum = None):
        self.setUsername(username)
        self.setPermissions(permissions)
        if password != None:
            self.setPassword(password)
        if idnum != None:
            self.setId(idnum)

    def setUsername(self, username):
        if len(username) > 3:
            if re.match(r'^[a-zA-Z0-9_\-]+$', username):
                self.username = username
            else:
                raise ValueError('Usernames can be alphanumeric, underscores, or dashes only.')
        else:
            raise ValueError('Usernames must be more than 3 characters.')

    def getUsername(self):
        return self.username

    def setPassword(self, password):
        if len(password) > 8:
            if re.match(r'\s', password):
                raise ValueError('Passwords can not contain spaces.')
            else:
                self.password = password
        else:
            raise ValueError('Passwords must be greater than 8 characters.')

    def getPassword(self):
        return self.password

    def setPermissions(self, permissions = 0):
        self.permissions = 0
        try:
            for x in permissions:
                self.setPermission(x, True)
        except TypeError:
            self.permissions = permissions

    def getPermissions(self):
        return self.permissions

    def setPermission(self, permission, allow = True):
        try:
            if allow:
                self.permissions = self.permissions | self.permission_bits[permission]
            else:
                self.permissions = self.permissions & ~self.permission_bits[permission]
        except KeyError:
            raise KeyError("User permission '%s' does not exist." % permission)

    def getPermission(self, permission):
        try:
            return self.permissions & self.permission_bits[permission]
        except KeyError:
            raise KeyError("Permission '%s' does not exist" % permission)
    def setId(self, id):
        if id > 0:
            self.id = id
        else:
            raise ValueError('User Id must be greater than 0.')
    def getId(self):
        return self.id
