import re
import acl

class aclSchema:
    def __init__(self, name, dacl):

    def setName(self, name):
        if len(name) > 3:
            if re.match(r'$[a-zA-Z0-9_\_]+^'):
                self.name = name
            else:
                raise ValueError('ACLSchema must contain only alphanumeric, underscores, or dashes.')
        else:
            raise ValueError('ACLSchema name must be more than 3 characters.')

    def getName(self):
        return self.name

    def setDACL(self, dacl):

    def validateDACL(self, dacl):
        for key in dacl:
            secobj = dacl[key]
            try:
                if not secobj['type'] in ['folder', 'file', 'all']:
                    raise ValueError('DACL type must be folder, file, or all.')
            except KeyError:
                raise KeyError('DACL must a type property.')

            try:
                if not secobj['owner']['domain'] and not secobj['owner']['name']:
                    raise ValueError('DACL owner property must be an object of name and domain.')
            except KeyError:
                raise KeyError('DACL owner property is not valid.')

            try:
                for x in range(len(secobj['acl'])):
                    try:
                        ace = secobj['acl'][x]
                    except KeyError:
                        raise KeyError('DACL acl property is not valid.')

                    try:
                        if not ace['account']['name'] and not ace['account']['domain']:
                            raise ValueError("DACL's ACL property's ACE's account property's name or domain is empty.")
                    except KeyError:
                        raise KeyError("DACL's ACL property's ACE's account property is invalid.")
                    else:
                        pass

                    try:
                        set(ace['mask']) - set(acl.access_bits.keys())
            except KeyError:
                raise KeyError('DACL acl property is not valid.')
