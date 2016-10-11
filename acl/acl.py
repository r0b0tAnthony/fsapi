import win32api
import win32security
import pywintypes
import ntsecuritycon as con

class ACL:
    #translation to ntsecuritycon constants
    access_bits = {
        'READ_DATA': con.FILE_READ_DATA,
        'LIST_DIRECTORY': con.FILE_LIST_DIRECTORY,
        'WRITE_DATA': con.FILE_WRITE_DATA,
        'ADD_FILE': con.FILE_ADD_FILE,
        'APPEND_DATA': con.FILE_APPEND_DATA,
        'ADD_SUBDIRECTORY': con.FILE_ADD_SUBDIRECTORY,
        'CREATE_PIPE_INSTANCE': con.FILE_CREATE_PIPE_INSTANCE,
        'READ_EA': con.FILE_READ_EA,
        'WRITE_EA': con.FILE_WRITE_EA,
        'EXECUTE': con.FILE_EXECUTE,
        'TRAVERSE': con.FILE_TRAVERSE,
        'DELETE_CHILD': con.FILE_DELETE_CHILD,
        'DELETE': con.DELETE,
        'READ_CONTROL': con.READ_CONTROL,
        'READ_ATTRIBUTES': con.FILE_READ_ATTRIBUTES,
        'WRITE_ATTRIBUTES': con.FILE_WRITE_ATTRIBUTES,
        'CUSTOM_ALL_ACCESS': (
            con.STANDARD_RIGHTS_REQUIRED | con.SYNCHRONIZE | con.FILE_READ_DATA | con.FILE_LIST_DIRECTORY |
            con.FILE_WRITE_DATA | con.FILE_ADD_FILE | con.FILE_APPEND_DATA | con.FILE_ADD_SUBDIRECTORY |
            con.FILE_CREATE_PIPE_INSTANCE | con.FILE_READ_EA | con.FILE_WRITE_EA | con.FILE_EXECUTE |
            con.FILE_TRAVERSE | con.FILE_DELETE_CHILD | con.FILE_READ_ATTRIBUTES | con.FILE_WRITE_ATTRIBUTES
        ),
        'CUSTOM_MODIFY': (
            con.DELETE | con.READ_CONTROL | con.SYNCHRONIZE | con.FILE_READ_DATA | con.FILE_LIST_DIRECTORY |
            con.FILE_WRITE_DATA | con.FILE_ADD_FILE | con.FILE_APPEND_DATA | con.FILE_ADD_SUBDIRECTORY |
            con.FILE_CREATE_PIPE_INSTANCE | con.FILE_READ_EA | con.FILE_WRITE_EA | con.FILE_EXECUTE |
            con.FILE_TRAVERSE | con.FILE_DELETE_CHILD | con.FILE_READ_ATTRIBUTES | con.FILE_WRITE_ATTRIBUTES
        ),
        'GENERIC_READ': con.FILE_GENERIC_READ,
        'GENERIC_WRITE': con.FILE_GENERIC_WRITE,
        'GENERIC_EXECUTE': con.FILE_GENERIC_EXECUTE,
        'WRITE_DAC': con.WRITE_DAC,
        'WRITE_OWNER': con.WRITE_OWNER,
        'SYNCHRONIZE': con.SYNCHRONIZE,
        'OBJECT_INHERIT': con.OBJECT_INHERIT_ACE,
        'CONTAINER_INHERIT': con.CONTAINER_INHERIT_ACE,
        'NO_PROPOGATE_INHERIT': con.NO_PROPAGATE_INHERIT_ACE,
        'INHERIT_ONLY': con.INHERIT_ONLY_ACE,
        'VALID_INHERIT_FLAGS': con.VALID_INHERIT_FLAGS,
        'INHERITED_ACE': win32security.INHERITED_ACE,
        'DACL_SECURITY_INFO': win32security.DACL_SECURITY_INFORMATION,
        'SACL_SECURITY_INFO': win32security.SACL_SECURITY_INFORMATION,
        'OWNER_SECURITY_INFO': win32security.OWNER_SECURITY_INFORMATION,
        'GROUP_SECURITY_INFO': win32security.GROUP_SECURITY_INFORMATION,
        'UNPROTECTED_DACL': win32security.UNPROTECTED_DACL_SECURITY_INFORMATION,
        'UNPROTECTED_SACL': win32security.UNPROTECTED_SACL_SECURITY_INFORMATION,
        'PROTECTED_DACL': win32security.PROTECTED_DACL_SECURITY_INFORMATION,
        'PROTECTED_SACL': win32security.PROTECTED_SACL_SECURITY_INFORMATION
    }

    def __init__(self, acl_type, owner, acl, ignore_inheritance = False, skip = False, children = {}):
        self.setType(acl_type)
        self.setOwner(owner)
        self.setACL(acl)
        self.ignore_inheritance = ignore_inheritance
        self.skip = skip

    def setType(self, acl_type):
        if acl_type not in ['file', 'folder', 'all']:
            raise ValueError('DACL type must be either file, folder, or all.')
        else:
            self.type = acl_type

    def getType(self):
        return self.type

    def setOwner(self, owner):
        try:
            if not owner['name'] and not owner['domain']:
                raise ValueError('DACL owner name or domain is not set.')
            else:
                self.owner = owner
        except KeyError:
            raise KeyError('DACL owner is missing name or domain property.')

    def setACL(self, acl):
        for x in range(len(acl)):
            self.validateACE(acl[x])
        self.acl = acl

    def getACL(self):
        return self.acl

    def validateACE(self, ace):
        try:
            ace['account']['id'] = self.getAccountId(ace['account']['name'], ace['account']['domain'])
        except KeyError:
            raise KeyError('ACE account property is invalid.')

        try:
            ace['mask_bits'] = self.getAccessMaskBits(ace['mask'])
        except KeyError:
            raise KeyError('ACE mask property is missing')

        try:
            if ace['type'] != 'deny' and ace['type'] != 'allow':
                raise ValueError('ACE type property must be either allow or deny')
        except KeyError:
            raise KeyError('ACE type property is missing.')

    @staticmethod
    def getAccountId(name, domain):
        return str(ACL.getAccount(name, domain)[0])[6:]

    @staticmethod
    def getAccount(name, domain):
        return win32security.LookupAccountName(domain, name)

    @staticmethod
    def getAccessMaskBits(masks):
        bits = 0
        for mask in masks:
            try:
                bits = bits | ACL.access_bits[mask]
            except KeyError:
                raise ValueError("ACE Mask does not exist: %s" % mask)
        return bits
