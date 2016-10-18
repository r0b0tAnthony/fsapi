import win32api
import win32security
import pywintypes
import ntsecuritycon as con
import posixpath as path

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
        'DACL_SECURITY_INFO': win32security.DACL_SECURITY_INFORMATION,
        'SACL_SECURITY_INFO': win32security.SACL_SECURITY_INFORMATION,
        'OWNER_SECURITY_INFO': win32security.OWNER_SECURITY_INFORMATION,
        'GROUP_SECURITY_INFO': win32security.GROUP_SECURITY_INFORMATION,
        'UNPROTECTED_DACL': win32security.UNPROTECTED_DACL_SECURITY_INFORMATION,
        'UNPROTECTED_SACL': win32security.UNPROTECTED_SACL_SECURITY_INFORMATION,
        'PROTECTED_DACL': win32security.PROTECTED_DACL_SECURITY_INFORMATION,
        'PROTECTED_SACL': win32security.PROTECTED_SACL_SECURITY_INFORMATION
    }

    inherit_bits = {
        'OBJECT_INHERIT': con.OBJECT_INHERIT_ACE,
        'CONTAINER_INHERIT': con.CONTAINER_INHERIT_ACE,
        'NO_PROPOGATE_INHERIT': con.NO_PROPAGATE_INHERIT_ACE,
        'INHERIT_ONLY': con.INHERIT_ONLY_ACE,
        'VALID_INHERIT_FLAGS': con.VALID_INHERIT_FLAGS,
        'INHERITED_ACE': win32security.INHERITED_ACE
    }

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
                self.owner['id'] = ACL.getAccountId(self.owner['name'], self.owner['domain'])
        except KeyError:
            raise KeyError('DACL owner is missing name or domain property.')

    def getOwner(self):
        return self.owner

    @staticmethod
    def ValidateACL(acl):
        for x in range(len(acl)):
            acl[x] = ACL.ValidateACE(acl[x])

        return acl

    def getACL(self):
        return self.acl

    @staticmethod
    def ValidateDACLSchema(dacl):
        if '__DEFAULT__' not in dacl:
            raise KeyError('Each level of a DACL schema must contain a __DEFAULT__ entry')

        for key in dacl:
            currentacl = dacl[key]
            try:
                currentacl['owner']['id'] = ACL.GetAccountId(currentacl['owner']['name'], currentacl['owner']['domain'])
            except KeyError:
                raise KeyError("%s DACL owner propety is invalid" % key)

            currentacl['acl'] = ACL.ValidateACL(currentacl['acl'])
            try:
                if len(currentacl['children']) > 0:
                    ACL.ValidateDACLSchema(currentacl['children'])
            except KeyError as e:
                if 'children' in str(e):
                    pass
                else:
                    raise e

    @staticmethod
    def ValidateACE(ace):
        try:
            ace['account']['id'] = ACL.GetAccountId(ace['account']['name'], ace['account']['domain'])
        except KeyError:
            raise KeyError('ACE account property is invalid.')

        try:
            ace['mask_bits'] = ACL.GetAccessMaskBits(ace['mask'])
        except KeyError:
            raise KeyError('ACE mask property is missing')

        try:
            if ace['type'] != 'deny' and ace['type'] != 'allow':
                raise ValueError('ACE type property must be either allow or deny')
        except KeyError:
            raise KeyError('ACE type property is missing.')

        try:
            ace['inherit_bits'] = ACL.GetInheritBits(ace['inherit'])
        except KeyError:
            ace['inherit_bits'] = 0
            pass

        return ace

    @staticmethod
    def getExpandedACL(acl):
        expanded_acl = []
        for x in range(len(acl)):
            current_acl = acl[x]
            expanded_acl.append({
                'account_id': current_acl['account']['id'],
                'mask_bits': current_acl['mask_bits'],
                'type': current_acl['type'],
                'inherit_bits': current_acl['inherit_bits']
            })

        return expanded_acl

    def getIgnoreInherit(self):
        return self.ignore_inheritance

    def getSkip(self):
        return self.skip
    @staticmethod
    def GetAccountId(name, domain):
        return str(ACL.GetAccount(name, domain)[0])[6:]

    @staticmethod
    def GetAccount(name, domain):
        return win32security.LookupAccountName(domain, name)

    @staticmethod
    def GetAccessMaskBits(masks):
        bits = 0
        for mask in masks:
            try:
                bits = bits | ACL.access_bits[mask]
            except KeyError:
                raise ValueError("ACE Mask does not exist: %s" % mask)
        return bits

    @staticmethod
    def GetInheritBits(flags):
        bits = 0
        for flag in flags:
            try:
                bits = bits | ACL.inherit_bits[flag]
            except KeyError:
                raise ValueError("ACE Inherit flag does not exist: %s" % flag)
        return bits

    @staticmethod
    def GetExpandedDACL(dacl, schema, acl_path = None):
        for key in dacl:
            current = dacl[key]
            expanded_acl = ACL.getExpandedACL(current['acl'])
            if len(expanded_acl) < 1:
                continue

            expanded = {
                'owner': current['owner']['id'],
                'type': current['type'],
                'acl': expanded_acl
            }
            try:
                expanded['ignore_inheritance'] = current['ignore_inheritance']
            except KeyError:
                pass
            try:
                expanded['skip'] = expanded['skip']
            except KeyError:
                pass

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
                ACL.GetExpandedDACL(dacl[key]['children'], schema, key)
            except KeyError as e:
                if 'children' in str(e):
                    pass
                else:
                    raise e
