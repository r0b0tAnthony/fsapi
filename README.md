# fsapi
fsapi is a python RESTful api for setting permissions/ ACLs on Windows Shares using predefined ACL JSON schemas associated with projects/file systems.

fsapi utilizes the [swagger/OpenAPI Specification](https://swagger.io), [serve_swagger](https://github.com/crowdwave/serve_swagger), [falcon](https://falconframework.org/), [waitress](https://docs.pylonsproject.org/projects/waitress/en/latest/), [pymongo](https://github.com/mongodb/mongo-python-driver), [pymodm](http://pymodm.readthedocs.io/en/stable/), and [pywin32](https://sourceforge.net/projects/pywin32/).

**fsapi is in beta.**

1. [Use Cases](#useCases)
2. [Dependencies](#dependencies)
3. [API Specification](#apiSpecification)
4. [Install](#install)
5. [How fsapi Works](#howFsapiWorks)
    1. [Objects](#objects)
        1. [User](#userObject)
            1. [User permissions](#userPermissions)
        2. [Project](#projectObject)
        3. [ACLSchema](#aclSchemaObject)
            1. [Schema Specification](#schemaSpecification)
            2. [Attributes](#schemaAttributes)
            3. [Access Masks](#accessMasks)
            4. [Inheritance Masks](#inheritanceMasks)


***

## <a name="useCases"></a> Use Cases
fsapi was built to allow non-admin users to set permissions / ACLs on files dynamically, especially for file structures that break Windows' ACL inheritance. Other methodologies of allowing local scripts to login as privileged user were entirely insecure.

The best way forward is to expose the pywin32 api via REST, laying a fsapi user, project, and schema based system on top to provide security and predicability in ACLs. The reason for making an independent user system was to avoid tying further into AD, possibly opening fsapi in the future to other filesystems / permissions management.

Additionally, fsapi allowed for a more dynamic setting of permissions via schemas that harness regex matching.

***

## <a name="dependencies"></a>Dependencies

* Windows Server(Tested on Windows Server 2012)
* Swagger 2.0 Spec
* Python 2.7.x
    * [serve_swagger](https://github.com/crowdwave/serve_swagger)
    * [falcon](https://falconframework.org/) >= 1.1.0
    * [waitress](https://docs.pylonsproject.org/projects/waitress/en/latest/) >= 1.0.1
    * [pymongo](https://github.com/mongodb/mongo-python-driver) >= 3.4.0
    * [pymodm](http://pymodm.readthedocs.io/en/stable/) >= 0.2.0
    * [pywin32](https://sourceforge.net/projects/pywin32/) >= build 220

***

## <a name="apiSpecification"></a>API Specification
You can preview using Swagger's online [Swagger UI](https://generator.swagger.io/).

Paste the following into the text box and hit *Explore*:
`https://raw.githubusercontent.com/r0b0tAnthony/fsapi/master/swagger.json`

***

## <a name="install"></a>Install

1. Setup a Windows Server with Access to AD
2. Install Python 2.7.x
3. Install pywin32
4. Install mongodb
4. Clone/Download fsapi
5. Install Python Modules
    * `pip -r requirements.txt`
6. Create First User
    1. Run fsapi.py via Python
    2. Send a `POST` request to `http://hostname:8080/api/users`, please reference the API Specification for query syntax.
        1. Be sure you first user has all [permissions](#userPermissions).
        2. For creation of the first user, you must still supply a basic http auth header. Can be credentials of the user you are creating or some fake credentials.

***

## <a name="howFsapiWorks"></a> How fsapi Works

### <a name="objects"></a> Objects

#### <a name="userObject"></a> User

fsapi has an independent user system from Windows or it's host platform in general. fsapi Users have permissions that allow them certain CRUD abilities within fsapi.

Users are assigned to projects and based on their user permissions they have certain abilities in projects.

##### <a name="userPermissions"></a>User Permissions

* **createUser** - Permission to Create a User Object
* **deleteUser** - Permission to Delete a User Object
* **createACLSchema** - Permission to Create an ACLSchema Object
* **deleteACLSchema** - Permission to Delete an ACLSchema Object
* **createProject** - Permission to Create a Project Object
* **deleteProject** - Permission to Delete a Project Object
* **createFile** - Permission to Create a File/Folder Within A Project
* **setACL** - Permission to Apply an ACLSchema to File/Folder in a Project

***

#### <a name="projectObject"></a> Project
Projects in fsapi map to a multi-platform(Linux, Windows, MacOS/Darwin) root folder and have an ACLSchema object assigned as well.

***

#### <a name="aclSchemaObject"></a> ACLSchema
ACLSchemas are JSON hierarchical structures of the filesystem relative to a Project's root folder.

##### <a name="schemaSpecification"></a> Schema Specification

```
{
  "pathcomponent":{
    "type": "file",
    "owner: {
      "name": "UserName"
      "domain": "DomainName"
    },
    "acl": [{
      "owner": {
        "name": "Username",
        "domain":	"DomaineName"
      },
      "mask": ["READ_DATA", "GENERIC_EXECUTE"],
      "inheritance": ["OBJECT_INHERIT", "CONTAINER_INHERIT"]
      "type": "allow",
    }],
    "children": {
      "child_pathcomponent":{
        "type": "file",
        "owner: {
          "name": "UserName"
          "domain": "DomainName"
        },
        "acl": [{
          "owner": {
            "name": "Username",
            "domain":	"DomaineName"
          },
          "mask": ["READ_DATA", "GENERIC_EXECUTE"],
          "inheritance": ["OBJECT_INHERIT", "CONTAINER_INHERIT"]
          "type": "allow",
        }],
        ignore_inheritance: True
        }
    }
    ignore_inheritance: True
    }    
}
```

##### <a name="schemaAttributes"></a> Attributes
**pathcomponent**: A string or regex to match against a path component.

**type**: Either `file` or `folder` representing what kind of file this ACL should be applied to.

**owner**:

* **name**: The name of the user/group who will own this file or folder.
* **domain**: The name of the domain this user/group is apart of.

**acl**: An array of Objects that represent ACEs

* **owner**: Similar to structure to file/folder's owner.
    * **name**: Name of user/group this ACE applies to.
    * **domain**: Domain of this user/group.
* **mask**: A list/array of Windows ACE Access Masks based off of standard Windows ACE Access Masks. These are combined together thru bit-wise operations.
* **inheritance**: A list/array of Windows ACE inheritance masks. These are combined thru bit-wise operations.
* **type**: Either the ACE is an `allow` or `deny`.

**ignore_inheritance**: Boolean whether to break/ignore the inheritance of this pathcomponent. Effectively, clearing all inherited ACEs for this file/folder.

**children**: Another dictionary definition of child path components, following the schema of the parent. Any children not defined will receive the same schema defined as their parent schema. This object setting is recursive allowing for creating full hierarchical representations of the file system.

***

##### <a name="accessMasks"></a> Access Masks
These are bit-wise masks that represent permissions for file and directories. You can read more on these at Microsoft's Documentation on [Access Masks](https://msdn.microsoft.com/en-us/library/windows/desktop/aa374896.aspx).

*Base Access Masks*:

`READ_DATA`, `LIST_DIRECTORY`, `WRITE_DATA`, `ADD_FILE`, `APPEND_DATA`, `ADD_SUBDIRECTORY`, `CREATE_PIPE_INSTANCE`, `READ_EA`, `WRITE_EA`, `EXECUTE`, `TRAVERSE`, `DELETE_CHILD`, `DELETE`, `READ_CONTROL`, `READ_ATTRIBUTES`, `WRITE_ATTRIBUTES`, `GENERIC_READ`, `GENERIC_WRITE`, `GENERIC_EXECUTE`, `WRITE_DAC`, `WRITE_OWNER`, `SYNCHRONIZE`

*Computed Access Masks*:

Are made of certain base access masks.

`CUSTOM_ALL_ACCESS` is made of: `SYNCHRONIZE`, `READ_DATA`, `LIST_DIRECTORY`, `WRITE_DATA`, `ADD_FILE`, `APPEND_DATA`, `ADD_SUBDIRECTORY`, `CREATE_PIPE_INSTANCE`, `READ_EA`, `WRITE_EA`, `EXECUTE`, `TRAVERSE`, `DELETE_CHILD`, `READ_ATTRIBUTES`, `WRITE_ATTRIBUTES`

`CUSTOM_MODIFY` is made of: `DELETE`, `READ_CONTROL`, `SYNCHRONIZE`, `READ_DATA`, `LIST_DIRECTORY`, `WRITE_DATA`, `ADD_FILE`, `APPEND_DATA`, `ADD_SUBDIRECTORY`, `CREATE_PIPE_INSTANCE`, `READ_EA`, `WRITE_EA`, `EXECUTE`, `TRAVERSE`, `DELETE_CHILD`, `READ_ATTRIBUTES`, `WRITE_ATTRIBUTES`

##### <a name="inheritanceMasks"></a> Inheritance Masks
These are bit-wise masks that represent how an ACE should be inherited in a file a structure. You can read more about Windows Inheritance Masks [here](https://msdn.microsoft.com/en-us/library/windows/desktop/aa374924.aspx).

*Base Inheritance Masks*:

`OBJECT_INHERIT`, `CONTAINER_INHERIT`, `NO_PROPOGATE_INHERIT`, `INHERIT_ONLY`
