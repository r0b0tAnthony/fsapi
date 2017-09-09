# fsapi
fsapi is a python RESTful api for setting permissions/ ACLs on Windows Shares using predefined ACL JSON schemas associated with projects/file systems.

fsapi utilizes the [swagger/OpenAPI Specification](https://swagger.io), [serve_swagger](https://github.com/crowdwave/serve_swagger), [falcon](https://falconframework.org/), [waitress](https://docs.pylonsproject.org/projects/waitress/en/latest/), [pymongo](https://github.com/mongodb/mongo-python-driver), [pymodm](http://pymodm.readthedocs.io/en/stable/), and [pywin32](https://sourceforge.net/projects/pywin32/).

**fsapi is in beta.**

## Use Cases
fsapi was built to allow non-admin users to set permissions / ACLs on files dynamically, especially for file structures that break Windows' ACL inheritance. Other methodologies of allowing local scripts to login as privileged user were entirely insecure.

The best way forward is to expose the pywin32 api via REST, laying a fsapi user, project, and schema based system on top to provide security and predicability in ACLs. The reason for making an independent user system was to avoid tying further into AD, possibly opening fsapi in the future to other filesystems / permissions management.

Additionally, fsapi allowed for a more dynamic setting of permissions via schemas that harness regex matching.

## Dependencies

* Windows Server(Tested on Windows Server 2012)
* Swagger 2.0 Spec
* Python 2.7.x
    * [serve_swagger](https://github.com/crowdwave/serve_swagger)
    * [falcon](https://falconframework.org/) >= 1.1.0
    * [waitress](https://docs.pylonsproject.org/projects/waitress/en/latest/) >= 1.0.1
    * [pymongo](https://github.com/mongodb/mongo-python-driver) >= 3.4.0
    * [pymodm](http://pymodm.readthedocs.io/en/stable/) >= 0.2.0
    * [pywin32](https://sourceforge.net/projects/pywin32/) >= build 220

## API Specification
You can preview using Swagger's online [Swagger UI](https://generator.swagger.io/).

Paste the following into the text box and hit *Explore*:
`https://raw.githubusercontent.com/r0b0tAnthony/fsapi/master/swagger.json`

## Install

1. Setup a Windows Server with Access to AD
2. Install Python 2.7.x
3. Install pywin32
4. Install mongodb
4. Clone/Download fsapi
5. Install Python Modules
    * `pip -r requirements.txt`

## How fsapi Works

### Objects

#### User

fsapi has an independent user system from Windows or it's host platform in general. fsapi Users have permissions that allow them certain CRUD abilities within fsapi.

Users are assigned to projects and based on their user permissions they have certain abilities in projects.

##### User Permissions

* **createUser** - Permission to Create a User Object
* **deleteUser** - Permission to Delete a User Object
* **createACLSchema** - Permission to Create an ACLSchema Object
* **deleteACLSchema** - Permission to Delete an ACLSchema Object
* **createProject** - Permission to Create a Project Object
* **deleteProject** - Permission to Delete a Project Object
* **createFile** - Permission to Create a File/Folder Within A Project
* **setACL** - Permission to Apply an ACLSchema to File/Folder in a Project

#### Project
Projects in fsapi map to a multi-platform(Linux, Windows, MacOS/Darwin) root folder and have an ACLSchema object assigned as well.

#### ACLSchema
ACLSchemas are JSON hierarchical structures of the filesystem relative to a Project's root folder.

##### Schema Specification

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

###### Attributes
**pathcomponent**: A string or regex to match against a path component.

**type**: Either `file` or `folder` representing what kind of file this ACL should be applied to.

**owner**:

* **name**: The name of the user/group who will own this file or folder.
* **domain**: The name of the domain this user/group is apart of.

**acl**: An array of Objects that represent ACEs

* **owner**: Similar to structure to file/folder's owner.
    * **name**: Name of user/group this ACE applies to.
    * **domain**: Domain of this user/group.
* **mask**: A list/array of Windows ACE Permission Masks based off of standard Windows ACE Masks.
* **inheritance**: A list/array of Windows ACE inheritance masks.
* **type**: Either `allow` or `deny` ACE.

**ignore_inheritance**: Boolean whether to break/ignore the inheritance of this pathcomponent.

###### Masks
