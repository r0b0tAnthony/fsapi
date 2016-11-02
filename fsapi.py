import falcon
import falcon.status_codes as status
from serve_swagger import SpecServer
from waitress import serve
from pymodm import connect, context_managers
from resources.models import User, Project, Schema
from resources.fs import ACL, ProjectFS
from bson.objectid import ObjectId
from bson.errors import InvalidId
import pprint
import json
import datetime


def ProcessJsonResp(**request_handler_args):
    if 'result' not in request_handler_args['req'].context:
        return

    request_handler_args['resp'].body = json.dumps(request_handler_args['req'].context['result'])

def ProcessJsonReq(**request_handler_args):
    # req.stream corresponds to the WSGI wsgi.input environ variable,
    # and allows you to read bytes from the request body.
    #
    # See also: PEP 3333
    req = request_handler_args['req']
    if req.content_length in (None, 0):
        raise falcon.HTTPBadRequest('Empty request body',
                                    'A valid JSON document is required.')

    body = req.stream.read()
    if not body:
        raise falcon.HTTPBadRequest('Empty request body',
                                    'A valid JSON document is required.')

    try:
        req.context['doc'] = json.loads(body.decode('utf-8'))

    except (ValueError, UnicodeDecodeError):
        raise falcon.HTTPError(falcon.HTTP_753,
                               'Malformed JSON',
                               'Could not decode the request body. The '
                               'JSON was incorrect or not encoded as '
                               'UTF-8.')

def RequireJson(**request_handler_args):
    req = request_handler_args['req']
    if not req.client_accepts_json:
        raise falcon.HTTPNotAcceptable('This API only supports responses encoded as JSON.')
    if req.method in ('POST', 'PUT', 'GET'):
        if 'application/json' not in req.content_type:
            raise falcon.HTTPUnsupportedMediaType('This API only supports requests encoded as JSON.')

def CreateUser(**request_handler_args):
    authUser(request_handler_args['req'], request_handler_args['resp'], ['createUser'])
    doc = request_handler_args['req'].context['doc']
    try:
        user = User(username = doc['username'], password = doc['password'], permissions = doc['permissions'], auth_b64 = User.GetAuthBase64(doc['username'], doc['password']))
    except KeyError as e:
        raise falcon.HTTPBadRequest('Invalid User Object', "User JSON Object is invalid. %s" % e)
    else:
        try:
            user.save()
            request_handler_args['resp'].status = falcon.HTTP_201
            request_handler_args['req'].context['result'] = user.to_dict()
        except User.ValidationError as e:
            raise falcon.HTTPBadRequest("Validation Error", e.message)
        except User.DuplicateKeyError as e:
            existing_user = User.objects.get({"username": user.username})
            raise falcon.HTTPConflict("Conflict", {"message":"User with username '%s' already exists." % user.username, "user": existing_user.to_dict()})

def UpdateUser(**request_handler_args):
    authUser(request_handler_args['req'], request_handler_args['resp'], ['createUser'])
    doc = request_handler_args['req'].context['doc']
    try:
        user = User.objects.get({"_id": ObjectId(request_handler_args['uri_fields']['id'])})
    except InvalidId as e:
        raise falcon.HTTPBadRequest('Bad Request', str(e))
    except User.DoesNotExist:
        raise falcon.HTTPNotFound()
    else:
        try:
            user.username = doc['username']
            user.permissions = doc['permissions']
        except KeyError as e:
            raise falcon.HTTPMissingParam(str(e))
        try:
            user.password = doc['password']
        except KeyError:
            user.auth_b64 = User.GetAuthBase64(doc['username'], user.password)
            pass
        else:
            user.auth_b64 = User.GetAuthBase64(doc['username'], doc['password'])
        try:
            user.save()
        except User.ValidationError as e:
            raise falcon.HTTPBadRequest("Validation Error", e.message)
        except User.DuplicateKeyError as e:
            existing_user = User.objects.get({"username": user.username})
            raise falcon.HTTPConflict("Conflict", {"message":"User with username '%s' already exists." % user.username, "user": existing_user.to_dict()})
        else:
            request_handler_args['req'].context['result'] = user.to_dict()

def GetUsers(**request_handler_args):
    users = []
    for user in User.objects.all():
        users.append(user.to_dict())
    request_handler_args['req'].context['result'] = users

def GetUser(**request_handler_args):
    try:
        user = User.objects.get({"_id": ObjectId(request_handler_args['uri_fields']['id'])})
    except InvalidId as e:
        raise falcon.HTTPBadRequest('Bad Request', str(e))
    except User.DoesNotExist:
        raise falcon.HTTPNotFound()
    else:
        request_handler_args['req'].context['result'] = user.to_dict()

def DeleteUser(**request_handler_args):
    authUser(request_handler_args['req'], request_handler_args['resp'], ['deleteUser'])
    try:
        user = User.objects.get({"_id": ObjectId(request_handler_args['uri_fields']['id'])})
    except InvalidId as e:
        raise falcon.HTTPBadRequest('Bad Request', str(e))
    except User.DoesNotExist:
        raise falcon.HTTPNotFound()
    else:
        user.delete()

def CreateACLSchema(**request_handler_args):
    authUser(request_handler_args['req'], request_handler_args['resp'], ['createACLSchema'])
    doc = request_handler_args['req'].context['doc']
    try:
        schema = Schema(name = doc['name'], schema = doc['schema'])
    except KeyError as e:
        raise falcon.HTTPMissingParam(str(e))
    else:
        try:
            schema.save()
        except Schema.ValidationError as e:
            raise falcon.HTTPBadRequest("Validation Error", e.message)
        else:
            request_handler_args['resp'].status = falcon.HTTP_201
            request_handler_args['req'].context['result'] = schema.to_dict()

def GetACLSchemas(**request_handler_args):
    schemas = []
    for schema in Schema.objects.all():
        schemas.append(schema.to_dict())
    request_handler_args['req'].context['result'] = schemas

def GetACLSchema(**request_handler_args):
    try:
        schema = Schema.objects.get({"_id": ObjectId(request_handler_args['uri_fields']['id'])})
    except InvalidId as e:
        raise falcon.HTTPBadRequest('Bad Request', str(e))
    except Schema.DoesNotExist:
        raise falcon.HTTPNotFound()
    else:
        request_handler_args['req'].context['result'] = schema.to_dict()

def UpdateACLSchema(**request_handler_args):
    authUser(request_handler_args['req'], request_handler_args['resp'], ['createACLSchema'])
    doc = request_handler_args['req'].context['doc']
    try:
        schema = Schema.objects.get({"_id": ObjectId(request_handler_args['uri_fields']['id'])})
    except InvalidId as e:
        raise falcon.HTTPMissing('Bad Request', str(e))
    except Schema.DoesNotExist:
        raise falcon.HTTPNotFound()
    else:
        try:
            schema.name = doc['name']
            schema.schema = doc['schema']
            schema.modified = datetime.datetime.now()
        except KeyError as e:
            raise falcon.HTTPMissingParam(str(e))
        try:
            schema.save()
        except schema.ValidationError as e:
            raise falcon.HTTPBadRequest("Validation Error", e.message)
        else:
            for project in Project.objects.raw({"acl_schema": schema._id}):
                project.save()
            request_handler_args['req'].context['result'] = schema.to_dict()

def DeleteACLSchema(**request_handler_args):
    authUser(request_handler_args['req'], request_handler_args['resp'], ['deleteACLSchema'])
    try:
        schema = Schema.objects.get({"_id": ObjectId(request_handler_args['uri_fields']['id'])})
    except InvalidId as e:
        raise falcon.HTTPBadRequest('Bad Request', str(e))
    except Schema.DoesNotExist:
        raise falcon.HTTPNotFound()
    else:
        try:
            schema.delete()
        except Schema.OperationError as e:
            raise falcon.HTTPInternalServerError('Internal Server Error', e.message)

def CreateProject(**request_handler_args):
    authUser(request_handler_args['req'], request_handler_args['resp'], ['createProject'])
    doc = request_handler_args['req'].context['doc']
    try:
        user_ids = []
        for x in range(len(doc['users'])):
            user_ids.append(ObjectId(doc['users'][x]))
    except InvalidId as e:
        raise falcon.HTTPBadRequest('Bad Request', str(e))
    except KeyError as e:
        raise falcon.HTTPMissingParam('users')

    try:
        project_users = User.objects.raw({'_id': { '$in': user_ids} })
    except User.DoesNotExist:
        raise falcon.HTTPNotFound()

    try:
        project_schema = Schema.objects.get({'_id': ObjectId(doc['acl_schema'])})
    except InvalidId as e:
        raise falcon.HTTPBadRequest('Bad Request', str(e))
    except KeyError as e:
        raise falcon.HTTPMissingParam('acl_schema')

    try:
        project = Project(name = doc['name'], acl_schema = project_schema, paths = doc['paths'], users = project_users)
    except KeyError as e:
        raise falcon.HTTPBadRequest('Invalid Project Object', "Project JSON Object is invalid. %s" % e)
    else:
        try:
            project.save()
        except project.ValidationError as e:
            raise falcon.HTTPBadRequest("Validation Error", e.message)
        else:
            #pprint.pprint(project)
            request_handler_args['resp'].status = falcon.HTTP_201
            request_handler_args['req'].context['result'] = project.to_dict()

def GetProjects(**request_handler_args):
    projects = []
    for project in Project.objects.all():
        projects.append(project.to_dict())
    request_handler_args['req'].context['result'] = projects

def GetProject(**request_handler_args):
    try:
        project = Project.objects.get({"_id": ObjectId(request_handler_args['uri_fields']['id'])})
    except InvalidId as e:
        raise falcon.HTTPBadRequest('Bad Request', str(e))
    except Project.DoesNotExist:
        raise falcon.HTTPNotFound()
    else:
        request_handler_args['req'].context['result'] = project.to_dict()

def UpdateProject(**request_handler_args):
    authUser(request_handler_args['req'], request_handler_args['resp'], ['createProject'])
    doc = request_handler_args['req'].context['doc']
    try:
        project = Project.objects.get({"_id": ObjectId(request_handler_args['uri_fields']['id'])})
    except InvalidId as e:
        raise falcon.HTTPBadRequest('Bad Request', str(e))
    except Project.DoesNotExist:
        raise falcon.HTTPNotFound()
    else:
        try:
            user_ids = []
            for x in range(len(doc['users'])):
                user_ids.append(ObjectId(doc['users'][x]))
        except InvalidId as e:
            raise falcon.HTTPBadRequest('Invalid User IDs', str(e))

        try:
            project_users = User.objects.raw({'_id': { '$in': user_ids} })
        except User.DoesNotExist:
            raise falcon.HTTPNotFound()

        try:
            project_schema = Schema.objects.get({'_id': ObjectId(doc['acl_schema'])})
        except InvalidId as e:
            raise falcon.HTTPBadRequest('Invalid Schema Id', str(e))

        try:
            project.name = doc['name']
            project.acl_schema = project_schema
            project.users = project_users
            project.paths = doc['paths']
        except KeyError as e:
            raise falcon.HTTPBadRequest('Invalid Project Object', "Project JSON Object is invalid. %s" % e)
        else:
            try:
                project.save()
            except project.ValidationError as e:
                raise falcon.HTTPBadRequest("Validation Error", e.message)
            else:
                #pprint.pprint(project)
                request_handler_args['req'].context['result'] = project.to_dict()

def DeleteProject(**request_handler_args):
    authUser(request_handler_args['req'], request_handler_args['resp'], ['deleteProject'])
    try:
        project = Project.objects.get({"_id": ObjectId(request_handler_args['uri_fields']['id'])})
    except InvalidId as e:
        raise falcon.HTTPBadRequest('Bad Request', str(e))
    except Project.DoesNotExist:
        raise falcon.HTTPNotFound()
    else:
        project.delete()

def GetProjectUsers(**request_handler_args):
    try:
        project = Project.objects.get({"_id": ObjectId(request_handler_args['uri_fields']['id'])})
    except InvalidId as e:
        raise falcon.HTTPMissingParam('id')
    except Project.DoesNotExist:
        raise falcon.HTTPNotFound()
    else:
        users = []
        for x in range(len(project.users)):
            users.append(project.users[x].to_dict())
        request_handler_args['req'].context['result'] = users

def UpdateProjectUsers(**request_handler_args):
    authUser(request_handler_args['req'], request_handler_args['resp'], ['createProject'])
    doc = request_handler_args['req'].context['doc']
    try:
        project = Project.objects.get({"_id": ObjectId(request_handler_args['uri_fields']['id'])})
    except InvalidId as e:
        raise falcon.HTTPMissingParam('id')
    except Project.DoesNotExist:
        raise falcon.HTTPNotFound()
    else:
        try:
            user_ids = []
            for x in range(len(doc['users'])):
                user_ids.append(ObjectId(doc['users'][x]))
        except InvalidId as e:
            raise falcon.HTTPBadRequest('Bad Request', str(e))

        try:
            project_users = User.objects.raw({'_id': { '$in': user_ids} })
        except User.DoesNotExist:
            raise falcon.HTTPNotFound()
        try:
            project.users = project_users
        except KeyError as e:
            raise falcon.HTTPBadRequest('Invalid Project Object', "Project JSON Object is invalid. %s" % e)
        else:
            try:
                project.save()
            except project.ValidationError as e:
                raise falcon.HTTPBadRequest("Validation Error", e.message)
            else:
                users = []
                for x in range(len(project.users)):
                    users.append(project.users[x].to_dict())
                request_handler_args['req'].context['result'] = users

def CreateFile(**request_handler_args):
    authUser(request_handler_args['req'], request_handler_args['resp'], ['createFile'])
    user = request_handler_args['req'].context['user']
    doc = request_handler_args['req'].context['doc']
    try:
        project = Project.objects.get({"_id": ObjectId(request_handler_args['uri_fields']['id'])})
    except InvalidId as e:
        raise falcon.HTTPBadRequest('Bad Request', str(e))
    except Project.DoesNotExist:
        raise falcon.HTTPNotFound()
    else:
        with context_managers.no_auto_dereference(Project):
            if user._id in project.users:
                try:
                    path = ProjectFS.TranslatePath(doc['path'], doc['platform'], project.paths)
                except (ValueError, KeyError) as e:
                    raise falcon.HTTPBadRequest('Bad Request', e.message)
                try:
                    if doc['type'] == 'file':
                        ProjectFS.CreateFile(path)
                    elif doc['type'] == 'folder':
                        ProjectFS.CreateDirectory(path)
                    else:
                        raise falcon.HTTPBadRequest('Bad Request', 'Type property of FS object must be either file or folder.')
                except (IOError, OSError) as e:
                    raise falcon.HTTPInternalServerError('Internal Server Error', str(e))
                except KeyError:
                    raise falcon.HTTPBadRequest('Bad Request', 'FS Object is missing type property.')
                try:
                    request_handler_args['resp'].status = falcon.HTTP_201
                    request_handler_args['req'].context['result'] = {
                            'path': path,
                            'security': ACL.GetACL(path),
                            'created': ProjectFS.GetCTime(path),
                            'modified': ProjectFS.GetMTime(path),
                            'accessed': ProjectFS.GetATime(path)
                    }
                except ACL.error as e:
                    raise falcon.HTTPInternalServerError('Internal Server Error', str(e))
            else:
                raise falcon.HTTPForbidden('Forbidden', "%s is not assigned to this project." % user.username)

def SetACL(**request_handler_args):
    authUser(request_handler_args['req'], request_handler_args['resp'], ['setACL'])
    user = request_handler_args['req'].context['user']
    doc = request_handler_args['req'].context['doc']
    try:
        project = Project.objects.get({"_id": ObjectId(request_handler_args['uri_fields']['id'])})
    except InvalidId as e:
        raise falcon.HTTPBadRequest('Bad Request', str(e))
    except Project.DoesNotExist:
        raise falcon.HTTPNotFound()
    else:
        with context_managers.no_auto_dereference(Project):
            if user._id in project.users:

                try:
                    matched_acl = ProjectFS.GetMatchACLPath(doc['path'], doc['platform'], project.acl_expanded, project.acl_expanded_depth)
                    path = ProjectFS.TranslatePath(doc['path'], doc['platform'], project.paths)
                except ValueError as e:
                    raise falcon.HTTPBadRequest("Bad Request: Invalid Value", e.message)
                except KeyError as e:
                    raise falcon.HTTPBadRequest('Bad Request: Missing Key', e.message)
                else:
                    if matched_acl != None:
                        try:
                            ACL.SetMatchedACL(path, matched_acl)
                        except ACL.error as e:
                            raise falcon.HTTPInternalServerError('Internal Server Error', e[2])

                        try:
                            request_handler_args['req'].context['result'] = {
                                    'path': path,
                                    'security': ACL.GetACL(path),
                                    'created': ProjectFS.GetCTime(path),
                                    'modified': ProjectFS.GetMTime(path),
                                    'accessed': ProjectFS.GetATime(path)
                            }
                        except ACL.error as e:
                            raise falcon.HTTPInternalServerError('Internal Server Error', str(e))
                    else:
                        request_handler_args['resp'].status = falcon.HTTP_202
                        try:
                            request_handler_args['req'].context['result'] = {
                                    'path': path,
                                    'security': ACL.GetACL(path),
                                    'created': ProjectFS.GetCTime(path),
                                    'modified': ProjectFS.GetMTime(path),
                                    'accessed': ProjectFS.GetATime(path)
                            }
                        except ACL.error as e:
                            raise falcon.HTTPInternalServerError('Internal Server Error', str(e))
            else:
                raise falcon.HTTPForbidden('Forbidden', "%s is not assigned to this project." % user.username)

def GetDoc(**request_handler_args):
    swagger_doc = open('swagger.json', 'r')
    request_handler_args['resp'].body = swagger_doc.read()

def authUser(req, resp, permissions):
    authHeader = req.get_header('Authorization')
    if authHeader == None:
        raise falcon.HTTPMissingHeader('Authorization')
    try:
        user = User.objects.get({"auth_b64": authHeader[6:]})
        diff_perms = list(set(permissions) - set(User.valid_permissions))
        if len(diff_perms) > 0:
            raise falcon.HTTPForbidden('Forbidden', "%s does not have the required permissions: %s" % (user.username, ', '.join(diff_perms)))
    except User.DoesNotExist:
        raise falcon.HTTPUnauthorized('Unauthorized','Username and password does not exist.', ['Basic realm="WallyWorld"'])
    else:
        req.context['user'] = user

def not_found(**request_handler_args):
    raise falcon.HTTPNotFound('Not found.', 'Requested resource not found.')

def forbidden(**request_handler_args):
    raise falcon.HTTPForbidden('Forbidden', 'You are forbidden from accessing this.')

def im_a_teapot(**request_handler_args):
    resp = request_handler_args['resp']
    resp.status = status.HTTP_IM_A_TEAPOT

operation_handlers = {
    'createUser':                   [RequireJson, ProcessJsonReq, CreateUser, ProcessJsonResp],
    'updateUser':                   [RequireJson, ProcessJsonReq, UpdateUser, ProcessJsonResp],
    'deleteUser':                   [DeleteUser, ProcessJsonResp],
    'getUser':                      [GetUser, ProcessJsonResp],
    'getUsers':                     [GetUsers, ProcessJsonResp],
    'getProjects':                  [GetProjects, ProcessJsonResp],
    'createProject':                [RequireJson, ProcessJsonReq,CreateProject, ProcessJsonResp],
    'getProject':                   [GetProject, ProcessJsonResp],
    'updateProject':                [RequireJson, ProcessJsonReq, UpdateProject, ProcessJsonResp],
    'deleteProject':                [DeleteProject, ProcessJsonResp],
    'createFile':                   [RequireJson, ProcessJsonReq, CreateFile, ProcessJsonResp],
    'setACL':                       [RequireJson, ProcessJsonReq, SetACL, ProcessJsonResp],
    'getProjectUsers':              [GetProjectUsers, ProcessJsonResp],
    'updateProjectUsers':           [RequireJson, ProcessJsonReq, UpdateProjectUsers, ProcessJsonResp],
    'createACLSchema':              [RequireJson, ProcessJsonReq, CreateACLSchema, ProcessJsonResp],
    'getACLSchemas':                [GetACLSchemas, ProcessJsonResp],
    'getACLSchema':                 [GetACLSchema, ProcessJsonResp],
    'updateACLSchema':              [RequireJson, ProcessJsonReq, UpdateACLSchema, ProcessJsonResp],
    'deleteACLSchema':              [DeleteACLSchema, ProcessJsonResp],
    'getDoc':                       [GetDoc, ProcessJsonResp]
}
connect("mongodb://localhost:27017/fsapi", alias='fsapi-app')

api = application = falcon.API()
server = SpecServer(operation_handlers=operation_handlers)
with open('swagger.json') as f:
    server.load_spec_swagger(f.read())
api.add_sink(server, r'/')
serve(api, host='0.0.0.0', port=8080)
"""
to test:
gunicorn -b 127.0.0.1:8001 petstore:application
curl 127.0.0.1:8001/3.0/pet/findByStatus
curl 127.0.0.1:8001/3.0/pet/1
curl -X DELETE 127.0.0.1:8001/3.0/pet/1
"""
