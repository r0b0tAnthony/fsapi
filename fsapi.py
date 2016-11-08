import falcon
import falcon.status_codes as status
from serve_swagger import SpecServer
from pymodm import connect, context_managers
from resources.models import User, Project, Schema
from resources.fs import ACL, ProjectFS
from bson.objectid import ObjectId
from bson.errors import InvalidId
import pprint
import json
import datetime
import logging
from logging.handlers import TimedRotatingFileHandler
from pythonjsonlogger import jsonlogger
from waitress import serve
import os
import sys

def get_script_path():
    return os.path.dirname(os.path.realpath(sys.argv[0]))

def SetupLogger(**request_handler_args):
    req = request_handler_args['req']
    class CustomJsonFormatter(jsonlogger.JsonFormatter):
        def process_log_record(self, log_record):
            log_record["uri"] = req.uri
            log_record["client"] = req.remote_addr
            log_record["timestamp"] = datetime.datetime.now().isoformat()
            try:
                log_record['loggedin_user'] = {'name': req.context['user'].username, 'id': str(req.context['user']._id)}
            except KeyError:
                pass
            return super(CustomJsonFormatter, self).process_log_record(log_record)

    logger = logging.getLogger(name = 'FSAPI')
    logHandler = TimedRotatingFileHandler('fsapi.log', when = 'd', interval= 1, backupCount=14)
    formatter = CustomJsonFormatter('%(levelname)')
    logHandler.setFormatter(formatter)
    logger.setLevel(logging.DEBUG)
    logger.addHandler(logHandler)

    request_handler_args['req'].context['logger'] = logger

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
        req.context['logger'].debug({'message': 'Failed login attempt', 'action': 'login'})
        raise falcon.HTTPUnauthorized('Unauthorized','Username and password does not exist.', ['Basic realm="WallyWorld"'])
    else:
        req.context['user'] = user
        req.context['logger'].debug({'message': "'%s' logged in." % user.username, 'action': 'login'})

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
    req = request_handler_args['req']
    authUser(req, request_handler_args['resp'], ['createUser'])
    doc = req.context['doc']
    try:
        user = User(username = doc['username'], password = doc['password'], permissions = doc['permissions'], auth_b64 = User.GetAuthBase64(doc['username'], doc['password']))
    except KeyError as e:
        raise falcon.HTTPBadRequest('Invalid User Object', "User JSON Object is invalid. %s" % e)
    else:
        try:
            user.save()
            request_handler_args['resp'].status = falcon.HTTP_201
            print req.uri
            user.uri = req.uri + '/' + str(user._id)
            request_handler_args['resp'].location = user.uri
            req.context['result'] = user.to_dict()
            req.context['logger'].info({'action': 'createUser', 'message': "'%s' user with id of %s was created successfully" % (user.username, user._id)})
        except User.ValidationError as e:
            raise falcon.HTTPBadRequest("Validation Error", e.message)
        except User.DuplicateKeyError as e:
            existing_user = User.objects.get({"username": user.username})
            raise falcon.HTTPConflict("Conflict", {"message":"User with username '%s' already exists." % user.username, "user": existing_user.to_dict()})

def UpdateUser(**request_handler_args):
    req = request_handler_args['req']
    authUser(req, request_handler_args['resp'], ['createUser'])
    doc = req.context['doc']
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
            user.uri = req.uri
            request_handler_args['resp'].location = user.uri
            request_handler_args['req'].context['result'] = user.to_dict()
            req.context['logger'].info({'action': 'updateUser', 'message': "'%s' user with id of %s was updated successfully." % (user.username, user._id)})

def GetUsers(**request_handler_args):
    users = []
    for user in User.objects.all():
        user.uri = request_handler_args['req'].uri + '/' + str(user._id)
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
        user.uri = request_handler_args['req'].uri
        request_handler_args['resp'].location = user.uri
        request_handler_args['req'].context['result'] = user.to_dict()

def DeleteUser(**request_handler_args):
    req = request_handler_args['req']
    authUser(req, request_handler_args['resp'], ['deleteUser'])
    try:
        user = User.objects.get({"_id": ObjectId(request_handler_args['uri_fields']['id'])})
    except InvalidId as e:
        raise falcon.HTTPBadRequest('Bad Request', str(e))
    except User.DoesNotExist:
        raise falcon.HTTPNotFound()
    else:
        user.delete()
        req.context['logger'].info({'action': 'deleteUser', 'message': "'%s' user with id of %s was deleted successfully." % (user.username, user._id)})

def CreateACLSchema(**request_handler_args):
    req = request_handler_args['req']
    authUser(req, request_handler_args['resp'], ['createACLSchema'])
    doc = req.context['doc']
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
            schema.uri = req.uri + '/' + str(schema._id)
            request_handler_args['resp'].location = schema.uri
            request_handler_args['req'].context['result'] = schema.to_dict()
            req.context['logger'].info({'action': 'createACLSchema', 'message': "'%s' ACLSchema with id of %s was created successfully." % (schema.name, schema._id)})

def GetACLSchemas(**request_handler_args):
    schemas = []
    for schema in Schema.objects.all():
        schema.uri = request_handler_args['req'].uri + '/' + str(schema._id)
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
        user.uri = request_handler_args['req'].uri
        request_handler_args['resp'].location = schema.uri
        request_handler_args['req'].context['result'] = schema.to_dict()

def UpdateACLSchema(**request_handler_args):
    req = request_handler_args['req']
    authUser(req, request_handler_args['resp'], ['createACLSchema'])
    doc = req.context['doc']
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
            schema.uri = req.uri + '/' + str(schema._id)
            request_handler_args['resp'].location = schema.uri
            request_handler_args['req'].context['result'] = schema.to_dict()
            req.context['logger'].info({'action': 'updateACLSchema', 'message': "'%s' ACLSchema with id of %s was updated successfully." % (schema.name, schema._id)})

def DeleteACLSchema(**request_handler_args):
    req = request_handler_args['req']
    authUser(req, request_handler_args['resp'], ['deleteACLSchema'])
    try:
        schema = Schema.objects.get({"_id": ObjectId(request_handler_args['uri_fields']['id'])})
    except InvalidId as e:
        raise falcon.HTTPBadRequest('Bad Request', str(e))
    except Schema.DoesNotExist:
        raise falcon.HTTPNotFound()
    else:
        try:
            schema.delete()
            req.context['logger'].info({'action': 'deleteACLSchema', 'message': "'%s' ACLSchema with id of %s was deleted successfully." % (schema.name, schema._id)})
        except Schema.OperationError as e:
            raise falcon.HTTPInternalServerError('Internal Server Error', e.message)

def CreateProject(**request_handler_args):
    req = request_handler_args['req']
    authUser(req, request_handler_args['resp'], ['createProject'])
    doc = req.context['doc']
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
            project.uri = req.uri + '/' + str(project._id)
            request_handler_args['resp'].location = project.uri
            request_handler_args['req'].context['result'] = project.to_dict()
            req.context['logger'].info({'action': 'createProject', 'message': "'%s' project with id of %s was created successfully." % (project.name, project._id)})

def GetProjects(**request_handler_args):
    projects = []
    for project in Project.objects.all():
        project.uri = request_handler_args['req'].uri + '/' + str(project._id)
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
        project.uri = request_handler_args['req'].uri
        request_handler_args['resp'].location = project.uri
        request_handler_args['req'].context['result'] = project.to_dict()

def UpdateProject(**request_handler_args):
    req = request_handler_args['req']
    authUser(req, request_handler_args['resp'], ['createProject'])
    doc = req.context['doc']
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
                req.context['logger'].info({'action': 'updateProject', 'message': "'%s' project with id of %s was updated successfully." % (project.name, project._id)})
            except project.ValidationError as e:
                raise falcon.HTTPBadRequest("Validation Error", e.message)
            else:
                #pprint.pprint(project)
                project.uri = req.uri + '/' + str(project._id)
                request_handler_args['resp'].location = project.uri
                request_handler_args['req'].context['result'] = project.to_dict()

def DeleteProject(**request_handler_args):
    req = request_handler_args['req']
    authUser(req, request_handler_args['resp'], ['deleteProject'])
    try:
        project = Project.objects.get({"_id": ObjectId(request_handler_args['uri_fields']['id'])})
    except InvalidId as e:
        raise falcon.HTTPBadRequest('Bad Request', str(e))
    except Project.DoesNotExist:
        raise falcon.HTTPNotFound()
    else:
        project.delete()
        req.context['logger'].info({'action': 'deleteProject', 'message': "'%s' project with id of %s was updated successfully." % (project.name, project._id)})

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
    req = request_handler_args['req']
    authUser(req, request_handler_args['resp'], ['createProject'])
    doc = req.context['doc']
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
                req.context['logger'].info({'action': 'updateProjectUsers', 'message': "'%s' project with id of %s users were updated successfully." % (project.name, project._id)})

def CreateFile(**request_handler_args):
    req = request_handler_args['req']
    authUser(req, request_handler_args['resp'], ['createFile'])
    user = req.context['user']
    doc = req.context['doc']
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
                    req.context['logger'].error({'action': 'createFile', 'message': str(e)})
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
                    req.context['logger'].info({'action': 'createFile', 'message': "File/Folder '%s' was created for project %s(%s)" % (path, project.name, project._id)})
                except ACL.error as e:
                    req.context['logger'].error({'action': 'createFile', 'message': str(e)})
                    raise falcon.HTTPInternalServerError('Internal Server Error', str(e))
            else:
                raise falcon.HTTPForbidden('Forbidden', "%s is not assigned to this project." % user.username)

def SetACL(**request_handler_args):
    req = request_handler_args['req']
    authUser(req, request_handler_args['resp'], ['setACL'])
    user = req.context['user']
    doc = req.context['doc']
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
                except (KeyError, ValueError) as e:
                    raise falcon.HTTPBadRequest('Bad Request: Missing Key', e.message)
                else:
                    if matched_acl != None:
                        try:
                            ACL.SetMatchedACL(path, matched_acl)
                        except ACL.error as e:
                            req.context['logger'].error({'action': 'setACL', 'message': e[2]})
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
                            req.context['logger'].error({'action': 'setACL', 'message': str(e)})
                            raise falcon.HTTPInternalServerError('Internal Server Error', str(e))
                    else:
                        request_handler_args['resp'].status = falcon.HTTP_202
                        try:
                            req.context['result'] = {
                                    'path': path,
                                    'security': ACL.GetACL(path),
                                    'created': ProjectFS.GetCTime(path),
                                    'modified': ProjectFS.GetMTime(path),
                                    'accessed': ProjectFS.GetATime(path)
                            }
                            req.context['logger'].info({'action': 'createFile', 'message': "File/Folder '%s' was created for project %s(%s)" % (path, project.name, project._id)})
                        except ACL.error as e:
                            req.context['logger'].error({'action': 'setACL', 'message': str(e)})
                            raise falcon.HTTPInternalServerError('Internal Server Error', str(e))
            else:
                raise falcon.HTTPForbidden('Forbidden', "%s is not assigned to this project." % user.username)

def GetDoc(**request_handler_args):
    swagger_doc = open('swagger.json', 'r')
    request_handler_args['resp'].body = swagger_doc.read()

operation_handlers = {
    'createUser':                   [SetupLogger, RequireJson, ProcessJsonReq, CreateUser, ProcessJsonResp],
    'updateUser':                   [SetupLogger, RequireJson, ProcessJsonReq, UpdateUser, ProcessJsonResp],
    'deleteUser':                   [SetupLogger, DeleteUser, ProcessJsonResp],
    'getUser':                      [SetupLogger, GetUser, ProcessJsonResp],
    'getUsers':                     [SetupLogger, SetupLogger, GetUsers, ProcessJsonResp],
    'getProjects':                  [SetupLogger, GetProjects, ProcessJsonResp],
    'createProject':                [SetupLogger, RequireJson, ProcessJsonReq,CreateProject, ProcessJsonResp],
    'getProject':                   [SetupLogger, GetProject, ProcessJsonResp],
    'updateProject':                [SetupLogger, RequireJson, ProcessJsonReq, UpdateProject, ProcessJsonResp],
    'deleteProject':                [SetupLogger, DeleteProject, ProcessJsonResp],
    'createFile':                   [SetupLogger, RequireJson, ProcessJsonReq, CreateFile, ProcessJsonResp],
    'setACL':                       [SetupLogger, RequireJson, ProcessJsonReq, SetACL, ProcessJsonResp],
    'getProjectUsers':              [SetupLogger, GetProjectUsers, ProcessJsonResp],
    'updateProjectUsers':           [SetupLogger, RequireJson, ProcessJsonReq, UpdateProjectUsers, ProcessJsonResp],
    'createACLSchema':              [SetupLogger, RequireJson, ProcessJsonReq, CreateACLSchema, ProcessJsonResp],
    'getACLSchemas':                [SetupLogger, GetACLSchemas, ProcessJsonResp],
    'getACLSchema':                 [SetupLogger, GetACLSchema, ProcessJsonResp],
    'updateACLSchema':              [SetupLogger, RequireJson, ProcessJsonReq, UpdateACLSchema, ProcessJsonResp],
    'deleteACLSchema':              [SetupLogger, DeleteACLSchema, ProcessJsonResp],
    'getDoc':                       [SetupLogger, GetDoc, ProcessJsonResp]
}
'''
def setupAPI():

    connect("mongodb://localhost:27017/fsapi", alias='fsapi-app')

    api = application = falcon.API()
    server = SpecServer(operation_handlers=operation_handlers)
    with open(get_script_path() + '\\swagger.json') as f:
        server.load_spec_swagger(f.read())
    api.add_sink(server, r'/')
    return api
    #serve(api, port='8080', ident='')
'''
connect("mongodb://localhost:27017/fsapi", alias='fsapi-app')

api = application = falcon.API()
server = SpecServer(operation_handlers=operation_handlers)
with open(get_script_path() + '\\swagger.json') as f:
    server.load_spec_swagger(f.read())
api.add_sink(server, r'/')
serve(api, port='8080', ident='')


"""
to test:
gunicorn -b 127.0.0.1:8001 petstore:application
curl 127.0.0.1:8001/3.0/pet/findByStatus
curl 127.0.0.1:8001/3.0/pet/1
curl -X DELETE 127.0.0.1:8001/3.0/pet/1
"""
