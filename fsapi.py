import falcon
import falcon.status_codes as status
from serve_swagger import SpecServer
from waitress import serve
from pymodm import connect
from resources.models import User, Project, Schema
from resources.acl import ACL
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
        # Nothing to do
        return

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
    if req.method in ('POST', 'PUT'):
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
        user.username = doc['username']
        user.password = doc['password']
        user.permissions = doc['permissions']
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
        raise falcon.HTTPBadRequest('Invalid Schema Object', "Schema JSON Object is invalid. %s" % e)
    else:
        try:
            schema.save()
        except Schema.ValidationError as e:
            raise falcon.HTTPBadRequest("Validation Error", e.message)
        else:
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
        raise falcon.HTTPBadRequest('Bad Request', str(e))
    except Schema.DoesNotExist:
        raise falcon.HTTPNotFound()
    else:
        schema.name = doc['name']
        schema.schema = doc['schema']
        schema.modified = datetime.datetime.now()
        try:
            schema.save()
        except schema.ValidationError as e:
            raise falcon.HTTPBadRequest("Validation Error", e.message)
        else:
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
        schema.delete()

def CreateProject(**request_handler_args):
    authUser(request_handler_args['req'], request_handler_args['resp'], ['createProject'])
    doc = request_handler_args['req'].context['doc']
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
        project_schema = Schema.objects.get({'_id': ObjectId(doc['acl_schema'])})
    except InvalidId as e:
        raise falcon.HTTPBadRequest('Bad Request', str(e))

    try:
        project = Project(name = doc['name'], acl_schema = project_schema, paths = doc['paths'], users = project_users)
    except KeyError as e:
        raise falcon.HTTPBadRequest('Invalid Schema Object', "Schema JSON Object is invalid. %s" % e)
    else:
        try:
            project.save()
        except project.ValidationError as e:
            raise falcon.HTTPBadRequest("Validation Error", e.message)
        else:
            #pprint.pprint(project)
            request_handler_args['req'].context['result'] = project.to_dict()

def GetProjects(**request_handler_args):
    projects = []
    for project in Project.objects.all():
        projects.append(project.to_dict())
    request_handler_args['req'].context['result'] = projects

def createFile(**request_handler_args):
        resp = request_handler_args['resp']
        resp.status = falcon.HTTP_200
        resp.body = ("%s HELP HELP" % resp.body)

def authUser(req, resp, permissions):
    authHeader = req.get_header('Authorization')
    if authHeader == None:
        raise falcon.HTTPMissingHeader('Authorization')
    resp.status = falcon.HTTP_200
    try:
        user = User.objects.get({"auth_b64": authHeader[6:]})
        diff_perms = list(set(permissions) - set(User.valid_permissions))
        if len(diff_perms) > 0:
            raise falcon.HTTPForbidden('Forbidden', "%s does not have the required permissions: %s" % (user.username, ', '.join(diff_perms)))
    except User.DoesNotExist:
        raise falcon.HTTPForbidden('Forbidden','Username and password does not exist.')


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
    'getProject':                   [not_found],
    'updateProject':                [not_found],
    'deleteProject':                [not_found],
    'createFile':                   [createFile],
    'getFile':                      [not_found],
    'setACL':                       [not_found],
    'getACL':                       [not_found],
    'getProjectUsers':              [not_found],
    'updateProjectUsers':           [not_found],
    'deleteProjectUser':            [not_found],
    'createACLSchema':              [RequireJson, ProcessJsonReq, CreateACLSchema, ProcessJsonResp],
    'getACLSchemas':                [GetACLSchemas, ProcessJsonResp],
    'getACLSchema':                 [GetACLSchema, ProcessJsonResp],
    'updateACLSchema':              [RequireJson, ProcessJsonReq, UpdateACLSchema, ProcessJsonResp],
    'deleteACLSchema':              [not_found],
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
