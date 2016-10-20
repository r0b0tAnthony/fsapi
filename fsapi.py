import falcon
import falcon.status_codes as status
from serve_swagger import SpecServer
from waitress import serve
from pymodm import connect
from resources.models import User, Project, Schema
import pprint
import json

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

def createUser(**request_handler_args):
    authUser(request_handler_args['req'], request_handler_args['resp'], ['createUser'])
    doc = request_handler_args['req'].context['doc']
    try:
        user = User(username = doc['username'], password = doc['password'], permissions = doc['permissions'], auth_b64 = User.GetAuthBase64(doc['username'], doc['password'])).save()
        request_handler_args['req'].context['result'] = user.to_dict()
    except KeyError as e:
        raise falcon.HTTPBadRequest('Invalid User Object', "User JSON Object is invalid. %s" % e)

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
    'createUser':                   [RequireJson, ProcessJsonReq, createUser, ProcessJsonResp],
    'updateUser':                   [not_found],
    'deleteUser':                   [not_found],
    'getUsers':                     [not_found],
    'getProjects':                  [not_found],
    'createProject':                [not_found],
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
    'createACLSchema':              [not_found],
    'getACLSchemas':                [not_found],
    'getACLSchema':                 [not_found],
    'updateACLSchema':              [not_found],
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
