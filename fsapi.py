import falcon
import falcon.status_codes as status
from serve_swagger import SpecServer
from waitress import serve

def createFile(**request_handler_args):
        resp = request_handler_args['resp']
        resp.status = falcon.HTTP_200
        resp.body = ("%s HELP HELP" % resp.body)
def authUser(**request_handler_args):
    req = request_handler_args['req']
    resp = request_handler_args['resp']
    authHeader = req.get_header('Authorization')
    resp.status = falcon.HTTP_200
    resp.body = authHeader

def not_found(**request_handler_args):
    raise falcon.HTTPNotFound('Not found.', 'Requested resource not found.')

def forbidden(**request_handler_args):
    raise falcon.HTTPForbidden('Forbidden.', 'You are forbidden from accessing this.')

def im_a_teapot(**request_handler_args):
    resp = request_handler_args['resp']
    resp.status = status.HTTP_IM_A_TEAPOT

operation_handlers = {
    'createUser':                   [not_found],
    'updateUser':                   [not_found],
    'deleteUser':                   [not_found],
    'getUsers':                     [not_found],
    'getProjects':                  [not_found],
    'createProject':                [not_found],
    'getProject':                   [not_found],
    'updateProject':                [not_found],
    'deleteProject':                [not_found],
    'createFile':                   [authUser, createFile],
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
