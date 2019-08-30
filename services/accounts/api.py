import os

from flask import Flask, abort
from flask_cors import CORS

from agaveflask.utils import AgaveApi, handle_error
from agaveflask.auth import authn_and_authz
from agaveflask.errors import PermissionsError

from resources import ServiceAccountsResource, ServiceAccountResource, ServiceAccountRolesResource, \
    RolesResource, RoleResource, RoleServiceAccountsResource, RoleServiceAccountResource, ServiceAccountRoleResource, \
    ClientsResource, ApisResource, ApiResource

import templates

app = Flask(__name__)
CORS(app)
api = AgaveApi(app)

# Authn/z
@app.before_request
def auth():
    authn_and_authz()

@app.errorhandler(Exception)
def handle_all_errors(e):
    return handle_error(e)

# Resources
api.add_resource(ServiceAccountsResource, '/admin/service_accounts')
api.add_resource(ServiceAccountResource, '/admin/service_accounts/<string:account_id>')
api.add_resource(ServiceAccountRolesResource, '/admin/service_accounts/<string:account_id>/roles')
api.add_resource(ServiceAccountRoleResource, '/admin/service_accounts/<string:account_id>/roles/<string:role_id>')

api.add_resource(RolesResource, '/admin/roles')
api.add_resource(RoleResource, '/admin/roles/<string:role_id>')
api.add_resource(RoleServiceAccountsResource, '/admin/roles/<string:role_id>/service_accounts')
api.add_resource(RoleServiceAccountResource, '/admin/roles/<string:role_id>/service_accounts/<string:account_id>')

api.add_resource(ClientsResource, '/admin/clients')

api.add_resource(ApisResource, '/admin/apis')
api.add_resource(ApiResource, '/admin/apis/<string:api_id>')



def compile():
    template_src = os.environ.get('template_path', '/services/accounts/UserAdmin-am19.wsdl.j2')
    wsdl_path = os.environ.get('wsdl_path', '/services/accounts/UserAdmin-am19.wsdl')
    templates.render_template(template_src, wsdl_path, context=os.environ)
    print("api.py finished compiling template.")

compile()


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
