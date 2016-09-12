import os

from flask import Flask
from flask_cors import CORS

from agaveflask.utils import AgaveApi
from agaveflask.auth import authn_and_authz

from resources import ServiceAccountsResource, ServiceAccountResource, ServiceAccountRolesResource, \
    RolesResource, RoleResource, RoleServiceAccountResource, ServiceAccountRoleResource

import templates

app = Flask(__name__)
CORS(app)
api = AgaveApi(app)

# Authn/z
@app.before_request
def auth():
    authn_and_authz()

# Resources
api.add_resource(ServiceAccountsResource, '/admin/service_accounts')
api.add_resource(ServiceAccountResource, '/admin/service_accounts/<string:account_id>')
api.add_resource(ServiceAccountRolesResource, '/admin/service_accounts/<string:account_id>/roles')
api.add_resource(ServiceAccountRoleResource, '/admin/service_accounts/<string:account_id>/roles/<string:role_id>')

api.add_resource(RolesResource, '/admin/roles')
api.add_resource(RoleResource, '/admin/roles/<string:role_id>')
api.add_resource(RoleServiceAccountResource, '/admin/roles/<string:role_id>/service_accounts')


def compile():
    template_src = os.environ.get('template_path', '/services/accounts/UserAdmin-am19.wsdl.j2')
    templates.render_template(template_src, '/services/accounts/UserAdmin-am19.wsdl', context=os.environ)
    print("api.py finished compiling template.")

compile()


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
