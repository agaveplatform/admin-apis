from flask import Flask
from flask_cors import CORS

from agaveflask.utils import AgaveApi
from agaveflask.auth import authn_and_authz

from resources import JwtResource

app = Flask(__name__)
CORS(app)
api = AgaveApi(app)

# Authn/z
@app.before_request
def auth():
    authn_and_authz()

# Resources
api.add_resource(JwtResource, '/admin/jwt')

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
