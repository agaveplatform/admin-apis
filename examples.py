import base64
import os
import ssl

from suds.client import Client

ssl._create_default_https_context = ssl._create_unverified_context

username = 'admin'
password = os.environ.get('wso2admin_password','changeme')

userpass = base64.standard_b64encode(str.encode("{}:{}".format(username, password)))

cl = Client('file://{}/UserAdmin-am19.wsdl'.format(os.getcwd()))
cl.set_options(headers={'Authorization': 'Basic {}'.format(userpass.decode('utf-8'))})
cl.service.listUsers(filter='', limit=100)

# curl -H "X-Jwt-Assertion-AGAVE-PROD: $jwt" localhost:5000/admin/jwt
