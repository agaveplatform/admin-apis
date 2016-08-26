import base64
import os

from suds.client import Client

username = 'admin'
password = 'changeme'

userpass = base64.standard_b64encode(str.encode("{}:{}".format(username, password)))

cl = Client('file://{}/UserAdmin-am19-staging.wsdl'.format(os.getcwd()))
cl.set_options(headers={'Authorization': 'Basic {}'.format(userpass.decode('utf-8'))})
cl.service.listUsers(filter='', limit=100)

