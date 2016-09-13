# A python module to expose the wso2admin services
# Example Usage:
# admin = UserAdmin()
# admin.listUsers(filter='', limit=100)


import base64
import os

from suds.client import Client
from suds import WebFault

class Wso2AdminException(Exception):
    def __init__(self, s):
        self.msg = s


class Wso2Admin(object):
    """Base class for interacting with a WSO2 admin SOAP service."""

    def __init__(self, username, password, wsdl):
        self.username = username
        self.password = password
        self.userpass = base64.standard_b64encode(str.encode("{}:{}".format(username, password)))
        self.wsdl = wsdl
        self.client = Client(wsdl)
        self.client.set_options(headers={'Authorization': 'Basic {}'.format(self.userpass.decode('utf-8'))})

    def error_msg(self, e):
        """Returns a properly formatted string from a suds exception."""
        if type(e) == WebFault:
            return str(e).strip('Server raised fault: ')
        # fallback for unrecognized exceptions:
        return str(e).strip('Server raised fault: ')

class UserAdmin(Wso2Admin):
    def __init__(self):
        username = os.environ.get('wso2admin_username', 'admin')
        password = os.environ.get('wso2admin_password')
        super(UserAdmin, self).__init__(username, password, 'file:///services/accounts/UserAdmin-am19.wsdl')

    def __getattr__(self, key):
        return getattr(self.client.service, key)
