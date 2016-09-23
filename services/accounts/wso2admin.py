# A python module to expose the wso2admin services
# Example Usage:
# admin = UserAdmin()
# admin.listUsers(filter='', limit=100)


import base64
import os

import requests
from suds.client import Client
from suds import WebFault

from agaveflask.errors import DAOError


class Wso2AdminException(Exception):
    def __init__(self, s):
        self.msg = s


class Wso2WSDLAdmin(object):
    """Base class providing Python binding to a WSO2 admin SOAP service."""

    def __init__(self, wsdl, username=None, password=None):
        username = username or os.environ.get('wso2admin_username', 'admin')
        password = password or os.environ.get('wso2admin_password')
        self.userpass = base64.standard_b64encode(str.encode("{}:{}".format(username, password)))
        self.wsdl = wsdl
        self.client = Client(wsdl)
        self.client.set_options(headers={'Authorization': 'Basic {}'.format(self.userpass.decode('utf-8'))})

    def __getattr__(self, key):
        return getattr(self.client.service, key)

    def error_msg(self, e):
        """Returns a properly formatted string from a suds exception."""
        if type(e) == WebFault:
            return str(e).strip('Server raised fault: ')
        # fallback for unrecognized exceptions:
        return str(e).strip('Server raised fault: ')


class UserAdmin(Wso2WSDLAdmin):
    def __init__(self):
        super(UserAdmin, self).__init__(wsdl='file:///services/accounts/UserAdmin-am19.wsdl')


class Wso2BasicAuthAdmin(object):
    """Base class providing Python binding to a WSO2 basic auth admin service."""
    def __init__(self, username=None, password=None):
        username = username or os.environ.get('wso2admin_username', 'admin')
        password = password or os.environ.get('wso2admin_password')
        self.userpass = base64.standard_b64encode(str.encode("{}:{}".format(username, password)))
        self.base_url = 'https://{}'.format(os.environ.get('base_url'))

    def _authn(self):
        """Authenticate to a WSO2 API (Store, Publisher) using basic auth."""
        data = {'action':'login',
                'username': self.username,
                'password': self.password}
        try:
            r = requests.post(self.login_url, data, verify=False)
        except Exception as e:
            raise DAOError(str(e))
        if not r.status_code == 200:
            raise DAOError("Unable to authenticate user; status code: "
                        + str(r.status_code) + "msg:" + str(r.content))
        if r.json().get("error"):
            if r.json().get("message"):
                raise DAOError(r.json().get("message").strip())
            raise DAOError("Invalid username/password combination.")
        self.cookies = r.cookies
        return r.cookies


class ApiAdmin(object):

    def __init__(self):
        super(ApiAdmin, self).__init__()
        self.login_url = self.base_url + '/publisher/site/blocks/user/login/ajax/login.jag'
        self.list_url = self.base_url + '/publisher/site/blocks/listing/ajax/item-list.jag'
        self.add_url = self.base_url + '/publisher/site/blocks/item-add/ajax/add.jag'
        self.publish_url = self.base_url + '/publisher/site/blocks/life-cycles/ajax/life-cycles.jag'
        self.delete_url = self.base_url + '/publisher/site/blocks/item-add/ajax/remove.jag'

    def list_apis(self):
        self._authn()
        rsp = requests.get(self.login_url)


