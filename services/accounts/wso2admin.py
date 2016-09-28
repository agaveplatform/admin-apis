# A python module to expose the wso2admin services
# Example Usage:
# admin = UserAdmin()
# admin.listUsers(filter='', limit=100)


import base64
import json
import os

import requests
from suds.client import Client
from suds import WebFault

from agaveflask.errors import DAOError

API_VERSION = 'v2'

class Wso2AdminException(Exception):
    def __init__(self, s):
        self.msg = s


class Wso2WSDLAdmin(object):
    """Base class providing Python binding to a WSO2 admin SOAP service."""

    def __init__(self, wsdl, username=None, password=None):
        self.username = username or os.environ.get('wso2admin_username', 'admin')
        self.password = password or os.environ.get('wso2admin_password')
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
        self.username = username or os.environ.get('wso2admin_username', 'admin')
        self.password = password or os.environ.get('wso2admin_password')
        self.userpass = base64.standard_b64encode(str.encode("{}:{}".format(username, password)))
        self.base_url = 'https://{}'.format(os.environ.get('base_url'))
        if self.verify_str.lower() == 'true':
            self.verify = True
        else:
            self.verify = False

    def _authn(self):
        """Authenticate to a WSO2 API (Store, Publisher) using basic auth."""
        data = {'action':'login',
                'username': self.username,
                'password': self.password}
        try:
            r = requests.post(self.login_url, data, verify=self.verify)
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


class ApiAdmin(Wso2BasicAuthAdmin):

    def __init__(self):
        super(ApiAdmin, self).__init__()
        self.login_url = self.base_url + '/publisher/site/blocks/user/login/ajax/login.jag'
        self.list_url = self.base_url + '/publisher/site/blocks/listing/ajax/item-list.jag'
        self.add_url = self.base_url + '/publisher/site/blocks/item-add/ajax/add.jag'
        self.status_url = self.base_url + '/publisher/site/blocks/life-cycles/ajax/life-cycles.jag'
        self.delete_url = self.base_url + '/publisher/site/blocks/item-add/ajax/remove.jag'

    def list_apis(self):
        self._authn()
        params = {'action': 'getAllAPIs'}
        rsp = requests.get(self.list_url, cookies=self.cookies, params=params, verify=self.verify)

        return rsp.json().get('apis')

    def get_api(self, api_name, api_version=API_VERSION, api_provider='admin'):
        self._authn()
        params = {'action': 'getAPI',
                  'name': api_name,
                  'version': api_version,
                  'provider': api_provider}
        rsp = requests.post(self.list_url, cookies=self.cookies, params=params, verify=self.verify)
        return rsp.json().get('api')

    def audit_api_def(self, d):
        """Check an API definition for correctness."""
        if not d.get('api_name'):
            raise DAOError('api_name is required.')
        if not d.get('context'):
            raise DAOError('context is required.')
        if not d.get('url'):
            raise DAOError('url is required: should be the production URL for the API.')
        if d.get('visibility'):
            if d.get('visibility').lower() not in ('public', 'restricted'):
                raise DAOError('visibility, if defined, must be either `public` or `restricted`.')
            if d.get('visibility').lower() == 'restricted':
                if not d.get('roles'):
                    raise DAOError('roles is required for visibility `restricted`. '
                                   'These are the roles required to subscribe to the API.')
                # roles should be a list and not a string
                if isinstance(d.get('roles'), str):
                    raise DAOError('roles should be a list, not a string.')
        if not d.get('methods'):
            raise DAOError('methods is required with at least one method from GET, POST, PUT, DELETE, HEAD.')
        try:
            for method in d.get('methods'):
                try:
                    if method.upper() not in ('GET', 'POST', 'PUT', 'DELETE', 'HEAD'):
                        raise DAOError('Invalid method {}: methods must be in (GET, POST, PUT, DELETE, HEAD).'.format(method))
                except AttributeError:
                    raise DAOError('Invalid method found {}: methods must be strings.'.format(method))
        except TypeError:
            raise DAOError('methods attribute must be an iterable list of strings, each in (GET, POST, PUT, DELETE, HEAD).')
        # auth can be either a string in ('none', 'oauth') or a list of strings, each of which in ('none', 'oauth').
        # in the latter case, the list should be as long as the method list
        auth = d.get('auth', '')
        if auth:
            if isinstance(auth, str):
                if auth.lower() not in ('none', 'oauth'):
                    raise DAOError('{} is not a valid auth value. auth should be in (none, oauth).'.format(auth))
            else:
                try:
                    auth_len = len(auth)
                except TypeError:
                    raise DAOError('auth parameter must be a single string or a list of string in (none, oauth).')
                if not auth_len == len(d.get('methods')):
                    raise DAOError('auth list must have same length as methods list.')
                for a in auth:
                    if a.lower() not in ('none', 'oauth'):
                        raise DAOError('{} is not a valid auth value. auth should be in (none, oauth).'.format(a))


    def add_api(self, d):
        """Add a new API from description, `d`, which should be a dictionary with the following fields."""
        self._authn()
        # by default, all apis are assumed to use http
        self.audit_api_def(d)
        endpoint_config = {
            'production_endpoints': {'url': d.get('url'),
                                     'config': ''},
            # note that endpoint_type for BOTH http and https endpoints should be `http`; see the wso2 docs here:
            # https://docs.wso2.com/display/AM190/Publisher+APIs
            # the actual protocol used by the backend service should be included in the `url` parameter.
            'endpoint_type': 'http'
        }
        params = {'action': 'addAPI',
                  'name': d.get('api_name'),
                  'context': d.get('context'),
                  'version': d.get('version', API_VERSION),
                  'visibility': d.get('visibility', 'public'),
                  'thumbUrl': '',
                  'description': d.get('description', ''),
                  'tags': d.get('tags', ''),
                  # this attribute dictates whether an additional username/password is needed to invoke the API. we
                  # don't ever need to use this feature
                  'endpointType': 'nonsecured',
                  # all tiers available to all APIs
                  'tiersCollection': 'Unlimited,Gold,Silver,Bronze',
                  # all our APIs use https for the front-end transport. The backend transport is governed by `url`.
                  'http_checked': '',
                  'https_checked': 'https',
                  'default_version_checked': '',
                  'default_version': '',
                  'bizOwnerMail': '',
                  'techOwner': '',
                  'techOwnerMail': '',
                  'endpoint_config': json.dumps(endpoint_config),
                  }
        # ensure lowercase
        params['visibility'] = params['visibility'].lower()
        #  add roles to params when visibility is restricted
        if params['visibility'] == 'restricted':
            try:
                role_str = ','.join(d.get('roles'))
            except TypeError:
                raise DAOError('Invalid roles parameter: roles must be an iterable list of role strings.')

            params['roles'] = role_str
        # add methods, auth types and throttling tiers
        methods = d.get('methods')
        auth = d.get('auth', 'oauth')
        params['resourceCount'] = len(methods)
        for i in range(len(methods)):
            params['resourceMethod-{}'.format(i)] = methods[i]
            params['uriTemplate-{}'.format(i)] = '/*'
            params['resourceMethodThrottlingTier-{}'.format(i)]= 'Unlimited'
            if isinstance(auth, str):
                if auth.lower() == 'oauth':
                    params['resourceMethodAuthType-{}'.format(i)] = 'Application and Application User'
                else:
                    params['resourceMethodAuthType-{}'.format(i)] = 'None'
            else:
                if auth[i].lower() == 'oauth':
                    params['resourceMethodAuthType-{}'.format(i)] = 'Application and Application User'
                else:
                    params['resourceMethodAuthType-{}'.format(i)] = 'None'
        try:
            rsp = requests.post(self.add_url, cookies=self.cookies, params=params, verify=self.verify)
        except Exception as e:
            raise DAOError('There was an error trying to add the API. Details: {}'.format(e))
        return rsp

    def update_api_status(self, api_name, status='PUBLISHED', api_version='v2', api_provider='admin'):
        """Update the status of an api to `status`."""
        self._authn()
        params = {'action': 'updateStatus',
                  'name': api_name,
                  'version': api_version,
                  'status': status,
                  'provider': api_provider,
                  'publishToGateway': 'true',
                  'requireResubscription': 'false'
                  }
        try:
            rsp = requests.post(self.status_url, cookies=self.cookies, params=params, verify=self.verify)
        except Exception as e:
            raise DAOError('There was an error trying to add the API. Details: {}'.format(e))
        return rsp.json().get('lcs')

    def delete_api(self, api_name, api_version='v2', api_provider='admin'):
        self._authn()
        params = {'action': 'removeAPI',
                  'name': api_name,
                  'version': api_version,
                  'provider': api_provider,
                  }
        try:
            rsp = requests.post(self.delete_url, cookies=self.cookies, params=params, verify=self.verify)
        except Exception as e:
            raise DAOError('There was an error trying to add the API. Details: {}'.format(e))
        return rsp

