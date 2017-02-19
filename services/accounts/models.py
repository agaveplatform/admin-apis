from datetime import datetime
import json
import os
import pytz

from suds import WebFault

from agaveflask.errors import DAOError, ResourceError
from wso2admin import UserAdmin, ApiAdmin, role_out, role_in


def all_roles():
    """Get all role_id's in the system."""
    admin =  UserAdmin()
    rsp = admin.getAllRolesNames(filter='', limit=100000)
    return [role_out(r.itemName) for r in rsp if r.itemName.startswith('Internal') and not r.itemName.endswith('_PRODUCTION')]

def all_accounts():
    """Get all account_id's in the system."""
    admin = UserAdmin()
    try:
        return admin.listUsers(filter='', limit=100)
    except WebFault as e:
        raise ResourceError(msg='error retrieving accounts: {}'.format(admin.error_msg(e)))
    except Exception as e:
        raise ResourceError(msg='Uncaught exception: {}'.format(e))

def accounts(role_id):
    """List all service_accounts occupying a role."""
    admin =  UserAdmin()
    rsp = admin.getUsersOfRole(roleName=role_in(role_id), filter='*', limit=100000)
    return [r.itemName for r in rsp if r.selected and '/' not in r.itemName]

def role_summary(role_id):
    """Return a role object summary fit for display."""
    return {'id': role_out(role_id),
            'owner': 'admin',
            '_links': {'self': {
                            'href': 'https://{}/admin/roles/{}'.format(os.environ.get('base_url'), role_id)},
                       'service_accounts': {
                            'href': 'https://{}/admin/roles/{}/service_accounts'.format(os.environ.get('base_url'), role_id)},
                       'profile': {
                            'href': 'https://{}/profiles/v2/{}'.format(os.environ.get('base_url'), 'admin')}}}

def roles(account_id):
    """Get all roles occupied by `account_id`."""
    admin = UserAdmin()
    rsp = admin.getRolesOfUser(userName=account_id, filter='*', limit=100)
    return [role_out(r.itemName) for r in rsp if r.selected]

def has_role(account_id, role_id):
    """Determine if `account_id` occupies a role."""
    rs = roles(account_id)
    for r in rs:
        if r == role_id:
            return True
    return False

def role_details(role_id):
    """Return a detailed role object fit for display."""
    return dict(role_summary(role_id), **{'accounts': accounts(role_id)})

def account_summary(account_id):
    """Return a service account summary object fit for display."""
    admin = UserAdmin()
    user = admin.listUsers(filter=account_id, limit=100)
    if len(user) == 0:
        raise DAOError(msg='service account does not exist.')
    return {'id': account_id,
            'owner': 'admin',
            '_links': {'self': {
                            'href': 'https://{}/admin/service_accounts/{}'.format(os.environ.get('base_url'), account_id)},
                       'roles': {
                            'href': 'https://{}/admin/service_accounts/{}/roles'.format(os.environ.get('base_url'), account_id)},
                       'profile': {
                            'href': 'https://{}/profiles/v2/{}'.format(os.environ.get('base_url'), 'admin')}}}
def account_details(account_id):
    """Return a detailed account object fit for display."""
    return dict(account_summary(account_id), **{'roles': roles(account_id)})



def client_summary(role_id):
    """Return a client object summary fit for display."""

    # client objects have an id with form Internal_<REALM>_<owner>_<client_name>_PRODUCTION
    # OR, in case the client is owned by a service account, Internal_<owner>_<client_name>_PRODUCTION
    # since service accounts do not belong to a realm.
    is_service_owner = False
    # we have to worry about whether the service account has an underscore in the name. we check all possible
    # substrings split by "_"
    accounts = all_accounts()
    pieces = role_id.split('Internal_')[1].split('_PRODUCTION')[0].split('_')
    acs = ['_'.join(pieces[0:i]) for i in range(1, len(pieces) + 1) if '_'.join(pieces[0:i]) in accounts]
    # if acs is not empty, then the first match should be the service account
    if len(acs) > 0:
        owner = acs[0]
        try:
            name = '_'.join(pieces).split(owner + '_', 1)[1]
        except KeyError:
            name = ''
        is_service_owner = True
    # otherwise, the owner is a profile user and there is a realm in the client id
    else:
        # throw out the first piece because it is the realm, and just guess that the owner is the very first piece
        # and the client name is the rest. this will be wrong if the owner has an '_' in it.
        # TODO - really, need to validate that we have an actual profile in the case where there are more than 2 pieces
        # because the profile could actually have an "_" in it.
        owner = pieces[1]
        try:
            name = '_'.join(pieces[2:])
        except KeyError:
            name = ''
    result = {'id': role_id,
              'name': name,
              'owner': owner,
              '_links': {'self': {
                            'href': 'https://{}/admin/service_roles/{}'.format(os.environ.get('base_url'), role_id)},
                         'profile': {
                            'href': 'https://{}/profiles/v2/{}'.format(os.environ.get('base_url'), owner)}}}    # service accounts dont have a profile
    if is_service_owner:
        if owner == 'admin':
            result['_links']['owner'] = 'admin'
        else:
            result['_links']['owner'] = 'https://{}/admin/service_accounts/{}'.format(os.environ.get('base_url'), owner)
    return result


def all_clients():
    """Get all client_id's in the system."""
    admin =  UserAdmin()
    rsp = admin.getAllRolesNames(filter='', limit=100000)
    return [role_out(r.itemName) for r in rsp if r.itemName.startswith('Internal') and r.itemName.endswith('_PRODUCTION')]


def break_api_id(api_id):
    """Return components of the api id from the id itself."""
    apis = all_apis()
    for api in apis:
        candidate = "{}-{}-{}".format(api['name'], api['provider'], api['version'])
        if candidate == api_id:
            return api['name'], api['provider'], api['version']
    else:
        raise DAOError('Invalid api id -- API does not exist.')

def get_api_id(api):
    """Return the id of an API from the API description."""
    # it's possible that the `api` object is coming from wso2, in which case it will container
    # `provider`; but if it is coming from our description it will contain `owner`
    try:
        return "{}-{}-{}".format(api['name'], api['provider'], api['version'])
    except KeyError:
        return "{}-{}-{}".format(api['name'], api['owner'], api['version'])


def get_api_templates(result):
    try:
        templates_list = result.pop('templates')
    except KeyError:
        result['templates'] = []
        return result
    temps = []
    if templates_list and isinstance(templates_list, list):
        for t in templates_list:
            try:
                d = {'route': t[0],
                     'methods': t[1],
                     'roles': t[2],
                     'tiers' : t[3],
                     }
                temps.append(d)
            # if we don't get a list, or we got a short list just ignore
            except (TypeError, IndexError, KeyError):
                pass
        result['templates'] = temps
    return result

def get_api_model(api=None, api_id=None, fields=None):
    """
    Generic API model retrieval; Will retrieve the model if `api` object is none and returns fields
    provided in `fields`. Otherwise, uses the api object passed and derives additional fields as needed.
    """
    if not fields:
        # default to summary fields
        fields = ['name', 'provider', 'status', 'version']
    if api:
        result = api
    else:
        admin = ApiAdmin()
        name, provider, version = break_api_id(api_id)
        api = admin.get_api(api_name=name, api_provider=provider, api_version=version)
        if not api:
            raise DAOError(msg='API does not exist.')
        result = {key: value for key, value in api.items() if key in fields}
        if 'resources' in fields:
            try:
                result['resources'] = json.loads(api['resources'])
                # try to pull the verbs out of the resources field
                result['methods'] = []
                try:
                    for verb, value in result['resources'][0]['http_verbs'].items():
                        result['methods'].append(verb)
                except Exception:
                    pass
            except ValueError:
                # didn't get json
                pass
        if 'roles' in fields:
            roles_str = result['roles']
            result['roles'] = [role_out(r) for r in roles_str.split(',')]
        if 'templates' in fields:
            result = get_api_templates(result)
    # change 'provider' to 'owner'
    if 'provider' in result:
        result['owner'] = result.pop('provider')
    # use ISO 180 time strings -- actually, the values being returned by APIM were not valid (mysql) timestamps;
    # often times the last updated field was actually NULL in the DB but an integer was still being returned.
    # if 'lastUpdated' in fields:
    #     tz = pytz.timezone('America/Chicago')
    # #     --- this is wrong; at the very least, need to cast to int before calling fromtimestamp()
    #     result['lastUpdated'] = datetime.fromtimestamp(result['lastUpdated'], tz).isoformat()

    result['id'] = get_api_id(api)
    result.update({'_links': {'owner': result['owner'],
                              'self': 'https://{}/admin/apis/{}'.format(os.environ.get('base_url'), result['id']),
                       }})
    return result

def api_details(api_id):
    """Return an API details fit for display."""
    fields = ['context', 'name', 'provider', 'resources', 'roles', 'status', 'version',
              'visibility']
    return get_api_model(api_id=api_id, fields=fields)

def api_summary(api):
    """Return an API summary fit for display."""
    return get_api_model(api=api)

def all_apis():
    """Get all apis in the system."""
    admin = ApiAdmin()
    return admin.list_apis()