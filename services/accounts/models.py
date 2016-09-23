import os

from agaveflask.errors import DAOError
from wso2admin import UserAdmin


def role_out(role_id):
    """Convert an internal role id to an external role id."""
    return role_id.replace('Internal/', 'Internal_')

def role_in(role_id):
    """Convert an external role id to an internal role id."""
    return role_id.replace('Internal_', 'Internal/')

def all_roles():
    """Get all role_id's in the system."""
    admin =  UserAdmin()
    rsp = admin.getAllRolesNames(filter='', limit=100000)
    return [role_out(r.itemName) for r in rsp if r.itemName.startswith('Internal') and not r.itemName.endswith('_PRODUCTION')]

def all_accounts():
    """Get all account_id's in the system."""
    admin = UserAdmin()
    return admin.listUsers(filter='', limit=100)

def accounts(role_id):
    """List all service_accounts occupying a role."""
    admin =  UserAdmin()
    rsp = admin.getUsersOfRole(roleName=role_in(role_id), filter='*', limit=100000)
    return [r.itemName for r in rsp if r.selected and '/' not in r.itemName]

def role_summary(role_id):
    """Return a role object summary fit for display."""
    return {'role_id': role_out(role_id),
            '_links': {'owner': 'admin',
                       'self': 'https://{}/admin/roles/{}'.format(os.environ.get('base_url'), role_id),
                       'service_accounts':
                           'https://{}/admin/roles/{}/service_accounts'.format(os.environ.get('base_url'), role_id)}}

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
    return {'account_id': account_id,
            '_links': {'owner': 'admin',
                       'self': 'https://{}/admin/service_accounts/{}'.format(os.environ.get('base_url'), account_id),
                       'roles':
                           'https://{}/admin/service_accounts/{}/roles'.format(os.environ.get('base_url'), account_id)}}

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
    result = {'client_id': role_id,
              'client_name': name,
              'client_owner': owner,
              '_links': {'owner': 'https://{}/profiles/v2/{}'.format(os.environ.get('base_url'), owner),
                         'self': 'https://{}/admin/service_roles/{}'.format(os.environ.get('base_url'), role_id),
                       }}
    # service accounts dont have a profile
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

