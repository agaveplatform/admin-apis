import os

from wso2admin import UserAdmin

def role_out(role_id):
    """Convert an internal role id to an external role id."""
    return role_id.replace('/', '_')

def role_in(role_id):
    """Convert an external role id to an internal role id."""
    return role_id.replace('_', '/')

def all_roles():
    """Get all role_id's in the system."""
    admin =  UserAdmin()
    rsp = admin.getAllRolesNames(filter='', limit=100000)
    return [role_out(r.itemName) for r in rsp if r.itemName.startswith('Internal')]

def all_accounts():
    """Get all account_id's in the system."""
    admin = UserAdmin()
    return admin.listUsers(filter='', limit=100)

def accounts(role_id):
    """List all service_accounts occupying a role."""
    admin =  UserAdmin()
    rsp = admin.getUsersOfRole(roleName=role_id.replace('_', '/'), filter='*', limit=100000)
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
    return {'account_id': account_id,
            '_links': {'owner': 'admin',
                       'self': 'https://{}/admin/service_accounts/{}'.format(os.environ.get('base_url'), account_id),
                       'roles':
                           'https://{}/admin/service_accounts/{}/roles'.format(os.environ.get('base_url'), account_id)}}

def account_details(account_id):
    """Return a detailed account object fit for display."""
    return dict(account_summary(account_id), **{'roles': roles(account_id)})
