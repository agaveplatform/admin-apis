from flask import g, request
from flask_restful import Resource

from suds import WebFault

from agaveflask.utils import ok, error, RequestParser, APIException

from wso2admin import UserAdmin, Wso2AdminException

class ServiceAccountsResource(Resource):

    def get(self):
        admin = UserAdmin()
        users = admin.listUsers(filter='', limit=100)
        result = {'accounts': users}
        return ok(result=result, msg="Service accounts retrieved successfully.")


    def validate_post(self):
        parser = RequestParser()
        parser.add_argument('account_id', type=str, required=True, help='The id for the service account.')
        parser.add_argument('password', type=str, required=True, help='The password for the service account.')
        return parser.parse_args()

    def post(self):
        args = self.validate_post()
        admin = UserAdmin()
        try:
            admin.addUser(userName=args['account_id'], password=args['password'])
        except WebFault as e:
            return error(msg=admin.error_msg(e))
        except Exception as e:
            return error(msg='Uncaught exception: {}'.format(e))
        return ok(result={'account_id': args['account_id']}, msg="Service account created successfully.")


class ServiceAccountResource(Resource):

    def get(self, account_id):
        admin = UserAdmin()
        user = admin.listUsers(filter=account_id, limit=100)
        result = {'account': user}
        return ok(result=result, msg="Service account retrieved successfully.")

    def delete(self, account_id):
        admin = UserAdmin()
        try:
            admin.deleteUser(userName=account_id)
        except WebFault as e:
            return error(msg=admin.error_msg(e))
        except Exception as e:
            return error(msg='Uncaught exception: {}'.format(e))
        return ok(result={'account_id': account_id}, msg="Service account deleted successfully.")


def roles(admin, account_id):
    """Get all roled occupied by `account_id`."""
    rsp = admin.getRolesOfUser(userName=account_id, filter='*', limit=100)
    return [r.itemName.replace('/', '_') for r in rsp if r.selected]

def has_role(admin, account_id, role_id):
    rs = roles(admin, account_id)
    for r in rs:
        if r == role_id:
            return True
    return False

class ServiceAccountRolesResource(Resource):

    def get(self, account_id):
        admin = UserAdmin()
        try:
            return ok(result={'roles': roles(admin, account_id)}, msg="Roles retrieved successfully.")
        except WebFault as e:
            return error(msg=admin.error_msg(e))
        except Exception as e:
            return error(msg='Uncaught exception: {}'.format(e))

    def validate_post(self):
        parser = RequestParser()
        parser.add_argument('role_id', type=str, required=True, help='The id of the role to add to the service account.')
        return parser.parse_args()

    def post(self, account_id):
        args = self.validate_post()
        admin = UserAdmin()
        try:
            admin.updateRolesOfUser(userName=account_id, newUserList=args['role_id'].replace('_', '/'))
        except WebFault as e:
            return error(msg=admin.error_msg(e))
        except Exception as e:
            return error(msg='Uncaught exception: {}'.format(e))
        return ok(result={'roles': roles(admin, account_id)}, msg="Role {} added successfully.".format(args['role_id']))


class ServiceAccountRoleResource(Resource):

    def get(self, account_id, role_id):
        admin = UserAdmin()
        if has_role(admin, account_id, role_id):
            return ok(result={'role_id': role_id}, msg="Role retrieved successfully.")
        return error(msg="{} does not occupy role {}".format(account_id, role_id))

    def delete(self, account_id, role_id):
        admin = UserAdmin()
        if has_role(admin, account_id, role_id):
            try:
                admin.addRemoveRolesOfUser(userName=account_id, deletedRoles=role_id.replace('_', '/'))
            except WebFault as e:
                return error(msg=admin.error_msg(e))
            except Exception as e:
                return error(msg='Uncaught exception: {}'.format(e))
        else:
            return error(msg="{} does not occupy role {}".format(account_id, role_id))
        return ok(result={'account_id': account_id, 'roles': roles(admin, account_id)},
                  msg='Role {} removed from service account.'.format(role_id))

def allroles(admin):
    """Get all roles in the system."""
    rsp = admin.getAllRolesNames(filter='', limit=100000)
    return [r.itemName.replace('/', '_') for r in rsp if r.itemName.startswith('Internal')]

def accounts(admin, role_id):
    """ Get all service_accounts occupying a role.
    :param admin:
    :param role_id:
    :return:
    """
    rsp = admin.getUsersOfRole(roleName=role_id.replace('_', '/'), filter='*', limit=100000)
    return [r.itemName for r in rsp if r.selected and not '/' in r.itemName]



class RolesResource(Resource):

    def get(self):
        return ok(result={'roles': allroles(UserAdmin())}, msg="Roles retrieved successfully.")

    def validate_post(self):
        parser = RequestParser()
        parser.add_argument('role_id', type=str, required=True, help='The id of the role to add to the system.')
        return parser.parse_args()

    def post(self):
        args = self.validate_post()
        admin = UserAdmin()
        try:
            admin.addInternalRole(roleName=args['role_id'].replace('_', '/'))
        except WebFault as e:
            raise APIException(admin.error_msg(e), 400)
        except Exception as e:
            raise APIException('Uncaught exception: {}'.format(e), 400)
        return ok(result={'role_id': args['role_id']}, msg="Role {} created successfully.".format(args['role_id']))


class RoleResource(Resource):

    def get(self, role_id):
        admin = UserAdmin()
        if role_id in allroles(admin):
            return ok(result={'role_id': role_id}, msg="Role retrieved successfully.")
        else:
            raise APIException("Role not found.", 404)

    def delete(self, role_id):
        admin = UserAdmin()
        try:
            admin.deleteRole(roleName=role_id.replace('_', '/'))
        except WebFault as e:
            raise APIException(admin.error_msg(e), 400)
        except Exception as e:
            raise APIException('Uncaught exception: {}'.format(e), 400)
        return ok(result={}, msg="Role {} deleted successfully.".format(role_id))


class RoleServiceAccountsResource(Resource):

    def get(self, role_id):
        admin = UserAdmin()
        try:
            return ok(result={'service_accounts': accounts(admin, role_id)},
                      msg="Service accounts retrieved successfully.")
        except WebFault as e:
            return error(msg=admin.error_msg(e))
        except Exception as e:
            return error(msg='Uncaught exception: {}'.format(e))

    def validate_post(self):
        parser = RequestParser()
        parser.add_argument('account_id',
                            type=str,
                            required=True,
                            help='The id of the service account to add to the role.')
        return parser.parse_args()

    def post(self, role_id):
        args = self.validate_post()
        admin = UserAdmin()
        try:
            admin.addRemoveUsersOfRole(roleName=role_id.replace('_', '/'), newUsers=args['account_id'])
        except WebFault as e:
            raise APIException(admin.error_msg(e), 400)
        except Exception as e:
            raise APIException('Uncaught exception: {}'.format(e), 400)
        return ok(result={'role_id': args['role_id'], 'service_accounts': accounts(admin, role_id)},
                  msg="Service account {} added to role.".format(args['account_id']))

class RoleServiceAccountResource(Resource):

    def get(self, role_id, account_id):
        admin = UserAdmin()
        if has_role(admin, account_id, role_id):
            return ok(result={'account_id': account_id}, msg="Service account retrieved successfully.")
        return error(msg="{} is not occupied by service account {}".format(role_id, account_id))

    def delete(self, role_id, account_id):
        admin = UserAdmin()
        if has_role(admin, account_id, role_id):
            # remove user from the role
            try:
                admin.addRemoveUsersOfRole(roleName=role_id.replace('_', '/'), deletedUsers=account_id)
            except WebFault as e:
                raise APIException(admin.error_msg(e), 400)
            except Exception as e:
                raise APIException('Uncaught exception: {}'.format(e), 400)
            return ok(result={'service_accounts': accounts(admin, role_id)},
                      msg="Service account {} removed from role {}.".format(account_id, role_id))
        return error(msg="{} is not occupied by service account {}".format(role_id, account_id))

