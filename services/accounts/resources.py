from flask import g, request
from flask_restful import Resource

from suds import WebFault

from agaveflask.utils import ok, error, RequestParser
from agaveflask.errors import DAOError, ResourceError

import models
from wso2admin import ApiAdmin, UserAdmin


class ServiceAccountsResource(Resource):
    """Manage service accounts in the system."""

    def get(self):
        """List all service accounts in the system."""
        return ok(result=[models.account_summary(a) for a in models.all_accounts()],
              msg="Service accounts retrieved successfully.")

    def validate_post(self):
        parser = RequestParser()
        parser.add_argument('accountId', type=str, required=True, help='The id for the service account.')
        parser.add_argument('password', type=str, required=True, help='The password for the service account.')
        return parser.parse_args()

    def post(self):
        """Create a new service account."""
        args = self.validate_post()
        account_id = args['accountId']
        if '-' in account_id:
            raise ResourceError(msg="Invalid account id: no '-' characters are allowed.")
        admin = UserAdmin()
        try:
            admin.addUser(userName=account_id, password=args['password'])
        except WebFault as e:
            raise ResourceError(msg=admin.error_msg(e))
        except Exception as e:
            raise ResourceError(msg='Uncaught exception: {}'.format(e))
        return ok(result=models.account_details(account_id), msg="Service account created successfully.")


class ServiceAccountResource(Resource):
    """Manage a specific service account."""

    def get(self, account_id):
        """Get details about a service account."""
        return ok(result=models.account_details(account_id), msg="Service account retrieved successfully.")

    def delete(self, account_id):
        """Delete a service account."""
        admin = UserAdmin()
        try:
            admin.deleteUser(userName=account_id)
        except WebFault as e:
            raise ResourceError(msg=admin.error_msg(e))
        return ('', 204)


class ServiceAccountRolesResource(Resource):
    """Manage the roles occupied by a service account."""

    def get(self, account_id):
        """List all roles occupied by a service account."""
        try:
            return ok(result=models.account_details(account_id), msg="Roles retrieved successfully.")
        except WebFault as e:
            admin = UserAdmin()
            raise ResourceError(msg=admin.error_msg(e))

    def validate_post(self):
        parser = RequestParser()
        parser.add_argument('roleId', type=str, required=True, help='The id of the role to add to the service account.')
        return parser.parse_args()

    def post(self, account_id):
        """Add a role to the list of roles occupied by a service account."""
        args = self.validate_post()
        admin = UserAdmin()
        try:
            admin.updateRolesOfUser(userName=account_id, newUserList=models.role_in(args['roleId']))
        except WebFault as e:
            raise ResourceError(msg=admin.error_msg(e))
        return ok(result=models.account_details(account_id), msg="Role {} added successfully.".format(args['roleId']))


class ServiceAccountRoleResource(Resource):
    """Manage a service account's occupation of a specific role."""

    def get(self, account_id, role_id):
        """Get details about a service account's occupation of a role."""
        if models.has_role(account_id, role_id):
            return ok(result=models.role_details(role_id), msg="Role retrieved successfully.")
        raise ResourceError(msg="{} does not occupy role {}".format(account_id, role_id))

    def delete(self, account_id, role_id):
        """Remove a role from a service account's list of occupied roles."""
        if models.has_role(account_id, role_id):
            admin = UserAdmin()
            try:
                admin.addRemoveRolesOfUser(userName=account_id, deletedRoles=models.role_in(role_id))
            except WebFault as e:
                raise ResourceError(msg=admin.error_msg(e))
        else:
            raise ResourceError(msg="{} does not occupy role {}".format(account_id, role_id))
        return ('', 204)


class RolesResource(Resource):
    """Manage roles in the system."""

    def get(self):
        """List all roles in the system."""
        return ok(result=[models.role_summary(r) for r in models.all_roles()],
                  msg="Roles retrieved successfully.")

    def validate_post(self):
        parser = RequestParser()
        parser.add_argument('roleId', type=str, required=True, help='The id of the role to add to the system.')
        return parser.parse_args()

    def post(self):
        """Create a new role."""
        args = self.validate_post()
        role_id = args['roleId']
        admin = UserAdmin()
        try:
            admin.addInternalRole(roleName=models.role_in(role_id))
        except WebFault as e:
            raise ResourceError(admin.error_msg(e))
        return ok(result=models.role_details(role_id), msg="Role {} created successfully.".format(args['roleId']))


class RoleResource(Resource):

    def get(self, role_id):
        """Get details about a role."""
        if role_id in models.all_roles():
            return ok(result=models.role_details(role_id), msg="Role retrieved successfully.")
        else:
            raise ResourceError(msg="Role not found.", code=404)

    def delete(self, role_id):
        """Delete a role from the system."""
        admin = UserAdmin()
        try:
            admin.deleteRole(roleName=models.role_in(role_id))
        except WebFault as e:
            raise ResourceError(admin.error_msg(e))
        return ('', 204)


class RoleServiceAccountsResource(Resource):

    def get(self, role_id):
        """List service accounts occupying a role."""
        try:
            return ok(result=models.role_details(role_id),
                      msg="Service accounts retrieved successfully.")
        except WebFault as e:
            admin = UserAdmin()
            raise ResourceError(msg=admin.error_msg(e))

    def validate_post(self):
        parser = RequestParser()
        parser.add_argument('accountId',
                            type=str,
                            required=True,
                            help='The id of the service account to add to the role.')
        return parser.parse_args()

    def post(self, role_id):
        """Add a service account to the list of accounts occupying a role."""
        args = self.validate_post()
        admin = UserAdmin()
        try:
            admin.addRemoveUsersOfRole(roleName=models.role_in(role_id), newUsers=args['accountId'])
        except WebFault as e:
            raise ResourceError(admin.error_msg(e))
        return ok(result=models.role_details(role_id),
                  msg="Service account {} added to role.".format(args['accountId']))


class RoleServiceAccountResource(Resource):
    """Manage a specific service account's occupation of a role."""

    def get(self, role_id, account_id):
        """List details about a service account's occupation of a role."""
        if models.has_role(account_id, role_id):
            return ok(result=models.account_details(account_id), msg="Service account retrieved successfully.")
        raise ResourceError(msg="{} is not occupied by service account {}".format(role_id, account_id))

    def delete(self, role_id, account_id):
        """Remove service account from a role's list of service account occupying it."""
        admin = UserAdmin()
        if models.has_role(account_id, role_id):
            # remove user from the role
            try:
                admin.addRemoveUsersOfRole(roleName=models.role_in(role_id), deletedUsers=account_id)
            except WebFault as e:
                raise ResourceError(admin.error_msg(e))
            return ('', 204)
        raise ResourceError(msg="{} is not occupied by service account {}".format(role_id, account_id))


class ClientsResource(Resource):
    """Manage OAuth clients in the system."""

    def get(self):
        """List all roles in the system."""
        return ok(result=[models.client_summary(c) for c in models.all_clients()],
                  msg="Clients retrieved successfully.")


class ApisResource(Resource):
    """Manage APIs in the system."""

    def get(self):
        """List all APIs in the system."""
        return ok(result=[models.api_summary(a) for a in models.all_apis()],
                  msg="APIs retrieved successfully.")

    def post(self):
        """Create a new API."""
        json_data = request.get_json()
        if not json_data:
            raise ResourceError(msg="Content type JSON required for creating APIs.")
        admin = ApiAdmin()
        try:
            admin.audit_api_def(json_data)
        except DAOError as e:
            raise ResourceError(msg="Invalid API definition: {}".format(e))
        try:
            rsp = admin.add_api(json_data)
        except DAOError as e:
            raise ResourceError(msg='Error trying to add API: {}'.format(e))
        if not rsp.status_code == 200 or rsp.json().get('error'):
            raise ResourceError(msg='Error trying to add API: {}'.format(rsp.content))
        a = {}
        a['name'] = json_data.get('name')
        a['version'] = json_data.get('version') or 'v2'
        a['provider'] = 'admin'
        return ok(result=models.api_details(models.get_api_id(a)),
                  msg="API created successfully.")


class ApiResource(Resource):
    """Manage a specific API."""

    def get(self, api_id):
        """Get details about an API."""
        return ok(result=models.api_details(api_id), msg="API retrieved successfully.")

    def post(self, api_id):
        """Update an API."""
        json_data = request.get_json()
        if not json_data:
            raise ResourceError(msg="Content type JSON required for creating APIs.")
        # first, find the API
        try:
            api = models.get_api_model(api_id=api_id)
        except DAOError:
            raise ResourceError(msg="API not found.")
        except TypeError as e:
            raise ResourceError(msg="Problem looking up API: {}.".format(e))

        admin = ApiAdmin()
        try:
            rsp = admin.update_api(json_data)
        except DAOError as e:
            raise ResourceError(msg='Error trying to update API: {}'.format(e))
        if not rsp.status_code == 200 or rsp.json().get('error'):
            raise ResourceError(msg='Error trying to update API: {}'.format(rsp.content))
        a = {}
        a['name'] = json_data.get('name')
        a['version'] = json_data.get('version') or 'v2'
        a['provider'] = 'admin'
        return ok(result=models.api_details(models.get_api_id(a)),
                  msg="API created successfully.")


    def validate_put(self):
        parser = RequestParser()
        parser.add_argument('status', type=str, required=True, help='The status for the API.')
        return parser.parse_args()

    def put(self, api_id):
        """ Update an api status.
        :param api_id:
        :return:
        """
        # first, find the API
        try:
            api = models.get_api_model(api_id=api_id)
        except DAOError:
            raise ResourceError(msg="API not found.")
        except TypeError as e:
            raise ResourceError(msg="Problem looking up API: {}.".format(e))
        args = self.validate_put()
        status = args['status']
        API_STATUSES = ('CREATED', 'PUBLISHED', 'RETIRED')
        if status not in API_STATUSES:
            raise ResourceError(msg='Invalid API status: must be one of {}'.format(API_STATUSES))
        admin = ApiAdmin()
        try:
            admin.update_api_status(api_name=api['name'],
                                    api_version=api['version'],
                                    api_provider=api['owner'],
                                    status=status)
        except DAOError as e:
            raise ResourceError(msg="Error updating API status: {}".format(e))
        except TypeError as e:
            raise ResourceError(msg="Problem updating API: {}.".format(e))
        return ok(result=models.api_details(api_id), msg="API status updated successfully.")

    def delete(self, api_id):
        """Delete an API."""
        # first, find the API
        try:
            name, provider, version = models.break_api_id(api_id)
        except DAOError:
            raise ResourceError(msg="API not found.")
        admin = ApiAdmin()
        try:
            admin.delete_api(api_name=name, api_provider=provider, api_version=version)
        except WebFault as e:
            raise ResourceError(msg=admin.error_msg(e))
        except Exception as e:
            raise ResourceError(msg='Uncaught exception: {}'.format(e))
        return ('', 204)


