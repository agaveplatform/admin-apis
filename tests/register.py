# This script can be used to register the admin services with APIM, create a service account with client keys
# subscribed to the Admin APIs.
# This script assumes that it has local access to the admin services
#
# Run this script using the agaveapi/flask_admin_testsuite image and replace the entrypoint:
#  docker run -it --rm --entrypoint=python3 -e tenant_id=dev_staging -e base_url=http://172.17.0.1:8000  agaveapi/flask_admin_testsuite /tests/register.py

# Parameters: pass as environment variables:
# tenant_id: used to set the role when registering the services.
# base_url: should be the URL for the admin nginx proxy directly since this script must bypass APIM.
# create_admin_account (defaults to false): Should be the string 'true' to generate a service account.
# admin_username (defaults to jfsadmin): String for the admin account to create.
# admin_password (defaults to abcd1234): String for the admin password

import json
import os
import sys

import requests

# override with env vars:
base_url = os.environ.get('base_url', 'http://172.17.0.1:8000')
tenant_id = os.environ.get('tenant_id', 'dev_sandbox')
create_admin_account = os.environ.get('create_admin_account', 'False')
admin_username = os.environ.get('admin_username', 'jfsadmin')
admin_password = os.environ.get('admin_password', 'abcd1234')


def headers():
    jwt = os.environ.get('jwt', open('/tests/jwt').read())
    if jwt:
        jwt_header = os.environ.get('jwt_header', 'X-Jwt-Assertion-AGAVE-PROD')
        headers = {jwt_header: jwt}
    else:
        token = os.environ.get('token', '')
        headers = {'Authorization': 'Bearer {}'.format(token)}
    return headers

def admin_services_registered():
    print("Checking if admin services are registered.")
    url = '{}/{}'.format(base_url, '/admin/apis/AdminServices-admin-v2')
    rsp = requests.get(url, headers=headers())
    if not rsp.status_code in [200, 201, 204]:
        # admin services do not exist:
        return False
    status = json.loads(rsp.content.decode('utf-8'))['result']['status']
    if not status == 'PUBLISHED':
        print("Admin services registered but not published.")
        publish_admin_services()
    print("Admin services registered and published.")
    return True

def register_admin_services():
    print("Registering admin services.")
    url = '{}/{}'.format(base_url, '/admin/apis')
    data = json.load(open('/tests/admin_services.json'))
    data['roles'] = ['Internal_{}-services-admin'.format(tenant_id)]
    hs = headers()
    hs['Content-Type'] = 'application/json'
    rsp = requests.post(url, data=json.dumps(data), headers=hs)
    if not rsp.status_code in [200, 201, 204]:
        print("Error registering admin services -- bad status code: {}; response: {}".format(rsp.status_code, rsp))
        sys.exit()
    print("Admin services registered.")

def publish_admin_services():
    print("Publishing admin services.")
    url = '{}/{}'.format(base_url, '/admin/apis/AdminServices-admin-v2')
    data = {'status': 'PUBLISHED'}
    hs = headers()
    hs['Content-Type'] = 'application/json'
    rsp = requests.put(url, data=json.dumps(data), headers=hs)
    if not rsp.status_code in [200, 201, 204]:
        print("Error publishing admin services -- bad status code: {}; response: {}".format(rsp.status_code, rsp))
        sys.exit()
    print("Admin services published.")


def create_admin():
    print("Checking if admin account {} exists.".format(admin_username))
    url = '{}/{}'.format(base_url, '/admin/service_accounts/{}'.format(admin_username))
    rsp = requests.get(url, headers=headers())
    if rsp.status_code in [200, 201, 204]:
        print("Admin account {} already exists.".format(admin_username))
    else:
        # admin account does not exist:
        url = '{}/{}'.format(base_url, '/admin/service_accounts')
        rsp = requests.post(url, data={'accountId': admin_username,'password': admin_password},
                            headers=headers())
        if not rsp.status_code in [200, 201, 204]:
            print("Error creating admin account -- bad status code: {}; response: {}".format(rsp.status_code, rsp))
            sys.exit()
        print("Admin account {} created.".format(admin_username))
    # check if admin has admin role:
    url = '{}/{}'.format(base_url, 'admin/service_accounts/{}/roles'.format(admin_username))
    rsp = requests.get(url, headers=headers())
    if rsp.status_code in [200, 201, 204]:
        roles = json.loads(rsp.content.decode('utf-8'))['result']['roles']
        role_id = 'Internal_{}-services-admin'.format(tenant_id)
        if role_id not in [role for role in roles]:
            # add admin to the admin role:
            url = '{}/{}'.format(base_url, 'admin/service_roles/{}/service_accounts'.format(role_id))
            rsp = requests.post(url, data={'accountId': admin_username}, headers=headers())
            if rsp.status_code in [200, 201, 204]:
                print("Admin account has tenant admin role.")
                return True
        else:
            print("Admin account already had tenant admin role.")
    else:
        print("Error looking up admin roles -- bad status code: {}; response: {}".format(rsp.status_code, rsp))

    return True


def main():
    if not admin_services_registered():
        register_admin_services()
        publish_admin_services()
    if create_admin_account.lower() == 'true':
        create_admin()

if __name__ == '__main__':
    main()