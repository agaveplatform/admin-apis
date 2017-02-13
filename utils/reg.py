# Module to ensure an API is registered and published in an APIM instance.
# This script assumes that it has local access to the admin services.
#
# Run this script using the agaveapi/flask_admin_utils image mounting an api.json file at the root:
#  docker run -it --rm -v /path/to/my_api.json:/api.json agaveapi/flask_admin_utils

# Parameters: pass as environment variables:
# base_url: should be the URL for the admin nginx proxy directly since this script must bypass APIM.

# For the A/B deployment of the Agave auth services, one approach is to link this container to the admin services
# nginx container. To do this, first determine whether the A stack or B stack is deployed and then run:
#
# for A stack:
# docker run --rm --link a_adminnginx_1 -it -e base_url=http://a_adminnginx_1:80 \
#            -v $(pwd)/admin_services.json:/api.json agaveapi/flask_admin_utils
#
# for B stack:
# docker run --rm --link b_adminnginx_1 -it -e base_url=http://b_adminnginx_1:80 \
#            -v $(pwd)/admin_services.json:/api.json agaveapi/flask_admin_utils

import json
import os
import sys

import requests

# override with env vars:
base_url = os.environ.get('base_url', 'http://172.17.0.1:8000')

def headers():
    jwt = os.environ.get('jwt', open('/utils/jwt').read())
    if jwt:
        jwt_header = os.environ.get('jwt_header', 'X-Jwt-Assertion-AGAVE-PROD')
        headers = {jwt_header: jwt}
    else:
        token = os.environ.get('token', '')
        headers = {'Authorization': 'Bearer {}'.format(token)}
    return headers

def get_api_id():
    data = json.load(open('/api.json'))
    try:
        return '{}-admin-{}'.format(data['name'], data['version'])
    except KeyError:
        sys.exit("API json missing name or version.")

def get_roles():
    data = json.load(open('/api.json'))
    roles = data.get('roles', [])
    if type(roles) == list:
        return roles
    else:
        return []

def check_role(role):
    print("Checking if {} role is registered.".format(role))
    url = '{}/admin/service_roles/{}'.format(base_url, role)
    rsp = requests.get(url, headers=headers())
    if not rsp.status_code in [200, 201, 204]:
        # role does not exist:
        return False
    return True

def register_roles(roles):
    for role in roles:
        if not check_role(role):
            # register role
            print("Registering role {}.".format(role))
            url = '{}/{}'.format(base_url, '/admin/service_roles')
            data = {'roleId': role}
            hs = headers()
            hs['Content-Type'] = 'application/json'
            rsp = requests.post(url, data=json.dumps(data), headers=hs)
            if not rsp.status_code in [200, 201, 204]:
                print("Error registering role {} -- bad status code: {}; response: {}".format(role, rsp.status_code, rsp))
                sys.exit()
            print("role {} registered.".format(role))
        else:
            print("Role {} already registered.".format(role))

def api_registered(api_id):
    print("Checking if {} API is registered.".format(api_id))
    url = '{}/admin/apis/{}'.format(base_url, api_id)
    rsp = requests.get(url, headers=headers())
    if not rsp.status_code in [200, 201, 204]:
        # API does not exist:
        return False
    status = json.loads(rsp.content.decode('utf-8'))['result']['status']
    if not status == 'PUBLISHED':
        print("API {} already registered but not published.".format(api_id))
        publish_api(api_id)
    print("API {} already registered and published.".format(api_id))
    return True

def register_api(api_id):
    print("Registering api {}.".format(api_id))
    url = '{}/{}'.format(base_url, '/admin/apis')
    data = json.load(open('/api.json'))
    hs = headers()
    hs['Content-Type'] = 'application/json'
    rsp = requests.post(url, data=json.dumps(data), headers=hs)
    if not rsp.status_code in [200, 201, 204]:
        print("Error registering API {} -- bad status code: {}; response: {}".format(api_id, rsp.status_code, rsp))
        sys.exit()
    print("API {} registered.".format(api_id))

def publish_api(api_id):
    print("Publishing API {}.".format(api_id))
    url = '{}/admin/apis//{}'.format(base_url, api_id)
    data = {'status': 'PUBLISHED'}
    hs = headers()
    hs['Content-Type'] = 'application/json'
    rsp = requests.put(url, data=json.dumps(data), headers=hs)
    if not rsp.status_code in [200, 201, 204]:
        print("Error publishing API {} -- bad status code: {}; response: {}".format(api_id, rsp.status_code, rsp))
        sys.exit()
    print("API {} published.".format(api_id))


def main():
    roles = get_roles()
    if roles:
        register_roles(roles)
    api_id = get_api_id()
    if not api_registered(api_id):
        register_api(api_id)
        publish_api(api_id)

if __name__ == '__main__':
    main()