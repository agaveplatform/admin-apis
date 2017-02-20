# Functional test suite for the admin services.
# This test suite runs in its own docker container. To build the image, run
#     docker build -f Dockerfile-test -t agaveapi/flask_admin_testsuite .
# from within the root project directory.
#
# The development stack, and therefore the test suite, depend on a working, instance of APIM where the WSDL services
# are available. By default, they run on port 9443, so this port on the APIM host needs to be available to the dev
# stack of admin services. Configuration of the APIM instance is done through environment variables defined in the
# docker-compose.yml file for the development stack (project root).
#
# To run the tests, first start the development stack using the docker-compose.yml in the root directory
# Then, also from the root directory, execute:
#     docker run -e base_url=http://172.17.0.1:8000 -e wso2admin_password=$pass -it --rm agaveapi/flask_admin_testsuite


import json
import os

import pytest
import requests

base_url = os.environ.get('base_url', 'http://localhost:8000')

print("Using base URL: {}".format(base_url))

@pytest.fixture(scope='session')
def headers():
    try:
        jwt = os.environ.get('jwt', open('/tests/jwt').read())
    except IOError:
        jwt = os.environ.get('jwt', open('{}/tests/jwt'.format(os.getcwd())).read())
    if jwt:
        jwt_header = os.environ.get('jwt_header', 'X-Jwt-Assertion-AGAVE-PROD')
        headers = {jwt_header: jwt}
    else:
        token = os.environ.get('token', '')
        headers = {'Authorization': 'Bearer {}'.format(token)}
    return headers


def basic_response_checks(rsp, check_links=False):
    assert rsp.status_code in [200, 201, 204]
    assert 'application/json' in rsp.headers['content-type']
    data = json.loads(rsp.content.decode('utf-8'))
    assert 'message' in data.keys()
    assert 'status' in data.keys()
    assert 'result' in data.keys()
    assert 'version' in data.keys()
    result = data['result']
    if check_links:
        assert '_links' in result
    return result


def test_basic_list_service_accounts(headers):
    url = '{}/{}'.format(base_url, '/admin/service_accounts')
    rsp = requests.get(url, headers=headers)
    basic_response_checks(rsp)

def test_add_service_account(headers):
    url = '{}/{}'.format(base_url, '/admin/service_accounts')
    data = {'accountId': 'admin_test_suite_account', 'password': 'abcd123'}
    rsp = requests.post(url, data=data, headers=headers)
    result = basic_response_checks(rsp, check_links=True)
    assert 'roles' in result
    assert 'id' in result
    assert 'password' not in result
    assert len(result['roles']) > 0
    assert 'Internal_everyone' in result['roles']
    assert result['id'] == 'admin_test_suite_account'

def test_list_service_accounts(headers):
    url = '{}/{}'.format(base_url, '/admin/service_accounts')
    rsp = requests.get(url, headers=headers)
    result = basic_response_checks(rsp)
    assert len(result) > 0
    for a in result:
        assert '_links' in a
        assert 'id' in a
        assert 'password' not in a
    # check that test account is in list
    test_list = [a for a in result if a['id'] == 'admin_test_suite_account']
    assert len(test_list) == 1

def test_list_test_service_account(headers):
    url = '{}/{}'.format(base_url, '/admin/service_accounts/admin_test_suite_account')
    rsp = requests.get(url, headers=headers)
    result = basic_response_checks(rsp, check_links=True)
    assert 'id' in result
    assert 'roles' in result
    assert 'password' not in result
    assert result['id'] == 'admin_test_suite_account'
    assert len(result['roles']) == 1
    assert 'Internal_everyone' in result['roles']

def test_list_test_service_account_roles(headers):
    url = '{}/{}'.format(base_url, '/admin/service_accounts/admin_test_suite_account/roles')
    rsp = requests.get(url, headers=headers)
    result = basic_response_checks(rsp, check_links=True)
    assert 'id' in result
    assert 'roles' in result
    assert 'password' not in result
    assert result['id'] == 'admin_test_suite_account'
    assert len(result['roles']) == 1
    assert 'Internal_everyone' in result['roles']


def test_basic_list_roles(headers):
    url = '{}/{}'.format(base_url, '/admin/service_roles')
    rsp = requests.get(url, headers=headers)
    basic_response_checks(rsp)

def test_add_role(headers):
    url = '{}/{}'.format(base_url, '/admin/service_roles')
    data = {'roleId': 'Internal_admin_test_suite_role'}
    rsp = requests.post(url, data=data, headers=headers)
    result = basic_response_checks(rsp, check_links=True)
    assert 'accounts' in result
    assert 'id' in result
    # roles should initially be unoccupied
    assert len(result['accounts']) == 0
    assert result['id'] == 'Internal_admin_test_suite_role'

def test_list_roles(headers):
    url = '{}/{}'.format(base_url, '/admin/service_roles')
    rsp = requests.get(url, headers=headers)
    result = basic_response_checks(rsp)
    assert len(result) > 0
    for a in result:
        assert '_links' in a
        assert 'id' in a
    # check that test role is in list
    test_list = [a for a in result if a['id'] == 'Internal_admin_test_suite_role']
    assert len(test_list) == 1

def test_list_role(headers):
    url = '{}/{}'.format(base_url, '/admin/service_roles/Internal_admin_test_suite_role')
    rsp = requests.get(url, headers=headers)
    result = basic_response_checks(rsp, check_links=True)
    assert 'id' in result
    assert 'accounts' in result
    assert result['id'] == 'Internal_admin_test_suite_role'
    assert len(result['accounts']) == 0

def test_list_role_basic_service_accounts(headers):
    url = '{}/{}'.format(base_url, '/admin/service_roles/Internal_admin_test_suite_role/service_accounts')
    rsp = requests.get(url, headers=headers)
    result = basic_response_checks(rsp)
    assert 'id' in result
    assert 'accounts' in result
    assert result['id'] == 'Internal_admin_test_suite_role'
    assert len(result['accounts']) == 0

def test_add_test_service_account_to_role(headers):
    url = '{}/{}'.format(base_url, '/admin/service_roles/Internal_admin_test_suite_role/service_accounts')
    data = {'accountId': 'admin_test_suite_account'}
    rsp = requests.post(url, data=data, headers=headers)
    result = basic_response_checks(rsp, check_links=True)
    assert 'id' in result
    assert 'accounts' in result
    assert result['id'] == 'Internal_admin_test_suite_role'
    assert len(result['accounts']) == 1
    assert result['accounts'][0] == 'admin_test_suite_account'

def test_list_role_service_accounts(headers):
    url = '{}/{}'.format(base_url, '/admin/service_roles/Internal_admin_test_suite_role/service_accounts')
    rsp = requests.get(url, headers=headers)
    result = basic_response_checks(rsp)
    assert 'id' in result
    assert 'accounts' in result
    assert result['id'] == 'Internal_admin_test_suite_role'
    assert len(result['accounts']) == 1
    assert result['accounts'][0] == 'admin_test_suite_account'

def test_list_role_service_account(headers):
    url = '{}/{}'.format(base_url, '/admin/service_roles/Internal_admin_test_suite_role/service_accounts/admin_test_suite_account')
    rsp = requests.get(url, headers=headers)
    result = basic_response_checks(rsp)
    assert 'id' in result
    assert 'roles' in result
    assert result['id'] == 'admin_test_suite_account'
    assert len(result['roles']) == 2
    assert 'Internal_everyone' in result['roles']
    assert 'Internal_admin_test_suite_role' in result['roles']

def test_list_added_service_account_roles(headers):
    url = '{}/{}'.format(base_url, '/admin/service_accounts/admin_test_suite_account/roles')
    rsp = requests.get(url, headers=headers)
    result = basic_response_checks(rsp)
    assert 'id' in result
    assert 'roles' in result
    assert 'password' not in result
    assert result['id'] == 'admin_test_suite_account'
    assert len(result['roles']) == 2
    assert 'Internal_everyone' in result['roles']
    assert 'Internal_admin_test_suite_role' in result['roles']

def test_delete_test_service_account_from_role(headers):
    url = '{}/{}'.format(base_url, '/admin/service_roles/Internal_admin_test_suite_role/service_accounts/admin_test_suite_account')
    rsp = requests.delete(url, headers=headers)
    assert rsp.status_code == 204

def test_service_account_removed_roles(headers):
    url = '{}/{}'.format(base_url, '/admin/service_roles/Internal_admin_test_suite_role/service_accounts')
    rsp = requests.get(url, headers=headers)
    result = basic_response_checks(rsp, check_links=True)
    assert 'id' in result
    assert 'accounts' in result
    assert result['id'] == 'Internal_admin_test_suite_role'
    assert len(result['accounts']) == 0

def test_service_account_removed_accounts(headers):
    url = '{}/{}'.format(base_url, '/admin/service_accounts/admin_test_suite_account/roles')
    rsp = requests.get(url, headers=headers)
    result = basic_response_checks(rsp, check_links=True)
    assert 'id' in result
    assert 'roles' in result
    assert 'password' not in result
    assert result['id'] == 'admin_test_suite_account'
    assert len(result['roles']) == 1
    assert 'Internal_everyone' in result['roles']

def test_add_role_to_service_account(headers):
    url = '{}/{}'.format(base_url, '/admin/service_accounts/admin_test_suite_account/roles')
    data = {'roleId': 'Internal_admin_test_suite_role'}
    rsp = requests.post(url, data=data, headers=headers)
    result = basic_response_checks(rsp, check_links=True)
    assert 'id' in result
    assert 'roles' in result
    assert 'password' not in result
    assert result['id'] == 'admin_test_suite_account'
    assert len(result['roles']) == 2
    assert 'Internal_everyone' in result['roles']
    assert 'Internal_admin_test_suite_role' in result['roles']

def test_list_role_service_account_2(headers):
    url = '{}/{}'.format(base_url, '/admin/service_roles/Internal_admin_test_suite_role/service_accounts/admin_test_suite_account')
    rsp = requests.get(url, headers=headers)
    result = basic_response_checks(rsp)
    assert 'id' in result
    assert 'roles' in result
    assert result['id'] == 'admin_test_suite_account'
    assert len(result['roles']) == 2
    assert 'Internal_everyone' in result['roles']
    assert 'Internal_admin_test_suite_role' in result['roles']

def test_list_added_service_account_roles_2(headers):
    url = '{}/{}'.format(base_url, '/admin/service_accounts/admin_test_suite_account/roles')
    rsp = requests.get(url, headers=headers)
    result = basic_response_checks(rsp)
    assert 'id' in result
    assert 'roles' in result
    assert 'password' not in result
    assert result['id'] == 'admin_test_suite_account'
    assert len(result['roles']) == 2
    assert 'Internal_everyone' in result['roles']
    assert 'Internal_admin_test_suite_role' in result['roles']

def test_delete_role_from_service_account(headers):
    url = '{}/{}'.format(base_url, '/admin/service_accounts/admin_test_suite_account/roles/Internal_admin_test_suite_role')
    rsp = requests.delete(url, headers=headers)
    assert rsp.status_code == 204

def test_service_account_removed_roles_2(headers):
    url = '{}/{}'.format(base_url, '/admin/service_roles/Internal_admin_test_suite_role/service_accounts')
    rsp = requests.get(url, headers=headers)
    result = basic_response_checks(rsp)
    assert 'id' in result
    assert 'accounts' in result
    assert result['id'] == 'Internal_admin_test_suite_role'
    assert len(result['accounts']) == 0

def test_service_account_removed_accounts_2(headers):
    url = '{}/{}'.format(base_url, '/admin/service_accounts/admin_test_suite_account/roles')
    rsp = requests.get(url, headers=headers)
    result = basic_response_checks(rsp)
    assert 'id' in result
    assert 'roles' in result
    assert 'password' not in result
    assert result['id'] == 'admin_test_suite_account'
    assert len(result['roles']) == 1
    assert 'Internal_everyone' in result['roles']

def test_delete_test_role(headers):
    url = '{}/{}'.format(base_url, '/admin/service_roles/Internal_admin_test_suite_role')
    rsp = requests.delete(url, headers=headers)
    assert rsp.status_code == 204

def test_deleted_role_not_present(headers):
    url = '{}/{}'.format(base_url, '/admin/service_accounts/Internal_admin_test_suite_role')
    rsp = requests.get(url, headers=headers)
    assert rsp.status_code == 400

def test_deleted_role_not_listed(headers):
    url = '{}/{}'.format(base_url, '/admin/service_roles')
    rsp = requests.get(url, headers=headers)
    result = basic_response_checks(rsp)
    # check that test role is NOT in list
    test_list = [a for a in result if a['id'] == 'Internal_admin_test_suite_role']
    assert len(test_list) == 0

def test_delete_test_service_account(headers):
    url = '{}/{}'.format(base_url, '/admin/service_accounts/admin_test_suite_account')
    rsp = requests.delete(url, headers=headers)
    assert rsp.status_code == 204

def test_deleted_account_not_present(headers):
    url = '{}/{}'.format(base_url, '/admin/service_accounts/admin_test_suite_account')
    rsp = requests.get(url, headers=headers)
    assert rsp.status_code == 400

def test_deleted_account_not_listed(headers):
    url = '{}/{}'.format(base_url, '/admin/service_accounts')
    rsp = requests.get(url, headers=headers)
    result = basic_response_checks(rsp)
    assert len(result) > 0
    for a in result:
        assert '_links' in a
        assert 'id' in a
        assert 'password' not in a
    # check that test account is NOT in list
    test_list = [a for a in result if a['id'] == 'admin_test_suite_account']
    assert len(test_list) == 0

def test_list_clients(headers):
    url = '{}/{}'.format(base_url, '/admin/service_accounts')
    rsp = requests.get(url, headers=headers)
    result = basic_response_checks(rsp)

def test_list_apis(headers):
    url = '{}/{}'.format(base_url, '/admin/apis')
    rsp = requests.get(url, headers=headers)
    result = basic_response_checks(rsp)
    for api in result:
        assert 'id' in api
        assert 'name' in api
        assert 'owner' in api
        assert 'status' in api
        assert 'version' in api

def check_basic_api_response(result, expected_status='CREATED', expected_context='/httpbin_admin_test_suite/v0.1'):
    assert 'id' in result
    assert result['id'] == 'httpbin_admin_test_suite-admin-v0.1'
    assert 'context' in result
    assert result['context'] == expected_context
    assert 'name' in result
    assert result['name'] == 'httpbin_admin_test_suite'
    assert 'owner' in result
    assert result['owner'] == 'admin'
    assert 'version' in result
    assert result['version'] == 'v0.1'
    assert 'status' in result
    assert result['status'] == expected_status
    assert 'visibility' in result
    assert result['visibility'] == 'public'
    assert 'roles' in result
    assert result['roles'] == ['']
    assert 'methods' in result
    assert 'GET' in result['methods']
    assert 'POST' in result['methods']
    assert 'PUT' in result['methods']
    assert 'DELETE' in result['methods']
    assert 'HEAD' in result['methods']


def test_add_basic_api(headers):
    url = '{}/{}'.format(base_url, '/admin/apis')
    data = json.load(open('/tests/httpbin_basic.json'))
    data['name'] = 'httpbin_admin_test_suite'
    data['path'] = '/httpbin_admin_test_suite'
    headers['Content-Type'] = 'application/json'
    rsp = requests.post(url, data=json.dumps(data), headers=headers)
    result = basic_response_checks(rsp, check_links=True)
    check_basic_api_response(result)

def test_list_added_basic_api(headers):
    url = '{}/{}'.format(base_url, '/admin/apis/httpbin_admin_test_suite-admin-v0.1')
    rsp = requests.get(url, headers=headers)
    result = basic_response_checks(rsp, check_links=True)
    check_basic_api_response(result)

def test_update_basic_api(headers):
    url = '{}/{}'.format(base_url, '/admin/apis/httpbin_admin_test_suite-admin-v0.1')
    data = json.load(open('/tests/httpbin_basic2.json'))
    data['name'] = 'httpbin_admin_test_suite'
    data['path'] = '/httpbin_admin_test_suite2'
    headers['Content-Type'] = 'application/json'
    rsp = requests.post(url, data=json.dumps(data), headers=headers)
    result = basic_response_checks(rsp, check_links=True)
    check_basic_api_response(result, expected_context='/httpbin_admin_test_suite2/v0.1')

def test_list_updated_basic_api(headers):
    url = '{}/{}'.format(base_url, '/admin/apis/httpbin_admin_test_suite-admin-v0.1')
    rsp = requests.get(url, headers=headers)
    result = basic_response_checks(rsp, check_links=True)
    check_basic_api_response(result, expected_context='/httpbin_admin_test_suite2/v0.1')

def test_update_basic_api_back(headers):
    url = '{}/{}'.format(base_url, '/admin/apis/httpbin_admin_test_suite-admin-v0.1')
    data = json.load(open('/tests/httpbin_basic.json'))
    data['name'] = 'httpbin_admin_test_suite'
    data['path'] = '/httpbin_admin_test_suite'
    headers['Content-Type'] = 'application/json'
    rsp = requests.post(url, data=json.dumps(data), headers=headers)
    result = basic_response_checks(rsp, check_links=True)
    check_basic_api_response(result)

def test_list_updated_back_basic_api(headers):
    url = '{}/{}'.format(base_url, '/admin/apis/httpbin_admin_test_suite-admin-v0.1')
    rsp = requests.get(url, headers=headers)
    result = basic_response_checks(rsp, check_links=True)
    check_basic_api_response(result)

def test_update_basic_status_published(headers):
    url = '{}/{}'.format(base_url, '/admin/apis/httpbin_admin_test_suite-admin-v0.1')
    data = {'status': 'PUBLISHED'}
    headers['Content-Type'] = 'application/json'
    rsp = requests.put(url, data=json.dumps(data), headers=headers)
    result = basic_response_checks(rsp, check_links=True)
    check_basic_api_response(result, expected_status='PUBLISHED')

def test_add_api_restricted_by_roles(headers):
    url = '{}/{}'.format(base_url, '/admin/apis')
    data = json.load(open('/tests/httpbin_restricted_by_role.json'))
    data['name'] = 'httpbin_restricted_admin_test_suite'
    data['path'] = '/httpbin_restricted_admin_test_suite'
    headers['Content-Type'] = 'application/json'
    rsp = requests.post(url, data=json.dumps(data), headers=headers)
    result = basic_response_checks(rsp, check_links=True)
    assert 'visibility' in result
    assert result['visibility'] == 'restricted'
    assert 'roles' in result
    assert result['roles'] == ['Internal_dev_sandbox-services-admin']

def test_delete_basic_api(headers):
    url = '{}/{}'.format(base_url, '/admin/apis/httpbin_admin_test_suite-admin-v0.1')
    rsp = requests.delete(url, headers=headers)
    assert rsp.status_code == 204

def test_delete_restricted_api(headers):
    url = '{}/{}'.format(base_url, '/admin/apis/httpbin_restricted_admin_test_suite-admin-v0.1')
    rsp = requests.delete(url, headers=headers)
    assert rsp.status_code == 204
    url = '{}/{}'.format(base_url, '/admin/apis/httpbin_restricted_admin_test_suite-admin-v0.1')
    rsp = requests.get(url, headers=headers)
    assert rsp.status_code == 400
    url = '{}/{}'.format(base_url, '/admin/apis')
    rsp = requests.get(url, headers=headers)
    result = basic_response_checks(rsp)
    for api in result:
        assert not api['id'] == 'httpbin_restricted_admin_test_suite-admin-v0.1'



