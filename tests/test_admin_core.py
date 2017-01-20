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


@pytest.fixture(scope='session')
def headers():
    jwt = os.environ.get('jwt', open('/tests/jwt').read())
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
    assert 'accountId' in result
    assert 'password' not in result
    assert len(result['roles']) > 0
    assert 'Internal_everyone' in result['roles']
    assert result['accountId'] == 'admin_test_suite_account'

def test_list_service_accounts(headers):
    url = '{}/{}'.format(base_url, '/admin/service_accounts')
    rsp = requests.get(url, headers=headers)
    result = basic_response_checks(rsp)
    assert len(result) > 0
    for a in result:
        assert '_links' in a
        assert 'accountId' in a
        assert 'password' not in a
    # check that test account is in list
    test_list = [a for a in result if a['accountId'] == 'admin_test_suite_account']
    assert len(test_list) == 1

def test_list_test_service_account(headers):
    url = '{}/{}'.format(base_url, '/admin/service_accounts/admin_test_suite_account')
    rsp = requests.get(url, headers=headers)
    result = basic_response_checks(rsp, check_links=True)
    assert 'accountId' in result
    assert 'roles' in result
    assert 'password' not in result
    assert result['accountId'] == 'admin_test_suite_account'
    assert len(result['roles']) == 1
    assert 'Internal_everyone' in result['roles']

def test_list_test_service_account_roles(headers):
    url = '{}/{}'.format(base_url, '/admin/service_accounts/admin_test_suite_account/roles')
    rsp = requests.get(url, headers=headers)
    result = basic_response_checks(rsp, check_links=True)
    assert 'accountId' in result
    assert 'roles' in result
    assert 'password' not in result
    assert result['accountId'] == 'admin_test_suite_account'
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
    assert 'roleId' in result
    # roles should initially be unoccupied
    assert len(result['accounts']) == 0
    assert result['roleId'] == 'Internal_admin_test_suite_role'

def test_list_roles(headers):
    url = '{}/{}'.format(base_url, '/admin/service_roles')
    rsp = requests.get(url, headers=headers)
    result = basic_response_checks(rsp)
    assert len(result) > 0
    for a in result:
        assert '_links' in a
        assert 'roleId' in a
    # check that test role is in list
    test_list = [a for a in result if a['roleId'] == 'Internal_admin_test_suite_role']
    assert len(test_list) == 1

def test_list_role(headers):
    url = '{}/{}'.format(base_url, '/admin/service_roles/Internal_admin_test_suite_role')
    rsp = requests.get(url, headers=headers)
    result = basic_response_checks(rsp, check_links=True)
    assert 'roleId' in result
    assert 'accounts' in result
    assert result['roleId'] == 'Internal_admin_test_suite_role'
    assert len(result['accounts']) == 0

def test_list_role_basic_service_accounts(headers):
    url = '{}/{}'.format(base_url, '/admin/service_roles/Internal_admin_test_suite_role/service_accounts')
    rsp = requests.get(url, headers=headers)
    result = basic_response_checks(rsp)
    assert 'roleId' in result
    assert 'accounts' in result
    assert result['roleId'] == 'Internal_admin_test_suite_role'
    assert len(result['accounts']) == 0

def test_add_test_service_account_to_role(headers):
    url = '{}/{}'.format(base_url, '/admin/service_roles/Internal_admin_test_suite_role/service_accounts')
    data = {'accountId': 'admin_test_suite_account'}
    rsp = requests.post(url, data=data, headers=headers)
    result = basic_response_checks(rsp, check_links=True)
    assert 'roleId' in result
    assert 'accounts' in result
    assert result['roleId'] == 'Internal_admin_test_suite_role'
    assert len(result['accounts']) == 1
    assert result['accounts'][0] == 'admin_test_suite_account'

def test_list_role_service_accounts(headers):
    url = '{}/{}'.format(base_url, '/admin/service_roles/Internal_admin_test_suite_role/service_accounts')
    rsp = requests.get(url, headers=headers)
    result = basic_response_checks(rsp)
    assert 'roleId' in result
    assert 'accounts' in result
    assert result['roleId'] == 'Internal_admin_test_suite_role'
    assert len(result['accounts']) == 1
    assert result['accounts'][0] == 'admin_test_suite_account'

def test_list_role_service_account(headers):
    url = '{}/{}'.format(base_url, '/admin/service_roles/Internal_admin_test_suite_role/service_accounts/admin_test_suite_account')
    rsp = requests.get(url, headers=headers)
    result = basic_response_checks(rsp)
    assert 'accountId' in result
    assert 'roles' in result
    assert result['accountId'] == 'admin_test_suite_account'
    assert len(result['roles']) == 2
    assert 'Internal_everyone' in result['roles']
    assert 'Internal_admin_test_suite_role' in result['roles']

def test_list_added_service_account_roles(headers):
    url = '{}/{}'.format(base_url, '/admin/service_accounts/admin_test_suite_account/roles')
    rsp = requests.get(url, headers=headers)
    result = basic_response_checks(rsp)
    assert 'accountId' in result
    assert 'roles' in result
    assert 'password' not in result
    assert result['accountId'] == 'admin_test_suite_account'
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
    assert 'roleId' in result
    assert 'accounts' in result
    assert result['roleId'] == 'Internal_admin_test_suite_role'
    assert len(result['accounts']) == 0

def test_service_account_removed_accounts(headers):
    url = '{}/{}'.format(base_url, '/admin/service_accounts/admin_test_suite_account/roles')
    rsp = requests.get(url, headers=headers)
    result = basic_response_checks(rsp, check_links=True)
    assert 'accountId' in result
    assert 'roles' in result
    assert 'password' not in result
    assert result['accountId'] == 'admin_test_suite_account'
    assert len(result['roles']) == 1
    assert 'Internal_everyone' in result['roles']

def test_add_role_to_service_account(headers):
    url = '{}/{}'.format(base_url, '/admin/service_accounts/admin_test_suite_account/roles')
    data = {'roleId': 'Internal_admin_test_suite_role'}
    rsp = requests.post(url, data=data, headers=headers)
    result = basic_response_checks(rsp, check_links=True)
    assert 'accountId' in result
    assert 'roles' in result
    assert 'password' not in result
    assert result['accountId'] == 'admin_test_suite_account'
    assert len(result['roles']) == 2
    assert 'Internal_everyone' in result['roles']
    assert 'Internal_admin_test_suite_role' in result['roles']

def test_list_role_service_account_2(headers):
    url = '{}/{}'.format(base_url, '/admin/service_roles/Internal_admin_test_suite_role/service_accounts/admin_test_suite_account')
    rsp = requests.get(url, headers=headers)
    result = basic_response_checks(rsp)
    assert 'accountId' in result
    assert 'roles' in result
    assert result['accountId'] == 'admin_test_suite_account'
    assert len(result['roles']) == 2
    assert 'Internal_everyone' in result['roles']
    assert 'Internal_admin_test_suite_role' in result['roles']

def test_list_added_service_account_roles_2(headers):
    url = '{}/{}'.format(base_url, '/admin/service_accounts/admin_test_suite_account/roles')
    rsp = requests.get(url, headers=headers)
    result = basic_response_checks(rsp)
    assert 'accountId' in result
    assert 'roles' in result
    assert 'password' not in result
    assert result['accountId'] == 'admin_test_suite_account'
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
    assert 'roleId' in result
    assert 'accounts' in result
    assert result['roleId'] == 'Internal_admin_test_suite_role'
    assert len(result['accounts']) == 0

def test_service_account_removed_accounts_2(headers):
    url = '{}/{}'.format(base_url, '/admin/service_accounts/admin_test_suite_account/roles')
    rsp = requests.get(url, headers=headers)
    result = basic_response_checks(rsp)
    assert 'accountId' in result
    assert 'roles' in result
    assert 'password' not in result
    assert result['accountId'] == 'admin_test_suite_account'
    assert len(result['roles']) == 1
    assert 'Internal_everyone' in result['roles']

def test_delete_test_role(headers):
    url = '{}/{}'.format(base_url, '/admin/service_roles/Internal_admin_test_suite_role')
    rsp = requests.delete(url, headers=headers)
    assert rsp.status_code == 204

def test_role_removed(headers):
    url = '{}/{}'.format(base_url, '/admin/service_roles')
    rsp = requests.get(url, headers=headers)
    result = basic_response_checks(rsp)
    # check that test role is NOT in list
    test_list = [a for a in result if a['roleId'] == 'Internal_admin_test_suite_role']
    assert len(test_list) == 0

def test_delete_test_service_account(headers):
    url = '{}/{}'.format(base_url, '/admin/service_accounts/admin_test_suite_account')
    rsp = requests.delete(url, headers=headers)
    assert rsp.status_code == 204

def test_account_removed(headers):
    url = '{}/{}'.format(base_url, '/admin/service_accounts')
    rsp = requests.get(url, headers=headers)
    result = basic_response_checks(rsp)
    assert len(result) > 0
    for a in result:
        assert '_links' in a
        assert 'accountId' in a
        assert 'password' not in a
    # check that test account is NOT in list
    test_list = [a for a in result if a['accountId'] == 'admin_test_suite_account']
    assert len(test_list) == 0

def test_list_clients(headers):
    url = '{}/{}'.format(base_url, '/admin/service_accounts')
    rsp = requests.get(url, headers=headers)
    result = basic_response_checks(rsp)

def test_list_apis(headers):
    url = '{}/{}'.format(base_url, '/admin/apis')
    rsp = requests.get(url, headers=headers)
    result = basic_response_checks(rsp)


