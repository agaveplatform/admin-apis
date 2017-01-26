# #######################################################################################
# Here are some curl examples of interacting with the local development stack using a JWT
# #######################################################################################

# list the service accounts
curl -H "X-Jwt-Assertion-AGAVE-PROD: $jwt" 172.17.0.1:8000/admin/service_accounts

# list the service roles
curl -H "X-Jwt-Assertion-AGAVE-PROD: $jwt" 172.17.0.1:8000/admin/service_roles

# create a service account
curl -H "X-Jwt-Assertion-AGAVE-PROD: $jwt" -d "accountId=curltest&password=abcd123" 172.17.0.1:8000/admin/service_accounts

# create a service role
curl -d "roleId=curl_test" -H "X-Jwt-Assertion-AGAVE-PROD: $jwt" 172.17.0.1:8000/admin/service_roles

# add a service account to a role
curl  -d "accountId=curltest" -H "X-Jwt-Assertion-AGAVE-PROD: $jwt" 172.17.0.1:8000/admin/service_roles/Internal_curl_test/service_accounts

# list the apis
curl -H "X-Jwt-Assertion-AGAVE-PROD: $jwt" 172.17.0.1:8000/admin/apis

# add an api
curl -H "Content-Type: application/json" -d "@httpbin_basic.json"  -H "X-Jwt-Assertion-AGAVE-PROD: $jwt" 172.17.0.1:8000/admin/apis

# retrieve the api
curl -H "X-Jwt-Assertion-AGAVE-PROD: $jwt" 172.17.0.1:8000/admin/apis/httpbin-admin-v0.1

# update api status
curl -X PUT -d "status=PUBLISHED" -H "X-Jwt-Assertion-AGAVE-PROD: $jwt" 172.17.0.1:8000/admin/apis/httpbin-admin-v0.1

# delete the api
curl -X DELETE -H "X-Jwt-Assertion-AGAVE-PROD: $jwt" 172.17.0.1:8000/admin/apis/httpbin-admin-v0.1


# #############################
# boot strap the admin services
# #############################

# add and publish the admin services
curl -H "Content-Type: application/json" -d "@admin_services.json"  -H "X-Jwt-Assertion-AGAVE-PROD: $jwt" 172.17.0.1:8000/admin/apis
curl -X PUT -d "status=PUBLISHED" -H "X-Jwt-Assertion-AGAVE-PROD: $jwt" 172.17.0.1:8000/admin/apis/AdminServices-admin-v2

# create a service account
curl -d "accountId=jfsadmin&password=something" -H "X-Jwt-Assertion-AGAVE-PROD: $jwt" 172.17.0.1:8000/admin/service_accounts

# add the service account to the admin role:
curl -d "accountId=jfsadmin" -H "X-Jwt-Assertion-AGAVE-PROD: $jwt" 172.17.0.1:8000/admin/service_roles/Internal_dev_sandbox-services-admin/service_accounts

# create a client and subscribe to the admin services with the service account
curl -k -d "clientName=test" -u jfsadmin $base/clients/v2
curl -d "apiName=AdminServices&apiVersion=v2&apiProvider=admin" -k -u jfsadmin $base/clients/v2/test/subscriptions






