# Here are some curl examples of interacting with the local development stack using a JWT:

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

