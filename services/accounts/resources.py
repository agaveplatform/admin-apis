from flask import g, request
from flask_restful import Resource

from agaveflask.utils import ok

class JwtResource(Resource):

    def get(self):
        result = {'headerName': g.jwt_header_name,
                  'jwtRaw': g.jwt,
                  'jwtDecoded': g.jwt_decoded}
        return ok(result=result, msg="JWT generated successfully.")
