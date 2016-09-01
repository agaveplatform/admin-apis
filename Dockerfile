# Image: agaveapi/flask_admin_services

from agaveapi/flask_api

ADD requirements.txt /requirements.txt
RUN pip install -r /requirements.txt
ADD UserAdmin-am19-staging.wsdl /UserAdmin-am19-staging.wsdl

ADD services /services

