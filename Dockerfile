# Image: jstubbs/admin_services

from jstubbs/template_compiler

RUN apt-get update 
RUN apt-get install -y python-dev 
RUN apt-get install -y libxml2-dev libxslt1-dev

ADD requirements.txt /requirements.txt
RUN pip install -r /requirements.txt

ADD UserAdmin-am19-staging.wsdl /UserAdmin-am19-staging.wsdl
