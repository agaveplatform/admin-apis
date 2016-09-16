# Image: agaveapi/flask_admin_services

from agaveapi/flask_api

ADD requirements.txt /requirements.txt
RUN pip3 install -r /requirements.txt

ADD services /services
RUN cp /services/service.conf /etc/service.conf

