# Image: agaveplatform/admin-api

FROM agaveplatform/python-api-starter:develop

MAINTAINER Rion Dooley <deardooley@gmail.com>

ADD requirements.txt /requirements.txt
RUN pip3 install -r /requirements.txt

ADD services /services
RUN cp /services/service.conf /etc/service.conf

