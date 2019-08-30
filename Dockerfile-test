# Image:  agaveplatform/admin-api-tests

FROM agaveplatform/python-api-starter:develop

MAINTAINER Rion Dooley <deardooley@gmail.com>

RUN pip3 install pytest

ADD tests /tests
ADD services /tests/services

entrypoint ["py.test", "/tests/test_admin_core.py"]