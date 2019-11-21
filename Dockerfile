FROM python:alpine3.7

RUN apk add --no-cache --virtual .build-deps gcc g++ musl-dev libffi-dev openssl-dev linux-headers zeromq-dev python3-dev libpcap-dev
COPY . /Effluvium

WORKDIR /Effluvium
RUN pip install -r requirements.txt
EXPOSE 5000
CMD python ./effluvium.py

