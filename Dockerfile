FROM ubuntu:18.04


# install requirements 
RUN apt update && apt install --yes build-essential flex bison wget subversion m4 python3 python3-dev python3-setuptools libgmp-dev libssl-dev clang python3-pip python3-venv vim checkinstall zlib1g-dev git
RUN wget https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz && tar xvf pbc-0.5.14.tar.gz && cd /pbc-0.5.14 && ./configure LDFLAGS="-lgmp" && make && make install && ldconfig

# install python crypto charms
COPY ./charm /charm
RUN cd /charm && ./configure.sh --static  && make && make install && ldconfig

COPY ./code/requirements.txt /code/requirements.txt

# setup environment & install dependencies
RUN cd /code 
#RUN python3 -m venv env  
#RUN /code/env/bin/pip3 install -r requirements.txt
RUN pip3 install -r /code/requirements.txt

# install openssl
RUN cd /usr/local/src/ && \
    wget https://www.openssl.org/source/openssl-1.1.1c.tar.gz && \
    tar -xf openssl-1.1.1c.tar.gz && cd openssl-1.1.1c && \
    ./config --prefix=/usr/local/ssl --openssldir=/usr/local/ssl shared zlib && \
    make && make install
RUN ldconfig -v

# compile ore
COPY ./code/fastore /code/fastore
RUN cd /code/fastore && make clean lib

# misc
RUN mkdir /secrets
WORKDIR /code

# copy code last
COPY ./code /code


# --prefix=/code/env/lib/python3.6/site-packages