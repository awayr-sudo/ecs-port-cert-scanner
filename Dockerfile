ARG FUNCTION_DIR="/scanner"
FROM ubuntu:24.04


# Include global arg in this stage of the build
ARG FUNCTION_DIR

ARG BUILD_VERSION=3.2
ARG ARCHIVE_URL=https://github.com/drwetter/testssl.sh/archive/
# ARG URL=https://github.com/drwetter/testssl.sh.git

RUN apt-get update -y
RUN apt-get install -y wget masscan nmap sudo libcap2-bin  openssl 
RUN apt-get install -y dnsutils bsdextrautils procps libengine-gost-openssl testssl.sh 
# RUN apt-get install -y bsdmainutils git openssl dnsutils
# RUN sudo se   tcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap)

RUN apt-get -y install curl gnupg
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash - &&\
sudo apt-get install -y nodejs





RUN mkdir -p ${FUNCTION_DIR} 

COPY * ${FUNCTION_DIR}
COPY ./ ${FUNCTION_DIR}

WORKDIR ${FUNCTION_DIR}

# Install Node.js dependencies
RUN npm install

ENV NPM_CONFIG_CACHE=/tmp/.npm


# CMD /bin/bash
CMD [ "node", "index.js" ]
EXPOSE 8081