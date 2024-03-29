FROM ubuntu:18.04

RUN apt update && \
    apt install -y build-essential libreadline-dev zip unzip cmake wget luajit libluajit-5.1-dev && \
    wget https://luarocks.org/releases/luarocks-3.8.0.tar.gz && \
    tar zxpf luarocks-3.8.0.tar.gz && \
    cd luarocks-3.8.0 && \
    ./configure && \
    make && make install && \
    cd .. && \
    rm -rf luarocks-3.8.0 && \
    rm luarocks-3.8.0.tar.gz

RUN luarocks install busted && \
    luarocks install rapidjson 0.7.1 && \
    luarocks install luasocket && \
    luarocks install lua-resty-openssl 0.8.8-1 && \
    luarocks install date 2.1.2-1

WORKDIR /my-workspace

COPY . .
