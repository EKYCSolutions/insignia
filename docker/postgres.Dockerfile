FROM timescale/timescaledb:2.13.0-pg16

RUN apk --no-cache --virtual .build-deps add git curl-dev postgresql-dev clang15 libc-dev llvm15 make g++ &&\
    apk --no-cache --virtual .deps add curl &&\
    git clone --depth 1 --branch v1.6.0 https://github.com/pramsey/pgsql-http &&\
    cd pgsql-http &&\
    make &&\
    make install &&\
    cd .. &&\
    apk del .build-deps &&\
    echo 'create extension if not exists http' > /docker-entrypoint-initdb.d/001_create-http-extension.sql
