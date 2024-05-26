FROM rust:1.74-alpine as builder

WORKDIR /opt/app

RUN apk add --no-cache --virtual .build-deps\
    clang\
    protoc\
    musl-dev\
    pkgconfig\
    build-base\
    openssl-dev\
    openssl-libs-static &&\
    rustup target add x86_64-unknown-linux-musl

COPY . .

RUN CC=clang PKG_CONFIG=pkg-config cargo build --release --target=x86_64-unknown-linux-musl &&\
    CC=clang PKG_CONFIG=pkg-config cargo build --release --target=x86_64-unknown-linux-musl --manifest-path migration/Cargo.toml

FROM rust:1.74-alpine

WORKDIR /opt/app

RUN apk add --no-cache --virtual .deps openssl

COPY ./migration/ ./

COPY --from=builder /opt/app/target/x86_64-unknown-linux-musl/release/migration db-migration
COPY --from=builder /opt/app/target/x86_64-unknown-linux-musl/release/insignia .
COPY --from=builder /opt/app/target/x86_64-unknown-linux-musl/release/insignia-integration-server .
