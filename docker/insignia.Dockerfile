FROM rust:1.74-alpine as builder

WORKDIR /opt/app

RUN apk add --no-cache --virtual .build-deps\
    clang\
    protoc\
    musl-dev\
    pkgconfig\
    build-base\
    openssl-dev\
    protobuf-dev\
    openssl-libs-static &&\
    rustup target add x86_64-unknown-linux-musl

COPY . .

# multiple cargo check
# as hack to get build.rs
# to output protobuf def
RUN cargo check || true &&\
    cargo check || true &&\
    cargo check || true &&\
    cargo build --release --target=x86_64-unknown-linux-musl &&\
    cargo build --release --target=x86_64-unknown-linux-musl --manifest-path migration/Cargo.toml

FROM alpine:3.20

WORKDIR /opt/app

RUN apk add --no-cache --virtual .deps openssl

COPY ./migration/ ./

COPY --from=builder /opt/app/target/x86_64-unknown-linux-musl/release/migration db-migration
COPY --from=builder /opt/app/target/x86_64-unknown-linux-musl/release/insignia .
COPY --from=builder /opt/app/target/x86_64-unknown-linux-musl/release/insignia-integration-server .
