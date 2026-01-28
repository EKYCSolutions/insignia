FROM rust:1.83-alpine AS builder

WORKDIR /opt/app

RUN apk add --no-cache --virtual .build-deps\
  gcc\
  clang\
  protoc\
  musl-dev\
  pkgconfig\
  build-base\
  openssl-dev\
  protobuf-dev\
  openssl-libs-static &&\
  rustup target add $(arch)-unknown-linux-musl

COPY . .

RUN cargo build -r --target=$(arch)-unknown-linux-musl &&\
  cargo build -r --target=$(arch)-unknown-linux-musl --manifest-path migration/Cargo.toml &&\
  mkdir out &&\
  cp /opt/app/target/$(arch)-unknown-linux-musl/release/migration /opt/app/target/$(arch)-unknown-linux-musl/release/insignia /opt/app/target/$(arch)-unknown-linux-musl/release/insignia-integration-server ./out/

FROM alpine:3.21

WORKDIR /opt/app

RUN apk add --no-cache --virtual .deps openssl

COPY ./migration/ ./

COPY --from=builder /opt/app/out/ ./
