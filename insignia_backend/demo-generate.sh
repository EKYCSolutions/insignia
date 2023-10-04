#!/bin/bash

openssl genpkey -algorithm Ed25519 > jwt-secret.pem

openssl pkey -in jwt-secret.pem -pubout > jwt-secret.pub

openssl rand 64 > session.key
