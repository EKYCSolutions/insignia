#!/bin/bash

openssl genpkey -algorithm Ed25519 >jwt.pem

openssl pkey -in jwt.pem -pubout >jwt.pub

openssl rand 64 >session.key
