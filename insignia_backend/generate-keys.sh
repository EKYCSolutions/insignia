#!/bin/bash

openssl genpkey -algorithm Ed25519 >jwt.priv

openssl pkey -in jwt.priv -pubout >jwt.pub

openssl rand 64 >session.key
