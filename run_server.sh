#!/bin/bash

PORT=${1:-12345}

cd "$(dirname "$0")/build"
./EchoServer $PORT
