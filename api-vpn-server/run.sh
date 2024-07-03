#!/bin/bash

#Load environment variables from .env file
set -a
source .env
set +a

# Run uvicorn with specified host and port
uvicorn wirevpnserver:app --host $API_HOST --port $API_PORT --reload
