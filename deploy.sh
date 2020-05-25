#!/bin/bash

set -euxo pipefail

REGION=us-east-1

python3 -m petze.template > petze-raw.json
aws cloudformation package --template-file petze-raw.json --s3-bucket schlarpc-deployment-us-east-1 \
    --use-json --output-template-file petze-packaged.json
jq -c . petze-packaged.json > petze.json
aws cloudformation deploy --region "$REGION" --stack-name Petze --template-file petze.json \
    --capabilities CAPABILITY_IAM
