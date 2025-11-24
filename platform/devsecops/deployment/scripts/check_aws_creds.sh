#!/bin/bash
set -e

REGION="us-east-1"
AWS_PROFILE=""

while [[ $# -gt 0 ]]; do
  case $1 in
    --region) REGION="$2"; shift 2 ;;
    --profile) AWS_PROFILE="$2"; shift 2 ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

AWS_CMD_PROFILE=""
if [ -n "$AWS_PROFILE" ]; then
  AWS_CMD_PROFILE="--profile $AWS_PROFILE"
  echo "Using AWS profile: $AWS_PROFILE"
fi

echo "Checking AWS credentials in region: $REGION"

command -v aws >/dev/null || { echo "AWS CLI missing"; exit 1; }

aws sts get-caller-identity $AWS_CMD_PROFILE --region "$REGION" >/dev/null \
  && echo "✅ AWS creds valid" || { echo "❌ AWS creds invalid"; exit 1; }
