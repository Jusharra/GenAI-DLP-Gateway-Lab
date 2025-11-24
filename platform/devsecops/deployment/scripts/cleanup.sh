#!/bin/bash
set -e

STACK_NAME="dlp-gateway-control-plane"
REGION="us-east-1"
AWS_PROFILE=""

while [[ $# -gt 0 ]]; do
  case $1 in
    --stack-name) STACK_NAME="$2"; shift 2 ;;
    --region) REGION="$2"; shift 2 ;;
    --profile) AWS_PROFILE="$2"; shift 2 ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

AWS_CMD_PROFILE=""
if [ -n "$AWS_PROFILE" ]; then AWS_CMD_PROFILE="--profile $AWS_PROFILE"; fi

echo "Deleting stack $STACK_NAME ..."
aws cloudformation delete-stack --stack-name "$STACK_NAME" --region "$REGION" $AWS_CMD_PROFILE
aws cloudformation wait stack-delete-complete --stack-name "$STACK_NAME" --region "$REGION" $AWS_CMD_PROFILE
echo "✅ Stack deleted."
