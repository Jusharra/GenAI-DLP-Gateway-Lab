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
if [ -n "$AWS_PROFILE" ]; then
  AWS_CMD_PROFILE="--profile $AWS_PROFILE"
fi

DEMO_BUCKET=$(aws cloudformation describe-stacks \
  --stack-name "$STACK_NAME" --region "$REGION" $AWS_CMD_PROFILE \
  --query "Stacks[0].Outputs[?OutputKey=='DemoBucketName'].OutputValue" --output text)

if [ -z "$DEMO_BUCKET" ]; then
  echo "❌ Could not find DemoBucketName output. Deploy stack first."
  exit 1
fi

export DEMO_BUCKET="$DEMO_BUCKET"
python platform/devsecops/scripts/seed_demo_data.py
echo "✅ Seeded demo data to s3://$DEMO_BUCKET/{clean,sensitive}/"
