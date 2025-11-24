#!/bin/bash
set -e

STACK_NAME="dlp-gateway-control-plane"
REGION="us-east-1"
AWS_PROFILE=""

PROJECT_NAME="genai-dlp-gateway-lab"
ENVIRONMENT="dev"

EVIDENCE_BUCKET="vhc-dlp-evidence-logs-dev"
DEMO_BUCKET="vhc-dlp-demo-data-dev"
QUAR_BUCKET="vhc-dlp-quarantine-dev"

while [[ $# -gt 0 ]]; do
  case $1 in
    --stack-name) STACK_NAME="$2"; shift 2 ;;
    --region) REGION="$2"; shift 2 ;;
    --profile) AWS_PROFILE="$2"; shift 2 ;;
    --project-name) PROJECT_NAME="$2"; shift 2 ;;
    --env) ENVIRONMENT="$2"; shift 2 ;;
    --evidence-bucket) EVIDENCE_BUCKET="$2"; shift 2 ;;
    --demo-bucket) DEMO_BUCKET="$2"; shift 2 ;;
    --quarantine-bucket) QUAR_BUCKET="$2"; shift 2 ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

AWS_CMD_PROFILE=""
if [ -n "$AWS_PROFILE" ]; then
  AWS_CMD_PROFILE="--profile $AWS_PROFILE"
  echo "Using AWS profile: $AWS_PROFILE"
fi

echo "Deploying stack: $STACK_NAME"

aws cloudformation deploy \
  --template-file platform/devsecops/deployment/templates/dlp-gateway-control-plane.yaml \
  --stack-name "$STACK_NAME" \
  --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM \
  --region "$REGION" \
  $AWS_CMD_PROFILE \
  --parameter-overrides \
    ProjectName="$PROJECT_NAME" \
    Environment="$ENVIRONMENT" \
    EvidenceBucketName="$EVIDENCE_BUCKET" \
    DemoBucketName="$DEMO_BUCKET" \
    QuarantineBucketName="$QUAR_BUCKET"

echo "✅ Stack deployed."
aws cloudformation describe-stacks --stack-name "$STACK_NAME" --region "$REGION" $AWS_CMD_PROFILE \
  --query "Stacks[0].Outputs"
