from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckResult, CheckCategories

class DLPEvidenceBucketKMSEnabled(BaseResourceCheck):
    def __init__(self):
        name = "DLP Evidence bucket must use SSE-KMS encryption"
        id = "CKV_DLP_001"
        supported_resources = ["aws_s3_bucket"]
        categories = [CheckCategories.ENCRYPTION]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        # Only target evidence/demo buckets by name pattern
        bucket_name = conf.get("bucket", [""])[0]
        if "dlp-evidence" not in bucket_name and "evidence" not in bucket_name:
            return CheckResult.PASSED

        sse = conf.get("server_side_encryption_configuration")
        if not sse:
            return CheckResult.FAILED

        rules = sse[0].get("rule", [])
        for r in rules:
            apply = r.get("apply_server_side_encryption_by_default", [])
            if apply and apply[0].get("sse_algorithm") == ["aws:kms"]:
                return CheckResult.PASSED

        return CheckResult.FAILED

check = DLPEvidenceBucketKMSEnabled()
