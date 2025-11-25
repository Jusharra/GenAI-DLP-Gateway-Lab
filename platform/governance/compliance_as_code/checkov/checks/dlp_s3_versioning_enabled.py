from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckResult, CheckCategories

class DLPEvidenceBucketVersioningEnabled(BaseResourceCheck):
    def __init__(self):
        name = "DLP Evidence bucket must have versioning enabled"
        id = "CKV_DLP_002"
        supported_resources = ["aws_s3_bucket"]
        categories = [CheckCategories.BACKUP_AND_RECOVERY]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        bucket_name = conf.get("bucket", [""])[0]
        if "dlp-evidence" not in bucket_name and "evidence" not in bucket_name:
            return CheckResult.PASSED

        versioning = conf.get("versioning")
        if not versioning:
            return CheckResult.FAILED

        enabled = versioning[0].get("enabled")
        return CheckResult.PASSED if enabled == [True] else CheckResult.FAILED

check = DLPEvidenceBucketVersioningEnabled()
