from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckResult, CheckCategories

class DLPPublicAccessBlocked(BaseResourceCheck):
    def __init__(self):
        name = "All DLP buckets must block public access"
        id = "CKV_DLP_003"
        supported_resources = ["aws_s3_bucket_public_access_block"]
        categories = [CheckCategories.NETWORKING]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        flags = [
            conf.get("block_public_acls", [False])[0],
            conf.get("ignore_public_acls", [False])[0],
            conf.get("block_public_policy", [False])[0],
            conf.get("restrict_public_buckets", [False])[0],
        ]
        return CheckResult.PASSED if all(flags) else CheckResult.FAILED

check = DLPPublicAccessBlocked()
