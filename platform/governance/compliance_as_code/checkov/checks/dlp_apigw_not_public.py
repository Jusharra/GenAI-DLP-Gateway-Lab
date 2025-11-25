from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckResult, CheckCategories

class DLPAPINotPublic(BaseResourceCheck):
    def __init__(self):
        name = "DLP API Gateway must not be public without auth"
        id = "CKV_DLP_005"
        supported_resources = ["aws_apigatewayv2_api"]
        categories = [CheckCategories.NETWORKING]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        # You can tighten later if you add authorizers
        disable_execute = conf.get("disable_execute_api_endpoint", [False])[0]
        return CheckResult.PASSED if disable_execute else CheckResult.FAILED

check = DLPAPINotPublic()
