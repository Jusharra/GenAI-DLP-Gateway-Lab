from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckResult, CheckCategories

REQUIRED_ENV = {"OPA_POLICY_PATH", "FLOWS_JSON_PATH"}

class DLPLambdaEnvVars(BaseResourceCheck):
    def __init__(self):
        name = "DLP Lambda must declare OPA + Data Movement env vars"
        id = "CKV_DLP_004"
        supported_resources = ["aws_lambda_function"]
        categories = [CheckCategories.IAM]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        fn_name = conf.get("function_name", [""])[0]
        if "dlp" not in fn_name:
            return CheckResult.PASSED

        env = conf.get("environment")
        if not env:
            return CheckResult.FAILED

        vars_map = env[0].get("variables", [{}])[0]
        missing = REQUIRED_ENV.difference(set(vars_map.keys()))
        return CheckResult.PASSED if not missing else CheckResult.FAILED

check = DLPLambdaEnvVars()
