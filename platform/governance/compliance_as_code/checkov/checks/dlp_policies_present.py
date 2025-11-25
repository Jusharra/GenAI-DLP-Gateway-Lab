import os
from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck

REQUIRED_PATHS = [
    "platform/governance/policies_as_code/opa/dlp_runtime/dlp_runtime.rego",
    "platform/governance/policies_as_code/opa/terraform_guardrails.rego",
    "platform/mlsecops/data_movement/flows.yaml",
    "platform/mlsecops/classification/classification_policy.rego"
]

class DLPGovernanceArtifactsPresent(BaseResourceCheck):
    def __init__(self):
        name = "Governance artifacts must exist (PaC + CaC + DMaC + ClaaC)"
        id = "CKV_DLP_006"
        supported_resources = ["aws_lambda_function"]  # anchor check
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        # run once per plan; anchor on any lambda
        for p in REQUIRED_PATHS:
            if not os.path.exists(p):
                return CheckResult.FAILED
        return CheckResult.PASSED

check = DLPGovernanceArtifactsPresent()
