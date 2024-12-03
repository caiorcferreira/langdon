import dspy
from pydantic import BaseModel, Field
from typing import Literal, Optional, Any
import os
from dspy.utils.callback import BaseCallback

class Detection(BaseModel):
    name: str = Field(description="detection rule concise name")
    mitre_tactic: str = Field(description="MITRE ATT&CK tactic")
    threat_behavior: str = Field(description="detection rule detailed description")
    log_evidence: str = Field(description="log data or events to be used in the detection, be specific and detailed, include event names and optionally fields")
    context: str = Field(description="relevant prerequisites or environmental factors")


class SuggestDetectionFromIntel(dspy.Signature):
    """# ROLE AND PURPOSE
You are an expert cybersecurity threat intelligence analyst.
The intel will be provided to you in the form of incident reports, threat intel reports, cybersecurity blogs, adverary emulation tools, existing detection content, or any description in natural language
of techniques, tactics and procedures (TTPs) used by cybersecurity threat actors.

# STEPS
1. Read the threat report description, then analyze the threat intelligence report.
2. Create a mental model of the threat actor's behavior and techniques (TTPs).
3. Relate each TTP to a specific log event or a set of log events from the data source that can be used to detect the threat actor's activity.
4. Write a list of suggested detections based on the threat intelligence.

# OUTPUT INSTRUCTIONS
- Provide a list with at least one detection rule for each TTP identified in the threat intelligence report.
- If no detections are found, return an empty list."""

    focus: str = dspy.InputField(desc="brief description about which content of threat intelligence report to focus on")
    report: str = dspy.InputField(desc="threat intelligence report")
    data_source: str = dspy.InputField(desc="data sources to write detections for")
    suggested_detections: list[Detection] = dspy.OutputField(desc="a list of suggested detections based on the threat intelligence")


class DetectionRule(BaseModel):
    code: str = Field(description="detection rule code")
    logic: str = Field(description="explanation of the rule's logic")
    limitations: str = Field(description="limitations and edge cases")
    false_positive_rate: str = Field(description="estimated false positive rate and rationale")


class CreateDetectionRule(dspy.Signature):
    """# ROLE AND PURPOSE
You are an experienced detection engineer specialized in creating robust detection rules. Your task is to create a detection rule based on the detection description provided as input.

Ensure that:
- The detection rule accurately captures the threat behavior described.
- The detection rule is written in the specified detection language.
- The detection rule follows the data conventions (field name, types, etc) presented in the example log data, if provided.
- The detection rule follows the format and idioms used in example detection rules, if provided.

# STEPS
1. Understand the Threat Behavior
    - Carefully read the detection description enclosed between <detection_description> tags.
    - Analyze the threat behavior and associated log data.
    - Note any detection steps provided for implementation.
2. Develop the Detection Rule
    - Write a detection rule in the specified detection language that captures the threat behavior.
    - Follow any supplied detection steps.
    - Include comments in the code explaining the logic and any assumptions.
3. Identify Limitations and Edge Cases
    - Outline any limitations and edge cases the detection rule may encounter.
    - Consider scenarios that could affect the rule’s effectiveness.
4. Estimate False Positive Rate
    - Provide an estimation of the false positive rate for the detection rule.
    - Justify your estimation with a clear rationale.

# ADDITIONAL INSTRUCTIONS
- If you cannot write a complete detection rule, explain why and specify the missing information.
- Separate the detection rule code from the explanations.
- Ensure your response is clear, professional, and free of errors.
"""
    detection_description: Detection = dspy.InputField(desc="description of the detection rule to be created")
    detection_language: str = dspy.InputField(desc="detection language to write the detection rule in")
    example_detection_rules: list[str] = dspy.InputField(desc="example detection rules showing the format and idioms used in detection rules")
    example_logs: list[str] = dspy.InputField(desc="example logs showing the structure of log data or events")
    detection_steps: Optional[str] = dspy.InputField(desc="outline the steps typically followed when writing detection rules (optional)")

    detection_rule: DetectionRule = dspy.OutputField(desc="complete detection rule with code, logic, limitations, and false positive rate")


class DevelopInvestigationGuide(dspy.Signature):
    """# ROLE AND PURPOSE
You are an experienced SOC analyst specialized in creating detailed investigation guides for detection rules. Your task is to create an investigation guide based on the provided detection rule and other inputs.

Ensure that:
- The investigation guide follows Palantir's alert and detection strategy framework.
- The guide incorporates elements from the provided standard operating procedure (SOP), if available.
- The guide includes clear, concise, and actionable steps.

# STEPS
1. **Review the Detection Rule and SOP**
    - Carefully read the detection rule enclosed given as input.
    - If a standard operating procedure is provided, read it carefully.

2. **Develop the Investigation Guide**
    - Create an investigation guide that includes:
        1. Initial triage steps to quickly assess the alert's validity.
        2. Detailed investigation procedures, including specific queries or commands.
        3. Criteria for escalation or closure of the alert.
        4. Potential related TTPs or lateral movements to look for.
        5. Recommended containment or mitigation actions.
    - Incorporate elements from Palantir's alert and detection strategy framework.
    - Include relevant elements from the SOP, if provided.

3. **Format the Guide**
    - Present the guide as a numbered list with clear, concise, and actionable steps.
    - Include any caveats, limitations, or decision points an analyst might encounter.

# ADDITIONAL INSTRUCTIONS
- If you cannot write a complete investigation guide, explain why and specify the missing information.
- Ensure your response is clear, professional, and free of errors.
- Return only the investigation guide, no comments.
"""
    detection_rule: DetectionRule = dspy.InputField(desc="description of the detection rule to be created")
    example_standard_operation_procedure: str = dspy.InputField(desc="example standard operation procedure showing the format and style of an investigation guide.")
    investigation_guide: str = dspy.OutputField(desc="investigation guide to triage and investigate detection rule alerts")


class PromptSignature:
    @staticmethod
    def suggest_detections_from_intel(focus: str, report: str, data_source: str, model_params: dict) -> list[Detection]:
        """Interpret the threat intelligence report and extract potential detections."""
        configure_lm("openai")

        predictor = dspy.ChainOfThought(SuggestDetectionFromIntel, **model_params)
        output = predictor(focus=focus, report=report, data_source=data_source)

        dspy.inspect_history(n=1)

        return output.suggested_detections

    @staticmethod
    def create_detection_rule(detection_description: Detection, detection_language: str, example_logs: list[str], example_detections: list[str], detection_steps: Optional[str], model_params: dict):
        """Create a detection rule based on the provided detection description."""
        configure_lm("openai")

        logging_callback = ModuleLoggingCallback()

        predictor = dspy.ChainOfThought(CreateDetectionRule, callbacks=[logging_callback], **model_params)
        output = predictor(
            detection_description=detection_description,
            detection_language=detection_language,
            example_logs=example_logs,
            example_detection_rules=example_detections,
            detection_steps=detection_steps,
        )
        rendered_prompt = logging_callback.history

        dspy.inspect_history(n=1)

        return output.detection_rule, rendered_prompt

    @staticmethod
    def develop_investigation_guide(detection_rule: DetectionRule, standard_op_procedure: Optional[str], model_params: dict):
        configure_lm("openai")

        logging_callback = ModuleLoggingCallback()

        predictor = dspy.ChainOfThought(DevelopInvestigationGuide, callbacks=[logging_callback], **model_params)
        output = predictor(
            detection_rule=detection_rule,
            example_standard_operation_procedure=standard_op_procedure,
        )
        rendered_prompt = logging_callback.history

        dspy.inspect_history(n=1)

        return output.investigation_guide, rendered_prompt



class ModuleLoggingCallback(BaseCallback):
    def __init__(self):
        self.history = ""

    def on_lm_start(self, call_id, instance, inputs):
        self.history += "Input prompt:\n"
        for k, v in inputs.items():
            self.history += f"{k}: {v}\n"

        self.history += "\n"

    def on_module_end(
        self,
        call_id: str,
        outputs: Optional[Any],
        exception: Optional[Exception] = None,
    ):
        self.history += "Response:\n"
        for k, v in outputs.items():
            self.history += f"{k}: {v}\n"

        self.history += "\n"


def configure_lm(provider: Literal["genplat", "openai"]):
    if provider == "genplat":
        print("Using GenPlat")

        default_headers = {
            'x-requester-token': os.getenv('GENPLAT_API_KEY')
        }

        lm = dspy.LM(
            model='openai/gpt-3.5-turbo-1106',
            api_base=os.getenv('GENPLAT_BASE_URL'),
            api_key="dummy",
            extra_headers=default_headers
        )

    elif provider == "openai":
        print("Using OpenAI")

        lm = dspy.LM(
            model='openai/gpt-4o-mini',
            api_key=os.getenv('OPENAI_API_KEY')
        )
    else:
        raise ValueError("Invalid provider")

    dspy.configure(lm=lm)

    return lm
