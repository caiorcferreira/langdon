import dspy
from pydantic import BaseModel, Field
from typing import Literal, Optional, Any
from app.llm.setup import configure_lm
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
    reports: list[str] = dspy.InputField(desc="list of threat intelligence reports")
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


class QAReview(dspy.Signature):
    """# ROLE AND PURPOSE
You are a QA specialist in cyber threat detection with extensive experience. Your task is to conduct a thorough and comprehensive review of a given detection rule, providing detailed assessments and actionable recommendations.

# STEPS
1.	Understand the Detection Rule and Analysis
    - Carefully read the detection rule provided as input.
    - Review the analysis from threat intelligence given as input.
    - Ensure you fully comprehend the detection logic and the threat behavior it is intended to capture.
2.	Assess the Detection Rule
    For each of the following aspects, provide:
        - A score out of 10.
        - A detailed explanation of your assessment.
        - Specific, actionable recommendations for improvement.
        - If no changes are needed, a thorough justification for why the current version is optimal.

    Aspects to Assess:
    1.	Syntactic Correctness
        - Is the rule syntactically correct based on the detection language?
        - Are there any syntax errors or potential runtime issues?
        - Does it follow best practices and conventions for the detection language?
    2.	Logical Accuracy
        - Does the rule accurately capture all aspects of the threat behavior described in the analysis?
        - Are there any logical errors or misinterpretations of the threat intelligence?
        - Is the detection logic complete and comprehensive?
    3.	Coverage
        - Does the rule cover all potential variations of the threat behavior?
        - Are there any edge cases or scenarios not addressed by the current implementation?
    4.	Performance and Efficiency
        - Is the detection optimized for performance in the target environment?
        - Are there any potential bottlenecks or resource	-intensive operations?
        - Could the rule be optimized without sacrificing accuracy?
    5.	False Positive/Negative Analysis
        - Provide a realistic estimate of both false positive and false negative rates.
        - Justify your estimates with specific scenarios or data points.
        - Suggest ways to minimize false positives without increasing false negatives.
    6.	Robustness and Evasion Resistance
        - How easily could an attacker evade this detection?
        - Are there any obvious bypass methods?
        - Suggest improvements to make the detection more robust against evasion techniques.
    7.	Investigation Guide Quality
        - Are the investigation steps clear, comprehensive, and actionable?
        - Do they cover all necessary aspects of validation, investigation, and response?
        - Are there any missing steps or areas that need more detail?
    8.	Integration and Dependencies
        - Does the rule rely on any external data sources or lookups?
        - Are there any potential issues with data availability or freshness?
    9.	Maintenance and Updatability
        - How easily can this rule be updated or modified in the future?
        - Are there any hard-coded elements that might require frequent updates?
    10.	Overall Effectiveness
        - How well does the detection rule achieve its intended purpose?
        - Does it strike a good balance between accuracy, performance, and maintainability?
    3.	Compile the QA Report
        - Present your findings as a structured report with clear recommendations for each aspect.
        - Include code snippets or pseudo-code where applicable to illustrate suggested improvements.
        - Ensure your report is clear, professional, and free of errors.
    4.	Provide an Overall Assessment
        - Conclude with an overall assessment of the detection rule’s quality and readiness for production deployment.
        - Include the total score out of 100.
        - Provide a brief explanation of the total score.

# ADDITIONAL INSTRUCTIONS
- If you cannot perform a complete assessment due to missing information, explain why and specify the missing details.
- Use clear and professional language throughout your report.
- Separate code snippets from the main text for readability.
- Ensure that all recommendations are specific and actionable.
- Return the score separated from the assessment.
"""
    detection_description: Detection = dspy.InputField(desc="detection description based on threat intel")
    detection_rule: DetectionRule = dspy.InputField(desc="detection rule implementation to be reviewed")
    score: int = dspy.OutputField(desc="total score out of 100")
    assessment: str = dspy.OutputField(desc="detailed assessment of the detection rule")


class FinalSummary(dspy.Signature):
    """# ROLE AND PURPOSE
You are a senior threat analyst tasked with compiling a comprehensive detection package for the security operations team. Your goal is to produce a markdown-formatted document that is well-structured, comprehensive, and ready for review and implementation.

# STEPS
1.	Analyze the Components
    - Carefully read the Detection Rule, Investigation Steps, and QA Findings provided.
    - Understand the threat behavior that the Detection Rule aims to identify.
    - Note any key issues or recommendations highlighted in the QA Findings.
2.	Compile the Detection Package
    - Create a markdown-formatted document using the following template:
        # [Threat TTP Name]: [Detection Rule Name]

        ## Threat Description
        [Provide a concise description of the threat behavior this detection aims to identify.]

        ## MITRE
        [Provide the MITRE ATT&CK tactic associated with this detection.]

        ## Detection Rule
        {detection_language}
        ```{previous_detection_rule}```

        ## Log Sources
        [List the specific log sources or data types required for this detection.]

        ## Investigation Steps
        [Provide a numbered list of investigation steps from the provided Investigation Steps.]

        ## Performance Considerations
        [Include brief notes on expected performance, including estimated false positive rate.]

        ## Quality Assessment
        **Score**: [Provide the overall score out of 100]

        [Summarize the key points from the QA Findings.]

3.	Review and Finalize
    - Ensure all sections are complete and accurately reflect the provided information.
    - Use clear, professional language and correct markdown formatting.
    - Verify that the document is ready for review and implementation by the security operations team.

# ADDITIONAL INSTRUCTIONS
- If any information is missing or incomplete, indicate this in the relevant section.
- Keep code blocks and explanations separate for clarity.
- Ensure your response is free of errors and adheres to the specified format.
"""
    detection_description: Detection = dspy.InputField(desc="detection description based on threat intel")
    detection_rule: DetectionRule = dspy.InputField(desc="detection rule implementation to be reviewed")
    investigation_guide: str = dspy.InputField(desc="investigation guide for the detection rule")
    qa_assessment: str = dspy.InputField(desc="QA assessment of the detection rule")
    qa_score: int = dspy.InputField(desc="QA score out of 100")
    final_summary: str = dspy.OutputField(desc="markdown-formatted document for the detection package")


class PromptSignature:
    @staticmethod
    def suggest_detections_from_intel(focus: str, reports: str, data_source: str, model_params: dict) -> list[Detection]:
        """Interpret the threat intelligence report and extract potential detections."""
        llm_ctx, model_params = PromptSignature.llm_context(model_params)
        with llm_ctx:
            predictor = dspy.ChainOfThought(SuggestDetectionFromIntel, **model_params)
            output = predictor(focus=focus, reports=reports, data_source=data_source)

            dspy.inspect_history(n=1)

        return output.suggested_detections

    @staticmethod
    def create_detection_rule(detection_description: Detection, detection_language: str, example_logs: list[str], example_detections: list[str], detection_steps: Optional[str], model_params: dict):
        """Create a detection rule based on the provided detection description."""
        logging_callback = ModuleLoggingCallback()

        llm_ctx, model_params = PromptSignature.llm_context(model_params)
        with llm_ctx:
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
        logging_callback = ModuleLoggingCallback()

        llm_ctx, model_params = PromptSignature.llm_context(model_params)
        with llm_ctx:
            predictor = dspy.ChainOfThought(DevelopInvestigationGuide, callbacks=[logging_callback], **model_params)
            output = predictor(
                detection_rule=detection_rule,
                example_standard_operation_procedure=standard_op_procedure,
            )
            rendered_prompt = logging_callback.history

            dspy.inspect_history(n=1)

        return output.investigation_guide, rendered_prompt

    @staticmethod
    def qa_review(detection_description: Detection, detection_rule: DetectionRule, model_params: dict):
        """Conduct a thorough and comprehensive review of a given detection rule."""
        logging_callback = ModuleLoggingCallback()

        llm_ctx, model_params = PromptSignature.llm_context(model_params)
        with llm_ctx:
            predictor = dspy.ChainOfThought(QAReview, callbacks=[logging_callback], **model_params)
            output = predictor(
                detection_description=detection_description,
                detection_rule=detection_rule,
            )
            rendered_prompt = logging_callback.history

            dspy.inspect_history(n=1)

        return output.score, output.assessment, rendered_prompt

    @staticmethod
    def final_summary(detection_description: Detection, detection_rule: DetectionRule, investigation_guide: str, qa_assessment: str, qa_score: int, model_params: dict):
        """Compile a comprehensive detection package for the security operations team."""
        logging_callback = ModuleLoggingCallback()

        llm_ctx, model_params = PromptSignature.llm_context(model_params)
        with llm_ctx:
            predictor = dspy.ChainOfThought(FinalSummary, callbacks=[logging_callback], **model_params)
            output = predictor(
                detection_description=detection_description,
                detection_rule=detection_rule,
                investigation_guide=investigation_guide,
                qa_assessment=qa_assessment,
                qa_score=qa_score,
            )
            rendered_prompt = logging_callback.history

            dspy.inspect_history(n=1)

        return output.final_summary, rendered_prompt

    @staticmethod
    def llm_context(model_params: dict):
        provider = model_params["llm_provider"]
        model = model_params["model"]

        lm = configure_lm(provider, model)

        del model_params["llm_provider"]
        del model_params["model"]

        return dspy.context(lm=lm), model_params


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


# def configure_lm(provider: Literal["genplat", "openai"]):
#     if provider == "genplat":
#         print("Using GenPlat")
#
#         default_headers = {
#             'x-requester-token': os.getenv('GENPLAT_API_KEY')
#         }
#
#         lm = dspy.LM(
#             model='openai/gpt-3.5-turbo-1106',
#             api_base=os.getenv('GENPLAT_BASE_URL'),
#             api_key="dummy",
#             extra_headers=default_headers
#         )
#
#     elif provider == "openai":
#         print("Using OpenAI")
#
#         lm = dspy.LM(
#             model='openai/gpt-4o-mini',
#             api_key=os.getenv('OPENAI_API_KEY')
#         )
#     else:
#         raise ValueError("Invalid provider")
#
#     dspy.configure(lm=lm)
#
#     return lm
