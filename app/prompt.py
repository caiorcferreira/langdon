import dspy
from pydantic import BaseModel, Field
from typing import Literal
import os


class Detection(BaseModel):
    name: str = Field(description="detection rule concise name")
    mitre_tactic: str = Field(description="MITRE ATT&CK tactic")
    threat_behavior: str = Field(description="detection rule detailed description")
    log_evidence: str = Field(description="log data or events to be used in the detection, be specific and detailed, include event names and optionally fields")
    context: str = Field(description="relevant prerequisites or environmental factors")


class SuggestDetectionFromIntel(dspy.Signature):
    """# IDENTITY AND PURPOSE
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


def suggest_detections_from_intel(focus: str, report: str, data_source: str, model_params: dict) -> list[Detection]:
    """Interpret the threat intelligence report and extract potential detections."""
    configure_lm("openai")

    predictor = dspy.ChainOfThought(SuggestDetectionFromIntel, **model_params)
    output = predictor(focus=focus, report=report, data_source=data_source)

    return output.suggested_detections


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
