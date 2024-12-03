import dspy
from pydantic import BaseModel, Field
from typing import Literal
import os


class Detection(BaseModel):
    name: str = Field(description="detection rule concise name")
    threat_behavior: str = Field(description="detection rule detailed description")
    log_evidence: str = Field(description="specific log data or events to be used in the detection")
    context: str = Field(description="relevant prerequisites or environmental factors")


class InterpretThreatIntel(dspy.Signature):
    """# IDENTITY AND PURPOSE
You are an expert cybersecurity threat intelligence analyst.
The intel will be provided to you in the form of incident reports, threat intel reports, cybersecurity blogs, adverary emulation tools, existing detection content, or any description in natural language
of techniques, tactics and procedures (TTPs) used by cybersecurity threat actors.

# OUTPUT INSTRUCTIONS
- Focus only on behaviors or techniques. Avoid using atomic indicators like IP addresses or domain names.
- Extract potential detections that have clear log evidence in the provided intelligence.
- Focus only on threat intelligence that can be used to write detections for the given data source.
- If no detections are found for the specified data sources, return an empty list."""

    report: str = dspy.InputField(desc="threat intelligence report")
    data_source: str = dspy.InputField(desc="data sources to write detections for")
    suggested_detections: list[Detection] = dspy.OutputField(desc="a list of suggested detections based on the threat intelligence")


def interpret_threat_intel(report: str, data_source: str) -> list[Detection]:
    """Interpret the threat intelligence report and extract potential detections."""
    configure_lm("openai")

    predictor = dspy.Predict(InterpretThreatIntel)

    return predictor(report=report, data_source=data_source).suggested_detections


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
