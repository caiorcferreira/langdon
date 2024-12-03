from enum import Enum
import streamlit as st


class DetectionEngineeringStep(Enum):
    INTERPRET_THREAT_INTEL = "interpret_threat_intel"
    GENERATE_DETECTION_RULE = "generate_detection_rule"
    DEVELOP_INVESTIGATION_PLAYBOOK = "develop_investigation_playbook"
    QA_REVIEW = "qa_review"
    FINAL_SUMMARY = "final_summary"


DETECTION_ENGINEERING_STEPS = [
    DetectionEngineeringStep.INTERPRET_THREAT_INTEL,
    DetectionEngineeringStep.GENERATE_DETECTION_RULE,
    DetectionEngineeringStep.DEVELOP_INVESTIGATION_PLAYBOOK,
    DetectionEngineeringStep.QA_REVIEW,
    DetectionEngineeringStep.FINAL_SUMMARY,
]


class StateKey(Enum):
    LLM_PROVIDER = "llm_provider"
    MODEL = "model"
    MODEL_TEMPERATURE = "model_temperature"
    MODEL_MAX_TOKENS = "model_max_tokens"
    DATA_SOURCE = "data_source"
    DETECTION_LANG = "detection_lang"

    DETECTION_ENG_CURRENT_STEP = "detection_eng_current_step"

    THREAT_SOURCE = "threat_source"
    THREAT_SOURCE_FOCUS = "threat_source_focus"
    UPLOADED_THREAT_FILE = "uploaded_threat_file"
    SUGGESTED_DETECTIONS = "suggested_detections"

    EXAMPLE_DETECTIONS = "example_detections"
    EXAMPLE_LOGS = "example_logs"


def component_key(key: StateKey):
    return f"{key.value}"


def set_state(key: StateKey, value):
    st.session_state[key.value] = value


def get_state(key: StateKey):
    return st.session_state.get(key.value, None)
