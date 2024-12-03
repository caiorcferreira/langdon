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
    SELECTED_DETECTION = "selected_detection"

    EXAMPLE_DETECTIONS = "example_detections"
    EXAMPLE_LOGS = "example_logs"


class State:
    @staticmethod
    def component_key(key: StateKey):
        return f"{key.value}"

    @staticmethod
    def set(key: StateKey, value):
        st.session_state[key.value] = value

    @staticmethod
    def advance_detection_engineering_step():
        current_step = State.get(StateKey.DETECTION_ENG_CURRENT_STEP)
        current_index = DETECTION_ENGINEERING_STEPS.index(current_step)
        next_index = current_index + 1

        if next_index < len(DETECTION_ENGINEERING_STEPS):
            next_step = DETECTION_ENGINEERING_STEPS[next_index]
            State.set(StateKey.DETECTION_ENG_CURRENT_STEP, next_step)
        else:
            st.error("No more steps to advance to.")

    @staticmethod
    def get(key: StateKey):
        return st.session_state.get(key.value, None)
