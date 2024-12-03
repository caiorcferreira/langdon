from enum import Enum
import streamlit as st
from streamlit.logger import get_logger

logger = get_logger(__name__)


class DetectionEngineeringStep(Enum):
    INIT = "init"
    SUGGEST_DETECTION_FROM_INTEL = "suggest_detection_from_intel"
    GENERATE_DETECTION_RULE = "generate_detection_rule"
    DEVELOP_INVESTIGATION_PLAYBOOK = "develop_investigation_playbook"
    QA_REVIEW = "qa_review"
    FINAL_SUMMARY = "final_summary"

    def __lt__(self, other):
        self_index = DETECTION_ENGINEERING_STEPS.index(self)
        other_index = DETECTION_ENGINEERING_STEPS.index(other)

        return self_index < other_index

    def __gt__(self, other):
        return self != other and not self < other


DETECTION_ENGINEERING_STEPS = [
    DetectionEngineeringStep.INIT,
    DetectionEngineeringStep.SUGGEST_DETECTION_FROM_INTEL,
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

    DETECTION_STEPS = "detection_steps"
    TRIAGE_STEPS = "triage_steps"

    DETECTION_ENG_CURRENT_STEP = "detection_eng_current_step"

    THREAT_SOURCE = "threat_source"
    THREAT_SOURCE_FOCUS = "threat_source_focus"
    UPLOADED_THREAT_FILE = "uploaded_threat_file"
    SUGGESTED_DETECTIONS = "suggested_detections"
    SELECTED_DETECTION = "selected_detection"

    EXAMPLE_DETECTIONS = "example_detections"
    EXAMPLE_LOGS = "example_logs"

    DETECTION_RULE = "detection_rule"
    INVESTIGATION_GUIDE = "investigation_guide"


class State:
    @staticmethod
    def init():
        if not State.has(StateKey.SUGGESTED_DETECTIONS):
            State.set(StateKey.SUGGESTED_DETECTIONS, None)

        if not State.has(StateKey.SELECTED_DETECTION):
            State.set(StateKey.SELECTED_DETECTION, None)

        if not State.has(StateKey.DETECTION_ENG_CURRENT_STEP):
            State.set(StateKey.DETECTION_ENG_CURRENT_STEP, DETECTION_ENGINEERING_STEPS[0])

    @staticmethod
    def component_key(key: StateKey):
        return f"{key.value}"

    @staticmethod
    def set(key: StateKey, value):
        st.session_state[key.value] = value

    @staticmethod
    def advance_detection_engineering_step():
        """
        Advance the detection engineering step to the next step.
        NOTE: call st.rerun() after calling this method to re-render the page.
        """
        current_step = State.get(StateKey.DETECTION_ENG_CURRENT_STEP)
        current_index = DETECTION_ENGINEERING_STEPS.index(current_step)
        next_index = current_index + 1

        if next_index < len(DETECTION_ENGINEERING_STEPS):
            next_step = DETECTION_ENGINEERING_STEPS[next_index]
            logger.info(
                f"Advancing from {DETECTION_ENGINEERING_STEPS[current_index]} to next step: {DETECTION_ENGINEERING_STEPS[next_index]}")

            State.set(StateKey.DETECTION_ENG_CURRENT_STEP, next_step)
        else:
            st.error("No more steps to advance to.")

    @staticmethod
    def get(key: StateKey):
        return st.session_state.get(key.value, None)

    @staticmethod
    def has(key: StateKey) -> bool:
        return key.value in st.session_state


def step_update_transaction():
    return StepUpdateTransaction()


class StepUpdateTransaction:
    def __init__(self):
        self.step_before = None

    def __enter__(self):
        self.step_before = State.get(StateKey.DETECTION_ENG_CURRENT_STEP)

        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if State.get(StateKey.DETECTION_ENG_CURRENT_STEP) != self.step_before:
            st.rerun()

        return False
