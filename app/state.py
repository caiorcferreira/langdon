from enum import Enum
import streamlit as st


class StateKeys(Enum):
    LLM_PROVIDER = "llm_provider"
    MODEL = "model"
    MODEL_TEMPERATURE = "model_temperature"
    MODEL_MAX_TOKENS = "model_max_tokens"
    DATA_SOURCE = "data_source"
    DETECTION_LANG = "detection_lang"

    THREAT_SOURCE = "threat_source"
    THREAT_SOURCE_FOCUS = "threat_source_focus"
    UPLOADED_THREAT_FILE = "uploaded_threat_file"
    START_DETECTION_GENERATION = "start_detection_generation"

    EXAMPLE_DETECTIONS = "example_detections"
    EXAMPLE_LOGS = "example_logs"


def component_key(key: StateKeys):
    return f"{key.value}"


def set_state(key: StateKeys, value):
    st.session_state[key.value] = value


def get_state(key: StateKeys):
    return st.session_state.get(key.value, None)
