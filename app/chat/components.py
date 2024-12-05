import streamlit as st
from app.llm.prompt import Debug


def line_separator():
    st.markdown("<hr>", unsafe_allow_html=True)


class DetectionDetailComponent:
    def __init__(self, detection):
        self.detection = detection

    def render(self):
        detection = self.detection

        st.markdown(f"**Detection Name:** {detection.name}")
        st.write(f"**Threat Behavior:** {detection.threat_behavior}")
        st.write(f"**Log Evidence:** {detection.log_evidence}")
        st.write(f"**MITRE ATT&CK Tactic:** {detection.mitre_tactic}")
        st.write(f"**Context:** {detection.context}")


class DebugInfoComponent:
    def render(self, success_msg: str, debug_info: Debug):
        st.success(success_msg)

        with st.expander("View Details", expanded=False):
            st.write("**Prompt**:")
            st.code(debug_info.prompt)

            st.write("**Response**:")
            st.code(debug_info.response)
