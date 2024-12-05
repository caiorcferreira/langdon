import streamlit as st


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
