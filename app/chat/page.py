import streamlit as st
from streamlit.logger import get_logger
from app.state import StateKey, State, DETECTION_ENGINEERING_STEPS
from .detection import DetectionCreationView
from app.llm.setup import PROVIDERS, MODELS

logger = get_logger(__name__)


class DetectionEngineeringPage:
    def configure_page(self):
        """Set the page configuration for the Streamlit app."""
        st.set_page_config(
            page_title=" Detection Engeneering",
            page_icon="",
            layout="wide",
            initial_sidebar_state="collapsed",
        )

    def render_sidebar(self):
        """Render the sidebar with configuration and links."""
        with st.sidebar:
            st.header("Langdon")
            st.write(" Detection Engineering engine powered by LLM.")

            self.render_configuration_section()

    def render_configuration_section(self):
        """Render the configuration section in the sidebar."""
        llm_providers = list(PROVIDERS.keys())

        selected_provider = State.get(StateKey.LLM_PROVIDER, llm_providers[0])
        models = MODELS.get(PROVIDERS[selected_provider])

        st.write("### Configuration")
        st.selectbox("LLM Provider", llm_providers, key=State.component_key(StateKey.LLM_PROVIDER))
        st.selectbox("Model Type", models, key=State.component_key(StateKey.MODEL))
        st.multiselect(
            "Security Data/Log Type(s)",
            [
                "AWS CloudTrail Logs",
                "GCP Audit Logs",
                "Azure Monitor Logs",
                "Kubernetes Audit Logs",
                "GitLab Audit Logs",
                "AWS EKS Plane logs",
                "Cisco Duo Logs",
                "Okta Logs",
            ],
            default=["AWS CloudTrail Logs"],
            key=State.component_key(StateKey.DATA_SOURCE),
        )
        st.selectbox(
            "Detection Language",
            [
                "Databricks PySpark",
                "Databricks SQL",
                "AWS Athena",
                "StreamAlert",
                "Splunk SPL",
                "Falcon LogScale",
                "Elastic Query DSL",
                "Kusto Query Language (KQL)",
                "Sigma Rules",
                "Panther (Python)",
                "Hunters (Snowflake SQL)",
            ],
            key=State.component_key(StateKey.DETECTION_LANG),
        )

        st.write("### Model Parameters")
        st.slider(
            "Temperature",
            min_value=0.0,
            max_value=1.0,
            value=0.5,
            step=0.01,
            key=State.component_key(StateKey.MODEL_TEMPERATURE),
        )
        st.number_input(
            "Max Tokens",
            min_value=1,
            max_value=4096,
            value=4096,
            key=State.component_key(StateKey.MODEL_MAX_TOKENS),
        )

    def render_main_header(self):
        """Render the main header with app title and subtitle."""
        st.markdown(
            "<h1 style='text-align: center;'>Langdon</h1>",
            unsafe_allow_html=True,
        )
        st.markdown(
            "<h2 style='text-align: center;'>Detection and Intelligence Analysis for New Alerts</h2>",
            unsafe_allow_html=True,
        )

    def render_tabs(self):
        """Render the tabs for different functionalities."""
        tabs = st.tabs(
            ["Detection Engineering", "Threat Research Crew", "Bulk Detection Processing [Coming Soon]"]
        )
        return tabs

    def render(self):
        """Main function to render the Streamlit app."""
        self.configure_page()
        self.render_sidebar()
        self.render_main_header()

        detection_tab = DetectionCreationView()

        detection_tab.render()
