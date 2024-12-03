import streamlit as st
from streamlit.logger import get_logger
from app.state import StateKey, State, DETECTION_ENGINEERING_STEPS
from .detection import DetectionCreationView

logger = get_logger(__name__)


class DetectionEngineeringPage:
    def configure_page(self):
        """Set the page configuration for the Streamlit app."""
        st.set_page_config(
            page_title=" Detection Engeneering",
            page_icon="",
            layout="wide",
        )

    def render_sidebar(self):
        """Render the sidebar with configuration and links."""
        with st.sidebar:
            st.markdown("""""")
            st.write("## Quick Start Guide")
            st.expander("Quick Start Guide")

            self.render_configuration_section()

    def render_configuration_section(self):
        """Render the configuration section in the sidebar."""
        st.write("### Configuration")
        st.selectbox("LLM Provider", ["OpenAI", "Claude", "Other"], key=State.component_key(StateKey.LLM_PROVIDER))
        st.selectbox("Model Type", ["gpt-4o-mini", "gpt-3.5", "Claude-mini"], key=State.component_key(StateKey.MODEL))
        st.multiselect(
            "Security Data/Log Type(s)",
            [
                "AWS CloudTrail Logs",
                "Azure Monitor Logs",
                "GCP Audit Logs",
            ],
            default=["AWS CloudTrail Logs"],
            key=State.component_key(StateKey.DATA_SOURCE),
        )
        st.selectbox(
            "Detection Language",
            ["Hunters (Snowflake SQL)", "KQL", "SQL"],
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
            "<h1 style='text-align: center;'> Detection Engineering</h1>",
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
        logger.info("rerendering page")

        self.configure_page()
        # improve initial state handling

        # if State.get(StateKey.DETECTION_ENG_CURRENT_STEP) is None:
        #     State.set(StateKey.DETECTION_ENG_CURRENT_STEP, DETECTION_ENGINEERING_STEPS[0])

        self.render_sidebar()
        self.render_main_header()
        tabs = self.render_tabs()

        detection_tab = DetectionCreationView()

        with tabs[0]:
            detection_tab.render()