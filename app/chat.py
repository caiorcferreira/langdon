import streamlit as st
import fitz
from .prompt import interpret_threat_intel, configure_lm
from streamlit.logger import get_logger
import dspy

logger = get_logger(__name__)

INTERPRET_THREAT_INTEL = "interpret_threat_intel"
GENERATE_DETECTION_RULE = "generate_detection_rule"
DEVELOP_INVESTIGATION_PLAYBOOK = "develop_investigation_playbook"
QA_REVIEW = "qa_review"
FINAL_SUMMARY = "final_summary"

detection_engineering_steps = [
    INTERPRET_THREAT_INTEL,
    GENERATE_DETECTION_RULE,
    DEVELOP_INVESTIGATION_PLAYBOOK,
    QA_REVIEW,
    FINAL_SUMMARY,
]

def line_separator():
    st.markdown("<hr>", unsafe_allow_html=True)


def serialize_file(uploaded_file):
    if uploaded_file.type == "application/pdf":
        file_content = ""

        pdf_document = fitz.open(stream=uploaded_file.read(), filetype="pdf")
        for page_num in range(pdf_document.page_count):
            page = pdf_document.load_page(page_num)
            file_content += page.get_text()

        return file_content

    else:  # todo: throw if unsupported file type
        # Process other text files
        return uploaded_file.getvalue().decode("utf-8")

class DetectionCreationView:
    def __init__(self):
        self.current_step = detection_engineering_steps[0]  # todo: replace with session_state

    def render(self):
        """Render the Detection Engineering tab."""
        st.progress(6 / 6, text="Current Step: 5/5")
        self.render_threat_intelligence_input()
        line_separator()
        self.render_example_detections()
        line_separator()
        self.render_example_logs()

        output_container = st.container()
        with output_container:
            line_separator()
            st.button(
                "Start detection generation",
                key="start_detection_generation",
                type="primary",
                on_click=lambda: self.start_detection_generation(output_container),
            )

    def start_detection_generation(self, parent):
        """Start the detection generation process."""
        with parent:
            st.subheader("Step 1: Analyze Threat Intel")
            # details = st.expander("View Details", expanded=False)

            with st.spinner("Analyzing threat intelligence..."):
                logger.info(f"Threat Source: {st.session_state["threat_source"]}")
                detections = interpret_threat_intel(report=st.session_state["threat_source"], data_source="AWS CloudTrail Logs")

            if not detections:
                st.warning("No detections found for the specified data sources.")
                return

            st.success("Analysis complete!")

            # Display the number of detections found
            st.info(f"Number of detections found: {len(detections)}")

            st.subheader("Detections found:")
            for detection in detections:
                st.markdown(f"**Detection Name:** {detection.name}")
                st.write(f"**Threat Behavior:** {detection.threat_behavior}")
                st.write(f"**Log Evidence:** {detection.log_evidence}")
                st.write(f"**Context:** {detection.context}")
                st.write("---")


    def render_threat_intelligence_input(self):
        """Render the Threat Intelligence Input section."""
        st.subheader("Threat Intelligence Input")
        col1, col2 = st.columns([1, 1])

        with col1:
            st.text_area(
                "Enter threat intelligence description:",
                placeholder="Detect a user trying to steal IAM Credentials and Event Data from Lambda.",
                height=400,
            )

        with col2:
            st.subheader("Fetch online threat intel")
            st.text_input("Enter URL:", "")
            if st.button("Scrape URL"):
                st.info("Scraping URL...")

            line_separator()

            st.subheader("Parse threat intel report")
            st.file_uploader(
                "Upload file (optional):",
                type=["txt", "pdf"],
                key="uploaded_threat_file",
                label_visibility="visible",
                on_change=self.update_threat_source_from_file,
            )

    def update_threat_source_from_file(self):
        """Update the threat source based on the uploaded file."""
        uploaded_file = st.session_state['uploaded_threat_file']
        logger.info(f"Uploaded File: {uploaded_file}")

        st.session_state["threat_source"] = serialize_file(uploaded_file)

    def render_example_detections(self):
        """Render the Example Detections section."""
        st.subheader("Example Detections")
        example_count = st.number_input("Number of example detections", min_value=1, max_value=5, value=2)
        for i in range(1, int(example_count) + 1):
            st.text_area(
                f"Example detection {i}",
                placeholder=f"SELECT DISTINCT * FROM control",
                height=100,
            )


    def render_example_logs(self):
        """Render the Example Logs section."""
        st.subheader("Example Logs")
        example_count = st.number_input("Number of example logs", min_value=1, max_value=5, value=2)
        for i in range(1, int(example_count) + 1):
            st.text_area(
                f"Example log {i}",
                placeholder=f"paste examples of your actual logs here, you may have different field names or logging structure",
                height=100,
            )



class DetectionEngineeringApp:
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
        st.selectbox("LLM Provider", ["OpenAI", "Claude", "Other"])
        st.selectbox("Model Type", ["gpt-4o-mini", "gpt-3.5", "Claude-mini"])
        st.multiselect(
            "Security Data/Log Type(s)",
            [
                "AWS CloudTrail Logs",
                "Azure Monitor Logs",
                "GCP Audit Logs",
            ],
            default=["AWS CloudTrail Logs"],
        )
        st.selectbox(
            "Detection Language",
            ["Hunters (Snowflake SQL)", "KQL", "SQL"],
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
        self.configure_page()

        self.render_sidebar()
        self.render_main_header()
        tabs = self.render_tabs()

        detection_tab = DetectionCreationView()

        with tabs[0]:
            detection_tab.render()

