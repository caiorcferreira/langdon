import streamlit as st
import fitz
from app.prompt import suggest_detections_from_intel
from streamlit.logger import get_logger
from app.state import StateKey, State, DETECTION_ENGINEERING_STEPS, DetectionEngineeringStep
from .components import line_separator

logger = get_logger(__name__)


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


class SuggestDetectionStepComponent:
    def render(self):
        """Render the Suggest Detection step."""
        logger.info("Rendering Suggest Detection step")
        st.subheader("Step 1: Analyze Threat Intel")
        # details = st.expander("View Details", expanded=False)

        detections = self.run_analysis()

        self.render_detection_list(detections)
        self.render_detection_selection()

    def run_analysis(self):
        detections = State.get(StateKey.SUGGESTED_DETECTIONS)
        if detections is not None:
            return detections

        threat_source = State.get(StateKey.THREAT_SOURCE)
        focus = State.get(StateKey.THREAT_SOURCE_FOCUS)
        data_source = State.get(StateKey.DATA_SOURCE)
        model_params = {
            "temperature": State.get(StateKey.MODEL_TEMPERATURE),
            "max_tokens": State.get(StateKey.MODEL_MAX_TOKENS),
        }

        with st.spinner("Analyzing threat intelligence..."):
            detections = suggest_detections_from_intel(
                focus=focus,
                report=threat_source,
                data_source=data_source,
                model_params=model_params,
            )

        if not detections:
            st.warning("No detections found for the specified data sources.")
            return

        st.success("Analysis complete!")

        State.set(StateKey.SUGGESTED_DETECTIONS, detections)

        return detections

    def render_detection_list(self, detections):
        if detections is None:
            return

        st.info(f"Number of detections found: {len(detections)}")

        st.subheader("Detections found:")
        for detection in detections:
            details = DetectionDetailComponent(detection)
            details.render()
            st.write("---")

    def render_detection_selection(self):
        detections = State.get(StateKey.SUGGESTED_DETECTIONS)

        selected_detection_name = st.selectbox("Select a detection to process:", [d.name for d in detections])

        if st.button("Process Selected Detection", type="primary", key="process_selected_detection"):
            logger.info("Processing selected detection")
            selected_detection = next(d for d in detections if d.name == selected_detection_name)

            State.set(StateKey.SELECTED_DETECTION, selected_detection)

            State.advance_detection_engineering_step()
            st.rerun()


class GenerateRuleStepComponent:
    def render(self):
        selected_detection = State.get(StateKey.SELECTED_DETECTION)

        st.write("Processing the selected detection:")
        details = DetectionDetailComponent(selected_detection)
        details.render()

        line_separator()


class DetectionCreationView:
    def render(self):
        """Render the Detection Engineering tab."""
        logger.info("rerendering")
        self.render_progress()

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
                type="primary",
                on_click=self.start_detection_generation
            )

            self.render_output()

    def start_detection_generation(self):
        State.advance_detection_engineering_step()
        st.rerun()

    def render_output(self):
        step = State.get(StateKey.DETECTION_ENG_CURRENT_STEP)
        logger.info(f"Rendering output for step {step}")

        step_render = {
            DetectionEngineeringStep.SUGGEST_DETECTION_FROM_INTEL: SuggestDetectionStepComponent(),
            DetectionEngineeringStep.GENERATE_DETECTION_RULE: GenerateRuleStepComponent(),
        }

        for s in DETECTION_ENGINEERING_STEPS:
            if s > step:
                break

            view = step_render.get(s)
            if view is None:
                continue

            view.render()


    def render_progress(self):
        current_step = State.get(StateKey.DETECTION_ENG_CURRENT_STEP)
        step_index = DETECTION_ENGINEERING_STEPS.index(current_step) + 1
        total = len(DETECTION_ENGINEERING_STEPS)

        st.progress(step_index / total,
                    text=f"Current Step: {step_index}/{total}")

    def render_threat_intelligence_input(self):
        """Render the Threat Intelligence Input section."""
        st.subheader("Threat Intelligence Input")
        col1, col2 = st.columns([1, 1])

        with col1:
            st.text_area(
                "Explain your focus subject in the threat report:",
                key=State.component_key(StateKey.THREAT_SOURCE_FOCUS),
                placeholder="Detect persistence and execution from a compromised Lambda.",
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
                key=State.component_key(StateKey.UPLOADED_THREAT_FILE),
                label_visibility="visible",
                on_change=self.update_threat_source_from_file,
            )




    def update_threat_source_from_file(self):
        """Update the threat source based on the uploaded file."""
        uploaded_file = State.get(StateKey.UPLOADED_THREAT_FILE)
        logger.info(f"Uploaded File: {uploaded_file}")

        State.set(StateKey.THREAT_SOURCE, serialize_file(uploaded_file))

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

