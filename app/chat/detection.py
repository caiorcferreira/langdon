import streamlit as st
import fitz
from app.prompt import PromptSignature
from streamlit.logger import get_logger
from app.state import StateKey, State, DETECTION_ENGINEERING_STEPS, DetectionEngineeringStep, step_update_transaction
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

        # todo: do not run without file or scrape link / and focus
        detections = self.run_analysis()

        self.render_detection_list(detections)

        with step_update_transaction():
            self.render_detection_selection()
            self.render_selected_detection()

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
            detections = PromptSignature.suggest_detections_from_intel(
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

        if st.button("Process Selected Detection", type="primary", disabled=State.get(StateKey.DETECTION_ENG_CURRENT_STEP) != DetectionEngineeringStep.SUGGEST_DETECTION_FROM_INTEL):
            logger.info("Processing selected detection")
            selected_detection = next(d for d in detections if d.name == selected_detection_name)

            State.set(StateKey.SELECTED_DETECTION, selected_detection)
            State.advance_detection_engineering_step()

    def render_selected_detection(self):
        selected_detection = State.get(StateKey.SELECTED_DETECTION)
        if selected_detection is None:
            return

        st.write("Processing the selected detection:")
        details = DetectionDetailComponent(selected_detection)
        details.render()
        line_separator()


class GenerateRuleStepComponent:
    def render(self):
        """Render the Generate Rule step."""
        logger.info("Rendering generate rule")
        st.subheader("Step 2: Create Detection Rule")

        with step_update_transaction():
            _, debug_info = self.run_create_rule()
            self.render_detection_rule(debug_info)

    def render_detection_rule(self, debug_info):
        st.success("Create detection rule complete!")

        with st.expander("View Details", expanded=False):
            st.write("Debug information:")
            st.text(debug_info)

    def run_create_rule(self):
        created_detection = State.get(StateKey.DETECTION_RULE)
        if created_detection is not None:
            return created_detection[0], created_detection[1]

        detection = State.get(StateKey.SELECTED_DETECTION)
        if detection is None:
            return

        detection_lang = State.get(StateKey.DETECTION_LANG)
        example_logs = State.get(StateKey.EXAMPLE_LOGS)
        logger.info(f"Example logs: {example_logs}")
        example_detections = State.get(StateKey.EXAMPLE_DETECTIONS)
        logger.info(f"Example detections: {example_detections}")

        detection_steps = State.get(StateKey.DETECTION_STEPS)
        model_params = {
            "temperature": State.get(StateKey.MODEL_TEMPERATURE),
            "max_tokens": State.get(StateKey.MODEL_MAX_TOKENS),
        }

        with st.spinner("Processing rule creation..."):
            detection_rule, debug_info = PromptSignature.create_detection_rule(
                detection_description=detection,
                detection_language=detection_lang,
                example_logs=[],
                example_detections=[],
                detection_steps=detection_steps,
                model_params=model_params,
            )

        State.set(StateKey.DETECTION_RULE, (detection_rule, debug_info))
        State.advance_detection_engineering_step()

        return detection_rule, debug_info


class InvestigationGuideStepComponent:
    def render(self):
        """Render the Investigation Guide step."""
        logger.info("Rendering investigation guide")
        st.subheader("Step 3: Develop Investigation Guide")

        with step_update_transaction():
            _, debug_info = self.run_develop_guide()
            self.render_debug_info(success_msg="Develop Investigation Guide complete!", debug_info=debug_info)

    def render_debug_info(self, success_msg, debug_info):
        st.success(success_msg)

        with st.expander("View Details", expanded=False):
            st.write("Debug information:")
            st.text(debug_info)

    def run_develop_guide(self):
        guide = State.get(StateKey.INVESTIGATION_GUIDE)
        if guide is not None:
            return guide[0], guide[1]

        detection_rule, _ = State.get(StateKey.DETECTION_RULE)
        if detection_rule is None:
            return

        triage_steps = State.get(StateKey.TRIAGE_STEPS)
        model_params = {
            "temperature": State.get(StateKey.MODEL_TEMPERATURE),
            "max_tokens": State.get(StateKey.MODEL_MAX_TOKENS),
        }

        with st.spinner("Processing rule creation..."):
            investigation_guide, debug_info = PromptSignature.develop_investigation_guide(
                detection_rule=detection_rule,
                standard_op_procedure=triage_steps,
                model_params=model_params,
            )

        State.set(StateKey.INVESTIGATION_GUIDE, (investigation_guide, debug_info))
        State.advance_detection_engineering_step()

        return investigation_guide, debug_info


class DetectionCreationView:
    def render(self):
        """Render the Detection Engineering tab."""
        self.render_progress()

        self.render_threat_intelligence_input()
        self.render_prompt_customization()

        line_separator()
        self.render_example_detections()
        line_separator()
        self.render_example_logs()

        output_container = st.container()
        with output_container:
            line_separator()

            # this guard clause would be better inside the SuggestDetectionStepComponent.run_analysis method
            # but due to the imperative nature of streamlit, it lives here.
            threat_source = State.get(StateKey.THREAT_SOURCE)
            focus = State.get(StateKey.THREAT_SOURCE_FOCUS)

            disable_start_button = State.get(StateKey.DETECTION_ENG_CURRENT_STEP) != DetectionEngineeringStep.INIT or \
                threat_source is None or \
                focus is None

            if st.button(
                "Start detection generation",
                type="primary",
                disabled=disable_start_button,
            ):
                State.advance_detection_engineering_step()
                st.rerun()

            if st.button("Reset", type="secondary"):
                State.reset()
                st.rerun()

            self.render_output()

    def render_output(self):
        step = State.get(StateKey.DETECTION_ENG_CURRENT_STEP)
        logger.info(f"Rendering output for step {step}")

        step_render = {
            DetectionEngineeringStep.SUGGEST_DETECTION_FROM_INTEL: SuggestDetectionStepComponent(),
            DetectionEngineeringStep.GENERATE_DETECTION_RULE: GenerateRuleStepComponent(),
            DetectionEngineeringStep.DEVELOP_INVESTIGATION_PLAYBOOK: InvestigationGuideStepComponent(),
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
        logger.info(f"Rendering progress bar for {current_step}, of all {DETECTION_ENGINEERING_STEPS}")
        step_index = DETECTION_ENGINEERING_STEPS.index(current_step) + 1
        total = len(DETECTION_ENGINEERING_STEPS)

        st.progress(step_index / total,
                    text=f"Current Step: {step_index}/{total}")

    def render_threat_intelligence_input(self):
        """Render the Threat Intelligence Input section."""
        st.subheader("Threat Intelligence")
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


    def render_prompt_customization(self):
        st.write("**Prompt customization**")
        with st.expander("Detection Steps", expanded=False):
            st.text_area(
                "Enter detection implementation steps:",
                height=150,
                placeholder="1. Identify the key indicators or behaviors from the threat intel\n2. Determine the relevant log sources and fields\n3. Write the query using the specified detection language\n4. Include appropriate filtering to reduce false positives\n5. Add comments to explain the logic of the detection",
                help="Outline the steps you typically follow when writing detection rules.",
                key=State.component_key(StateKey.DETECTION_STEPS),
            )

        with st.expander("Alert Triage Steps", expanded=False):
            st.text_area(
                "Enter standard operating procedures or investigation steps for your current detections and alerts:",
                height=150,
                placeholder="1. Validate the alert by reviewing the raw log data\n2. Check for any related alerts or suspicious activities from the same source\n3. Investigate the affected systems and user accounts\n4. Determine the potential impact and scope of the incident\n5. Escalate to the incident response team if a true positive is confirmed",
                help="Describe your standard operating procedures for triaging and investigating alerts.",
                key=State.component_key(StateKey.TRIAGE_STEPS),
            )

    def update_threat_source_from_file(self):
        """Update the threat source based on the uploaded file."""
        uploaded_file = State.get(StateKey.UPLOADED_THREAT_FILE)
        logger.info(f"Uploaded File: {uploaded_file}")

        State.set(StateKey.THREAT_SOURCE, serialize_file(uploaded_file))

    def render_example_detections(self):
        """Render the Example Detections section."""
        st.subheader("Example Detections")
        example_count = st.number_input(
            "Number of example detections",
            min_value=1,
            max_value=5,
            value=2,
            key=State.component_key(StateKey.EXAMPLE_DETECTIONS, suffix="_size"),
        )

        for i in range(1, int(example_count) + 1):
            st.text_area(
                f"Example detection {i}",
                placeholder=f"SELECT DISTINCT * FROM control",
                height=100,
                key=State.component_key(StateKey.EXAMPLE_DETECTIONS, suffix=f"_{i-1}"),
                on_change=self.update_list(StateKey.EXAMPLE_DETECTIONS, i-1),
            )


    def render_example_logs(self):
        """Render the Example Logs section."""
        st.subheader("Example Logs")
        example_count = st.number_input(
            "Number of example logs",
            min_value=1,
            max_value=5,
            value=2,
            key=State.component_key(StateKey.EXAMPLE_LOGS, suffix="_size")
        )

        for i in range(1, int(example_count) + 1):
            st.text_area(
                f"Example log {i}",
                placeholder=f"paste examples of your actual logs here, you may have different field names or logging structure",
                height=100,
                key=State.component_key(StateKey.EXAMPLE_LOGS, suffix=f"_{i-1}"),
                on_change=self.update_list(StateKey.EXAMPLE_LOGS, i-1),
            )

    def update_list(self, state_key, index):
        def update():
            current_list = State.get(state_key)
            if current_list is None:
                size = State.get(State.component_key(state_key, suffix="_size"))
                current_list = [None] * size

            value = State.get(State.component_key(state_key, suffix=f"_{index}"))

            current_list[index] = value
            State.set(state_key, current_list)

        return update
