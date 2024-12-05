import streamlit as st
from streamlit.logger import get_logger
from app.state import StateKey, State, DETECTION_ENGINEERING_STEPS, DetectionEngineeringStep
from .components import line_separator
from app.ingestion import pdf, scrape

from .steps import (SuggestDetectionStepComponent,
                    GenerateRuleStepComponent,
                    InvestigationGuideStepComponent,
                    QAReviewStepComponent,
                    FinalSummaryStepComponent)

logger = get_logger(__name__)


class DetectionCreationView:
    def render(self):
        """Render the Detection Engineering tab."""
        self.render_progress()

        self.render_threat_intelligence_input()
        self.render_prompt_customization()

        line_separator()

        col1, col2 = st.columns(2)
        with col1:
            self.render_example_detections()
        with col2:
            self.render_example_logs()

        output_container = st.container()
        with output_container:
            line_separator()

            # this guard clause would be better inside the SuggestDetectionStepComponent.run_analysis method
            # but due to the imperative nature of streamlit, it lives here.
            goal = State.get(StateKey.DETECTION_GOAL)

            disable_start_button = State.get(StateKey.DETECTION_ENG_CURRENT_STEP) != DetectionEngineeringStep.INIT or \
                goal is None

            col1, col2, _ = st.columns([1, 1, 2])

            with col1:
                if st.button(
                    "Start detection generation",
                    type="primary",
                    disabled=disable_start_button,
                    use_container_width=True,
                ):
                    State.advance_detection_engineering_step()
                    st.rerun()

            with col2:
                if st.button("Reset", type="secondary", use_container_width=True):
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
            DetectionEngineeringStep.QA_REVIEW: QAReviewStepComponent(),
            DetectionEngineeringStep.FINAL_SUMMARY: FinalSummaryStepComponent(),
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
        st.subheader("Detection Goal")

        st.text_area(
            "Explain your goal (it will help ignoring irrelevant information in reports):",
            key=State.component_key(StateKey.DETECTION_GOAL),
            placeholder="Detect persistence and execution from a compromised Lambda.",
            height=400,
        )

        st.subheader("Threat Intelligence")

        if st.button("Add threat source", type="secondary"):
            self.render_threat_source_modal()

        sources = State.get(StateKey.THREAT_SOURCES, [])
        for i, source in enumerate(sources):
            with st.expander(f"Threat Source {i + 1}", expanded=False):
                st.write(f"**Type:** {source['type']}")
                st.write(f"**ID:** {source['id']}")

                st.button("Remove", key=f"remove_source_{i}", on_click=self.remove_threat_source(i))

    def remove_threat_source(self, index):
        def remove_at():
            sources = State.get(StateKey.THREAT_SOURCES)
            sources.pop(index)

            State.set(StateKey.THREAT_SOURCES, sources)

        return remove_at

    @st.dialog(title="New Threat Source")
    def render_threat_source_modal(self):
        st.subheader("Fetch online threat intel")
        scrape_url = st.text_input("Enter URL:", "")
        if st.button("Scrape URL"):
            with st.spinner("Scraping URL..."):
                scraped = scrape.website_to_md(scrape_url)
                State.set(StateKey.SCRAPED_THREAT_SOURCE, scraped)

        if State.get(StateKey.SCRAPED_THREAT_SOURCE) is not None:
            st.success("Scraping complete!")

        line_separator()

        st.subheader("Parse threat intel report")
        st.file_uploader(
            "Upload file (optional):",
            type=["txt", "md", "pdf"],
            key=State.component_key(StateKey.UPLOADED_THREAT_FILE),
            label_visibility="visible",
            on_change=self.update_threat_source_from_file,
        )

        if st.button("Submit", type="primary"):
            if State.get(StateKey.SCRAPED_THREAT_SOURCE) is not None:
                scraped = State.get(StateKey.SCRAPED_THREAT_SOURCE)

                State.append(StateKey.THREAT_SOURCES, {'type': 'scrape', 'id': scrape_url, 'content': scraped})
                State.delete(StateKey.SCRAPED_THREAT_SOURCE)
            elif State.get(StateKey.UPLOADED_THREAT_FILE) is not None:
                uploaded_file = State.get(StateKey.UPLOADED_THREAT_FILE)
                file_content = pdf.serialize_file(uploaded_file)

                State.append(StateKey.THREAT_SOURCES, {'type': 'file', 'id': uploaded_file.name, 'content': file_content})
                State.delete(StateKey.UPLOADED_THREAT_FILE)

            st.rerun()


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

    def render_example_detections(self):
        """Render the Example Detections section."""
        st.subheader("Example Detections")
        example_count = st.number_input(
            "Number of example detections",
            min_value=1,
            max_value=5,
            value=1,
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
            value=1,
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
