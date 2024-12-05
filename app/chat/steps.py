import base64
import streamlit as st
from streamlit.components import v1 as components
from streamlit.logger import get_logger
from app.chat.components import DetectionDetailComponent, line_separator
from app.llm.prompt import PromptSignature
from app.state import step_update_transaction, State, StateKey, DetectionEngineeringStep


logger = get_logger(__name__)


class SuggestDetectionStepComponent:
    def render(self):
        """Render the Suggest Detection step."""
        logger.info("Rendering Suggest Detection step")

        st.subheader("Step 1: Analyze Threat Intel")

        detections = self.run_analysis()

        self.render_detection_list(detections)

        with step_update_transaction():
            self.render_detection_selection()
            self.render_selected_detection()

    def run_analysis(self):
        detections = State.get(StateKey.SUGGESTED_DETECTIONS)
        if detections is not None:
            return detections

        threat_sources = State.get(StateKey.THREAT_SOURCES)
        focus = State.get(StateKey.THREAT_SOURCE_FOCUS)
        data_source = State.get(StateKey.DATA_SOURCE)
        model_params = {
            "temperature": State.get(StateKey.MODEL_TEMPERATURE),
            "max_tokens": State.get(StateKey.MODEL_MAX_TOKENS),
            "llm_provider": State.get(StateKey.LLM_PROVIDER),
            "model": State.get(StateKey.MODEL),
        }

        with st.spinner("Analyzing threat intelligence..."):
            detections = PromptSignature.suggest_detections_from_intel(
                focus=focus,
                reports=threat_sources,
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

        disable_selection = not State.get(StateKey.DETECTION_ENG_CURRENT_STEP) in [DetectionEngineeringStep.SUGGEST_DETECTION_FROM_INTEL, DetectionEngineeringStep.FINAL_SUMMARY]

        if st.button("Process Selected Detection", type="primary", disabled=disable_selection):
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
            "llm_provider": State.get(StateKey.LLM_PROVIDER),
            "model": State.get(StateKey.MODEL),
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
            "llm_provider": State.get(StateKey.LLM_PROVIDER),
            "model": State.get(StateKey.MODEL),
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


class QAReviewStepComponent:
    def render(self):
        """Render the Quality Assurance Review step."""
        logger.info("Rendering Quality Assurance Review")
        st.subheader("Step 4: Quality Assurance Review")

        with step_update_transaction():
            _, _, debug_info = self.run_review()
            self.render_debug_info(success_msg="Quality Assurance Review complete!", debug_info=debug_info)

    def render_debug_info(self, success_msg, debug_info):
        st.success(success_msg)

        with st.expander("View Details", expanded=False):
            st.write("Debug information:")
            st.text(debug_info)

    def run_review(self):
        review = State.get(StateKey.QA_REVIEW)
        if review is not None:
            return review[0], review[1], review[1]

        selected_detection = State.get(StateKey.SELECTED_DETECTION)
        detection_rule, _ = State.get(StateKey.DETECTION_RULE)
        model_params = {
            "temperature": State.get(StateKey.MODEL_TEMPERATURE),
            "max_tokens": State.get(StateKey.MODEL_MAX_TOKENS),
            "llm_provider": State.get(StateKey.LLM_PROVIDER),
            "model": State.get(StateKey.MODEL),
        }

        with st.spinner("Processing QA assessment..."):
            score, review, debug_info = PromptSignature.qa_review(
                detection_description=selected_detection,
                detection_rule=detection_rule,
                model_params=model_params,
            )

        State.set(StateKey.QA_REVIEW, (score, review, debug_info))
        State.advance_detection_engineering_step()

        return score, review, debug_info


class FinalSummaryStepComponent:
    def render(self):
        """Render the Quality Assurance Review step."""
        logger.info("Rendering Quality Assurance Review")
        st.subheader("Step 5: Final Summary")

        _, debug_info = self.run_summary()
        self.render_debug_info(success_msg="Final Summary complete!", debug_info=debug_info)
        line_separator()
        self.render_summary()

        # st.rerun()

    def render_summary(self):
        summary, _ = State.get(StateKey.FINAL_SUMMARY)
        if summary is None:
            return

        st.markdown(summary)

        col1, col2, _ = st.columns([1, 1, 2])

        with col1:
            summary_enc = base64.b64encode(summary.encode('utf-8')).decode('utf-8')

            components.html(f"""
                <script>
                    function copyToClipboard(content) {{
                        const textToCopy = atob(content);
    
                        navigator.clipboard.writeText(textToCopy)
                    }}
                </script>
                <style>
                    body {{
                        margin: 0;
                    }}
                </style>
    
                <button id="copyButton" 
                    style="background-color: #ff4b4b; color: white; border: none; border-radius: 8px; padding: 12px 6px; font-size: 16px; font-weight: 400; text-align: center; cursor: pointer; transition: background-color 0.3s ease, transform 0.2s ease;"
                    onclick="copyToClipboard('{summary_enc}')">
                    Copy final summary to clipboard
                </button>
            """, height=50)

        with col2:
            if st.button("Reset", type="secondary", key="bottom_summary_reset", use_container_width=True):
                State.reset()

    def render_debug_info(self, success_msg, debug_info):
        st.success(success_msg)

        with st.expander("View Details", expanded=False):
            st.write("Debug information:")
            st.text(debug_info)

    def run_summary(self):
        summary = State.get(StateKey.FINAL_SUMMARY)
        if summary is not None:
            return summary[0], summary[1]

        selected_detection = State.get(StateKey.SELECTED_DETECTION)
        detection_rule, _ = State.get(StateKey.DETECTION_RULE)
        investigation_guide, _ = State.get(StateKey.INVESTIGATION_GUIDE)
        score, qa_review, _ = State.get(StateKey.QA_REVIEW)
        model_params = {
            "temperature": State.get(StateKey.MODEL_TEMPERATURE),
            "max_tokens": State.get(StateKey.MODEL_MAX_TOKENS),
            "llm_provider": State.get(StateKey.LLM_PROVIDER),
            "model": State.get(StateKey.MODEL),
        }

        with st.spinner("Processing final summary..."):
            summary, debug_info = PromptSignature.final_summary(
                detection_description=selected_detection,
                detection_rule=detection_rule,
                investigation_guide=investigation_guide,
                qa_assessment=qa_review,
                qa_score=score,
                model_params=model_params,
            )

        State.set(StateKey.FINAL_SUMMARY, (summary, debug_info))

        return summary, debug_info
