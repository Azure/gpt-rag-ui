import chainlit as cl
import logging
import inspect

from orchestrator_client import call_orchestrator_for_feedback
from dependencies import get_config

config = get_config()

ENABLE_FEEDBACK = config.get("ENABLE_USER_FEEDBACK", False, bool)
FEEDBACK_RATING = config.get("USER_FEEDBACK_RATING", False, bool)

def create_feedback_actions(question_id: str, conversation_id: str, ask: str) -> list:
    """Create feedback actions for a message.

    Behavior:
    - If feedback is disabled: return no actions.
    - If rating is enabled: open feedback form (existing behavior).
    - If rating is disabled: send quick feedback directly (no popup).
    """

    if ENABLE_FEEDBACK is not True:
        return []

    if FEEDBACK_RATING:
        # Existing detailed form flow (rating + text)
        return [
            cl.Action(
                name="show_feedback_form",
                payload={
                    "questionId": question_id,
                    "conversationId": conversation_id,
                    "ask": ask,
                    "is_positive": 1,
                },
                label="👍",
                description="Give detailed feedback",
            ),
            cl.Action(
                name="show_feedback_form",
                payload={
                    "questionId": question_id,
                    "conversationId": conversation_id,
                    "ask": ask,
                    "is_positive": 0,
                },
                label="👎",
                description="Give detailed feedback",
            ),
        ]

    # Quick feedback (no rating/text) -> submit immediately
    return [
        cl.Action(
            name="submit_feedback",
            payload={
                "questionId": question_id,
                "conversationId": conversation_id,
                "ask": ask,
                "isPositive": True,
                # Explicit placeholders for compatibility; backend will ignore when rating is disabled
                "rating": None,
                "text": "",
            },
            label="👍",
            description="Send quick feedback",
        ),
        cl.Action(
            name="submit_feedback",
            payload={
                "questionId": question_id,
                "conversationId": conversation_id,
                "ask": ask,
                "isPositive": False,
                "rating": None,
                "text": "",
            },
            label="👎",
            description="Send quick feedback",
        ),
    ]


def register_feedback_handlers(auth_info=None):
    """Register feedback-related Chainlit event handlers"""

    feedback_msg: cl.Message | None = None
    last_feedback_context: dict | None = None

    @cl.action_callback("show_feedback_form")
    async def on_show_feedback_form(action):
        """Show feedback form action"""
        nonlocal feedback_msg
        nonlocal last_feedback_context

        # If rating flow is disabled, ignore the popup action gracefully
        if not FEEDBACK_RATING:
            logging.info("[feedback] Rating flow disabled; ignoring show_feedback_form action")
            return await cl.context.emitter.send_toast("Feedback form is disabled.", "info")

        question_id = action.payload.get("questionId", "dummy-question-id")
        conversation_id = action.payload.get("conversationId", "dummy-conversation-id")
        logging.info("[feedback] Opening feedback form with questionId=%s conversationId=%s", question_id, conversation_id)
        # Persist the context to recover in case the frontend omits fields when submitting
        last_feedback_context = {
            "question_id": question_id,
            "conversation_id": conversation_id,
            "ask": action.payload.get("ask"),
            "is_positive": action.payload.get("is_positive"),
        }
        feedback_element = cl.CustomElement(
            name="FeedbackForm",
            props={
                "conversationId": conversation_id,
                "questionId": question_id,
                "ask": action.payload.get("ask"),
                "isPositive": action.payload.get("is_positive"),
                "feedbackType": "general",
                "show": True,
            },
            display="inline",
        )

        feedback_msg = cl.Message(content="", elements=[feedback_element])
        await feedback_msg.send()

    @cl.action_callback("submit_feedback")
    async def handle_feedback(action):
        """Handle feedback submission"""
        nonlocal feedback_msg
        nonlocal last_feedback_context
        try:
            logging.info("[feedback] Received submit_feedback action with payload: %s", action.payload)
            question_id = action.payload.get("questionId")
            ask = action.payload.get("ask")
            conversation_id = action.payload.get("conversationId")
            text = action.payload.get("text", "")
            rating = action.payload.get("rating")
            is_positive = action.payload.get("isPositive")

            # Fallback from stored context if fields are missing
            if not question_id and last_feedback_context:
                question_id = last_feedback_context.get("question_id")
            if not ask and last_feedback_context:
                ask = last_feedback_context.get("ask")
            if not conversation_id and last_feedback_context:
                conversation_id = last_feedback_context.get("conversation_id")
            if is_positive is None and last_feedback_context:
                is_positive = last_feedback_context.get("is_positive")

            # Validate required fields
            if not conversation_id:
                raise ValueError("[app] Conversation ID is required.")
            if FEEDBACK_RATING and rating is None:
                raise ValueError("[app] Rating is required when USER_FEEDBACK_RATING is enabled.")
            if not question_id:
                raise ValueError("[app] Ask ID is missing; cannot submit feedback.")

            # Call orchestrator
            auth_payload = auth_info() if auth_info else {}
            if inspect.isawaitable(auth_payload):
                auth_payload = await auth_payload
            orc_feedback_response = await call_orchestrator_for_feedback(
                conversation_id=conversation_id,
                question_id=question_id,
                ask=ask,
                is_positive=is_positive,
                star_rating=rating,
                feedback_text=text,
                auth_info=auth_payload,
            )
            # Remove the feedback form message
            if feedback_msg is not None:
                await feedback_msg.remove()
                feedback_msg = None

            # Send appropriate response
            if orc_feedback_response:
                return await cl.context.emitter.send_toast("Thank you for your feedback!", "success")
            else:
                return await cl.context.emitter.send_toast("Error: Failed to submit feedback", "error")

        except Exception as e:
            if feedback_msg is not None:
                await feedback_msg.remove()
                feedback_msg = None
            logging.exception("[feedback] Error while handling feedback submission")
            return await cl.context.emitter.send_toast(
                f"An unexpected error occurred while submitting feedback: {e}", "error"
            )

    @cl.action_callback("close_feedback_popup")
    async def close_feedback_handler(action):
        nonlocal feedback_msg
        if feedback_msg is not None:
            await feedback_msg.remove()
            feedback_msg = None
