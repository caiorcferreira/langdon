from app.chat.page import DetectionEngineeringPage
from dotenv import load_dotenv
from app.llm.prompt import configure_lm
from app.state import State


def main():
    load_dotenv()

    State.init()

    page = DetectionEngineeringPage()
    page.render()


if __name__ == "__main__":
    main()
