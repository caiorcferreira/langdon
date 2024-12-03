from app.chat.page import DetectionEngineeringPage
from dotenv import load_dotenv
from app.prompt import configure_lm
from app.state import State


def main():
    load_dotenv()
    configure_lm("openai")

    State.init()

    page = DetectionEngineeringPage()
    page.render()


if __name__ == "__main__":
    main()
