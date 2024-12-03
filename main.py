from app.chat.page import DetectionEngineeringPage
from dotenv import load_dotenv
from app.prompt import configure_lm


def main():
    load_dotenv()
    configure_lm("openai")

    page = DetectionEngineeringPage()
    page.render()


if __name__ == "__main__":
    main()
