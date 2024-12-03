from app.chat import DetectionEngineeringApp
from dotenv import load_dotenv
from app.prompt import configure_lm


def main():
    load_dotenv()
    configure_lm("openai")

    app = DetectionEngineeringApp()
    app.render()


if __name__ == "__main__":
    main()
