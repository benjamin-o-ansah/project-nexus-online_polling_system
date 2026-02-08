from app import create_app
from dotenv import load_dotenv
load_dotenv()

application = create_app()

if __name__ == "__main__":
    application.run()
