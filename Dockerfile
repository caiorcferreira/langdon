# Use the official Python image from the Docker Hub
FROM python:3.12-slim

ENV POETRY_VERSION=1.8.3
ENV PYTHONUNBUFFERED=1

RUN pip install -U pip setuptools && pip install "poetry==$POETRY_VERSION"

WORKDIR /app

COPY pyproject.toml poetry.lock /app/

RUN poetry install --no-root --no-dev

COPY . /app

ENV LANGDON_PORT 8081
EXPOSE 8081

# Run the Streamlit app
# CMD ["poetry", "run", "streamlit", "run", "main.py", "--server.port=${LANGDON_PORT}"]
CMD poetry run streamlit run main.py --server.port=${LANGDON_PORT}