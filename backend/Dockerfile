FROM python:3.14-slim

RUN pip install --no-cache-dir poetry

WORKDIR /app

COPY . /app/backend

COPY pyproject.toml poetry.lock* ./

RUN poetry config virtualenvs.create false

RUN poetry install --no-interaction --no-ansi --no-root

COPY . .

CMD ["uvicorn", "backend.api:app", "--host", "0.0.0.0", "--port", "8000"]
