FROM python:3.14-slim

RUN pip install --no-cache-dir poetry

WORKDIR /app

COPY ../pyproject.toml ../poetry.lock* ./

RUN poetry config virtualenvs.create false

RUN poetry install --no-interaction --no-ansi --no-root

COPY . .

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
