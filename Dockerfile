FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN python -m pip install --no-cache-dir -r requirements.txt

COPY . .
RUN mkdir -p /app/data

EXPOSE 8000 8501

CMD ["uvicorn", "ulpf.ingest:app", "--host", "0.0.0.0", "--port", "8000"]