FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN apt-get update && apt-get install -y --no-install-recommends tesseract-ocr \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY contracts contracts
COPY detectors detectors
COPY eval eval
COPY gateway gateway
COPY injection injection
COPY rag rag
CMD ["uvicorn", "gateway.main:app", "--host", "0.0.0.0", "--port", "8000"]
