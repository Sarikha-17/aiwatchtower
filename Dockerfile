FROM python:3.11-slim
WORKDIR /app
COPY backend/requirements.txt backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt
COPY backend backend
COPY data data
COPY policies policies
ENV AIWATCHTOWER_DB=/app/storage/aiwatchtower.db
RUN mkdir -p /app/storage
WORKDIR /app/backend
EXPOSE 8000
# Hosts like Render pass the port in $PORT; default to 8000 locally.
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
