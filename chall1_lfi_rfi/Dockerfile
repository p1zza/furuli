FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py secret_flag.py ./
COPY templates/ ./templates/

# каталог для базы аудита (монтируется как volume)
ENV AUDIT_DB=/data/audit.db PORT=5050
VOLUME ["/data"]

EXPOSE 5050
CMD ["python", "app.py"]
