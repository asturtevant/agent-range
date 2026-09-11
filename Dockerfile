FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY agent/ ./agent/
EXPOSE 5000
WORKDIR /app/agent
CMD ["python", "app.py"]