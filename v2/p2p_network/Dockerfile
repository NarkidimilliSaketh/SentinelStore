FROM python:3.10-slim

WORKDIR /app

# --- START OF MODIFICATION ---
# Install curl, which is required for the healthcheck in docker-compose.yml
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*
# --- END OF MODIFICATION ---

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["uvicorn", "p2p_node:app", "--host", "0.0.0.0", "--port", "8001"]