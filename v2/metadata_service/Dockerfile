FROM python:3.10-slim

WORKDIR /app

# 1. Install Node.js, npm, and other utilities
RUN apt-get update && \
    apt-get install -y nodejs npm curl && \
    rm -rf /var/lib/apt/lists/*

# 2. Install the Node.js helper's dependencies
COPY package.json ./
RUN npm install

# 3. Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 4. Copy the rest of the application code (including .js and .py files)
COPY . .

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]