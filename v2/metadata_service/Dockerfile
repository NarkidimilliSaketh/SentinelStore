# Use a specific, stable "slim" version of Python for a smaller image size
FROM python:3.10-slim

# Set the working directory inside the container
WORKDIR /app

# Copy the requirements file first to leverage Docker's layer caching
COPY requirements.txt .

# Install the Python dependencies specified in requirements.txt
# --no-cache-dir makes the image smaller by not storing the download cache
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application source code into the container
COPY . .

# The command to run when the container starts.
# This starts the Uvicorn server, making the FastAPI app available.
# --host 0.0.0.0: Makes the server accessible from outside the container.
# --port 8000: The port the server will listen on inside the container.
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]