FROM mcr.microsoft.com/devcontainers/python:3.12-bookworm

# Set app dir
WORKDIR /app

# Copy and install dependencies
COPY requirements.txt .
RUN pip install -r requirements.txt

# Copy app code
COPY . .

# Expose port 8080
EXPOSE 8080

# Launch via Uvicorn (main.py configures CHAINLIT_AUTH_SECRET before importing Chainlit)
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
