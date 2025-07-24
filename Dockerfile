FROM mcr.microsoft.com/devcontainers/python:dev-3.12

RUN apt-get update  
RUN apt-get install ca-certificates -y
RUN update-ca-certificates 

# Set app dir
WORKDIR /app

# Copy and install dependencies
COPY requirements.txt .
RUN pip install -r requirements.txt

# Copy app code
COPY . .

# Expose port 80
EXPOSE 80

# Launch via Uvicorn
#CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port 80 || sleep 3600"]
CMD ["chainlit", "run", "app.py", "--host", "0.0.0.0", "--port", "80"]
