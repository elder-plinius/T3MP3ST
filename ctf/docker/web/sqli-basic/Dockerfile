# T3MP3ST CTF Challenge: SQL Injection - Login Bypass
# Difficulty: Easy (1)
# Category: Web Exploitation

FROM python:3.11-slim

WORKDIR /app

# Install dependencies
RUN pip install flask flask-cors

# Create vulnerable application
COPY app.py /app/
COPY templates/ /app/templates/

# Set environment variables
ENV FLASK_APP=app.py
ENV CTF_FLAG=T3MP3ST{default_flag_replace_me}

EXPOSE 80

CMD ["python", "app.py"]
