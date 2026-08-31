# T3MP3ST CTF Challenge: SSRF to Cloud Metadata
# Difficulty: Hard (3)
# Category: Web Exploitation

FROM python:3.11-slim

WORKDIR /app

# Install dependencies
RUN pip install flask flask-cors requests

# Create vulnerable application
COPY app.py /app/

# Set environment variables
ENV FLASK_APP=app.py
ENV CTF_FLAG=T3MP3ST{ssrf_t0_cl0ud_m3t4d4t4}

EXPOSE 80

CMD ["python", "app.py"]
