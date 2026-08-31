# T3MP3ST CTF Challenge: Stored XSS - Cookie Theft
# Difficulty: Medium (2)
# Category: Web Exploitation

FROM python:3.11-slim

WORKDIR /app

# Install dependencies
RUN pip install flask flask-cors requests

# Create vulnerable application
COPY app.py /app/

# Set environment variables
ENV FLASK_APP=app.py
ENV CTF_FLAG=T3MP3ST{st0r3d_xss_c00k13_th3ft}
ENV WEBHOOK_URL=http://webhook-receiver:9999

EXPOSE 80

CMD ["python", "app.py"]
