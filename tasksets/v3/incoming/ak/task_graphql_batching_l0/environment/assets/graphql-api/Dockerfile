FROM python:3.12

WORKDIR /app

# Install dependencies
RUN pip install flask==2.3.3 graphene==3.3 flask-cors==4.0.0

# Copy application files
COPY app.py .
COPY flag.txt .

# Expose port
EXPOSE 5000

# Run the application
CMD ["python", "app.py"]