# ./super_admin/Dockerfile
FROM python:3.9-slim

# Install required packages
RUN pip install requests

# Set working directory
WORKDIR /app

# Copy the super_admin script
COPY super_admin.py .

# Run the super_admin script
CMD ["python", "super_admin.py"]

