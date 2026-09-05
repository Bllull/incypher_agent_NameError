FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1

# Create non-root execution user
RUN useradd -m -s /bin/bash agentuser

WORKDIR /app

# Copy dependency list and install packages
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY solver.py agent.py ./
COPY tools/ ./tools/

# Set owner permissions
RUN chown -R agentuser:agentuser /app

USER agentuser

CMD ["python3", "agent.py"]