FROM registry.in-cypher.com:5001/base/agent-base:latest

ENV PYTHONUNBUFFERED=1

WORKDIR /opt/agent

# Copy dependency list and install packages
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# Copy application source code
COPY solver.py agent.py /opt/agent/
COPY tools/ /opt/agent/tools/
COPY .env /opt/agent/.env

ENTRYPOINT ["python3", "/opt/agent/agent.py"]
