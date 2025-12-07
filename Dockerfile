FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install uv for fast Python package management
RUN pip install uv

# Copy necessary files for package installation
COPY pyproject.toml uv.lock README.md ./

# Copy source code
COPY src/ ./src/

# Create virtual environment and install dependencies
RUN uv venv && \
    . .venv/bin/activate && \
    uv pip install -e .

# Define all environment variables with defaults
# Non-sensitive defaults
ENV COROOT_BASE_URL=http://localhost:8080

# Sensitive variables - should be overridden at runtime
ENV COROOT_USERNAME=""
ENV COROOT_PASSWORD=""
ENV COROOT_SESSION_COOKIE=""
ENV COROOT_API_KEY=""
ENV MCP_AUTH_TOKEN=""

# Transport configuration
ENV MCP_TRANSPORT=streamable-http
ENV MCP_HOST=0.0.0.0
ENV MCP_PORT=8000

# Expose the default port for HTTP transport
EXPOSE 8000

# Run the MCP server with streamable-http transport by default
CMD [".venv/bin/mcp-coroot", "--transport", "streamable-http", "--host", "0.0.0.0", "--port", "8000"]