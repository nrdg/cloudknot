###############################################################################
# Dockerfile to build test-func-input application container
# Based on python:3
###############################################################################

# Use official python base image
FROM python:3

# Install python dependencies
COPY requirements.txt /tmp/
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# Create a default user. Available via runtime flag `--user unit-test-username`.
# Add user to "staff" group.
# Give user a home directory.
RUN groupadd -f staff \
    && useradd --create-home --groups staff "unit-test-username"

# Copy the python script
COPY --chown="unit-test-username" "test-func-input.py" "/home/unit-test-username/"

# Set user
USER "unit-test-username"

# Set working directory
WORKDIR "/home/unit-test-username"

# Set entrypoint
ENTRYPOINT ["/home/unit-test-username/test-func-input.py"]
