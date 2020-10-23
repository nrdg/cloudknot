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
RUN (id -u unit-test-username >/dev/null 2>&1 || useradd unit-test-username) \
    && addgroup unit-test-username staff \
    && mkdir -p /home/unit-test-username \
    && chown -R unit-test-username:staff /home/unit-test-username

ENV HOME /home/unit-test-username

# Set working directory
WORKDIR /home/unit-test-username

# Set entrypoint
ENTRYPOINT ["python", "/home/unit-test-username/test-func-input.py"]

# Copy the python script
COPY test-func-input.py /home/unit-test-username/
