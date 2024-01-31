###############################################################################
# Dockerfile to build unit-testing-func application container
# Based on python:3
###############################################################################

# Use official python base image
FROM python:3

# Install python dependencies
COPY requirements.txt /tmp/
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# Create a default user. Available via runtime flag `--user cloudknot-user`.
# Add user to "staff" group.
# Give user a home directory.
RUN groupadd -f staff \
    && useradd --create-home --groups staff "cloudknot-user"

# Copy the python script
COPY --chown="cloudknot-user" "unit-testing-func.py" "/home/cloudknot-user/"

# Set user
USER "cloudknot-user"

# Set working directory
WORKDIR "/home/cloudknot-user"

# Set entrypoint
ENTRYPOINT ["/home/cloudknot-user/unit-testing-func.py"]
