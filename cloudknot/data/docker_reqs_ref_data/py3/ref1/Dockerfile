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
RUN (id -u cloudknot-user >/dev/null 2>&1 || useradd cloudknot-user) \
    && addgroup cloudknot-user staff \
    && mkdir -p /home/cloudknot-user \
    && chown -R cloudknot-user:staff /home/cloudknot-user

ENV HOME /home/cloudknot-user

# Set working directory
WORKDIR /home/cloudknot-user

# Set entrypoint
ENTRYPOINT ["python", "/home/cloudknot-user/unit-testing-func.py"]

# Copy the python script
COPY unit-testing-func.py /home/cloudknot-user/
