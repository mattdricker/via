FROM alpine:3.13.1
MAINTAINER Hypothes.is Project and Ilya Kreymer

# Install runtime deps.
RUN apk add --update \
    git \
    curl \
    libffi \
    python2 \
    openssl \
    supervisor \
    squid \
  && rm -rf /var/cache/apk/*

# Install pip via get-pip.py as it is no longer packaged for Python 2 by Alpine.
# pip is a runtime as well as build dependency because it includes `pkg_resources`.
RUN curl https://bootstrap.pypa.io/pip/2.7/get-pip.py -o get-pip.py && python get-pip.py

# Create the via user, group, home directory and package directory.
RUN addgroup -S via && adduser -S -G via -h /var/lib/via via
WORKDIR /var/lib/via

ADD requirements/requirements.txt .

# Install build deps, build, and then clean up.
RUN apk add --update --virtual build-deps \
    build-base \
    git \
    libffi-dev \
    linux-headers \
    openssl-dev \
    python2-dev \
  && pip install --no-cache-dir -U pip \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del build-deps \
  && rm -rf /var/cache/apk/*

# Copy squid config
COPY conf/squid.conf /etc/squid/squid.conf
RUN mkdir /var/spool/squid \
 && chown via:via /var/run/squid /var/spool/squid /var/log/squid

# Use local squid by default
ENV HTTP_PROXY http://localhost:3128
ENV HTTPS_PROXY http://localhost:3128

# Install app.
COPY . .

EXPOSE 9080

CMD ["supervisord", "-c" , "conf/supervisord.conf"]
