FROM python:3.11-slim

# Labels
LABEL maintainer="Renan Altendorf Bernordi"

RUN apt-get update && \
    apt-get -y upgrade && \
    apt-get install -y -q \
        git \
        curl \
        supervisor \
        libjpeg-turbo-progs \
        graphicsmagick \
        libgraphicsmagick++3 \
        libgraphicsmagick++1-dev \
        libgraphicsmagick-q16-3 \
        libmagickwand-dev \
        zlib1g-dev \
        libboost-python-dev \
        libmemcached-dev \
        gifsicle \
        ffmpeg \
        build-essential \
        pkg-config \
        logrotate \
        nginx

# Install Certbot with NGINX support
RUN apt-get install -y \
    certbot \
    python3-certbot-nginx

RUN apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /tmp/* \
    && rm -rf /var/tmp/* \
    && rm -rf /var/cache/apt/archives/*

ENV HOME=/app
ENV SHELL=bash
ENV WORKON_HOME=/app
WORKDIR /app

# Copy requirements and install python dependencies
COPY requirements.txt /app/requirements.txt
RUN pip install --trusted-host None --no-cache-dir -r /app/requirements.txt

# Copy configuration templates
COPY thumbor.conf.tpl /app/thumbor.conf.tpl

# SIMD optimization support
ARG SIMD_LEVEL

RUN PILLOW_VERSION=$(python -c 'import PIL; print(PIL.__version__)') ; \
    if [ "$SIMD_LEVEL" ]; then \
      pip uninstall -y pillow || true && \
      CC="cc -m$SIMD_LEVEL" pip install --no-cache-dir -U --force-reinstall --no-binary=:all: "pillow-SIMD<=${PILLOW_VERSION}.post99" \
      # --global-option="build_ext" --global-option="--debug" \
      --global-option="build_ext" --global-option="--enable-lcms" \
      --global-option="build_ext" --global-option="--enable-zlib" \
      --global-option="build_ext" --global-option="--enable-jpeg" \
      --global-option="build_ext" --global-option="--enable-tiff" ; \
    fi ;

# Create supervisor configuration
RUN mkdir -p /etc/supervisor/conf.d

# Copy supervisor configuration
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# Copy NGINX configuration
COPY nginx/ /etc/nginx/

# Create required directory structure
RUN mkdir -p \
    /site/app \
    /site/private \
    /etc/nginx/ssl \
    /etc/ssl/certs \
    /var/www/certbot \
    /etc/letsencrypt \
    /var/log/nginx \
    /var/log/supervisor \
    /var/log/system \
    /data/loader \
    /data/storage \
    /data/result

COPY scripts/ /usr/local/bin/
RUN chmod +x /usr/local/bin/*.sh

# Define volumes
VOLUME ["/data", "/var/www/certbot", "/var/cache/nginx/thumbor", "/etc/letsencrypt", "/etc/ssl/certs", "/var/log"]

EXPOSE 8888 80 443

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]