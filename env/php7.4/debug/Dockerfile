FROM phusion/baseimage:jammy-1.0.1

# dependencies required for running "phpize"
# (see persistent deps below)
ENV PHPIZE_DEPS \
        autoconf \
        dpkg-dev \
        file \
        g++ \
        gcc \
        libc-dev \
        make \
        pkg-config \
        re2c \
        bison \
        build-essential

# persistent / runtime deps
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        $PHPIZE_DEPS \
        ca-certificates \
        curl \
        wget \
        xz-utils \
        unzip \
        gdb \
        openssl \
        libargon2-dev \
        libcurl4-openssl-dev \
        libedit-dev \
        libonig-dev \
        libsodium-dev \
        libsqlite3-dev \
        libssl-dev \
        libxml2-dev \
        zlib1g-dev \
        libfreetype6-dev \
        libjpeg-turbo8-dev \
        libpng-dev \
        vim

# download and install apache2
RUN set -eux \
    && mkdir -p /usr/src/apache2 \
    && curl -fsSL -o apache2.tar.gz https://dlcdn.apache.org/httpd/httpd-2.4.57.tar.gz \
    && tar -zxf apache2.tar.gz -C /usr/src/apache2 \
    && rm -rf apache2.tar.gz

RUN apt-get install libapr1-dev libaprutil1-dev libpcre3 libpcre3-dev -y

RUN set -eux; \
    cd /usr/src/apache2/httpd-2.4.57; \
    ./configure --enable-so; \
    make; \
    make install

# download binary openssl packages from Impish builds
RUN wget http://security.ubuntu.com/ubuntu/pool/main/o/openssl/openssl_1.1.1f-1ubuntu2.19_amd64.deb && wget http://security.ubuntu.com/ubuntu/pool/main/o/openssl/libssl-dev_1.1.1f-1ubuntu2.19_amd64.deb && wget http://security.ubuntu.com/ubuntu/pool/main/o/openssl/libssl1.1_1.1.1f-1ubuntu2.19_amd64.deb

# install downloaded binary packages
RUN dpkg -i libssl1.1_1.1.1f-1ubuntu2.19_amd64.deb && dpkg -i libssl-dev_1.1.1f-1ubuntu2.19_amd64.deb && dpkg -i openssl_1.1.1f-1ubuntu2.19_amd64.deb

ARG PHP_INI_DIR="/usr/local/etc/php"
RUN set -eux; \
    mkdir -p "$PHP_INI_DIR/conf.d"; \
# allow running as an arbitrary user (https://github.com/docker-library/php/issues/743)
    [ ! -d /var/www/html ]; \
    mkdir -p /var/www/html; \
    chown www-data:www-data /var/www/html; \
    chmod 777 /var/www/html

ARG PHP_URL="https://www.php.net/distributions/php-7.4.33.tar.gz"

RUN set -eux \
    && mkdir -p /usr/src/php \
    && cd /usr/src \
    && curl -fsSL -o php.tar.gz "$PHP_URL" \
    && tar -zxf php.tar.gz -C /usr/src/php --strip-components=1 \
    && rm -rf php.tar.gz

RUN set -eux; \
    cd /usr/src/php; \
    gnuArch="$(dpkg-architecture --query DEB_BUILD_GNU_TYPE)"; \
    debMultiarch="$(dpkg-architecture --query DEB_BUILD_MULTIARCH)"; \
# https://bugs.php.net/bug.php?id=74125
    if [ ! -d /usr/include/curl ]; then \
        ln -sT "/usr/include/$debMultiarch/curl" /usr/local/include/curl; \
    fi; \
    ./configure \
        --build="$gnuArch" \
        --with-config-file-path="$PHP_INI_DIR" \
        --with-config-file-scan-dir="$PHP_INI_DIR/conf.d" \
        \
# make sure invalid --configure-flags are fatal errors instead of just warnings
        --enable-option-checking=fatal \
        \
# https://github.com/docker-library/php/issues/439
        --with-mhash \
        \
# https://github.com/docker-library/php/issues/822
        --with-pic \
        \
# --enable-ftp is included here because ftp_ssl_connect() needs ftp to be compiled statically (see https://github.com/docker-library/php/issues/236)
        --enable-ftp \
# --enable-mbstring is included here because otherwise there's no way to get pecl to use it properly (see https://github.com/docker-library/php/issues/195)
        --enable-mbstring \
# --enable-mysqlnd is included here because it's harder to compile after the fact than extensions are (since it's a plugin for several extensions, not an extension in itself)
        --enable-mysqlnd \
# https://wiki.php.net/rfc/argon2_password_hash (7.2+)
        \
        --enable-opcache \
        --with-freetype \
        --with-jpeg \
        --with-password-argon2 \
        # always build against system sqlite3 (https://github.com/php/php-src/commit/6083a387a81dbbd66d6316a3a12a63f06d5f7109)
        --with-pdo-sqlite=/usr \
        --with-sqlite3=/usr \
        --with-apxs2=/usr/local/apache2/bin/apxs \
# https://wiki.php.net/rfc/libsodium
        --with-sodium=shared \
        \
        --with-curl \
        --with-libedit \
        --with-openssl \
        --with-zlib \
        \
# in PHP 7.4+, the pecl/pear installers are officially deprecated (requiring an explicit "--with-pear")
        --with-pear \
        \
# bundled pcre does not support JIT on s390x
# https://manpages.debian.org/stretch/libpcre3-dev/pcrejit.3.en.html#AVAILABILITY_OF_JIT_SUPPORT
        $(test "$gnuArch" = 's390x-linux-gnu' && echo '--without-pcre-jit') \
        --with-libdir="lib/$debMultiarch" \
        \
        --enable-debug \
    ; \
    make -j "$(nproc)"; \
    make install; \
    make clean; \
    find -type f -name '*.a' -delete; \
    cp -v php.ini-* "$PHP_INI_DIR/"; \
    \
    cd /; \
    \
# update pecl channel definitions https://github.com/docker-library/php/issues/443
    pecl update-channels; \
    rm -rf /tmp/pear ~/.pearrc; \
    \
# smoke test
    php --version


RUN rm -f /etc/service/sshd/down
COPY ./opcache.ini /usr/local/etc/php/conf.d/
COPY ./php.ini /usr/local/etc/php/conf.d/
COPY ./sodium.ini /usr/local/etc/php/conf.d/

ENTRYPOINT [ "/sbin/my_init", "--enable-insecure-key" ]

