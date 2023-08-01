FROM php:8.2-apache

RUN apt-get update && apt-get install -y vim
RUN docker-php-ext-install opcache && docker-php-ext-enable opcache
COPY ./opcache.ini $PHP_INI_DIR/conf.d/
COPY ./src/* /var/www/html/
RUN service apache2 restart
