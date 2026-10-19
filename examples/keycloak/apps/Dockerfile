FROM nginx:1.27-alpine
ARG APP
COPY shared/ /usr/share/nginx/html/
COPY ${APP}/config.js /usr/share/nginx/html/config.js
COPY nginx.conf /etc/nginx/conf.d/default.conf
