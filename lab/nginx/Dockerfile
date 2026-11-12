# Alpine 3.22 ships OpenSSL 3.5, which supports ML-KEM / ML-DSA natively.
FROM alpine:3.22
RUN apk add --no-cache nginx openssl \
 && mkdir -p /run/nginx /etc/nginx/certs \
 && openssl version
COPY nginx.conf /etc/nginx/nginx.conf
EXPOSE 443
CMD ["nginx", "-g", "daemon off;"]
