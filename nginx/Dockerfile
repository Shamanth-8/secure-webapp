# nginx/Dockerfile — reverse proxy image with config + certs baked in.
#
# WHY NOT BIND MOUNTS: on SELinux hosts (Fedora/RHEL) bind-mounted files need
# relabelling, which fails on filesystems like NTFS. Copying them into the
# image avoids that. Rebuild after changing nginx.conf or the certs.
FROM nginx:1.27-alpine

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY certs/server.crt /etc/nginx/certs/server.crt
COPY certs/server.key /etc/nginx/certs/server.key
RUN chmod 600 /etc/nginx/certs/server.key
