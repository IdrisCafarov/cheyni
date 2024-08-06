FROM certbot/certbot:v1.27.0

COPY certify-init.sh /opt/

RUN chmod 777 /dev/shm


RUN chmod +x /opt/certify-init.sh


ENTRYPOINT []
CMD ["certbot", "renew"]
