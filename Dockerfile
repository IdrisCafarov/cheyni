FROM python:3.10-alpine3.16


ENV PYTHONUNBUFFERED 1

COPY ./requirements.txt /tmp/requirements.txt
COPY ./scripts /scripts

ARG DEV=false   
RUN python -m venv /py && \
    /py/bin/pip install --upgrade pip && \
    apk add --update --no-cache postgresql-client jpeg-dev && \
    apk add --update --no-cache --virtual .tmp-build-deps \
        build-base postgresql-dev musl-dev zlib zlib-dev linux-headers && \
    /py/bin/pip install -r /tmp/requirements.txt && \
    rm -rf /tmp && \
    apk del .tmp-build-deps && \
    adduser \
        --disabled-password \
        --no-create-home \
        django && \
    mkdir -p /vol/web/media && \
    mkdir -p /vol/web/static && \
    chown -R django:django /vol && \
    chmod -R 755 /vol && \
    chmod -R +x /scripts

RUN chmod 777 /dev/shm



COPY app/ /app

WORKDIR /app
EXPOSE 8000
EXPOSE 8001




ENV PATH="/scripts:/py/bin:$PATH"

USER django



CMD ["run.sh"]