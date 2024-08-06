#!/bin/sh

set -e

# Train the language model
# python manage.py train_model

# Wait for the database
python manage.py wait_for_db

# Collect static files
python manage.py collectstatic --noinput

# Apply database migrations
python manage.py migrate


uwsgi --socket :9000 --workers 4 --master --enable-threads --module app.wsgi &

daphne -b 0.0.0.0 -p 8001 app.asgi:application

