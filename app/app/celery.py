import os
from celery import Celery
from django.conf import settings
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'app.settings')

app = Celery('app')
django.setup()

app.config_from_object('django.conf:settings', namespace='CELERY')

app.autodiscover_tasks()

from .tasks import *