"""
Celery application configuration for NetworkOps async task processing.
"""

import os
from celery import Celery

# Redis configuration
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
CELERY_BROKER_URL = os.getenv('CELERY_BROKER_URL', 'redis://localhost:6379/1')
CELERY_RESULT_BACKEND = os.getenv('CELERY_RESULT_BACKEND', 'redis://localhost:6379/2')

# Create Celery app
app = Celery(
    'networkops',
    broker=CELERY_BROKER_URL,
    backend=CELERY_RESULT_BACKEND,
    include=['core.tasks']
)

# Celery configuration
app.conf.update(
    # Task settings
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,

    # Result settings
    result_expires=3600,  # 1 hour

    # Worker settings
    worker_prefetch_multiplier=1,
    worker_concurrency=10,

    # Task routing (optional, for future queue separation)
    task_routes={
        'core.tasks.health_check': {'queue': 'health'},
        'core.tasks.send_command': {'queue': 'commands'},
        'core.tasks.send_config': {'queue': 'config'},
    },

    # Beat schedule for periodic tasks
    beat_schedule={
        'health-check-all-devices': {
            'task': 'core.tasks.scheduled_health_check',
            'schedule': 300.0,  # Every 5 minutes
        },
    },
)

# Optional: Add task discovery
app.autodiscover_tasks(['core'])
