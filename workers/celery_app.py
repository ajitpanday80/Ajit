"""Celery worker entrypoint:  celery -A workers.celery_app.celery worker -l info
                              celery -A workers.celery_app.celery beat -l info"""
from celery import Celery
from celery.signals import worker_process_init

from backend.bootstrap import bootstrap
from backend.config import Config

cfg = Config.from_env()
celery = Celery("msp", broker=cfg.redis_url, backend=cfg.redis_url)
celery.conf.update(
    task_acks_late=True,                 # a crashed worker's job is redelivered; execution is idempotent
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
    task_default_retry_delay=10,
    beat_schedule={
        "recover-interrupted-runs": {"task": "msp.run_job", "schedule": 120.0, "args": ["recover", None]},
        "purge-raw-evidence": {"task": "msp.run_job", "schedule": 86400.0, "args": ["purge_raw", None]},
    },
)


@worker_process_init.connect
def _init(**_):
    bootstrap(cfg)


@celery.task(name="msp.run_job", bind=True, max_retries=0)
def run_job_task(self, name, tenant_id, *args):
    from backend.jobs import run_job
    run_job(name, tenant_id, *args)
