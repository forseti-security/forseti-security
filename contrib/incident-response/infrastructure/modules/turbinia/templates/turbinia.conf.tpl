# General
INSTANCE_ID         = 'turbinia-${turbinia_id}'
STATE_MANAGER       = 'Datastore'
TASK_MANAGER        = 'PSQ'
OUTPUT_DIR          = '/var/tmp'
TMP_DIR             = '/tmp'
LOG_FILE            = '/var/log/turbinia.log'
LOCK_FILE           = '/var/lock/turbinia-worker.lock'
SLEEP_TIME          = 10
SINGLE_RUN          = False
MOUNT_DIR_PREFIX    = '/mnt/turbinia'
SHARED_FILESYSTEM   = False
DEBUG_TASKS         = False

# GCP
TURBINIA_PROJECT    = '${project}'
TURBINIA_REGION     = '${region}'
TURBINIA_ZONE       = '${zone}'
BUCKET_NAME         = '${bucket}'
PSQ_TOPIC           = '${pubsub_topic_psq}'
PUBSUB_TOPIC        = '${pubsub_topic}'
GCS_OUTPUT_PATH     = 'gs://${bucket}/output'

# Celery
CELERY_BROKER       = None
CELERY_BACKEND      = None
KOMBU_BROKER        = None
KOMBU_CHANNEL       = None
KOMBU_DURABLE       = True
REDIS_HOST          = None
REDIS_PORT          = None
REDIS_DB            = None