# General
INSTANCE_ID         = 'turbinia-${turbinia_id}'
STATE_MANAGER       = 'Datastore'
TASK_MANAGER        = 'PSQ'
OUTPUT_DIR          = '/var/lib/turbinia'
TMP_DIR             = '/tmp'
LOG_FILE            = '/var/log/turbinia/turbinia.log'
LOCK_FILE           = '/var/lock/turbinia-worker.lock'
SLEEP_TIME          = 10
SINGLE_RUN          = False
MOUNT_DIR_PREFIX    = '/mnt/turbinia'
SHARED_FILESYSTEM   = False
DEBUG_TASKS         = False

# This will enable the usage of docker containers for the worker.
DOCKER_ENABLED = False

# Any jobs added to this list will disable it from being used.
DISABLED_JOBS = []

# Configure additional job dependency checks below.
DEPENDENCIES = [{
    'job': 'BinaryExtractorJob',
    'programs': ['image_export.py'],
    'docker_image': None
}, {
    'job': 'BulkExtractorJob',
    'programs': ['bulk_extractor'],
    'docker_image': None
}, {
    'job': 'GrepJob',
    'programs': ['grep'],
    'docker_image': None
}, {
    'job': 'HadoopAnalysisJob',
    'programs': ['strings'],
    'docker_image': None
}, {
    'job': 'HindsightJob',
    'programs': ['hindsight.py'],
    'docker_image': None
}, {
    'job': 'JenkinsAnalysisJob',
    'programs': ['john'],
    'docker_image': None
}, {
    'job': 'PlasoJob',
    'programs': ['log2timeline.py'],
    'docker_image': None
}, {
    'job': 'PsortJob',
    'programs': ['psort.py'],
    'docker_image': None
}, {
    'job': 'StringsJob',
    'programs': ['strings'],
    'docker_image': None
}, {
    'job': 'VolatilityJob',
    'programs': ['vol.py'],
    'docker_image': None
}]


# GCP
TURBINIA_PROJECT    = '${project}'
TURBINIA_REGION     = '${region}'
TURBINIA_ZONE       = '${zone}'
BUCKET_NAME         = '${bucket}'
PSQ_TOPIC           = '${pubsub_topic_psq}'
PUBSUB_TOPIC        = '${pubsub_topic}'
GCS_OUTPUT_PATH     = 'gs://${bucket}/output'
STACKDRIVER_LOGGING = False
STACKDRIVER_TRACEBACK = False

# Celery
CELERY_BROKER       = None
CELERY_BACKEND      = None
KOMBU_BROKER        = None
KOMBU_CHANNEL       = None
KOMBU_DURABLE       = True
REDIS_HOST          = None
REDIS_PORT          = None
REDIS_DB            = None

# Docker
DOCKER_ENABLED = False

# Jobs and dependencies
DISABLED_JOBS = []
DEPENDENCIES = [{
    'job': 'BinaryExtractorJob',
    'programs': ['image_export.py'],
    'docker_image': None
}, {
    'job': 'BulkExtractorJob',
    'programs': ['bulk_extractor'],
    'docker_image': None
}, {
    'job': 'GrepJob',
    'programs': ['grep'],
    'docker_image': None
}, {
    'job': 'HadoopAnalysisJob',
    'programs': ['strings'],
    'docker_image': None
}, {
    'job': 'HindsightJob',
    'programs': ['hindsight.py'],
    'docker_image': None
}, {
    'job': 'JenkinsAnalysisJob',
    'programs': ['john'],
    'docker_image': None
}, {
    'job': 'PhotorecJob',
    'programs': ['photorec'],
    'docker_image': None
}, {
    'job': 'PlasoJob',
    'programs': ['log2timeline.py'],
    'docker_image': None
}, {
    'job': 'PsortJob',
    'programs': ['psort.py'],
    'docker_image': None
}, {
    'job': 'StringsJob',
    'programs': ['strings'],
    'docker_image': None
}, {
    'job': 'VolatilityJob',
    'programs': ['vol.py'],
    'docker_image': None
}]
