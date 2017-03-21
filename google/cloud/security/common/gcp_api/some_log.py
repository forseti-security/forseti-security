from google.apputils import app

from google.cloud.security.common.util import log_util

def main(_):
    logger = log_util.get_logger(__name__)
    logger.info('hi')

if __name__ == '__main__':
    app.run()
