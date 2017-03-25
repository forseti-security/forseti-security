from google.apputils import app

from google.cloud.security.common.util import log_util

def main(_):
    logger = log_util.get_logger(__name__)

    for i in range(10):
        hi(logger)
        bye(logger)

def hi(logger):
    logger.info('hi')
    print 'hi'

def bye(logger):
    logger.info('bye')
    print 'bye'

if __name__ == '__main__':
    app.run()
