from google.apputils import app

from google.cloud.security.common.gcp_api.cloud_logging import LoggingClient

def main(_):
    client = LoggingClient()
    logger = client.get_logger()
    logger.log_text('hi')

if __name__ == '__main__':
    app.run()
