import logging

logging.basicConfig(level=logging.DEBUG,
                    format='%(message)s',
                    filename='gcp_setup.log',
                    filemode='w')
console = logging.StreamHandler()
console.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(message)s')
console.setFormatter(formatter)
logging.getLogger('').addHandler(console)
LOGGER = logging.getLogger('')

def main():
    LOGGER.info('hello')
    LOGGER.info('I am printing stuff here, hope you don\'t mind')

if __name__ == '__main__':
    main()
