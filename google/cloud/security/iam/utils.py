
import logging

def logcall(f, level=logging.CRITICAL):
    def wrapper(*args, **kwargs):
        logging.log(level, 'enter {}({})'.format(f.__name__, args))
        result = f(*args)
        logging.log(level, 'exit {}({}) -> {}'.format(f.__name__, args, result))
        return result
    return wrapper