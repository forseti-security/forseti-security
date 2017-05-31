
""" Thread pool implementation for async job distribution. """

from Queue import Queue
from threading import Thread, Lock


class Worker(Thread):
    """Thread executing callables from queue."""
    def __init__(self, queue):
        Thread.__init__(self)
        self.queue = queue
        self.daemon = True
        self.start()

    # pylint: disable=W0703
    def run(self):
        while True:
            func, args, kargs, result = self.queue.get()
            try:
                val = func(*args, **kargs)
                result.put(val, False)
            except Exception, e:
                result.put(e, True)
            finally:
                self.queue.task_done()


class Result(object):
    """Used to communicate job result values and exceptions."""
    def __init__(self):
        self.lock = Lock()
        self.lock.acquire()
        self.value = Exception()
        self.raised = False

    def put(self, value, raised):
        """Worker puts value or exception into result."""
        self.value = value
        self.raised = raised
        self.lock.release()

    def get(self):
        """Get value after worker has completed."""
        self.lock.acquire()
        try:
            if self.raised:
                raise self.value
            return self.value
        finally:
            self.lock.release()


class ThreadPool(object):
    """ThreadPool consumes tasks via queue."""
    def __init__(self, num_workers):
        self.queue = Queue(num_workers)
        self.workers = []
        for _ in range(num_workers):
            self.workers.append(Worker(self.queue))

    def add_func(self, func, *args, **kargs):
        """Add a callable to the queue"""
        result = Result()
        self.queue.put((func, args, kargs, result))
        return result

    def join(self):
        """Returns after completion of all pending callables."""
        self.queue.join()
