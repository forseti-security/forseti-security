import yaml


def read_yaml_file(full_file_path):
    """Read and parse yaml file.

    Args:
        full_file_path (str): The full file path.
    """
    with open(full_file_path, 'r') as f:
        try:
            return yaml.safe_load(f)
        except yaml.YAMLError as yaml_error:
            raise yaml_error


def create_file_and_writer_listener(file_path, content_queue):
    """Create file and a write listener listens to the content queue.

    Args:
        file_path (str): The file path.
        content_queue (Queue): The content queue to listen to.
    """
    with open(file_path, 'w+') as f:
        while True:
            item = content_queue.get()
            if item == 'EOQ':
                break
            print(item, file=f)
