from data_generator.file_handler import read_yaml_file
from data_generator.generator import CAIDataGenerator


if __name__ == '__main__':
    config_file_path = 'config.yaml'
    config = read_yaml_file(config_file_path)

    CAIDataGenerator(config).generate()
