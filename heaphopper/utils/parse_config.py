import yaml
import os

def parse_config(config_file):
    config = yaml.load(config_file, Loader=yaml.SafeLoader)
    for k, v in config.items():
        if k in ['libc', 'allocator', 'loader']:
            v = os.path.abspath(os.path.join(os.path.dirname(config_file.name), v))
            config[k] = v
    if 'global_config' in config:
        global_config_path = os.path.abspath(os.path.join(os.path.dirname(config_file.name), config['global_config']))
        with open(global_config_path) as f:
            base = yaml.load(f, Loader=yaml.SafeLoader)
            for k, v in base.items():
                if k not in config:
                    if k in ['libc', 'allocator', 'loader']:
                        v = os.path.abspath(os.path.join(os.path.dirname(global_config_path), v))
                    config[k] = v
    # Insert parsing here if necessary
    return config
