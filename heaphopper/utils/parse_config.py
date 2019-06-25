import yaml

def parse_config(config_file):
    config = yaml.load(config_file, Loader=yaml.SafeLoader)
    if 'global_config' in config:
        with open(config['global_config']) as f:
            base = yaml.load(f, Loader=yaml.SafeLoader)
            for k, v in base.items():
                if k not in config:
                    config[k] = v
    # Insert parsing here if necessary
    return config
