# Utilities for compiling Jinja2 templates

import jinja2

class ConfigGen(object):
    """
    Utility class for generating a config file from a jinja template.
    """
    def __init__(self, template_str):
        self.template_str = template_str

    def compile(self, configs, env):
        template = env.get_template(self.template_str)
        return template.render(configs)

    def generate_conf(self, configs, dest_path, env):
        output = self.compile(configs, env)
        with open(dest_path, 'w+') as f:
            f.write(output)


def render_template(src_path, dest_path, context):
    """Render a template at `src_path` to `dest_path` using `context`."""
    conf = ConfigGen(src_path)
    env = jinja2.Environment(loader=jinja2.FileSystemLoader('/'), trim_blocks=True, lstrip_blocks=True)
    conf.generate_conf(context, dest_path, env)
    print("Compiled template ", src_path)


