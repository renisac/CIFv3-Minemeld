import pkg_resources

def prototypes():
    import os

    return os.path.join(os.path.dirname(__file__), 'prototypes')

def webui_blueprint():
    from minemeld.flask import aaa

    return aaa.MMBlueprint('cifv3Webui', __name__, static_folder='webui', static_url_path='')

__version__ = pkg_resources.require('minemeld-cifv3')[0].version
