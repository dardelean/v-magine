# Copyright 2014 Cloudbase Solutions Srl
# All Rights Reserved.
# Licensed under the AGPLv3, see LICENCE file for details.

import logging
import os
import tempfile
import shutil
import jinja2

from v_magine import utils
from v_magine import diskimage


LOG = logging

def _get_preseed_template():
    return os.path.join(utils.get_resources_dir(), "preseed.template")

def _get_postrun_template():
    return os.path.join(utils.get_resources_dir(), "postrun.template")

def _get_config_network_template():
    return os.path.join(utils.get_resources_dir(), "config_networking.template")

def _generate_preseed_file(params):
    env = jinja2.Environment(trim_blocks=True, lstrip_blocks=True)
    with open(_get_preseed_template(), "rb") as f:
        template_seed = env.from_string(f.read().decode())

    LOG.debug("Preseed params: %s", params)
    seed = template_seed.render(params)
    LOG.debug("Preseed generated content:\n%s", seed)

    seed_file = os.path.join(tempfile.gettempdir(), 'preseed.cfg')
    with open(seed_file, "wb") as f:
        f.write(seed.encode())

    return seed_file

def _generate_postrun_file(params):
    env = jinja2.Environment(trim_blocks=True, lstrip_blocks=True)
    with open(_get_postrun_template(), "rb") as f:
        template_postrun = env.from_string(f.read().decode())

    LOG.debug("Postrun script params: %s", params)
    postrun = template_postrun.render(params)
    LOG.debug("Postrun script generated content:\n%s", postrun)

    postrun_file = os.path.join(tempfile.gettempdir(), 'postrun.sh')
    with open(postrun_file, "wb") as f:
        f.write(postrun.encode())

    return postrun_file

def _generate_config_network_file(params):
    env = jinja2.Environment(trim_blocks=True, lstrip_blocks=True)
    with open(_get_config_network_template(), "rb") as f:
        template_config_net = env.from_string(f.read().decode())

    LOG.debug("Postrun script params: %s", params)
    config_net = template_config_net.render(params)
    LOG.debug("Postrun script generated content:\n%s", config_net)

    config_network_file = os.path.join(tempfile.gettempdir(), 'config_networking.sh')
    with open(config_network_file, "wb") as f:
        f.write(config_net.encode())

    return config_network_file


def generate_preseed_files(params):
    seed_file = _generate_preseed_file(params)
    postrun_file = _generate_postrun_file(params)
    config_network_file = _generate_config_network_file(params)

    shutil.copy2(seed_file, utils.get_pxe_files_dir())
    shutil.copy2(postrun_file, utils.get_pxe_files_dir())
    shutil.copy2(config_network_file, utils.get_resources_dir())
