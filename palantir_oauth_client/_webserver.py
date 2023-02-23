#  Copyright (C) 2021 Palantir Technologies Inc. All rights reserved.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import socket
from contextlib import closing

from .errors import ConnectionError


LOCALHOST = "127.0.0.1"
DEFAULT_PORTS_TO_TRY = 100


def is_port_open(port: int):
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        try:
            sock.bind((LOCALHOST, port))
            sock.listen(1)
        except socket.error:
            is_open = False
        else:
            is_open = True
    return is_open


def find_open_port(start=8888, stop=None):
    if not stop:
        stop = start + DEFAULT_PORTS_TO_TRY

    for port in range(start, stop):
        if is_port_open(port):
            return port

    # No open ports found.
    return None


def run_local_server(app_flow):
    port = find_open_port()
    if not port:
        raise ConnectionError("Could not find open port.")
    return app_flow.run_local_server(host=LOCALHOST, port=port)
