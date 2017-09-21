import SimpleHTTPServer
import SocketServer
import utils
import os

file_dir = utils.get_resources_dir()
os.chdir(file_dir)


class SimpleHttpd(object):
    def __init__(self):
        self._service = None

    def start(self, listen_address, port):

        handler = SimpleHTTPServer.SimpleHTTPRequestHandler
        self._service = SocketServer.TCPServer((listen_address, port), handler)
        self._service.serve_forever()

    def stop(self):
        self._service.shutdown()
