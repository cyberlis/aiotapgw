import asyncio
import logging
logging.basicConfig(level = logging.DEBUG)
logging.getLogger('asyncio').setLevel(logging.WARNING)


SERVER_IP = ''
SERVER_PORT = 12000
MAGIC = b'CoproAnal'
MTU = 1500
ETHERNET_HEADER_SIZE = 18
PACKET_SIZE = MTU + ETHERNET_HEADER_SIZE


def chunks(l, n):
    """Yield successive n-sized chunks from l."""
    for i in range(0, len(l), n):
        yield l[i:i+n]

class TapServerProtocol:
    def __init__(self):
        self.clients = set()

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, peer):
        for chunk in chunks(data, PACKET_SIZE):
            if chunk.startswith(MAGIC):
                self.clients.add(peer)
                self.transport.sendto(MAGIC, peer)
                logging.debug("Client connected: {}".format(peer))
            elif peer in self.clients and chunk:
                self.send_to_clients(chunk, exclude=[peer])
                logging.debug("Data from: {}".format(peer))
            else:
                logging.debug("Trash data from {}".format(peer))
    
    def send_to_clients(self, data, exclude=None):
        for client in self.clients:
            if exclude is not None and client in exclude:
                continue
            self.transport.sendto(data, client)

loop = asyncio.get_event_loop()
print("Starting UDP server")
# One protocol instance will be created to serve all client requests
listen = loop.create_datagram_endpoint(
    TapServerProtocol, local_addr=('0.0.0.0', 12000))
transport, protocol = loop.run_until_complete(listen)

try:
    loop.run_forever()
except KeyboardInterrupt:
    pass

transport.close()
loop.close()
