import argparse
import logging

from client import Client
from server import Server


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-l", "--listen", help="Listen mode, for inbound connects", action='store_true')
    parser.add_argument("-p", "--server-port", required=False, type=int)
    parser.add_argument("-s", "--secure", default=True)
    parser.add_argument("--log", type=str, default='DEBUG')
    parser.add_argument("destination", nargs='?')
    parser.add_argument("port", nargs='?', type=int)

    args = parser.parse_args()

    log_level = getattr(logging, args.log.upper(), None)
    if not isinstance(log_level, int):
        raise ValueError('Invalid log level: %s' % args.log)
    logging.basicConfig(level=log_level, format='%(levelname)s:%(message)s')

    if args.listen and args.server_port:
        server = Server(secure=args.secure)
        try:
            server.start(port=args.server_port)
        except Exception as e:
            server.socket.close()
            raise e
    elif args.destination and args.port:
        client = Client(secure=args.secure)
        try:
            client.connect(args.destination, args.port)
        except Exception as e:
            client.socket.close()
            raise e
    else:
        raise Exception()



if __name__ == "__main__":
    main()
