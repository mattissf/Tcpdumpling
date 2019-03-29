import argparse
import logging
import multiprocessing
import time
import ctypes
import signal

import paramiko


class RemoteTcpDump(multiprocessing.Process):
    def __init__(self, remote_host, stdout_pipe, poison_pill, username=None, password=None, log_level=logging.INFO):
        super(RemoteTcpDump, self).__init__()
        self.daemon = True
        self.remote_host = remote_host
        self.username = username
        self.password = password
        self.stdout_pipe = stdout_pipe
        self.poison_pill = poison_pill
        self.log_level = log_level

    def run(self):
        logging.basicConfig(level=self.log_level)

        def sigint_handler(signal, frame):
            logging.debug(f"{self.remote_host}: Child received CTRL+C")

        signal.signal(signal.SIGINT, sigint_handler)

        while True:
            if self.poison_pill.is_set():
                logging.debug(f"{self.remote_host}: Received poison pill, exiting")
                break

            print(f'{self.remote_host}: Just echoing something here')
            time.sleep(3)


def set_up_logging(cli_arguments):
    logging.getLogger("paramiko").setLevel(logging.WARNING)

    # Paramiko module outputted a lot of deprecation warnings to CLI
    import warnings
    warnings.filterwarnings(action='ignore', module='.*paramiko.*')

    if cli_arguments.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)


def main(cli_arguments):
    set_up_logging(cli_arguments)
    remote_processes = []

    for host in cli_arguments.hosts:
        parent_connection, child_connection = multiprocessing.Pipe()
        poison_pill = multiprocessing.Event()
        process = RemoteTcpDump(host, child_connection, poison_pill,
                                log_level=logging.DEBUG if cli_arguments.debug else logging.INFO)
        remote_processes.append((process, parent_connection, child_connection, poison_pill))
        process.start()

    ctrl_c_received = False

    def keyboard_interrupt_handler(signal, frame):
        logging.debug("Parent: Received CTRL+C, stopping jobs")
        nonlocal ctrl_c_received
        ctrl_c_received = True

        for _, _, _, poison_pill in remote_processes:
            poison_pill.set()

    signal.signal(signal.SIGINT, keyboard_interrupt_handler)

    while ctrl_c_received is False:
        print("Parent: In its main loop doing stuff")
        time.sleep(1)

    for process, _, _, _ in remote_processes:
        process.join()


def process_cli_arguments():
    parser = argparse.ArgumentParser(
        description="TCP Dumpling - Connect to multiple hosts and run tcpdump",
        epilog="Author: Mattis Stordalen Flister (mattis@altibox.no)",
    )

    parser.add_argument(
        'FILTER',
        help="The TCP DUMP filter you want to run on the remote hosts"
    )

    parser.add_argument(
        '--hosts',
        nargs="+",
        help="List of comma separated hosts you want to connect to",
        required=True,
    )

    parser.add_argument(
        '--debug',
        action='store_true',
        help='Print debugging information to console'
    )

    parser.add_argument(
        '--echo-only',
        action='store_true',
        help='Only echo commands on remote machines and print to console'
    )

    return parser.parse_args()


if __name__ == '__main__':
    main(process_cli_arguments())
