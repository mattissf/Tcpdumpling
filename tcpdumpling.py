import argparse
import logging
import multiprocessing
import signal

import paramiko


class RemoteTcpDump(multiprocessing.Process):
    def __init__(
            self,
            remote_host,
            stdout_pipe,
            poison_pill,
            username=None,
            password=None,
            pem_file=None,
            ssh_safety=True,
            log_level=logging.INFO
    ):
        super(RemoteTcpDump, self).__init__()

        self.daemon = True
        self.remote_host = remote_host
        self.username = username
        self.password = password
        self.stdout_pipe = stdout_pipe
        self.poison_pill = poison_pill
        self.log_level = log_level
        self.pem_file = pem_file
        self.ssh_safety = ssh_safety

    def connect(self):
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        arguments_to_paramiko = {
            'hostname': self.remote_host,
            'username': self.username,
        }

        if self.pem_file:
            arguments_to_paramiko['key_filename'] = self.pem_file

        ssh_client.connect(**arguments_to_paramiko)

        return ssh_client

    def run(self):
        logging.basicConfig(level=self.log_level)

        ssh_client = self.connect()

        stdin, stdout, stderr = ssh_client.exec_command('while true; do echo "Hello"; sleep 1; done;')
        stdin.close()
        stderr.close()

        while not stdout.channel.exit_status_ready() or stdout.channel.recv_ready():
            try:
                if stdout.channel.recv_ready():
                    data = stdout.channel.recv(1024)
                    while data:
                        self.stdout_pipe.send_bytes(data)
                        data = stdout.channel.recv(1024)
            except KeyboardInterrupt:
                logging.debug(f"{self.remote_host}: Received CTRL+C, exiting")
                break

        self.stdout_pipe.close()
        stdout.close()
        ssh_client.close()


def set_up_logging(log_level):
    logging.getLogger("paramiko").setLevel(logging.WARNING)

    # Paramiko module outputted a lot of deprecation warnings to CLI
    import warnings
    warnings.filterwarnings(action='ignore', module='.*paramiko.*')

    logging.basicConfig(level=log_level)


def main(cli_arguments):
    log_level = logging.DEBUG if cli_arguments.debug else logging.INFO
    set_up_logging(log_level)
    remote_processes = []

    for host in cli_arguments.hosts:
        parent_connection, child_connection = multiprocessing.Pipe()
        poison_pill = multiprocessing.Event()

        process = RemoteTcpDump(
            host,
            child_connection,
            poison_pill,
            log_level=log_level,
            username=cli_arguments.username,
            pem_file=cli_arguments.pem_file,
        )

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

    while not ctrl_c_received:
        for process, child_stdout, _, _ in remote_processes:
            if child_stdout.poll():
                print(f'Parent: got line from {process.remote_host}: {child_stdout.recv_bytes()}')

    for process, _, _, _ in remote_processes:
        process.join()


def process_cli_arguments():
    parser = argparse.ArgumentParser(
        description="TCP Dumpling - Connect to multiple hosts and run tcpdump",
        epilog="Author: Mattis Stordalen Flister (mattis@altibox.no)",
    )

    parser.add_argument(
        'FILTER',
        help="The TCP DUMP filter you want to run on the remote hosts",
    )

    parser.add_argument(
        '--hosts',
        nargs="+",
        help="List of space separated hosts you want to connect to",
        required=True,
    )

    parser.add_argument(
        '--debug',
        action='store_true',
        help='Print debugging information to console',
    )

    parser.add_argument(
        '--echo-only',
        action='store_true',
        help='Only echo commands on remote machines and print to console',
    )

    parser.add_argument(
        '--pem-file',
        help="For example Amazon EC2 instances uses PEM files to authenticate",
        default=None,
    )

    parser.add_argument(
        '--username',
        help="Username when connecting to hosts",
        default=None,
    )

    return parser.parse_args()


if __name__ == '__main__':
    main(process_cli_arguments())
