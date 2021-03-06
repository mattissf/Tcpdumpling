import argparse
import io
import logging
import multiprocessing
import multiprocessing.connection
import getpass
import warnings
import copy

from functools import partial

import paramiko
from scapy.all import rdpcap
from scapy.utils import PcapReader


class RemoteTcpDump(multiprocessing.Process):
    stdout_pipe: multiprocessing.connection.Connection

    def __init__(
            self,
            tcpdump_filter: str,
            remote_host: str,
            stdout_pipe: multiprocessing.connection.Connection,
            username: str = None,
            password: str = None,
            pem_file: str = None,
            ssh_safety: bool = True,
            sudo: bool = False,
            echo_only: bool = False,
            pcap: bool = False,
            log_level: int = logging.INFO
    ) -> None:
        """
        Class that encapsulates logic to perform tcpdump on a remote machine

        :param tcpdump_filter: a valid tcpdump filter
        :param remote_host: the machine this process should connect to
        :param stdout_pipe: a multiprocess.connection.Connection that is used to transfer output from tcpdump
        :param username: ssh username
        :param password: optional ssh password
        :param pem_file: optional ssh pemfile
        :param ssh_safety: settings this to 'False' will capture SSH traffice
        :param sudo: prepends command with 'sudo' - expects no password prompt
        :param echo_only: prepends command with 'echo' - dryrun
        :param pcap: captures to pcap file instead of stdout
        :param log_level: adjust log level, default logging.INFO
        """
        super(RemoteTcpDump, self).__init__()
        self.daemon = True

        self.remote_host = remote_host
        self.username = username
        self.password = password
        self.stdout_pipe = stdout_pipe
        self.log_level = log_level
        self.pem_file = pem_file
        self.pcap = pcap

        self.command = self.build_command(tcpdump_filter, ssh_safety, sudo, echo_only, pcap)

        self.debug(f"Final command: {self.command}")

        if not self.pem_file and not self.password:
            self.password = getpass.getpass(f"{self.remote_host}: Please enter password: ", )

    def connect(self) -> paramiko.SSHClient:
        """
        Helper method to connect to a remote host

        :rtype: paramiko.SSHClient
        """
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        arguments_to_paramiko = {
            'hostname': self.remote_host,
            'username': self.username,
        }

        if self.pem_file:
            arguments_to_paramiko['key_filename'] = self.pem_file

        if self.password:
            arguments_to_paramiko['password'] = self.password

        ssh_client.connect(**arguments_to_paramiko)

        return ssh_client

    def build_command(self, tcpdump_filter: str, ssh_safety: bool, sudo: bool, echo_only: bool, pcap: bool) -> str:
        """
        Helper method to build the command that should run on the remote host

        :param tcpdump_filter:
        :param ssh_safety:
        :param sudo:
        :param echo_only:
        :param pcap:
        :return: str
        """
        command = f"tcpdump -n"

        if pcap:
            command = f"{command} -w -"

        command = f"{command} '({tcpdump_filter})'"

        if ssh_safety:
            command = f"{command} and '(port not 22)'"

        if sudo:
            command = f'sudo {command}'

        if echo_only:
            command = f'echo {command}'

        return command

    def debug(self, msg: str) -> None:
        logging.debug(f"{self.remote_host}: {msg}")

    def info(self, msg: str) -> None:
        logging.info(f"{self.remote_host}: {msg}")

    def warning(self, msg: str) -> None:
        logging.warning(f"{self.remote_host}: {msg}")

    def run(self) -> None:
        '''
        Main loop of the remote process

        :return: None
        '''
        logging.basicConfig(level=self.log_level)

        # Paramiko module outputted a lot of deprecation warnings to CLI
        warnings.filterwarnings(action='ignore', module='.*paramiko.*')

        ssh_client = self.connect()

        stdout: paramiko.ChannelFile
        _, stdout, stderr = ssh_client.exec_command(self.command)

        four_bytes = b''

        while not stdout.channel.exit_status_ready() or stdout.channel.recv_ready():
            try:
                if self.pcap:
                    for chunk in stdout.read(1):
                        # I have no idea why I have to do this - but it works.
                        # For some reason the read(1) returns an integer
                        byte = int(chunk).to_bytes(1, byteorder='big')
                        four_bytes += byte
                        if len(four_bytes) == 4:
                            self.stdout_pipe.send_bytes(four_bytes)
                            four_bytes = b''
                else:
                    line = b""
                    # This was a bit tricky, because I want to flush one line at a time to the parent process.
                    # To trigger on the newline sentinel, I have to read every single byte.
                    # Probably slow.. But it works like above.
                    for byte in iter(partial(stdout.read, 1), b"\n"):
                        line += byte

                    self.stdout_pipe.send_bytes(line)

            except KeyboardInterrupt:
                self.info("Received CTRL+C, exiting")
                ssh_client.close()
                break

        exit_code = stdout.channel.recv_exit_status()

        if exit_code > 0:
            self.warning(f"Something happened to the process, exited with non-zero exit code: {exit_code}.")
            self.warning(f"{stderr.readlines()}")

        stdout.close()
        stderr.close()
        self.stdout_pipe.close()


def main(cli_arguments: argparse.Namespace) -> None:
    """
    Connects to multiple hosts and reads the output from their tcpdump processes

    :param cli_arguments: arguments passed to the main function
    """
    log_level = logging.DEBUG if cli_arguments.debug else logging.INFO
    logging.basicConfig(level=log_level)
    remote_processes = []

    for host in cli_arguments.hosts:
        parent_pipe, child_pipe = multiprocessing.Pipe()

        process = RemoteTcpDump(
            cli_arguments.filter,
            host,
            child_pipe,
            log_level=log_level,
            username=cli_arguments.username,
            pem_file=cli_arguments.pem_file,
            echo_only=cli_arguments.echo_only,
            sudo=cli_arguments.sudo,
            pcap=True if cli_arguments.pcap else False,
        )

        remote_processes.append((process, parent_pipe, child_pipe))
        process.start()

        # Close it here so that it is closed on both ends
        child_pipe.close()

    pcap_file = io.BytesIO()
    pcap_reader = None
    pcap_file_header_length = 24
    pcap_reader_exit_pos = False

    while True:
        try:
            for process, parent_pipe, _ in remote_processes:
                if cli_arguments.pcap:
                    for integer in parent_pipe.recv_bytes():
                        byte = int(integer).to_bytes(1, byteorder='big')
                        pcap_file.write(byte)
                        pcap_file_write_pos = pcap_file.tell()

                        # Read the headers and start the pcap reader instance
                        if pcap_file_write_pos > pcap_file_header_length and not pcap_reader_exit_pos:
                            pcap_file.seek(0)
                            pcap_reader = PcapReader(pcap_file)

                            # Keep this for later
                            pcap_reader_exit_pos = pcap_file.tell()

                        if pcap_reader_exit_pos:
                            # Put the file in state that pcap reader expects
                            pcap_file.seek(pcap_reader_exit_pos)

                            packet = pcap_reader.read_packet()

                            if packet:
                                # Only on successful packet, store position for next iteration
                                pcap_reader_exit_pos = pcap_file.tell()
                                print(packet.time)

                        # Return to original write position for next iteration
                        pcap_file.seek(pcap_file_write_pos)

                else:
                    for line in parent_pipe.recv_bytes().decode("utf-8").split("\n"):
                        print(f'{process.remote_host}: {line}')

        except KeyboardInterrupt:
            logging.debug("Parent: Received CTRL+C, stopping processing")
            break

    for process, _, _ in remote_processes:
        process.join()

    if pcap_file:
        pcap_file.close()


def process_cli_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="TCP Dumpling - Connect to multiple hosts and run tcpdump",
        epilog="Author: Mattis Stordalen Flister (mattis.stordalen.flister@gmail.com)",
    )

    parser.add_argument(
        '--filter',
        help="The tcpdump filter you want to run on the remote hosts",
        required=True,
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

    parser.add_argument(
        '--sudo',
        help="Execute tcpdump with sudo, expects no password prompt",
        action='store_true',
    )

    parser.add_argument(
        '--pcap',
        help="Instruct tcpdump to echo out in pcap format and store locally for analysis",
    )

    return parser.parse_args()


if __name__ == '__main__':
    main(process_cli_arguments())
