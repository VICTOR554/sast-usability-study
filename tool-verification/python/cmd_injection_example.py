import os
import sys


def ping_host(hostname):
    # Vulnerable: user input passed straight into a shell command.
    os.system("ping -c 1 " + hostname)


if __name__ == "__main__":
    ping_host(sys.argv[1])
