import socketserver
import json

# List of servers to be broadcast by the broker server
server_options = []

# Address to bind to. Port 8372 is the default broker server port
broker_address, broker_port = "0.0.0.0", 8372

# GunBound Thor's Hammer packet layout:
# Packet Data: 0c 00 eb cb 12 13 30 00 ff ff ff ff
# Index:       00 01 02 03 04 05 06 07 08 09 0a 0b
#
# 00, 01 = Packet size, 00 = LSB, 01 = MSB
# 02, 03 = Packet sequence
# 04, 05 = Packet command
# 06 onwards = Packet parameters


class ServerOption:
    # Describes a server to be broadcast by the broker server
    def __init__(self, server_name: str, server_description: str, server_address: str, server_port: int,
                 server_utilization: int, server_capacity: int, server_enabled: bool):
        self.server_name = server_name
        self.server_description = server_description
        self.server_address = server_address
        self.server_port = server_port
        self.server_utilization = server_utilization
        self.server_capacity = server_capacity
        self.server_enabled = server_enabled


class BrokerTCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request.recv(1024).strip()
        print("Packet from", self.client_address[0], "(", len(data), "bytes )")
        print_hex(data)

        if (data[4] == 0x10) and (data[5] == 0x13):
            print("Authentication Request")
            self.request.sendall(get_response_login())
        elif (data[3] == 0x00) and (data[4] == 0x11):
            print("Server Directory Request")
            self.request.sendall(get_response_directory())
            # Keeps the connection alive for longer, else the client drops out
            for delay in range(0, 1000):
                self.request.recv(1024).strip()
        else:
            print("Unknown Packet")
            self.request.sendall(get_response_directory())

        print("------------------------")


# Zero-indexed, 0 = LSB
def get_byte(in_byte, index):
    return (in_byte >> (index * 8)) & 0xFF


# GunBound packet sequence, generated from sum of packet lengths
# Normally the overall length is stored/incremented per socket, but the broker only uses this once (hence unnecessary)
# Taken from function at 0x40B760 in GunBoundServ2.exe (SHA-1: b8fce1f100ef788d8469ca0797022b62f870b79b)
#
# ECX: packet length
# 0040B799  IMUL CX,CX,43FD ; Multiply packet length with 43FD (int16)
# 0040B79E  ...
# 0040B7A1  ...
# 0040B7A9  ...
# 0040B7AB  ...
# 0040B7B2  ADD ECX,FFFFAC03 ; Inverted sign of FFFFAC03 equivalent would be SUB 53FD (implemented below)
#
# The client checks this output value. For the server to verify the client's packet sequence, subtract 0x613D instead
def get_sequence(sum_packet_length):
    return (((sum_packet_length * 0x43FD) & 0xFFFF) - 0x53FD) & 0xFFFF


def print_hex(input_bytes):
    print(" ".join("{:02x}".format(b) for b in input_bytes))


# Response to an authentication packet.
# The game server can perform a proper check against the database so this part always allows the login to proceed
def get_response_login():
    command = 0x1312
    base_packet = bytearray.fromhex('ff' * 8)

    # Packet command (get login response)
    base_packet[4] = get_byte(command, 0)
    base_packet[5] = get_byte(command, 1)

    # Alternative responses can be set in desired_response
    response_success = 0x0000
    # response_bad_username = 0x0010
    # response_bad_password = 0x0011
    # response_banned_user = 0x0030
    # response_bad_version = 0x0060
    desired_response = response_success

    # Packet parameter (login response)
    base_packet[6] = get_byte(desired_response, 0)
    base_packet[7] = get_byte(desired_response, 1)

    # Packet Length
    base_packet[0] = get_byte(len(base_packet), 0)
    base_packet[1] = get_byte(len(base_packet), 1)

    # Packet Sequence (First login packet is special and uses 0xEBCB regardless of packet size)
    sequence = 0xcbeb
    base_packet[2] = get_byte(sequence, 0)
    base_packet[3] = get_byte(sequence, 1)

    return base_packet


def get_response_directory():
    command = 0x1102
    base_packet = bytearray.fromhex('ff' * 10)

    # Packet command (get server directory)
    base_packet[4] = get_byte(command, 0)
    base_packet[5] = get_byte(command, 1)

    # Unknown
    base_packet[6] = 0x00
    base_packet[7] = 0x00
    base_packet[8] = 0x01

    # Number of server entries
    base_packet[9] = len(server_options)

    # Server entries
    server_position = 0
    for individual_server in server_options:
        base_packet.extend(get_individual_server(individual_server, server_position))
        server_position += 1

    # Bytes 0-3 depend on the overall size and are computed last
    # Packet Length
    base_packet[0] = get_byte(len(base_packet), 0)
    base_packet[1] = get_byte(len(base_packet), 1)

    # Packet Sequence
    sequence = get_sequence(len(base_packet))
    base_packet[2] = get_byte(sequence, 0)
    base_packet[3] = get_byte(sequence, 1)

    return base_packet


def get_individual_server(entry, position):
    response = bytearray()

    # Server Index (position)
    response.extend([position, 0x00, 0x00])
    # Server Name
    response.extend([len(entry.server_name)])
    response.extend(entry.server_name.encode("ascii"))
    # Server Description
    response.extend([len(entry.server_description)])
    response.extend(entry.server_description.encode("ascii"))
    # Server IP
    response.extend(map(int, entry.server_address.split('.')))
    # Server Port
    response.extend([get_byte(entry.server_port, 1), get_byte(entry.server_port, 0)])
    # Unknown (Active users? Does not affect gauge or ability to login)
    response.extend([get_byte(entry.server_utilization, 1), get_byte(entry.server_utilization, 0)])
    # Server Utilization
    response.extend([get_byte(entry.server_utilization, 1), get_byte(entry.server_utilization, 0)])
    # Server Capacity
    response.extend([get_byte(entry.server_capacity, 1), get_byte(entry.server_capacity, 0)])
    # Server Enabled
    response.extend([int(entry.server_enabled)])

    return response


def load_json_from_file():
    with open('directory.json') as directory_data_text:
        directory_data = json.load(directory_data_text)
        for json_row in directory_data["server_options"]:
            server_options.append(ServerOption(json_row["server_name"], json_row["server_description"],
                                               json_row["server_address"], json_row["server_port"],
                                               json_row["server_utilization"], json_row["server_capacity"],
                                               json_row["server_enabled"]))


if __name__ == "__main__":
    load_json_from_file()

    print("GunBound Broker - Directory: ")
    for server_option in server_options:
        print("Server:", server_option.server_name, "-", server_option.server_description,
              "on port", server_option.server_port)

    server = socketserver.TCPServer((broker_address, broker_port), BrokerTCPHandler)

    print("Listening on", broker_address, "at port", broker_port)
    print("------------------------")
    server.serve_forever()
