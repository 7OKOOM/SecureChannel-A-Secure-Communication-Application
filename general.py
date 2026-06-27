from hdkf import HKDF
from secure_channel import SecureChannel

def worker(channel: SecureChannel):
    while not channel.closed:
        try:
            msg_type, plaintext = channel.receive_message()
            print("HIM: " + plaintext.decode())

            # If the other side sent a close message type
            if msg_type == 2:
                print("Closing Connection...")
                channel.close()
                return

        except (ConnectionAbortedError, ConnectionResetError, OSError):
            print("\n[!] Connection lost.")
            channel.close()
            return

        except Exception as e:
            # to not hide real bugs
            print(f"\n[!] Unexpected error: {e}")
            channel.close()
            return

def print_instructions(): print("Instructions:\n1.Insert text and hit enter to send\n2.type :eq and hit enter to exit")

def generate_channel(psk, shared_secret, version, identity, s,serverId):
    mixer = HKDF()
    key = mixer.hkdf(psk, shared_secret, version + b" PhaseA", 88)
    key_server_to_client = key[:32]
    key_client_to_server = key[32:64]
    nonce_server_to_client = key[64:76]
    nonce_client_to_server = key[76:]
    if identity != serverId:
        channel = SecureChannel(s, key_client_to_server, key_server_to_client, nonce_client_to_server, nonce_server_to_client, version, identity)
    else:
        channel = SecureChannel(s,key_server_to_client,key_client_to_server,nonce_server_to_client,nonce_client_to_server,version,identity)
    return channel