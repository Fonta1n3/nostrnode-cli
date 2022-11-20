from base64 import b64decode, b64encode
from datetime import datetime
from event import Event
import websockets
import asyncio
import pathlib
import ssl
import json
import os
import binascii
import secp256k1
import encryption
import rpcauth
import hashlib
import requests
import uuid
from getpass import getpass


relay_input_prompt = 'Enter your relay url (wss://nostr-relay.wlvs.space/ used by default if blank): '
default_relay = 'wss://nostr-relay.wlvs.space/'
relay_url = input(relay_input_prompt) or default_relay

port_prompt = 'Enter the rpcport. 8332 main, 18443 regtest (default), 38332 signet, 18332 test: '
port = input(port_prompt) or '18443'

sub_id = binascii.hexlify(os.urandom(32)).decode()
pubkey_prompt = 'Enter Fully Noded pubkey (required): '
light_client_pubkey = input(pubkey_prompt)
if light_client_pubkey == '':
    print('Fully Noded pubkey required, start over.')
    quit()

encryption_input_prompt = 'Enter nostr encryption words from Fully Noded (required): '
encryption_words = getpass(encryption_input_prompt)
encryption_words = "".join(encryption_words.split())
if encryption_words == "":
    print('Encryption words are required, start over.')
    quit()

rpcpass = rpcauth.main()
rpcuser = 'nostrnode'

OUR_PRIVKEY = secp256k1.PrivateKey()
OUR_PRIVKEY_SERIALIZED = OUR_PRIVKEY.serialize()
OUR_PUBKEY = OUR_PRIVKEY.pubkey.serialize(compressed=True).hex()
print(f'Subscribe Fully Noded to this pubkey: {OUR_PUBKEY}')


async def listen():
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    ssl_context.load_verify_locations(cafile=f'{pathlib.Path(__file__).parent}/cert.pem')

    async with websockets.connect(relay_url, ssl=ssl_context) as ws:
        req = ['REQ', sub_id, {'authors': [light_client_pubkey[2:]]}]
        print(f'Sent: {req} to {relay_url}')
        await ws.send(json.dumps(req))
        while True:
            msg = await ws.recv()
            msg_json = json.loads(msg)
            msg_type =  msg_json[0]
            if msg_type == 'EOSE':
                print(f'{msg_json}')
            elif msg_type == 'EVENT':
                event = msg_parse(msg_json)
                if event is not None:
                    await ws.send(event)


def msg_parse(msg_json):
    for index, value in enumerate(msg_json):
        if index == 2:
            if msg_json[0] == 'EVENT':
                nostr_event = Event.from_JSON(value)
                if nostr_event.is_valid():
                    return parse_event(value)


def parse_event(event):
    for (key, value) in event.items():
        if key == 'content':
            decrypted_content = encryption.decrypt(b64decode(value), encryption_words)
            json_content = json.loads(decrypted_content)
            (command, wallet, param_json) = parse_received_command(json_content)
            response = make_command(command, wallet, param_json)
            if response.status_code != 200:
                print(f'http status code: {response.status_code}')
            if response.status_code == 200:
                content = response.content
                json_content = json.loads(content)
                error_desc = ""
                if not json_content["error"] is None:
                    error_check = json_content["error"]
                    if "message" in error_check:
                        error_desc = error_check["message"]
                        print(f'ERROR: {error_desc}')
                else:
                    if "result" in json_content:
                        part = {"response": json_content["result"], "errorDesc": error_desc}
                        json_part_data = json.dumps(part).encode('utf8')
                        encrypted_content = encryption.encrypt(json_part_data, encryption_words)
                        b64_encrypted_content = b64encode(encrypted_content).decode("ascii")
                        created_at = int(datetime.now().timestamp())
                        raw_event = f'''[
                                                                0,
                                                                "{OUR_PUBKEY[2:]}",
                                                                {created_at},
                                                                20001,
                                                                [],
                                                                "{b64_encrypted_content}"
                                                            ]'''
                        event_id = hashlib.sha256(raw_event.encode('utf8')).hexdigest()
                        event_dict = {
                            'id': event_id,
                            'pubkey': OUR_PUBKEY[2:],
                            'created_at': created_at,
                            'kind': 20001,
                            'tags': [],
                            'content': b64_encrypted_content,
                            'sig': None
                        }
                        event = Event.from_JSON(event_dict)
                        event.sign(OUR_PRIVKEY_SERIALIZED)
                        if event.is_valid():
                            e = ['EVENT', event.event_data()]
                            return json.dumps(e)
                        else:
                            print('Event invalid!')


def parse_received_command(json_content):
    command: str = None
    wallet = ""
    param_value: dict = None
    if "command" in json_content:
        command = json_content['command']
    if "wallet" in json_content:
        wallet = json_content['wallet']
    if "paramDict" in json_content:
        param_dict = json_content['paramDict']
        param_value = param_dict['param']
        if param_value == "":
            param_value = []

    return command, wallet, param_value


def make_command(command, wallet, param):
    headers = {
        'Content-Type': 'text/plain',
    }
    url = f'http://nostrnode:{rpcpass}@localhost:{port}'
    if wallet != "":
        url += f'/wallet/{wallet}'
    req_id = uuid.uuid4().hex
    data = {'jsonrpc': '1.0', 'id': req_id, 'method': command, 'params': param}
    json_data = json.dumps(data)
    return requests.post(url, data=json_data.encode('utf8'), headers=headers, auth=('nostrnode', f'{rpcpass}'))


def listen_until_complete():
    asyncio.get_event_loop().run_until_complete(listen())
