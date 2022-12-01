from base64 import b64decode, b64encode
from datetime import datetime
from event import Event
from getpass import getpass
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


relay_input_prompt = 'Enter your relay url (wss://nostr-relay.wlvs.space/ used by default if blank): '
default_relay: str = 'wss://nostr-relay.wlvs.space/'
relay_url = input(relay_input_prompt) or default_relay

sub_id = binascii.hexlify(os.urandom(32)).decode()
pubkey_prompt = 'Subscription pubkey (required): '
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

RPC_PASS = rpcauth.main()
RPC_USER = 'nostrnode'
OUR_PRIVKEY = secp256k1.PrivateKey()
OUR_PRIVKEY_SERIALIZED = OUR_PRIVKEY.serialize()
OUR_PUBKEY = OUR_PRIVKEY.pubkey.serialize(compressed=True).hex()
print(f'Subscribe Fully Noded to this pubkey: {OUR_PUBKEY}')


async def listen():
    async with websockets.connect(relay_url, ssl=ssl_context('cert.pem')) as ws:
        req = ['REQ', sub_id, {'authors': [light_client_pubkey[2:]]}]
        print(f'Sent: {req} to {relay_url}')
        await ws.send(json.dumps(req))
        while True:
            msg = await ws.recv()
            msg_json = json.loads(msg)
            msg_type = msg_json[0]
            if msg_type == 'EOSE':
                print(f'{msg_json}')
            elif msg_type == 'EVENT':
                event = msg_parse(msg_json)
                if event is not None:
                    await ws.send(event)


def ssl_context(filename):
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    context.load_verify_locations(cafile=f'{pathlib.Path(__file__).parent}/{filename}')
    return context


def msg_parse(msg_json):
    for index, value in enumerate(msg_json):
        if index == 2:
            if msg_json[0] == 'EVENT':
                nostr_event = Event.from_JSON(value)
                if nostr_event.is_valid():
                    return parse_event(value)


def parse_event(event):
    print(f'received event: {event}')
    for (key, value) in event.items():
        if key == 'content':
            decrypted_content = encryption.decrypt(b64decode(value), encryption_words)
            json_content = json.loads(decrypted_content)
            (command, wallet, param_json, port, request_id) = parse_received_command(json_content)
            if is_btc_rpc(port):
                response = make_btc_command(command, wallet, param_json, port, request_id)
                json_content = parse_response(response)
                if json_content is not None:
                    btc_response = parse_btc_response(json_content)
                    if btc_response is not None:
                        our_response_to_send = our_btc_response(btc_response, request_id)
                        if our_response_to_send is not None:
                            print(f'send event: {our_response_to_send}')
                            return our_response_to_send

            elif is_jm_rpc(port):
                (http_method, url_path, http_body, token) = parse_jm_command(json_content)
                response = make_jm_command(http_method, url_path, http_body, token)
                our_jm_response_to_send = our_jm_response(response.content)
                return our_jm_response_to_send


def is_btc_rpc(port):
    if port == 8332 or port == 18443 or port == 38332 or port == 18332:
        return True
    else:
        return False


def is_jm_rpc(port):
    return port == 28183


def parse_response(response):
    if response.status_code != 200:
        print(f'http status code: {response.status_code}')
    if response.status_code == 200:
        return json.loads(response.content)


def parse_btc_response(json_content):
    if json_content["error"] is not None:
        error_check = json_content["error"]
        if "message" in error_check:
            print(f'ERROR: {error_check["message"]}')
            return error_check["message"]
    else:
        if "result" in json_content:
            return json_content


def parse_jm_command(json_content):
    url_path = None
    http_method = None
    http_body = None
    token = None
    if 'http_method' in json_content:
        http_method = json_content["http_method"]
    if 'url_path' in json_content:
        url_path = json_content["url_path"]
    if 'http_body' in json_content:
        http_body = json_content["http_body"]
    if 'token' in json_content:
        token = json_content["token"]
    return http_method, url_path, http_body, token


def our_btc_response(btc_response, request_id):
    result: dict = None
    message: str = ''
    if 'result' in btc_response:
        result = btc_response["result"]
    if 'message' in btc_response:
        message = btc_response["message"]
    part = {
        "request_id": request_id,
        "response": result,
        "errorDesc": message
    }
    json_response_data = json.dumps(part).encode('utf8')
    event = create_event(json_response_data)
    event.sign(OUR_PRIVKEY_SERIALIZED)
    if event.is_valid():
        return json.dumps(['EVENT', event.event_data()])
    else:
        print('Event invalid!')


def our_jm_response(json_content):
    response_dict = {
        "response": json.loads(json_content)
    }
    json_response_data = json.dumps(response_dict).encode('utf8')
    event = create_event(json_response_data)
    event.sign(OUR_PRIVKEY_SERIALIZED)
    if event.is_valid():
        return json.dumps(['EVENT', event.event_data()])
    else:
        print('Event invalid!')


def create_event(json_response_data):
    encrypted_content = encryption.encrypt(json_response_data, encryption_words)
    b64_encrypted_content = b64encode(encrypted_content).decode("ascii")
    created_at = int(datetime.now().timestamp())
    raw_event = f'''
    [
        0,
        "{OUR_PUBKEY[2:]}",
        {created_at},
        20001,
        [],
        "{b64_encrypted_content}"
    ]
    '''
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
    return Event.from_JSON(event_dict)


def parse_received_command(json_content):
    command: str = ''
    wallet: str = ''
    param_value: dict = None
    port: int = 18443
    request_id: str = ''
    if "command" in json_content:
        command = json_content['command']
    if "wallet" in json_content:
        wallet = json_content['wallet']
    if "param" in json_content:
        param_value = json_content['param']
    if "port" in json_content:
        port = json_content['port']
    if "request_id" in json_content:
        request_id = json_content['request_id']
    return command, wallet, param_value, port, request_id


def make_btc_command(command, wallet, param, port, request_id):
    headers = {
        'Content-Type': 'text/plain',
    }
    url = f"http://{RPC_USER}:{RPC_PASS}@localhost:{port}"
    if wallet != "":
        url += f'/wallet/{wallet}'
    data = {'jsonrpc': '1.0', 'id': request_id, 'method': command, 'params': param}
    json_data = json.dumps(data)
    return requests.post(url,
                         data=json_data.encode('utf8'),
                         headers=headers,
                         auth=(f'{RPC_USER}', f'{RPC_PASS}'))


def get_headers(param, token):
    headers = {}
    if param != {}:
        headers['Content-Type'] = 'application/json'
        headers['Content-Length'] = f'{len(json.dumps(param).encode("utf8"))}'
    else:
        headers['Content-Type'] = 'text/plain'
    if token is not None:
        headers["Authorization"] = f'Bearer {token}'
    return headers


# Requires you to copy nostrnode-cli/jm_cert.pem to jmdatadir/ssl/cert.pem
def make_jm_command(http_method, url_path, http_body, token):
    url = f"https://localhost:28183/{url_path}"
    cert_path = f'{pathlib.Path(__file__).parent}/jm_cert.pem'
    if http_method == 'GET':
        return requests.get(url,
                            data=http_body,
                            headers=get_headers(http_body, token),
                            verify=cert_path)
    elif http_method == 'POST':
        return requests.post(url,
                             json=http_body,
                             headers=get_headers(http_body, token),
                             verify=cert_path)


def listen_until_complete():
    asyncio.get_event_loop().run_until_complete(listen())
