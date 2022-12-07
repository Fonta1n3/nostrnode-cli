import configparser
from base64 import b64decode, b64encode
from datetime import datetime
from event import Event
from getpass import getpass
from termcolor import colored
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

# TODO: Currently if we attempt to send a command to a service that is off nostrnode crashes
# TODO: Create db to store credentials encrypted, removing them from memory when not in use
# TODO: Embed a relay? join market?
# TODO: Sanity checks for user input
# TODO: One method to parse/build all commands/responses

config = configparser.ConfigParser()
parent = pathlib.Path(__file__).parents[0]
config_path = f'{parent}/config.cfg'
existing_config = pathlib.Path(config_path)

relay_url = ''
subscription_pubkey = ''
btc_rpc_user = ''
btc_rpc_pass = ''
our_privkey_serialized = ''
our_pubkey = ''
sparko_key_serialized = ''

if existing_config.is_file():
    config.read('config.cfg')
    if 'DEFAULT' in config:
        default = config['DEFAULT']
        if 'relay_url' in default:
            relay_url = default['relay_url']
        if 'subscription_pubkey' in default:
            subscription_pubkey = default['subscription_pubkey']
        if 'btc_rpc_user' in default:
            btc_rpc_user = default['btc_rpc_user']
        if 'btc_rpc_pass' in default:
            btc_rpc_pass = default['btc_rpc_pass']
        if 'our_privkey_serialized' in default:
            our_privkey_serialized = default['our_privkey_serialized']
        if 'our_pubkey' in default:
            our_pubkey = default['our_pubkey']
        if 'sparko_key_serialized' in default:
            sparko_key_serialized = default['sparko_key_serialized']

if relay_url == '':
    relay_input_prompt = colored('Enter your relay url (wss://nostr-relay.wlvs.space/ used by default if blank): ', 'blue')
    default_relay: str = 'wss://nostr-relay.wlvs.space/'
    relay_url = input(relay_input_prompt) or default_relay

sub_id = binascii.hexlify(os.urandom(32)).decode()

if subscription_pubkey == '':
    pubkey_prompt = colored('Subscription pubkey (required): ', 'blue')
    subscription_pubkey = input(pubkey_prompt)

if subscription_pubkey == '':
    print(colored('Pubkey required, start over.', 'red'))
    quit()

encryption_input_prompt = colored('Enter nostr encryption words (required): ', 'blue')
encryption_words = getpass(encryption_input_prompt)
encryption_words = "".join(encryption_words.split())

if encryption_words == "":
    print(colored('Encryption words are required, start over.', 'red'))
    quit()

if btc_rpc_pass == '':
    btc_rpc_pass = rpcauth.main()

if btc_rpc_user == '':
    btc_rpc_user = 'nostrnode'

if our_privkey_serialized == '':
    OUR_PRIVKEY = secp256k1.PrivateKey()
    our_privkey_serialized = OUR_PRIVKEY.serialize()
    our_pubkey = OUR_PRIVKEY.pubkey.serialize(compressed=True).hex()

print(colored(f'Subscribe to this pubkey (required): {our_pubkey}\n', 'green'))

if sparko_key_serialized == '':
    SPARKO_KEY = secp256k1.PrivateKey()
    sparko_key_serialized = SPARKO_KEY.serialize()

print(colored(f'Add this full access Sparko key to your lightning config: {sparko_key_serialized}\n', 'green'))

if existing_config.is_file():
    config['DEFAULT'] = {'btc_rpc_pass': btc_rpc_pass,
                         'btc_rpc_user': btc_rpc_user,
                         'our_privkey_serialized': our_privkey_serialized,
                         'our_pubkey': our_pubkey,
                         'sparko_key_serialized': sparko_key_serialized,
                         'subscription_pubkey': subscription_pubkey,
                         'relay_url': relay_url}

    with open('config.cfg', 'w') as configfile:
        config.write(configfile)


async def listen():
    async with websockets.connect(relay_url, ssl=ssl_context('cert.pem')) as ws:
        req = ['REQ', sub_id, {'authors': [subscription_pubkey[2:]]}]
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
    for (key, value) in event.items():
        if key == 'content':
            decrypted_content = encryption.decrypt(b64decode(value), encryption_words)
            json_content = json.loads(decrypted_content)
            (command, wallet, param_json, port, request_id) = parse_received_command(json_content)
            print(colored(f'Received nostr event content:\n{json_content}\n', 'magenta'))
            if is_btc_rpc(port):
                response = make_btc_command(command, wallet, param_json, port, request_id)
                print(colored(f'Bitcoin Core response http status code: {response.status_code}\n', 'white'))
                print(colored(f'{response.content}\n', 'white'))
                json_content = parse_response(response)
                if json_content is not None:
                    btc_response = parse_btc_response(json_content)
                    if btc_response is not None:
                        our_response_to_send = our_btc_response(btc_response, request_id)
                        if our_response_to_send is not None:
                            print(colored(f'Send Bitcoin Core event:\n{our_response_to_send}\n', 'blue'))
                            return our_response_to_send

            elif is_jm_rpc(port):
                (http_method, url_path, http_body, token) = parse_jm_command(json_content)
                response = make_jm_command(http_method, url_path, http_body, token)
                print(colored(f'Join market response http status code: {response.status_code}\n', 'white'))
                print(colored(f'{response.content}\n', 'white'))
                our_jm_response_to_send = our_jm_response(response.content)
                print(colored(f'Send Join Market event: {our_jm_response_to_send}\n', 'blue'))
                return our_jm_response_to_send

            elif is_cln(port):
                if 'http_body' in json_content:
                    http_body = json_content["http_body"]
                    response = make_cln_command(http_body)
                    if response.status_code != 200:
                        print(colored(response.text, 'red'))
                        print(colored(f'Core lightning response http status code: {response.status_code}', 'red'))
                        print(colored(f'{response.content}', 'red'))
                        if 'message' in response.content:
                            our_cln_response = our_jm_response(response.content)
                            return our_cln_response
                    else:
                        print(colored(f'Core lightning response http status code: {response.status_code}', 'white'))
                        print(colored(f'{response.content}', 'white'))
                        our_cln_response = our_jm_response(response.content)
                        print(colored(f'Send Core Lightning event: {our_cln_response}', 'blue'))
                        return our_cln_response


def is_btc_rpc(port):
    if port == 8332 or port == 18443 or port == 38332 or port == 18332:
        return True
    else:
        return False


def is_jm_rpc(port):
    return port == 28183


def is_cln(port):
    return port == 9737


def parse_response(response):
    if response.status_code == 200 or response.status_code == 500:
        return json.loads(response.content)


def parse_btc_response(json_content):
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
    if 'error' in btc_response:
        btc_error = btc_response["error"]
        if btc_error is not None:
            if 'message' in btc_error:
                if btc_error["message"] is not None:
                    message = btc_error["message"]
    part = {
        "request_id": request_id,
        "response": result,
        "errorDesc": message
    }
    json_response_data = json.dumps(part).encode('utf8')
    event = create_event(json_response_data)
    event.sign(our_privkey_serialized)
    if event.is_valid():
        return json.dumps(['EVENT', event.event_data()])
    else:
        print(colored('Event invalid!', 'red'))


def our_jm_response(json_content):
    response_dict = {
        "response": json.loads(json_content)
    }
    json_response_data = json.dumps(response_dict).encode('utf8')
    event = create_event(json_response_data)
    event.sign(our_privkey_serialized)
    if event.is_valid():
        return json.dumps(['EVENT', event.event_data()])
    else:
        print(colored('Event invalid!', 'red'))


def create_event(json_response_data):
    encrypted_content = encryption.encrypt(json_response_data, encryption_words)
    b64_encrypted_content = b64encode(encrypted_content).decode("ascii")
    created_at = int(datetime.now().timestamp())
    raw_event = f'''
    [
        0,
        "{our_pubkey[2:]}",
        {created_at},
        20001,
        [],
        "{b64_encrypted_content}"
    ]
    '''
    event_id = hashlib.sha256(raw_event.encode('utf8')).hexdigest()
    event_dict = {
        'id': event_id,
        'pubkey': our_pubkey[2:],
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
    endpoint = f"http://{btc_rpc_user}:{btc_rpc_pass}@localhost:{port}"
    if wallet != "":
        endpoint += f'/wallet/{wallet}'
    json_data = {'jsonrpc': '1.0', 'id': request_id, 'method': command, 'params': param}
    print(colored(f'Bitcoin request:\n{json_data}', 'green'))
    return requests.post(endpoint,
                         json=json_data,
                         headers=headers,
                         auth=(f'{btc_rpc_user}', f'{btc_rpc_pass}'))


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


# Requires you to copy nostrnode-cli/jm_cert.pem and key.pem to jmdatadir/ssl/cert.pem and key.pem prior to starting jm
def make_jm_command(http_method, url_path, http_body, token):
    endpoint = f"https://localhost:28183/{url_path}"
    cert_path = f'{pathlib.Path(__file__).parent}/jm_cert.pem'
    print(colored(f'Join Market request:\n{endpoint}\n{http_body}', 'green'))
    if http_method == 'GET':
        return requests.get(endpoint,
                            data=http_body,
                            headers=get_headers(http_body, token),
                            verify=cert_path)
    elif http_method == 'POST':
        return requests.post(endpoint,
                             json=http_body,
                             headers=get_headers(http_body, token),
                             verify=cert_path)


def make_cln_command(http_body):
    endpoint = "http://localhost:9737/rpc"
    headers = {
        'X-Access': sparko_key_serialized
    }
    print(colored(f'Core Lightning request:\n{http_body}', 'green'))
    return requests.post(endpoint, json=http_body, headers=headers)


def listen_until_complete():
    asyncio.get_event_loop().run_until_complete(listen())
