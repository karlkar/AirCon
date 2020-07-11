#!/usr/bin/env python3.7
"""
Small command line program to query HiSense servers.
Generates a small config file, to control the AC locally.

After configuring the AC from your phone, pass the username, password
and application type to this script, in order to be able to control
the device locally.

Note that this script needs to be run only once. The generated config
file needs to be passed to the hisense server script, to continuously
control the AC.

The --app flag depends on your AC.
"""
__author__ = 'droreiger@gmail.com (Dror Eiger)'

import argparse
import base64
import gzip
import json
import logging
import ssl
import sys
from http.client import HTTPSConnection

_AYLA_USER_SERVERS = {
  'us': 'user-field.aylanetworks.com',
  'eu': 'user-field-eu.aylanetworks.com',
  'cn': 'user-field.ayla.com.cn',
}
_AYLA_DEVICES_SERVERS = {
  'us': 'ads-field.aylanetworks.com',
  'eu': 'ads-eu.aylanetworks.com',
  'cn': 'ads-field.ayla.com.cn',
}
_SECRET_MAP = {
  'oem-us': b'\x1dgAPT\xd1\xa9\xec\xe2\xa2\x01\x19\xc0\x03X\x13j\xfc\xb5\x91',
  'mid-us': b'\xdeCx\xbe\x0cq8\x0b\x99\xb4Z\x93>\xfc\xcc\x9ag\x98\xf8\x14',
  'tornado-us': b'\x87O\xf2.&;X\xfb\xf6L\xfdRq\'\x0f\t6\x0c\xfd)',
  'wwh-us': b'(\xcb9w\xc5\xc9\xb7\xab{*k8T!Yb\xaa\xcf\xd0\x85',
  'winia-us': b'\xeb_\xce\xb2\xc6\xff`\xa9\xfa\xa8r\x1c\x0bH\xf8\xe27\xa7U\xec',
  'york-us': b'\xc6A\x7fHyV<\xb2\xa2\xde<\x1f{c\xa9\rt\x9fy\xef',
  'beko-eu': b'\xa9C\n\xdb\xf7+\x01\xe2X\ne\x85\x06\x89\xaa\x88ZP+\x07>~s{\xd3\x1f\x05\x91&\x8c\x81\x84&\xe11\xef=s"*\xa4',
  'oem-eu': b'a\x1ez\xf5\xc4\x0f\x18~\xe5\xeb\xb1\x9f\xe4\xf5&B\xfe#\x88\xcb>\x06O,y\xc1\x06c\x9d\x99J\xc2x\xac\xeb\x82\x93\xe5\r\x89d',
  'mid-eu': b'\x05$\xe6\xecW\xa3\xd1B\xa0\x84\xab*\xf0\x04\x80\xce\xae\xe5`\xc4>w\xf8\xc4\xf3X\xf6<\xd2\xd2I\x14!\xd0\x98\xed\xf2\xab\xae\xc6\x03',
  'haxxair': b'\xd8\xaf\x89--\x00\xabI\x93\x83j\xab\x9acX\xac^\x90f;',
  'fglair-cn': b'\xcd\xec\xe0\xed\x8e\xb4b\x90/\xcbq\xcf\xc3\x1b\xd6.wx:\x1e',
  'fglair-eu': b'\x82\x91[T\x14h\x88\x9f\x04\xdd\x05\x89\xf9\x04T,\xb2\xf7\x8fu',
  'fglair-us': b'U\xbf\x0c@\xbf\xe5\x16&\x10\xec2\xa37G\x82\x15|\xe7)\x91',
  'field-us': b'\xc8b\x08\xfa\xce8\xf8\xf1\x81\xa5\x81\x8fX\xb4\x80\xc0\xdc\xf5\ny',
  'huihe-us': b'\xa2\xbcZ3\xbch\xfa7.`\xbc\xef0\xa3p\xa1\xf0\xaf\xf4\xd4',
  'denali-us': b'\xf1\'\xb0K \xdbZ\xd84;\xeb\x02\xa2\xee\x008\xda\x95\xfd\x93',
  'hisense-eu': b'\xc0\xedK,\xff+X\xfa\xf6p\x87\xaa\xbcV\x88\xfbI\xb4\xcf\xad',
  'hisense-us': b'x\x04\xdf\xef6\x08\x8e\x06\n\x97\xfc\xed4m\xd8\xc7\xa3=\xce\x9f',
  'hismart-eu': b'0\x07\xe9\x04a\xa6e\xc4\x1c\x08+"\r\x84w\x91\x8f\xa8)\x98',
  'hismart-us': b'\xd6+\x1f\xb0b\t\x19G\x87\x8c\xaak\xd0\xf8y\xf5\x933\xafp',
}
_SECRET_ID_MAP = {
  'haxxair': 'HAXXAIR',
  'field-us': 'pactera-field-f624d97f-us',
  'fglair-cn': 'FGLairField-cn',
  'fglair-eu': 'FGLair-eu',
  'fglair-us': 'CJIOSP',
  'huihe-us': 'huihe-d70b5148-field-us',
  'denali-us': 'DenaliAire',
  'hisense-eu': 'Hisense',
  'hisense-us': 'APP1',
  'hismart-eu': 'Hismart',
  'hismart-us': 'App1',
}
_SECRET_ID_EXTRA_MAP = {
  'denali-us': 'iA',
  'hisense-eu': 'mw',
  'hisense-us': 'pg',
  'hismart-eu': 'fA',
  'hismart-us': 'Lg',
}
_USER_AGENT = 'Dalvik/2.1.0 (Linux; U; Android 9.0; SM-G850F Build/LRX22G)'

def escape_name(name: str):
  safe_name = name.replace(' ', '_').lower()
  return "".join(x for x in safe_name if x.isalnum())
  
if __name__ == '__main__':
  arg_parser = argparse.ArgumentParser(
      description='Command Line to query HiSense server.',
      allow_abbrev=False)
  arg_parser.add_argument('-a', '--app', required=True,
                          choices=set(_SECRET_MAP),
                          help='The app used for the login.')
  arg_parser.add_argument('-u', '--user', required=True,
                          help='Username for the app login.')
  arg_parser.add_argument('-p', '--passwd', required=True,
                          help='Password for the app login.')
  arg_parser.add_argument('-d', '--device', default=None,
                          help='Device name to fetch data for. If not set, takes the first.')
  arg_parser.add_argument('--prefix', required=False, default='config_',
                          help='Config file prefix.')
  arg_parser.add_argument('--properties', type=bool, default=False,
                          help='Fetch the properties for the device.')
  args = arg_parser.parse_args()
  logging_handler = logging.StreamHandler(stream=sys.stderr)
  logging_handler.setFormatter(
      logging.Formatter(fmt='{levelname[0]}{asctime}.{msecs:03.0f}  '
                        '{filename}:{lineno}] {message}',
                         datefmt='%m%d %H:%M:%S', style='{'))
  logger = logging.getLogger()
  logger.setLevel('INFO')
  logger.addHandler(logging_handler)
  if args.app in _SECRET_ID_MAP:
    app_prefix = _SECRET_ID_MAP[args.app]
  else:
    app_prefix = 'a-Hisense-{}-field'.format(args.app)
  if args.app in _SECRET_ID_EXTRA_MAP:
    app_id = '-'.join((app_prefix, _SECRET_ID_EXTRA_MAP[args.app], 'id'))
  else:
    app_id = '-'.join((app_prefix, 'id'))
  secret = base64.b64encode(_SECRET_MAP[args.app]).decode('utf-8').rstrip('=').replace('+', '-').replace('/', '_')
  app_secret = '-'.join((app_prefix, secret))
  # Extract the region from the app ID (and fallback to US)
  region = args.app[-2:]
  if region not in _AYLA_USER_SERVERS:
    region = 'us'
  user_server = _AYLA_USER_SERVERS[region]
  devices_server = _AYLA_DEVICES_SERVERS[region]
  ssl_context = ssl.SSLContext()
  ssl_context.verify_mode = ssl.CERT_NONE
  ssl_context.check_hostname = False
  ssl_context.load_default_certs()
  conn = HTTPSConnection(user_server, context=ssl_context)
  query = {
    'user': {
      'email': args.user,
      'password': args.passwd,
      'application': {
        'app_id': app_id,
        'app_secret': app_secret
      }
    }
  }
  headers = {
    'Accept': 'application/json',
    'Connection': 'Keep-Alive',
    'Authorization': 'none',
    'Content-Type': 'application/json',
    'User-Agent': _USER_AGENT,
    'Host': user_server,
    'Accept-Encoding': 'gzip'
  }
  logging.debug('POST /users/sign_in.json, body=%r, headers=%r' % (json.dumps(query), headers))
  conn.request('POST', '/users/sign_in.json', body=json.dumps(query), headers=headers)
  resp = conn.getresponse()
  if resp.status != 200:
    logging.error('Failed to login to Hisense server:\nStatus %d: %r',
                  resp.status, resp.reason)
    sys.exit(1)
  resp_data = resp.read()
  try:
    resp_data = gzip.decompress(resp_data)
  except OSError:
    pass  # Not gzipped.
  try:
    tokens = json.loads(resp_data)
  except UnicodeDecodeError:
    logging.exception('Failed to parse login tokens to Hisense server:\nData: %r',
                      resp_data)
    sys.exit(1)
  conn.close()
  conn = HTTPSConnection(devices_server, context=ssl_context)
  headers = {
    'Accept': 'application/json',
    'Connection': 'Keep-Alive',
    'Authorization': 'auth_token ' + tokens['access_token'],
    'User-Agent': _USER_AGENT,
    'Host': devices_server,
    'Accept-Encoding': 'gzip'
  }
  logging.debug('GET /apiv1/devices.json, headers=%r' % headers)
  conn.request('GET', '/apiv1/devices.json', headers=headers)
  resp = conn.getresponse()
  if resp.status != 200:
    logging.error('Failed to get devices data from Hisense server:\nStatus %d: %r',
                  resp.status, resp.reason)
    sys.exit(1)
  resp_data = resp.read()
  try:
    resp_data = gzip.decompress(resp_data)
  except OSError:
    pass  # Not gzipped.
  try:
    devices = json.loads(resp_data)
  except UnicodeDecodeError:
    logging.exception('Failed to parse devices data from Hisense server:\nData: %r',
                      resp_data)
    sys.exit(1)
  if not devices:
    logging.error('No device is configured! Please configure a device first.')
    sys.exit(1)
  logging.info('Found devices: %r', devices)
  for device in devices:
    if args.device and args.device != device['device']['product_name']:
      continue
    dsn = device['device']['dsn']
    conn.request('GET', '/apiv1/dsns/{}/lan.json'.format(dsn), headers=headers)
    resp = conn.getresponse()
    if resp.status != 200:
      logging.error('Failed to get device data from Hisense server: %r', resp)
      sys.exit(1)
    resp_data = resp.read()
    try:
      resp_data = gzip.decompress(resp_data)
    except OSError:
      pass  # Not gzipped.
    lanip = json.loads(resp_data)['lanip']
    properties = ''
    if args.properties:
      conn.request('GET', '/apiv1/dsns/{}/properties.json'.format(dsn), headers=headers)
      resp = conn.getresponse()
      if resp.status != 200:
        logging.error('Failed to get properties data from Hisense server: %r', resp)
        sys.exit(1)
      resp_data = resp.read()
      try:
        resp_data = gzip.decompress(resp_data)
      except OSError:
        pass  # Not gzipped.
      properties = 'Properties:\n%s', json.dumps(json.loads(resp_data), indent=2)
    logging.info('Device %s has:\nIP address: %s\nlanip_key: %s\nlanip_key_id: %s\n%s\n', 
                 device['device']['product_name'], device['device']['lan_ip'], 
                 lanip['lanip_key'], lanip['lanip_key_id'], properties)
    conn.close()
    config = {
      'lanip_key': lanip['lanip_key'],
      'lanip_key_id': lanip['lanip_key_id'],
      'random_1': '',
      'time_1': 0,
      'random_2': '',
      'time_2': 0
    }
    with open(args.prefix + escape_name(device['device']['product_name']) + '.json', 'w') as f:
      f.write(json.dumps(config))
