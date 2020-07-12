from copy import deepcopy
from dataclasses import fields
import enum
import logging
import random
import string
import threading
from typing import Callable
import queue
from Crypto.Cipher import AES

from .config import Config, Encryption
from .error import Error
from .properties import AcProperties, FastColdHeat, FglProperties, FglBProperties, HumidifierProperties, Properties

class BaseDevice:
  def __init__(self, ip_address: str, lanip_key: str, lanip_key_id: str, properties: Properties):
    self.ip_address = ip_address
    self._config = Config(lanip_key, lanip_key_id)
    self._properties = properties
    self._properties_lock = threading.Lock()

    self._next_command_id = 0

    self.commands_queue = queue.Queue()
    self._commands_seq_no = 0
    self._commands_seq_no_lock = threading.Lock()

    self._updates_seq_no = 0
    self._updates_seq_no_lock = threading.Lock()

    self.change_listener: Callable[[str, str], None]

  def get_all_properties(self) -> Properties:
    with self._properties_lock:
      return deepcopy(self._properties)

  def get_property(self, name: str):
    """Get a stored property."""
    with self._properties_lock:
      return getattr(self._properties, name)

  def get_property_type(self, name: str):
    return self._properties.get_type(name)

  def update_property(self, name: str, value) -> None:
    """Update the stored properties, if changed."""
    with self._properties_lock:
      old_value = getattr(self._properties, name)
      if value != old_value:
        setattr(self._properties, name, value)
        logging.debug('Updated properties: %s' % self._properties)
      if self.change_listener:
        self.change_listener(name, value)

  def get_command_seq_no(self) -> int:
    with self._commands_seq_no_lock:
      seq_no = self._commands_seq_no
      self._commands_seq_no += 1
      return seq_no

  def is_update_valid(self, cur_update_no: int) -> bool:
    with self._updates_seq_no_lock:
      # Every once in a while the sequence number is zeroed out, so accept it.
      if self._updates_seq_no > cur_update_no and cur_update_no > 0:
        logging.error('Stale update found %d. Last update used is %d.',
                      cur_update_no, self._updates_seq_no)
        return False # Old update
      self._updates_seq_no = cur_update_no
      return True

  def queue_command(self, name: str, value) -> None:
    if self._properties.get_read_only(name):
      raise Error('Cannot update read-only property "{}".'.format(name))
    data_type = self._properties.get_type(name)
    base_type = self._properties.get_base_type(name)
    if issubclass(data_type, enum.Enum):
      data_value = data_type[value].value
    elif data_type is int and type(value) is str and '.' in value:
      # Round rather than fail if the input is a float.
      # This is commonly the case for temperatures converted by HA from Celsius.
      data_value = round(float(value))
    else:
      data_value = data_type(value)
    command = {
      'properties': [{
        'property': {
          'base_type': base_type,
          'name': name,
          'value': data_value,
          'id': ''.join(random.choices(string.ascii_letters + string.digits, k=8)),
        }
      }]
    }
    # There are (usually) no acks on commands, so also queue an update to the
    # property, to be run once the command is sent.
    typed_value = data_type[value] if issubclass(data_type, enum.Enum) else data_value
    property_updater = lambda: self.update_property(name, typed_value)
    self.commands_queue.put_nowait((command, property_updater))

    # Handle turning on FastColdHeat
    if name == 't_temp_heatcold' and typed_value is FastColdHeat.ON:
      self.queue_command('t_fan_speed', 'AUTO')
      self.queue_command('t_fan_mute', 'OFF')
      self.queue_command('t_sleep', 'STOP')
      self.queue_command('t_temp_eight', 'OFF')

  def queue_status(self) -> None:
    for data_field in fields(self._properties):
      command = {
        'cmds': [{
          'cmd': {
            'method': 'GET',
            'resource': 'property.json?name=' + data_field.name,
            'uri': '/local_lan/property/datapoint.json',
            'data': '',
            'cmd_id': self._next_command_id,
          }
        }]
      }
      self._next_command_id += 1
      self.commands_queue.put_nowait((command, None))

  def update_key(self, key: dict) -> dict:
    return self._config.update(key)

  def get_app_encryption(self) -> Encryption:
    return self._config.app

  def get_dev_encryption(self) -> Encryption:
    return self._config.dev

class AcDevice(BaseDevice):
  def __init__(self, ip_address: str, lanip_key: str, lanip_key_id: str):
    super().__init__(ip_address, lanip_key, lanip_key_id, AcProperties())

class FglDevice(BaseDevice):
  def __init__(self, ip_address: str, lanip_key: str, lanip_key_id: str):
    super().__init__(ip_address, lanip_key, lanip_key_id, FglProperties())

class FglBDevice(BaseDevice):
  def __init__(self, ip_address: str, lanip_key: str, lanip_key_id: str):
    super().__init__(ip_address, lanip_key, lanip_key_id, FglBProperties())

class HumidifierDevice(BaseDevice):
  def __init__(self, ip_address: str, lanip_key: str, lanip_key_id: str):
    super().__init__(ip_address, lanip_key, lanip_key_id, HumidifierProperties())