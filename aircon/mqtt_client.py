from dataclasses import fields
import enum
import logging
import paho.mqtt.client as mqtt

from . import aircon
from .aircon import BaseDevice
from .store import Data
from .properties import AcWorkMode

class MqttClient(mqtt.Client):
  def __init__(self, client_id: str, mqtt_topics: dict, device: BaseDevice):
    super(self, client_id=client_id, clean_session=True)
    self._mqtt_topics = mqtt_topics
    self._device = device

    self.on_connect = self.mqtt_on_connect
    self.on_message = self.mqtt_on_message

  def mqtt_on_connect(self, client: mqtt.Client, userdata, flags, rc):
    client.subscribe([(self._mqtt_topics['sub'].format(data_field.name), 0)
                      for data_field in fields(self._device.data.properties)])
    # Subscribe to subscription updates.
    client.subscribe('$SYS/broker/log/M/subscribe/#')

  def mqtt_on_message(self, client: mqtt.Client, userdata, message: mqtt.MQTTMessage):
    logging.info('MQTT message Topic: %r, Payload %r',
                message.topic, message.payload)
    if message.topic.startswith('$SYS/broker/log/M/subscribe'):
      return self.mqtt_on_subscribe(message.payload)
    name = message.topic.rsplit('/', 2)[1]
    payload = message.payload.decode('utf-8')
    if name == 't_work_mode' and payload == 'fan_only':
      payload = 'FAN'
    try:
      self._device.queue_command(name, payload.upper())
    except Exception:
      logging.exception('Failed to parse value %r for property %r',
                        payload.upper(), name)

  def mqtt_on_subscribe(self, payload: bytes):
    # The last segment in the space delimited string is the topic.
    topic = payload.decode('utf-8').rsplit(' ', 1)[-1]
    if topic not in self._mqtt_topics['pub']:
      return
    name = topic.rsplit('/', 2)[1]
    self.mqtt_publish_update(name, self._device.data.get_property(name))

  def mqtt_publish_update(self, name: str, value) -> None:
    if isinstance(value, enum.Enum):
      payload = 'fan_only' if value is AcWorkMode.FAN else value.name.lower()
    else:
      payload = str(value)
    self.publish(self._mqtt_topics['pub'].format(name), payload=payload.encode('utf-8'))
