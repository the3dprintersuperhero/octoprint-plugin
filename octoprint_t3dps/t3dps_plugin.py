# coding=utf-8

import argparse
from awscrt import io, mqtt, auth, http
from awsiot import mqtt_connection_builder

import octoprint.plugin
import requests
import json
import sys
import base64
import logging
import threading


_logger = logging.getLogger('octoprint.plugins.t3dps')
_connected = False;

class The3DPrinterSuperheroPlugin(
	octoprint.plugin.StartupPlugin,
	octoprint.plugin.SettingsPlugin,
	octoprint.plugin.TemplatePlugin,
	octoprint.plugin.EventHandlerPlugin):

	def __init__(self):
		_logger.info("__init__:")
		self.topic_template = 'c/3dv/{}'
		self.mqtt_connection = None

	# ~~ StartupPlugin mixin

	def on_startup(self, host, port):
		_logger.info("on_startup: host:{}, port:{}".format(host, port))
		self.port = port

	def on_after_startup(self):
		_logger.info("on_after_startup:")

	# ~~ SettingsPlugin mixin

	def get_settings_defaults(self):
		_logger.info("get_settings_defaults:")
		return dict(
			license_key="<enter your license key>",
			octoprint_api_key="<enter octoprint api key>",
			printerId='',
			client_id='',
			certificate_pem='',
			private_key='',
			root_ca='',
			endpoint=''
		)

	def on_settings_save(self, data):
		_logger.info("on_settings_save: data:{}".format(data))

		octoprint.plugin.SettingsPlugin.on_settings_save(self, data)
		
		self.aws_disconnect()

		license_key = self._settings.get(["license_key"])

		if len(license_key)>0:
			config = base64.b64decode(license_key)
			config_json = json.loads(config)

			_logger.debug("on_settings_save: printer_id: {}", config_json['printerId'])
			_logger.debug("on_settings_save: client_id: {}", config_json['clientId'])
			_logger.debug("on_settings_save: certificate_pem: {}", config_json['certificatePem'])
			_logger.debug("on_settings_save: private_key: {}", config_json['privateKey'])
			_logger.debug("on_settings_save: root_ca: {}", config_json['rootCa'])
			_logger.debug("on_settings_save: endpoint: {}", config_json['endpoint'])

			self._settings.set(["printer_id"], config_json['printerId'])
			self._settings.set(["client_id"], config_json['clientId'])
			self._settings.set(["certificate_pem"], config_json['certificatePem'])
			self._settings.set(["private_key"], config_json['privateKey'])
			self._settings.set(["root_ca"], config_json['rootCa'])
			self._settings.set(["endpoint"], config_json['endpoint'])

			self.aws_connect()

		else:
			_logger.debug("on_settings_save: clearing out")

			self._settings.set(["printer_id"], '')
			self._settings.set(["client_id"], '')
			self._settings.set(["certificate_pem"], '')
			self._settings.set(["private_key"], '')
			self._settings.set(["root_ca"], '')
			self._settings.set(["endpoint"], '')
			

	def on_settings_initialized(self):
		_logger.info("on_settings_initialized:")
		self.aws_connect()

	# ~~ TemplatesPlugin mixin

	# def get_template_vars(self):
	# 	return dict(
	# 		license_key=self._settings.get(["license_key"]),
	# 		octoprint_api_key=self._settings.get(["octoprint_api_key"])
	# 	)

	def get_template_configs(self):
		_logger.info("get_template_configs:")
		return [
			dict(type="settings", custom_bindings=False)
		]

	# ~~ EventHandlerPlugin mixin ~~ #

	def on_event(self, event, payload):
		if event == 'Connected' or event == 'ConnectivityChanged':
			_logger.info("on_event: event: {}, payload: {}".format(event, payload))
			t = threading.Timer(5, self.aws_connect())
			t.start()

	# ~~ Softwareupdate hook

	def get_update_information(self):
		_logger.info("get_update_information:")
		return dict(
			t3dps=dict(
				displayName="The 3D Printer Superhero",
				displayVersion=self._plugin_version,

				# version check: github repository
				type="github_release",
				user="the3dprintersuperhero",
				repo="octoprint-plugin",
				current=self._plugin_version,

				# update method: pip
				pip="https://github.com/the3dprintersuperhero/octoprint-plugin/archive/{target_version}.zip"
			)
		)

	# ~~ app logic...

	def aws_connect(self):
		_logger.info("aws_connect:")

		global _connected
		if _connected == True:
			_logger.info("aws_connect: ignoring")
			return

		root_ca = self._settings.get(['root_ca'])
		certificate_pem = self._settings.get(['certificate_pem'])
		private_key = self._settings.get(['private_key'])
		endpoint = self._settings.get(['endpoint'])
		client_id = self._settings.get(['client_id'])

		_logger.debug("aws_connect: config: endpoint: {}".format(endpoint))
		_logger.debug("aws_connect: config: certificate_pem: {}".format(certificate_pem))
		_logger.debug("aws_connect: config: private_key: {}".format(private_key))
		_logger.debug("aws_connect: config: root_ca: {}".format(root_ca))
		_logger.debug("aws_connect: config: client_id: {}".format(client_id))

		has_root_ca = root_ca is not None and root_ca.startswith("-----BEGIN CERTIFICATE-----")
		has_certificate_pem = certificate_pem is not None and certificate_pem.startswith("-----BEGIN CERTIFICATE-----")
		has_private_key = private_key is not None and private_key.startswith("-----BEGIN RSA PRIVATE KEY-----")
		has_endpoint = endpoint is not None and endpoint.endswith(".amazonaws.com")
		has_client_id = client_id is not None and len(client_id)>0

		if (not has_root_ca or not has_certificate_pem or not has_private_key or not has_endpoint or not has_client_id):
			_logger.warn("aws_connect: Insufficient config to connect")
			return

		try:
			event_loop_group = io.EventLoopGroup(1)
			host_resolver = io.DefaultHostResolver(event_loop_group)
			client_bootstrap = io.ClientBootstrap(event_loop_group, host_resolver)

			_logger.info("aws_connect: Connecting to {} with client ID '{}'...".format(endpoint, client_id))

			self.mqtt_connection = mqtt_connection_builder.mtls_from_bytes(
				endpoint=endpoint,
				cert_bytes=str.encode(certificate_pem),
				pri_key_bytes=str.encode(private_key),
				client_bootstrap=client_bootstrap,
				ca_bytes=str.encode(root_ca),
				on_connection_interrupted=self.on_aws_connection_interrupted,
				on_connection_resumed=self.on_aws_connection_resumed,
				client_id=client_id,
				clean_session=True)

			connect_future = self.mqtt_connection.connect()
			connect_future.result()

			_logger.debug("aws_connect: Connected!")
			_connected = True

			# Subscribe
			topic = self.topic_template.format( client_id)
			_logger.debug("aws_connect: Subscribing to topic '{}'...".format(topic))
			subscribe_future, packet_id = self.mqtt_connection.subscribe(
				topic=topic,
				qos=mqtt.QoS.AT_LEAST_ONCE,
				callback=self.on_aws_message_received )
			subscribe_result = subscribe_future.result()
			_logger.debug("aws_connect: Subscribed with {}".format(str(subscribe_result['qos'])))

		except Exception as e:
			_logger.error("aws_connect: error {}".format(str(e)))
			self._plugin_manager.send_plugin_message(self._identifier, dict(error=str(e)))

	def aws_disconnect(self):
		_logger.info("aws_disconnect:")
		if self.mqtt_connection:
			try:
				disconnect_future = self.mqtt_connection.disconnect()
				disconnect_future.result()
				_logger.debug("aws_disconnect: Disconnected!")
				global _connected
				_connected = False
			except:
				pass

	def on_aws_connection_interrupted(self, connection, error, **kwargs):
		_logger.warn("on_aws_connection_interrupted: error: {}".format(error))

	def on_aws_connection_resumed(self, connection, return_code, session_present, **kwargs):
		_logger.info("on_aws_connection_resumed: session_present: {}".format(session_present))

		if return_code == mqtt.ConnectReturnCode.ACCEPTED and not session_present:
			resubscribe_future, _ = connection.resubscribe_existing_topics()
			# Cannot synchronously wait for resubscribe result because we're on the connection's event-loop thread,
			# evaluate result with a callback instead.
			resubscribe_future.add_done_callback(self.aws_resubscribe_complete)
			global _connected
			_connected = True

	def on_aws_resubscribe_complete(self, resubscribe_future):
		resubscribe_results = resubscribe_future.result()
		_logger.debug("on_aws_resubscribe_complete: results: {}".format(resubscribe_results))

		for topic, qos in resubscribe_results['topics']:
			if qos is None:
				_logger.warn("on_aws_resubscribe_complete: Server rejected resubscribe to topic: {}".format(topic))

	def on_aws_message_received(self, topic, payload, **kwargs):
		_logger.debug("on_aws_message_received: Received message from topic '{}': {}".format(topic, payload))

		payloadStr=str(payload,"utf-8")
		payloadJson=json.loads(payloadStr)

		results = dict()
		headers = {'Content-type': 'application/json', 'X-Api-Key': self._settings.get(["octoprint_api_key"])}
		base_url = "http://localhost:{}".format(self.port)

		for name, req in payloadJson["requests"].items():
			try:
				url = base_url + req["url"]
				headers = req["headers"]
				headers["X-Api-Key"] = self._settings.get(["octoprint_api_key"])
				if req["method"] == "GET":
					_logger.debug("on_aws_message_received: Calling GET {}, headers: {}".format(url, headers))
					response = requests.get(url, headers=headers)
				elif req["method"] == "POST":
					_logger.debug("on_aws_message_received: Calling POST {}, headers: {}, body `{}`".format(url, headers, req["body"]))
					response = requests.post(url, data=json.dumps(req["body"]), headers=headers)
				results[name] = dict(
					statusCode=response.status_code
				)
				try:
					results[name]['response']=json.loads(response.text)
				except ValueError:
					results[name]['response']=response.text

			except:
				err = sys.exc_info()[0]
				_logger.error("on_aws_message_received: error: {}".format(err))
				results[name] = dict(
					status_code= -1,
					body= str(err)
				)
				self._plugin_manager.send_plugin_message( self._identifier, dict(error=str(err)))

		response_topic=payloadJson["responseTopic"]
		response_payload=json.dumps(results)
		_logger.debug("on_aws_message_received: Publishing response: `{}` to topic: {}".format(response_payload, response_topic))
		self.mqtt_connection.publish(
			topic=response_topic,
			payload=response_payload,
			qos=mqtt.QoS.AT_LEAST_ONCE)
