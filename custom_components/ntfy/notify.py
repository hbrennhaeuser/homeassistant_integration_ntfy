"""Ntfy notification service."""
import logging
from homeassistant.components.notify import (
    ATTR_MESSAGE,
    ATTR_TITLE,
    ATTR_TITLE_DEFAULT,
    ATTR_DATA,
    PLATFORM_SCHEMA,
    BaseNotificationService,
)
import homeassistant.helpers.config_validation as cv

from tokenize import String
from requests.auth import HTTPBasicAuth
import requests
import voluptuous as vol
import urllib.parse
from base64 import b64encode


CONF_TOPIC = 'topic'
CONF_ALLOW_TOPIC_OVERRIDE = 'allow_topic_override'
CONF_TOKEN = 'token'

from homeassistant.const import (
    CONF_PASSWORD,
    CONF_USERNAME,
    CONF_VERIFY_SSL,
    CONF_URL,
    CONF_AUTHENTICATION,
)


_LOGGER = logging.getLogger(__name__)


def get_service(hass,config, discovery_info=None):
    return NtfyNotificationService(config)



class NtfyNotificationService(BaseNotificationService):
    def __init__ (self, config):
        """Initialize the Ntfy notification service."""
        self.request_timeout=5

        self.topic = None
        if config.get(CONF_TOPIC) is not None:
            self.topic = config.get(CONF_TOPIC)

        self.url = config.get(CONF_URL)
        try:
            vol.Schema(vol.Url())(self.url)
        except vol.MultipleInvalid as e:
            raise SyntaxError('url syntax invalid') from e

        self.verifyssl = True
        if config.get(CONF_VERIFY_SSL) is not None:
            self.verifyssl = bool(config.get(CONF_VERIFY_SSL))

        self.allow_topic_override = False
        if config.get(CONF_ALLOW_TOPIC_OVERRIDE) is not None:
            self.allow_topic_override = bool(config.get(CONF_ALLOW_TOPIC_OVERRIDE))

        self.auth = False
        if config.get(CONF_AUTHENTICATION) is not None:
            schema_authentication = ['user-pass','token']
            if config.get(CONF_AUTHENTICATION) not in schema_authentication:
                raise SyntaxError('Invalid value specified for authentication')
            self.auth = config.get(CONF_AUTHENTICATION)

        self.username = None
        self.password = None
        self.token = None
        if self.auth is not False:
            if self.auth == 'user-pass':
                if config.get(CONF_USERNAME) is None:
                    raise SyntaxError("Authentication username is missing")
                if config.get(CONF_PASSWORD) is None:
                    raise SyntaxError("Authentication password is missing")
                self.username = config.get(CONF_USERNAME)
                self.password = config.get(CONF_PASSWORD)
            elif self.auth == 'token':
                if config.get(CONF_TOKEN) is None:
                    raise SyntaxError('Authentication token is missing')
                self.token = config.get(CONF_TOKEN)



    def send_message(self, message="", **kwargs):
        """Send message"""
        title=kwargs.get(ATTR_TITLE,ATTR_TITLE_DEFAULT)
        data=kwargs.get(ATTR_DATA,[])
        topic=self.topic

        req_data=None
        req_headers={}

        # --
        if "topic" in data:
            if self.allow_topic_override:
                topic=data["topic"]
            else:
                raise PermissionError('Trying to override topic without allow_topic_override being True')
        if topic is None:
            raise SyntaxError("No topic specified")
        url=str(self.url) + '/' + urllib.parse.quote(str(topic))

        # --
        req_data=message.encode('utf-8')

        if title is not None:
            req_headers["Title"] = title

        if "tags" in data:
            # TODO: validate tag format
            req_headers["Tags"] = data["tags"]

        if "priority" in data:
            schema_priority = ['max','urgent','high','default','low','min']
            if str(data["priority"]) not in schema_priority:
                raise SyntaxError('Incorrect value for attribute priority given')
            req_headers["Priority"] = data["priority"]

        if "click" in data:
            schema_url = vol.Schema(vol.Url())
            try:
                schema_url(data["click"])
            except vol.MultipleInvalid as e:
                raise SyntaxError('expected a URL for attribute click') from e
            req_headers["Click"] = data["click"]


        # --
        if self.auth == 'user-pass':
            req_headers['Authorization'] = 'Basic ' + b64encode( f"{self.username}:{self.password}".encode() ).decode()
        elif self.auth == 'token':
            req_headers['Authorization'] = 'Bearer ' + self.token

        requests.post(
            url=url,
            data=req_data,
            headers=req_headers,
            verify=self.verifyssl,
            timeout=self.request_timeout
        )
