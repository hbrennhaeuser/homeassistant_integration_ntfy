"""Ntfy notification service."""
import logging
from base64 import b64encode
import os
import zipfile
from io import BytesIO
import re
import urllib.parse
import requests
import urllib3
import voluptuous as vol
from PIL import Image

from homeassistant.components.notify import (
    ATTR_TITLE,
    ATTR_TITLE_DEFAULT,
    ATTR_DATA,
    BaseNotificationService,
)
from homeassistant.exceptions import ServiceValidationError
from homeassistant.exceptions import HomeAssistantError
from homeassistant.const import (
    CONF_PASSWORD,
    CONF_USERNAME,
    CONF_VERIFY_SSL,
    CONF_URL,
    CONF_AUTHENTICATION,
)
from .const import (
    CONF_TOPIC,
    CONF_ALLOW_TOPIC_OVERRIDE,
    CONF_TOKEN,
    CONF_ATTACHMENT_MAXSIZE,
    DEFAULT_VERIFY_SSL,
    DEFAULT_ALLOW_TOPIC_OVERRIDE,
    DEFAULT_ATTACHMENT_MAXSIZE,
    DEFAULT_REQUEST_TIMEOUT

)

_LOGGER = logging.getLogger(__name__)


def get_service(hass,config, discovery_info=None):
    return NtfyNotificationService(config)


class NtfyNotificationService(BaseNotificationService):
    def __init__ (self, config):
        """Initialize the Ntfy notification service."""
        self.request_timeout = DEFAULT_REQUEST_TIMEOUT

        config_schema = vol.Schema(
            vol.All(
                {
                    vol.Optional('auth'): vol.In(['token', 'user-pass', None, False])
                },
                vol.Any(
                    {
                        vol.Required('auth'): 'token',
                        vol.Required(CONF_TOKEN): str,
                    },
                    {
                        vol.Required('auth'): 'user-pass',
                        vol.Required(CONF_USERNAME): str,
                        vol.Required(CONF_PASSWORD): str,
                    },
                    {
                        vol.Optional('auth', default=None): vol.Any(None, False, str),
                        vol.Optional(CONF_TOKEN): vol.Any(None, str),
                        vol.Optional(CONF_USERNAME): vol.Any(None, str),
                        vol.Optional(CONF_PASSWORD): vol.Any(None, str),
                    }
                ),
                # common fields
                {
                    vol.Required(CONF_TOPIC): str,
                    vol.Required(CONF_URL): vol.Url(),
                    vol.Optional(CONF_VERIFY_SSL): bool,
                    vol.Optional(CONF_ALLOW_TOPIC_OVERRIDE): bool,
                    vol.Optional(CONF_ATTACHMENT_MAXSIZE): vol.Coerce(int),
                }
            ), extra=vol.ALLOW_EXTRA )
    
        try:
            config_schema(config)
        except Exception as e:
            raise ServiceValidationError from e

        self.auth = config.get(CONF_AUTHENTICATION, False)
        self.username = config.get(CONF_USERNAME, None)
        self.password = config.get(CONF_PASSWORD, None)
        self.token = config.get(CONF_TOKEN, None)

        self.topic = config.get(CONF_TOPIC)
        self.url = config.get(CONF_URL)
        self.verifyssl = config.get(CONF_VERIFY_SSL, DEFAULT_VERIFY_SSL)
        self.allow_topic_override = config.get(CONF_ALLOW_TOPIC_OVERRIDE, DEFAULT_ALLOW_TOPIC_OVERRIDE)
        self.attachment_maxsize = config.get(CONF_ATTACHMENT_MAXSIZE, DEFAULT_ATTACHMENT_MAXSIZE)

        if not self.verifyssl:
            _LOGGER.warning("InsecureRequestWarning: Unverified HTTPS request could be made to '%s'. Setting %s to True is recommended. All further InsecureRequestWarning will be suppressed!", self.url, CONF_VERIFY_SSL)
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


    def _parse_attachment_maxsize(self, size=None):
        attachment_maxsize_bytes = None

        if isinstance(size,int):
            attachment_maxsize_bytes = size
        elif isinstance(size, str):
            search = re.search('^([0-9]+)([a-zA-Z]{0,3})$', size)
            value = int(search.group(1))
            unit = search.group(2)

            match unit:
                case 'b' | 'B':
                    attachment_maxsize_bytes = value
                case 'k' | 'K':
                    attachment_maxsize_bytes = value * 1024
                case 'm' | 'M':
                    attachment_maxsize_bytes = value * (1024 ** 2)
                case _:
                    raise ServiceValidationError(f"Unknown unit {unit}")

        return attachment_maxsize_bytes


    def _compress_image(self, data, attach_file_content):
        attach_image_content_compressed = BytesIO()
        with Image.open(attach_file_content) as img:
            img = img.convert('RGB')
            img.save(attach_image_content_compressed, quality=data['attachment_compress_image'], format='jpeg')
        return attach_image_content_compressed


    def _resize_image(self, data, attach_file_content):
        attach_image_content_resized = BytesIO()
        with Image.open(attach_file_content) as img:
            img = img.convert('RGB')
            width, height = img.size
            factor = height/width

            search = re.search('^([0-9]+)((?:px|%))$', data['attachment_resize_image'])
            value = int(search.group(1))
            unit = search.group(2)

            width_new = width
            height_new = height

            if unit == 'px':
                width_new = value
            elif unit == '%':
                width_new = round(width*(value/100),0)

            height_new = round(width_new * factor,0)

            img = img.resize((int(width_new), int(height_new)))

            img.save(attach_image_content_resized, quality=100, format='jpeg')
        return attach_image_content_resized


    def _compress_file(self, data, attach_file_content, attach_file_name):
        attach_file_content_compressed = BytesIO()
        with zipfile.ZipFile(attach_file_content_compressed, mode="a", compression=zipfile.ZIP_DEFLATED, compresslevel=data['attachment_compress_file']) as zip_file:
            zip_file.writestr(attach_file_name, attach_file_content.getvalue())
        return attach_file_content_compressed.getvalue()


    def _escape_header_value(self, value):
        decoded_value = urllib.parse.unquote(value)
        escaped_value = urllib.parse.quote(decoded_value)
        return escaped_value


    def _validate_filesize(self, data):
        attach_file_size = os.stat(data['attach_file']).st_size
        if self.attachment_maxsize is not None and attach_file_size > self.attachment_maxsize:
            raise HomeAssistantError(f"Specified file '{data['attach_file']}', {attach_file_size}B is larger than specified max size {self.attachment_maxsize}B")
        return True


    def _validate_message_params_action_view(self, action):
        view_schema = vol.Schema({
            vol.Required('action'): str,
            vol.Required('label'): str,
            vol.Required('url'): vol.Url(),
            vol.Optional('clear', default=False): bool,
        })
        try:
            view_schema(action)
        except Exception as e:
            raise ServiceValidationError from e


    def _validate_message_params_action_broadcast(self, action):
        broadcast_schema = vol.Schema({
            vol.Required('action'): str,
            vol.Required('label'): str,
            vol.Optional('intent'): str,
            vol.Optional('extras', default={}): vol.Schema({str: str}),
        })
        try:
            broadcast_schema(action)
        except Exception as e:
            raise ServiceValidationError from e


    def _validate_message_params_action_http(self, action):
        http_schema = vol.Schema({
            vol.Required('action'): str,
            vol.Required('label'): str,
            vol.Required('url'): vol.Url(),
            vol.Optional('method', default='GET'): vol.In(['GET', 'POST', 'PUT', 'DELETE']),
            vol.Optional('headers', default={}): vol.Schema({str: str}),
            vol.Optional('body', default=''): str,
            vol.Optional('clear', default=False): bool,
        })
        try:
            http_schema(action)
        except Exception as e:
            raise ServiceValidationError from e


    def _validate_message_params(self, data):
        schema = vol.Schema({
            vol.Optional("topic"): str,
            vol.Optional("priority"): vol.In(['max', 'urgent', 'high', 'default', 'low', 'min']),
            vol.Optional("click"): vol.Url(),
            vol.Optional("tags"): str,
            vol.Optional("actions"): object,
            vol.Optional("attach_url"): vol.Url(),
            vol.Optional("attach_file"): vol.All(str, vol.IsFile),
            vol.Optional("attachment_filename"): str,
            vol.Optional("attachment_compress_image"): vol.All(vol.Coerce(int), vol.Range(min=0, max=100)),
            vol.Optional("attachment_compress_file"): vol.All(vol.Coerce(int), vol.Range(min=0, max=9)),
            vol.Optional("attachment_resize_image"): vol.Match(r'^[0-9]+(px|%)$'),
        })

        try:
            schema(data)
        except Exception as e:
            raise ServiceValidationError from e

        if "topic" in data and not self.allow_topic_override:
            raise ServiceValidationError('Trying to override topic without allow_topic_override being True')

        if self.topic is None and 'topic' not in data:
            raise ServiceValidationError("No topic specified")

        if "attach_url" in data and "attach_file" in data:
            raise ServiceValidationError("attach_url and attach_file cannot be specified at the same time")

        if "attachment_filename" in data and not ("attach_url" in data or "attach_file" in data):
            raise ServiceValidationError("attachment_filename cannot be specified without an attachment")

        if "attach_file" not in data and ('attachment_compress_image' in data or 'attachment_compress_file' in data or 'attachment_resize_image' in data):
            raise ServiceValidationError("attachment_compress_image, attachment_compress_file, attachment_resize_image cannot be specified without attach_file")

        if "attach_file" in data and ('attachment_compress_image' in data or 'attachment_resize_image' in data):
            try:
                with Image.open(data['attach_file']) as img:
                    img.verify()
            except (IOError, SyntaxError) as e:
                raise ServiceValidationError("attach_file does not seem to be an image-file, unable to open with PIL") from e

        if 'actions' in data:
            for action in data.get("actions", []):
                if action.get('action', '') == 'view':
                    self._validate_message_params_action_view(action)
                elif action.get('action', '') == 'broadcast':
                    self._validate_message_params_action_broadcast(action)
                elif action.get('action', '') == 'http':
                    self._validate_message_params_action_http(action)
                else:
                    raise ServiceValidationError(f"unknown action type {action}")

        return True


    def _build_actions_header_view(self, action):
        tmp_header: str = ''
        tmp_header += f"view, {action['label']}"
        tmp_header +=f", {action.get('url')}"
        if action.get('clear', False):
            tmp_header += ', clear=true'
        return tmp_header


    def _build_actions_header_broadcast(self, action):
        tmp_header:str = ''
        tmp_header += f"broadcast, {action['label']}"

        if action.get('intent', None):
            tmp_header +=f", intent={action.get('intent')}"

        if action.get('extras', []):
            for key, value in action.get('extras').items():
                tmp_header += f", extras.{key}={value}"

        if action.get('clear', False):
            tmp_header += ', clear=true'

        return tmp_header


    def _build_actions_header_http(self, action):
        _LOGGER.debug("action: %s", action)
        tmp_header:str = ''
        tmp_header += f"http, {action['label']}, {action['url']}"

        if action.get('method', None):
            tmp_header +=f", method={action.get('method')}"
               
        if action.get('headers', []):
            for key, value in action.get('headers').items():
                tmp_header += f", headers.{key}={value}"
        
        if action.get('clear', False):
            tmp_header += ', clear=true'

        if action.get('body', None):
            body = action.get('body','').replace('"', '\"').replace("'", "\'")
            tmp_header += f", body={body}"

        _LOGGER.debug("Tmp header: %s", tmp_header)

        return tmp_header


    def _build_actions_header(self, data):
        header_x_actions: str = ""

        for action in data.get("actions", []):
            tmp_header: str = ''
            #TODO: Ensure escaped special characters
            if action.get('action', '') == 'view':
                tmp_header = self._build_actions_header_view(action)
            elif action.get('action', '') == 'broadcast':
                tmp_header = self._build_actions_header_broadcast(action)
            elif action.get('action', '') == 'http':
                tmp_header = self._build_actions_header_http(action)

            header_x_actions = f"{header_x_actions}; {tmp_header}" if header_x_actions else tmp_header

        return header_x_actions


    def _get_topic(self, data):
        topic = self.topic
        if "topic" in data:
            topic=data["topic"]

        return topic


    def _get_auth(self):
        auth_header=None
        if self.auth == 'user-pass':
            auth_header = 'Basic ' + b64encode( f"{self.username}:{self.password}".encode() ).decode()
        elif self.auth == 'token':
            auth_header = 'Bearer ' + self.token
        return auth_header


    def send_message(self, message="", **kwargs):
        """Send message"""
        title=kwargs.get(ATTR_TITLE,ATTR_TITLE_DEFAULT)
        data=kwargs.get(ATTR_DATA) or {}

        req_data=None
        req_headers={}

        # --
        self._validate_message_params(data)
        url = '/'.join([self.url, urllib.parse.quote(self._get_topic(data))])
        req_headers['Message'] = message.replace('\r\n', '\n').replace('\n', '\\n').encode('utf-8')

        # --
        if title is not None:
            req_headers["Title"] = title.encode('utf-8')

        if "tags" in data:
            req_headers["Tags"] = data["tags"]

        if "priority" in data:
            req_headers["Priority"] = data["priority"]

        if "click" in data:
            req_headers["Click"] = data["click"].encode('utf-8')

        if "attachment_filename" in data:
            req_headers["Filename"] = data["attachment_filename"].encode('utf-8')

        if "attach_url" in data:
            req_headers["Attach"] = data["attach_url"].encode('utf-8')

        if "attach_file" in data:
            self._validate_filesize(data)

            attach_file_name = os.path.basename(data['attach_file'])

            attach_file_content = None
            with open(data['attach_file'], mode='rb') as file:
                attach_file_content = BytesIO(file.read())

            if "attachment_resize_image" in data:
                attach_file_content = self._resize_image(data, attach_file_content)

            if "attachment_compress_image" in data:
                attach_file_content = self._compress_image(data, attach_file_content)

            elif "attachment_compress_file" in data:
                attach_file_content = self._compress_file(data, attach_file_content, attach_file_name)

            req_data = attach_file_content.getvalue()

        if "actions" in data:
            header_x_actions = self._build_actions_header(data)
            if header_x_actions:
                req_headers['X-Actions'] = header_x_actions

        # --
        req_headers['Authorization'] = self._get_auth()

        try:
            requests.put(
                url=url,
                data=req_data,
                headers=req_headers,
                verify=self.verifyssl,
                timeout=self.request_timeout
            )
        except Exception as e:
            raise HomeAssistantError from e
