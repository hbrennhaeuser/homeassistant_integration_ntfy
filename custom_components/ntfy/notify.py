"""Ntfy notification service."""
import logging
from base64 import b64encode
import os
import zipfile
from io import BytesIO
import re
import urllib.parse
import requests
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
    CONF_ATTACHMENT_MAXSIZE
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
            raise ServiceValidationError('url syntax invalid') from e

        # TODO: Set default values using constants
        self.verifyssl = True
        if config.get(CONF_VERIFY_SSL) is not None:
            self.verifyssl = bool(config.get(CONF_VERIFY_SSL))

        self.allow_topic_override = False
        if config.get(CONF_ALLOW_TOPIC_OVERRIDE) is not None:
            self.allow_topic_override = bool(config.get(CONF_ALLOW_TOPIC_OVERRIDE))

        self.attachment_maxsize = 15728640
        if config.get(CONF_ATTACHMENT_MAXSIZE) is not None:
            # TODO: Syntax validation
            self.attachment_maxsize = self._parse_attachment_maxsize(config.get(CONF_ATTACHMENT_MAXSIZE))


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
                    raise ServiceValidationError("Authentication username is missing")
                if config.get(CONF_PASSWORD) is None:
                    raise ServiceValidationError("Authentication password is missing")
                self.username = config.get(CONF_USERNAME)
                self.password = config.get(CONF_PASSWORD)
            elif self.auth == 'token':
                if config.get(CONF_TOKEN) is None:
                    raise ServiceValidationError('Authentication token is missing')
                self.token = config.get(CONF_TOKEN)

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


    def _validate_filesize(self, data):
        attach_file_size = os.stat(data['attach_file']).st_size
        if self.attachment_maxsize is not None and attach_file_size > self.attachment_maxsize:
            raise HomeAssistantError(f"Specified file '{data['attach_file']}', {attach_file_size}B is larger than specified max size {self.attachment_maxsize}B")
        return True

    def _validate_message_params(self, data):
        if "topic" in data and not self.allow_topic_override:
            raise ServiceValidationError('Trying to override topic without allow_topic_override being True')

        if self.topic is None and 'topic' not in data:
            raise ServiceValidationError("No topic specified")

        # TODO: validate tag format

        schema_priority = ['max','urgent','high','default','low','min']
        if "priority" in data and str(data["priority"]) not in schema_priority:
                raise ServiceValidationError('Incorrect value for attribute priority given')

        if 'click' in data:
            schema_url = vol.Schema(vol.Url())
            try:
                schema_url(data["click"])
            except vol.MultipleInvalid as e:
                raise ServiceValidationError('expected a URL for attribute click') from e

        if "attach_url" in data and "attach_file" in data:
            raise ServiceValidationError("attach_url and attach_file cannot be specified at the same time")

        if 'attach_file' in data and not os.access(data['attach_file'], os.R_OK):
            raise HomeAssistantError(f"Specified file '{data['attach_file']}' is not readable")

        if "attachment_filename" in data and not ("attach_url" in data or "attach_file" in data):
            raise ServiceValidationError("attachment_filename cannot be specified without an attachment")

        if "attach_file" not in data and ( 'attachment_compress_image' in data or 'attachment_compress_file' in data or 'attachment_resize_image' in data):
            raise ServiceValidationError("attachment_compress_image, attachment_compress_file, attachment_resize_image cannot be specified without attach_file")

        if 'attachment_compress_image' in data and not isinstance(data['attachment_compress_image'], int):
            raise ServiceValidationError("attachment_compress_image is not an integer")

        if 'attachment_compress_image' in data and (data['attachment_compress_image'] < 0 or data['attachment_compress_image'] > 100):
            raise ServiceValidationError("attachment_compress_image < 0 or > 100")

        if 'attachment_compress_file' in data and not isinstance(data['attachment_compress_file'],int):
            raise ServiceValidationError("attachment_compress_file is not an integer")

        if 'attachment_compress_file' in data and (data['attachment_compress_file'] < 0 or data['attachment_compress_file'] > 9):
            raise ServiceValidationError("attachment_compress_file < 0 or > 9")

        if 'attachment_resize_image' in data and not re.match(r'^[0-9]+(px|%)$', data['attachment_resize_image']):
            raise ServiceValidationError("attachment_compress_image format is not valid")

        # TODO: Catch attachment_compress_image and attachment_resize_image being used with non-image files

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
        tmp_header:str = ''
        tmp_header += f"http, {action['label']}, {action['url']}"

        if action.get('method', None):
            tmp_header +=f", method={action.get('method')}"

        if action.get('headers', []):
            for key, value in action.get('extras').items():
                tmp_header += f", headers.{key}={value}"

        if action.get('clear', False):
            tmp_header += ', clear=true'

        if action.get('body', None):
            body = action.get('body','').replace('"', '\\"').replace("'", "\\'").replace('=', '\\=')
            tmp_header += f", body={body}"

        return tmp_header


    def _build_actions_header(self, data):
        header_x_actions: str = ""

        for action in data.get("actions", []):
            tmp_header: str = ''
            #TODO: Schema validation
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
        url=str(self.url) + '/' + urllib.parse.quote(self._get_topic(data))
        req_headers['Message'] = message.encode('utf-8')



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
            # TODO: syntax validation
            req_headers["Filename"] = data["attachment_filename"].encode('utf-8')

        if "attach_url" in data:
            # TODO: syntax validation
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

        requests.put(
            url=url,
            data=req_data,
            headers=req_headers,
            verify=self.verifyssl,
            timeout=self.request_timeout
        )
