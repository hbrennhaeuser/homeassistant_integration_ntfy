"""Ntfy notification service."""

from tokenize import String
from homeassistant.components.notify import (
    ATTR_MESSAGE,
    ATTR_TITLE,
    ATTR_TITLE_DEFAULT,
    ATTR_DATA,
    PLATFORM_SCHEMA,
    BaseNotificationService,
)

import homeassistant.helpers.config_validation as cv

from requests.auth import HTTPBasicAuth
import requests
import logging
import voluptuous as vol

CONF_TOPIC="topic"

from homeassistant.const import (
    CONF_PASSWORD,
    CONF_USERNAME,
    CONF_VERIFY_SSL,
    CONF_URL,
    CONF_AUTHENTICATION,
)


_LOGGER = logging.getLogger(__name__)


def get_service(hass,config,discovery_info=None):
    return NtfyNotificationService(config)



class NtfyNotificationService(BaseNotificationService):
    def __init__ (self, config):
        """Initialize the Ntfy notification service."""
        self.user = config.get(CONF_USERNAME)
        _LOGGER.debug("Got User: ",self.user)
        self.password = config.get(CONF_PASSWORD)
        _LOGGER.debug("Got Password: XXXXXXXXXX")

        self.topic = config.get(CONF_TOPIC)
        _LOGGER.debug("Got User: ",self.user)

        self.url = config.get(CONF_URL)
        _LOGGER.debug("Got URL: ",self.url)
        
        self.auth = config.get(CONF_AUTHENTICATION)
        _LOGGER.debug("Got Authentication: ",self.auth)
        
        self.verifyssl = config.get(CONF_VERIFY_SSL)
        _LOGGER.debug("Got Verify_SSL: ",self.verifyssl)



    def send_message(self, message="", **kwargs):
        
        title=kwargs.get(ATTR_TITLE,ATTR_TITLE_DEFAULT)
        data=kwargs.get(ATTR_DATA,[])

        
        req_data=message.encode('utf-8')
        req_headers={
            "Title": title.encode('utf-8')
        }
        
        if data is not None:
            if "tags" in data:
                req_headers["Tags"] = data["tags"]

            if "priority" in data:
                schema_click = ['max','urgent','high','default','low','min']
                if str(data["priority"]) not in schema_click:
                    raise SyntaxError('Incorrect value for attribute priority given')
                req_headers["Priority"] = data["priority"]
    
            if "click" in data:
                schema_url = vol.Schema(vol.Url())
                try:
                    schema_url(data["click"])
                except vol.MultipleInvalid as e:
                    raise SyntaxError('expected a URL for attribute click')
                req_headers["Click"] = data["click"]
        
        
        req_verify=True
        if self.verifyssl == False:
            req_verify=False

        if self.auth == True :
            requests.post(str(self.url)+'/'+str(self.topic),data=req_data,headers=req_headers,verify=req_verify,auth=HTTPBasicAuth(self.user,self.password))
        else:
            requests.post(str(self.url)+'/'+str(self.topic),data=req_data,headers=req_headers,verify=req_verify)
