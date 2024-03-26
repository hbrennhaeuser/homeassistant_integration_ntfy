# Notify via ntfy.sh / selfhosted ntfy-server
[![hacs_badge](https://img.shields.io/badge/HACS-Custom-41BDF5.svg)](https://github.com/hacs/integration)

This custom component allows you to send notifications through [ntfy.sh](https://ntfy.sh/) or selfhosted ntfy-servers.
Authentication and additional ntfy-features like tags are supported.

## Installation

The recommended way to install this integration is through HACS.
### HACS

Add this repository as a custom repository in hacs (category: integration).
When the custom repository is added you can search for and install this integration.

Make sure to restart Homeassistant after the installation.

### Manual

Copy custom_components/ntfy to config/custom_components/ntfy.

Make sure to restart Homeassistant after the installation.

## Configuration

Define a new ntfy notification-service in configuration.yaml:

Example:

```yaml
notify:
    - name: ntfy_notification
      platform: ntfy
      authentication: 'token'
      #username: 'user' 
      #password: 'password' 
      token: 'tk_odlbse211n74kf8N7h4qhqvj409qb'
      topic: 'mytopic'
      url: 'https://ntfy.domain.tld' 
      #verify_ssl: True 
      allow_topic_override: True 
```

Options:

| Option | Required | Default value | Values | Description |
| --- | --- | --- | --- | --- |
|authentication|No|False|user-pass/token/False|Specify authentication-type to use. Set to False to connect to the server anonymously.|
|username|If authentication is 'user-pass'||username|ntfy username|
|password|If authentication is 'user-pass'||password|ntfy password|
|token|If authentication is 'token'||token|ntfy authentication token|
|topic|No||topic|Topic to publish to. It's recommended to set the topic here, but you can also set it in each notification-call if allow_topic_override is True.|
|url|Yes||url|ntfy-instance-url, example: https://ntfy.domain.tld|
|verify_ssl|No|True|True/False|Specifies if the certificate of the ntfy-server should be verified. Set to False for self-signed certificates.|
|allow_topic_override|No|False|True/False|Allow topic-override in each notification-call.|

## Usage

Call the notification service anywhere in Homeassistant:

Minimal call:

```yaml
service: notify.ntfy_notification
data:
  message: Terrace door is open
```

Optional parameters/Additional data:

```yaml
service: notify.ntfy_notification
data:
  title: Homeassistant Notification
  message: Terrace door is open
  data:
    tags: door
    priority: high
    click: https://myhomassistant.domain.tld
    topic: myothertopic
```

Currently the ntfy-features tags, priority and click are supported. Please refer to the [ntfy documentation](https://docs.ntfy.sh/publish) for more information about those features.

You can override the default topic by providing a topic in the notification data.
