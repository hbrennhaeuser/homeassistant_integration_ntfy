# Notify via ntfy.sh / selfhosted ntfy-server
[![hacs_badge](https://img.shields.io/badge/HACS-Custom-41BDF5.svg)](https://github.com/hacs/integration) ![hacs_validation](https://github.com/hbrennhaeuser/homeassistant_integration_ntfy/actions/workflows/hacs_validation.yml/badge.svg?branch=main) ![validate_with_hassfest](https://github.com/hbrennhaeuser/homeassistant_integration_ntfy/actions/workflows/validate_with_hassfest.yml/badge.svg?branch=main)


This custom component allows you to send notifications through [ntfy.sh](https://ntfy.sh/) or selfhosted ntfy-servers.
Authentication and some additional ntfy-features like tags are supported.

## Installation

The recommended way to install this integration is through HACS.
### HACS

Add this repository as a custom repository in hacs (category: integration).
When the custom repository is added you can search for and install this integration like any other hacs-integration.

Make sure to restart Homeassistant after the installation.

### Manual

Copy custom_components/ntfy to config/custom_components/ntfy.

Make sure to restart Homeassistant after the installation.



## Configuration

Define a new ntfy notification-service in configuration.yaml:

```yaml
notify:
    - name: ntfy_test
      platform: ntfy
      username: 'user'
      password: 'password'
      topic: 'test'
      url: 'https://ntfy.domain.tld'
      authentication: True
      verify_ssl: True
```

Set `authentication` to False to connect to the server anonymously.

## Usage

Call the notification service anywhere in Homeassistant:

```yaml
service: notify.ntfy_test
data:
  title: Homeassistant Notification
  message: Terrace door is open
```

Optionally define additional data:

```yaml
service: notify.ntfy_test
data:
  title: Homeassistant Notification
  message: Terrace door is open
  data:
    tags: door
    priority: high
```

Currently tags, priority and click are supported.