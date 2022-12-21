# Notify via ntfy.sh

This custom component allows you to send notifications through [ntfy.sh](https://ntfy.sh/).
This component supports authentication and some additional ntfy-features like tags.

## Installation

Copy custom_components/ntfy to config/custom_components/ntfy.

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

Call the notification service anywhere in homeassistant:

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