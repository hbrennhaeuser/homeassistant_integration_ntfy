# Notify via ntfy.sh / selfhosted ntfy-server
[![hacs_badge](https://img.shields.io/badge/HACS-Custom-41BDF5.svg)](https://github.com/hacs/integration) ![hacs_validation](https://github.com/hbrennhaeuser/homeassistant_integration_ntfy/actions/workflows/hacs_validation.yml/badge.svg?branch=main) ![validate_with_hassfest](https://github.com/hbrennhaeuser/homeassistant_integration_ntfy/actions/workflows/validate_with_hassfest.yml/badge.svg?branch=main)

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
      #attachment_maxsize: 300K
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
|attachment_maxsize|No|15M|filesize, allowed Units B/K/M, default=B, factor=1024 |Set max size for file-attachments. This should match or be below the settings of the ntfy-server. Currently the file-size is checked before any compression is applied. Keep in mind the file is loaded into memory before sending when setting this value.|

## Usage

Call the notification service anywhere in Homeassistant:

Minimal call:

```yaml
service: notify.ntfy_notification
data:
  message: Terrace door is open
```

| Option | Required | Default value | Values | Description |
| --- | --- | --- | --- | --- |
|title|No|||Notification title|
|message|Yes|||Notification message|
|data/tags|No|||Message tags|
|data/priority|No|||Message priority|
|data/click|No||url|URL to open when the notification is clicked|
|data/topic|No||topic|Override the default topic if allow_topic_override is True|
|data/attach_url|No||url|URL to file/image|
|data/attach_file|No||file-path|Path to local file|
|data/attachment_filename|No||filename|Filename. If compression is active, this applies to the final compressed file.|
|data/attachment_compress_image|No||int<0-100>|[Only applies to attach_file] Convert image to JPEG. Value is the JPEG-quality|
|data/attachment_compress_file|No||int<0-9>|[Only applies to attach_file] Compress file to zip using zlib. Value is the zlib-compression-level|
|data/attachment_resize_image|No||int%/intpx|[Only applies to attach_file] Resize image (and convert to jpeg). Value is either in percent (25%) or px (800px). When using px, you specify the new image width, the height is calculated using the original aspect-ratio.|


Please refer to the [ntfy documentation](https://docs.ntfy.sh/publish) for more information about those features.

## Usage examples

Set a title, tags, message-priority, add a click-action and override the default topic:

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

Attach a local file (image), compress it and override the filename:

```yaml
service: notify.ntfy_notification
data:
  title: Homeassistant Notification
  message: Movement in backyard detected
  data:
    attach_file: /media/local/cam0_latest_detection.png
    attachment_compress_image: 25
    attachment_filename: detection.jpg
```
