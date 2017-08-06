# Piwik OneLogin Plugin

## Description

This plugin extends Piwik to support [OneLogin Federated authentication](https://apps.onelogin.com/apps/new/2594)

## Setup

1. Create an app for Piwik in your account here: https://apps.onelogin.com/apps/new/2594
2. Change the name, add it, then on the Configuration tab of the next page:

| Name | Example Value |
|---|---|
| Destination URL | `https://piwik.yourinstall.com/?module=OneLogin&action=callback&` |
| Security Token  | create a random salt/secret |

3. Add your company subdomain and app ID to [config.ini.php](example.ini).

## License

Apache 2
