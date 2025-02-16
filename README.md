# Secure Auto Login

A WordPress plugin that automatically logs in specific users based on their IP address whenever they visit any page.

## Features

- Automatic login based on IP address
- AJAX-powered instant login
- Multiple IP support per user (up to 3 IPs)
- Email verification for shared IPs
- Cookie-based user preference for shared IPs
- Admin interface for IP management

## Installation

1. Download the plugin files
2. Upload to your `/wp-content/plugins/` directory
3. Activate the plugin through the 'Plugins' menu in WordPress
4. Configure IP addresses in user profiles

## Usage

1. Go to your user profile in WordPress admin
2. Add up to 3 IP addresses that should automatically log in as you
3. Visit any page on your site from those IPs to be automatically logged in

## Security

This plugin includes several security measures:
- IP validation
- Nonce protection
- Email verification for shared IPs
- Cookie-based preferences
- Sanitization of all inputs

## Requirements

- WordPress 5.0 or higher
- PHP 7.0 or higher

## License

This project is licensed under the GPL v2 or later

## Author

Jonathan Albiar & ChatGPT 