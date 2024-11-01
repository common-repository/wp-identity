=== UFP Identity ===
Contributors: richardl@ufp.com
Tags: security, login, spam, filtering, identity, authentication
Requires at least: 3.5
Tested up to: 4.0
Stable tag: 2.2.3
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html

The UFP Identity plugin integrates Wordpress login and user management seamlessly with the UFP Identity platform.

== Description ==
UFP Identity is the only dynamic security platform created for e-commerce sites, design agencies and developers that simplifies login authentication. 

If there is a token, we support it. UFP Identity supports a wide variety of secure tokens enabling faster, more streamlined access to your websites all the while protecting user accounts from being compromised and preventing spam enrollments to your website.

= Our challenge =
UFP Identity set out to solve a huge technical challenge: To protect (I mean really, really make private!) online user’s personal info, make the process to access any number of websites at once really easy, and stop bad guys from hacking your stuff.

Our technology platform includes:

*   Strongest level of password authentication and encryption!
*   Spam protection preventing unwanted user account creation
*   Account-compromise protection
*   Threat level adjustment to heighten login protection for your users
*   Seamless token integration (password, Yubico, OTP, various OATH tokens, one-time codes to phone/email/irc)
*   Quicker logins for your users. By the way we’re building a mobile app for that.
*   Universal password support for websites that use UFP Identity. This means login credentials can work on multiple websites.
*   Real-time monitoring of every login ensures your users are your users
*   Reporting tool for website administrators details every login transaction and outcome (coming soon!)
*   Multiple tokens to single account
*   Multiple accounts to single account

= Certificate Signing Request =
The Certificate Signing Request requires a private/public key
pair and the private key is encrypted with a secret key. In order to
create a good secret key the plugin attempts to get good random data
from /dev/urandom. If this fails, the plugin makes an attempt to
securely retrieve random data from https://www.random.org

= Enrolling users =
Activating this plugin by installing the certificate will upload
information about your users to our servers. We only enroll the
username, email and hashed password over a private SSL connection
using 2048 bit keys. We will never use any information about your
users for any purpose other than authentication and verification. We
will never use the email for any purpose other than resetting
credentials or authentication. We will never sell or give up any of
the information about your users.

= Telemetry =
We send telemetry data to our servers over an SSL connection with 2048 bit keys. This telemetry data only contains data that we 
would otherwise get with a successful install of the UFP Identity plugin. The telemetry can be turned off by adding an option
‘identity_telemetry_enabled’ => ‘no’.

= Location Information =
We make a call to http://freegeoip.net/json/ to get location information for the Certificate Signing Request. This
is to help pre-populate the required fields and minimize the amount of work you need to do. We only do this once, upon install.

== Installation ==

The Wordpress UFP Identity plugin requires OpenSSL.

1. Just activating the plugin will not protect your site with UFP Identity. If you need help please email us at info@ufp.com
1. As admin, navigate to Plugins/Add New, Search Plugins for 'UFP Identity'
1. Click the 'Install Now' link in the search results for 'UFP Identity' and confirm the installation
1. After a successful installation, click 'Activate Plugin'
1. Navigate to Settings/Identity
1. Create a Certificate Signing Request following the instructions, if successful the CSR will be mailed to info@ufp.com
1. Upon receiving a certificate, navigate to Settings/Identity and install the certificate. This will cause existing users to be enrolled with UFP Identity
1. After enrolling existing users, the plugin will be fully initialized and handling logins for your site.

== Changelog ==

= 1.0 =
* Initial version

= 1.0.1 =
* changed readme to reflect install from wordpress.org
* identity enabled for new users, even while enrolling and editing is disabled
* disable delete user if editing disabled. n.b. no way to indicate why delete was stopped
* more detailed status on Settings/Identity
* if openssl_random_pseudo_bytes doesn't exist, try uniqid
* telemetry on activate, deactivate, uninstall

= 1.0.2 =
* fix check status and call it if editing disabled and nothing scheduled
* Pulled out loading up library so that it can be used in places that don't require the provider loaded.

= 2.0.0 =
* handle reset properly
* static method call generates E_STRICT warning
* check to make sure certificate file uploaded is really a certificate file
* additional text changes
* removed un-necessary label
* migrate to strong, cohesive naming strategy
* fix missing locality description; add in Company/Organization header
* removing old drupal links; expecting wordpress links
* remove need for output_buffering
* remove cURL dependencies

= 2.0.1 =
* handle both cases users_can_register = TRUE/FALSE

= 2.1.0 =
* simplify enrollment check timing
* update instructios for CSR creation
* remove documented requirement for cURL
* describe location functionality
* formatting and some additional explanatory text
* prefill as much as we can for CSR
* nothing to remove with interim_login
* admin notice that identity is not installed

= 2.1.1 =
* clean up unused certificate files
* copy key to certificate file if dealing with PHP_VERSION < 5.3.3
* must specify mode to fopen

= 2.1.2 =
* if we don't handle the login page return an empty error
* only prevent updates/edits when editing is disabled
* indicate status more simply and clearly
* really simplify checking enroll status
* tested with 4.0

= 2.2.2 =
* woocommerce integration
* consistent usage of true vs. TRUE
* reduction in irrelevant error_log'ing
* don't override color in username input
* handle profile update with errors and potential blank user
* handle whether token is resettable (forgot password)

= 2.2.3 =
* https://github.com/woothemes/woocommerce/issues/6667
* override pluggable wp_check_password
