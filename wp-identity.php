<?php
/*
Plugin Name: Identity Plugin
Plugin URI: https://www.ufp.com
Description: UFP Identity authentication for Wordpress
Author: Richard Levenberg
Version: 2.2.3
Compatibility: WordPress 3.5
Text Domain: identity
Domain Path: /lang
*/
define( 'IDENTITY_DIRECTORY', WP_CONTENT_DIR . '/files/identity' );

function identity_activate() {
  if (!is_dir(IDENTITY_DIRECTORY)) {
    $success = @mkdir(IDENTITY_DIRECTORY, 0700, true);
    error_log('created directory: ' . $success);
  }
  send_telemetry('Plugin Activation', 'plugin was activated from '.get_option('blogname').' at '.get_option('siteurl'));
}
register_activation_hook(__FILE__, 'identity_activate');

function identity_deactivate() {
  send_telemetry('Plugin De-Activation', 'plugin was deactivated from '.get_option('blogname').' at '.get_option('siteurl'));
}
register_deactivation_hook(__FILE__, 'identity_deactivate');

function identity_uninstall() {
  send_telemetry('Plugin Un-Install', 'plugin was uninstalled from '.get_option('blogname').' at '.get_option('siteurl'));
}
register_uninstall_hook(__FILE__, 'identity_uninstall');

include_once( ABSPATH . 'wp-admin/includes/plugin.php' );
if (is_plugin_active( 'woocommerce/woocommerce.php' )) {
  require_once( 'identity-woocommerce.php' );
}

function identity_admin_notices() {
  if ( !get_option('identity_login_enabled', FALSE ) ) {
    if ( current_user_can( 'manage_options' )  && current_user_can( 'install_plugins' ) ) {
      if ( empty( $_SERVER['QUERY_STRING'] ) || ( $_SERVER['QUERY_STRING'] != 'page=wp-identity.php' ) ) {
        $message = 'UFP Identity not enabled! <a href="' . admin_url( 'options-general.php?page=wp-identity.php' ) . '">Click here to complete the install</a>';
        ?>
          <div class="error">
            <p><?php _e(  $message, 'wp-identity' ); ?></p>
          </div>
        <?php
      }
    }
  }
}
add_action( 'admin_notices', 'identity_admin_notices' );

function identity_handle_admin_post() {
  if (($_SERVER['REQUEST_METHOD'] == 'POST') && current_user_can('activate_plugins') ) {
    if ((isset($_POST['crt']) || isset($_POST['x500'])) && check_admin_referer('identity_config_action')) {
      if (isset($_POST['crt'])) {
        global $wpdb;

        if (isset($_FILES['file']) && ($_FILES['file']['size'] > 0)) {
          $uploadedfile = $_FILES['file'];
          error_log(print_r( $uploadedfile, true));
          if (current_user_can( 'upload_files' ) ) {
            if (get_certificate_expires($uploadedfile['tmp_name'])) {
              $randomized_filename = generate_random_file(30, $uploadedfile['name']);
              $new_file =  IDENTITY_DIRECTORY . '/' . $randomized_filename;
              if ( false === @rename( $uploadedfile['tmp_name'], $new_file ) ) {
                error_log('error renaming ' . $uploadedfile['tmp_name'] . ' to ' . $new_file);
              } else {
                error_log("File is valid, and was successfully uploaded.");
                if (version_compare(phpversion(), '5.3.3', '<')) {
                  error_log('Really old version of PHP (' . phpversion() . '), copying key to certificate file');
                  $fp_cert_file = @fopen($new_file, "a+");
                  if ($fp_cert_file) {
                    $key_file = file_get_contents(IDENTITY_DIRECTORY . '/' . get_option('identity_key_file'));
                    if ($key_file) {
                      $bytes = @fwrite($fp_cert_file, $key_file);
                    }
                    @fclose($fp_cert_file);
                  }
                }

                if (!get_option('identity_cert_file', FALSE))
                  add_option('identity_cert_file', $randomized_filename, '', 'no');
                else
                  update_option('identity_cert_file', $randomized_filename);

                // clean up any unused certificates
                foreach (glob(IDENTITY_DIRECTORY . '/*.crt.pem') as $certificate_file) {
                  if ($certificate_file !== $new_file)
                    @unlink($certificate_file);
                }

                if (!get_option('identity_login_enabled', FALSE) && !get_option('identity_editing_disabled', FALSE)) {
                  $success = identity_import_users();
                  if ($success) {
                    add_option('identity_login_enabled', true, '', 'no');
                    $offset = 300;
                    error_log('scheduling single event with offset' . $offset);
                    wp_schedule_single_event(time() + $offset, 'identity_check_status_event');
                    add_settings_error('identity_status', 'wp-identity', 'Congratulations, almost there. Existing users are currently being imported into the Identity system. Please avoid editing any users until the import is complete. See <a href="https://www.ufp.com/identity/wordpress/#enroll">here</a> for more information.', 'updated');
                  } else {
                    add_settings_error('identity_error', 'wp-identity', 'An error occurred. Please see our <a href="https://www.ufp.com/identity/wordpress/#troubleshooting">troubleshooting tips</a>', 'error');
                  }
                }
              }
            } else
              add_settings_error('identity_error', 'wp-identity', 'Invalid certificate file - ' . $uploadedfile['name']);
          } else
            error_log("current user doesn't have rights to upload files");
        }
      } elseif (isset($_POST['x500'])) {
        $email = NULL;

        $dn = array();
        foreach ($_POST['x500'] as $k => $v) {
          $pos = strpos($k, 'identity_');
          if ($pos !== FALSE) {
            $name = substr($k, strlen('identity_'));
            if (!empty($v)) {
              $dn[$name] = $v;
            }
            if ($name == 'emailAddress') {
              $email = $v;
            }
          }
        }
        $err = FALSE;
        $mail_err = FALSE;
        // Now copy the module's .htaccess into the new directory.
        $directory = plugin_dir_path( __FILE__ );
        $access_file =  $directory . 'identity4php/.htaccess';
        $success = copy($access_file, IDENTITY_DIRECTORY . '/.htaccess');
        if ($success) {
          // Generate a new private (and public) key pair.
          $config = array(
                          'private_key_bits' => 2048,
                          'private_key_type' => OPENSSL_KEYTYPE_RSA,
                          'encrypt_key' => true,
                          'encrypt_key_cipher' => OPENSSL_CIPHER_3DES,
                          'digest_alg' => 'sha1',
                          );
          $privkey = openssl_pkey_new($config);

          // Generate a certificate signing request.
          $csr = openssl_csr_new($dn, $privkey);

          // Encrypt and export the key material.
          $encrypt_key = get_key();
          if (!$encrypt_key) {
            $err = 'Unable to get a secret key. ';
          }
          error_log('exporting private key with config set to : ' . print_r($config, true));
          $randomized_filename = generate_random_file(30, 'identity.key.pem');
          $success = openssl_pkey_export_to_file($privkey, IDENTITY_DIRECTORY . '/'. $randomized_filename, ($encrypt_key) ? base64_decode($encrypt_key) : NULL, $config);
          if ($success) {
            openssl_free_key($privkey);
            add_option('identity_key_password', $encrypt_key, '', 'no');
            add_option('identity_key_file', $randomized_filename, '', 'no');
            // Save off csr.
            $randomized_filename = generate_random_file(30, 'identity.csr.pem');
            $success = openssl_csr_export_to_file($csr, IDENTITY_DIRECTORY . '/'. $randomized_filename);
            if ($success) {
              // Attempt to mail out the csr.
              $success = openssl_csr_export($csr, $csrout);
              if ($success) {
                if (!empty($email)) {
                  $from = get_option('admin_email');
                  $headers = 'From: ' . $from . "\r\n" .
                    'X-Mailer: PHP/' . phpversion();
                  $sent = mail('info@ufp.com', 'Certificate Request for ' . $dn['commonName'], $csrout, $headers);

                  if (!$sent) {
                    $mail_err = true;
                    $err .= 'Failed to mail certificate request.';
                  }
                }
                else {
                  $err .= 'No email provided.';
                }
              }
              else {
                $err .= 'Failed to export certificate request to string.';
              }
            }
            else {
              $err .= 'Failed to export certificate request to file.';
            }
          }
          else {
            $err .= 'Failed to export private key to file.';
          }
        }
        else {
          $err .= 'Failed to copy ' . $access_file . ' to ' . $directory . '.';
        }

        if ($err) {
          error_log($err);
          $err_handle = fopen($directory . 'identity.err', 'a+');
          if ($err_handle) {
            fwrite($err_handle, $err . PHP_EOL);
            fclose($err_handle);
          }
        }

        if ($mail_err) {
          $err_handle = fopen($directory . 'identity.mail.err', 'a+');
          if ($err_handle) {
            fclose($err_handle);
          }
        }

        if ($success) {
          add_settings_error( 'identity_status', 'wp-identity', 'Your site is not yet secured by the UFP Identity module. You should receive an email reply within 24 hours with an attached certificate that is ready for use.', 'updated');
        } else {
          add_settings_error( 'identity_status', 'wp-identity', $err . ' Please see our <a href="https://www.ufp.com/identity/wordpress/#troubleshooting">troubleshooting tips</a>', 'error');
        }
      }
    }
  }
}
add_action( 'admin_init', 'identity_handle_admin_post');

add_action('init', 'identity_start_session', 1);
add_action('wp_logout', 'identity_end_session');
add_action('wp_login', 'identity_end_session');
function identity_start_session() {
  if (!session_id()) {
    session_start();
  }
}

function identity_end_session() {
  session_destroy ();
}

function identity_includes() {
  $plugin_dir_path = plugin_dir_path( __FILE__ );

  foreach ( glob( $plugin_dir_path."identity4php/*.php" ) as $file )
    include_once $file;
  return $plugin_dir_path;
}

function identity_service_provider() {
  $plugin_dir_path = identity_includes();
  $provider = new IdentityServiceProvider();

  $provider->getConnectionHandler()->setCAInfo($plugin_dir_path . get_option('identity_ca_file', 'identity4php/truststore.pem'));
  $provider->getConnectionHandler()->setSSLCert(IDENTITY_DIRECTORY . '/' . get_option('identity_cert_file', NULL));
  $provider->getConnectionHandler()->setSSLKey(IDENTITY_DIRECTORY . '/' . get_option('identity_key_file', 'identity.key.pem'));

  $encrypt_key = get_option('identity_key_password', FALSE);
  $provider->getConnectionHandler()->setSSLKeyPassword(($encrypt_key)?base64_decode($encrypt_key) : NULL);
  return $provider;
}

function identity_login_form_login() {
  ob_start();
}
add_action( 'login_form_login', 'identity_login_form_login' );

function identity_disable_forgot_password() {
  $disable_forgot_password = true;
  if (!empty($_SESSION['IDENTITY_USERNAME']) && !empty($_SESSION['IDENTITY_DISPLAY_ITEMS'])) {
    identity_includes();
    $display_items = unserialize($_SESSION['IDENTITY_DISPLAY_ITEMS']);
    error_log('identity_login_footer (reset) ' . print_r($display_items[0]->getReset(), true));
    if ((count($display_items) == 1) && ($display_items[0]->getReset() == 'forgettable'))
      $disable_forgot_password = FALSE;
  }
  return $disable_forgot_password;
}

function identity_login_footer() {
  global $interim_login;
  $disable_forgot_password = identity_disable_forgot_password();

  if (!$interim_login && $disable_forgot_password) {
    $content = ob_get_contents();
    $nav_position = strrpos($content, 'nav', -1);
    $start_position = strpos($content, '<a', $nav_position);
    if (get_option('users_can_register', FALSE)) {
      $start_position = strpos($content, '|', $start_position);
    }
    $p_position = strpos($content, '</a>', $start_position);

    $output = substr($content, 0, $start_position);
    $output .= substr($content, $p_position+4);
    ob_end_clean();
    echo $output;
  }
}
add_action( 'login_footer', 'identity_login_footer' );

function identity_login_form() {
  identity_includes();
  $content = ob_get_contents();

  $p_position = strrpos($content, '<p>', -1);
  $delta = strlen($content) - $p_position + 1;
  $additional_content = FALSE;

  if (!empty($_SESSION['IDENTITY_USERNAME']) && !empty($_SESSION['IDENTITY_DISPLAY_ITEMS'])) {
    // we want to back up two <p> and show static username and display items
    $p_position = strrpos($content, '<p>', -$delta);
    $delta = strlen($content) - $p_position + 1;
    $name = $_SESSION['IDENTITY_USERNAME'];
    $additional_content = <<<EOT

<div class="wrap">
  <div id="user-text">$name</div>
</div>

EOT;
    $display_items = unserialize($_SESSION['IDENTITY_DISPLAY_ITEMS']);
    foreach ($display_items as $index => $display_item) {
      $id = 'AuthParam' . $index;
      $name = $display_item->getDisplayName();
      $nickname =  $display_item->getNickName();
      $input = add_size($display_item->getFormElement(), 20);

      $additional_content .= <<<EOT
<p>
  <abbr title="$nickname"><label for="$id">$name</label></abbr><br />
  $input
</p>

EOT;
    }
  }
  // else we want to just show the username input
  $our_content = substr($content, 0, strlen($content) - $delta);
  if ($additional_content)
    $our_content .= $additional_content;

  ob_end_clean();
  echo $our_content;
  ob_start();
}
add_action( 'login_form', 'identity_login_form' );

function process_context($context) {
  $errors = new WP_Error();
  if ($context['result']->getText() == 'CONTINUE') {
    $_SESSION['IDENTITY_DISPLAY_ITEMS'] = serialize($context['display_items']);
    $errors->add('continue_login', $context['result']->getMessage(), 'message');
  } elseif ($context['result']->getText() == 'RESET') {
    unset($_SESSION['IDENTITY_USERNAME']);
    unset($_SESSION['IDENTITY_DISPLAY_ITEMS']);
  } elseif ($context['result']->getText() == 'SUCCESS') {
    error_log('process_context, context: ' . print_r($context, true));
    $user = get_user_by('login', $context['name']);
    if ( !$user )
      $errors->add('invalid_username', sprintf(__('<strong>ERROR</strong>: Invalid username. <a href="%s" title="Password Lost and Found">Lost your password</a>?'), wp_lostpassword_url()));
    else {
      /*
       * We have to do this before unsetting session variables and UFP did succeed
       * so we remove the session variables and then let WP handle the rest.
       */
      if (identity_disable_forgot_password()) {
        $update = update_user_meta($user->ID, 'disable_forget_password', true);
        error_log('update_user_meta: ' . (int)$update);
      }
    }
    unset($_SESSION['IDENTITY_USERNAME']);
    unset($_SESSION['IDENTITY_DISPLAY_ITEMS']);

    if ( is_multisite() ) {
      // Is user marked as spam?
      if ( 1 == $user->spam)
        $errors->add('invalid_username', __('<strong>ERROR</strong>: Your account has been marked as a spammer.'));

      // Is a user's blog marked as spam?
      if ( !is_super_admin( $user->ID ) && isset($user->primary_blog) ) {
        $details = get_blog_details( $user->primary_blog );
        if ( is_object( $details ) && $details->spam == 1 )
          $errors->add('blog_suspended', __('Site Suspended.'));
      }
    }

    $user = apply_filters('wp_authenticate_user', $user, NULL);
    if ( is_wp_error($user) )
      return $user;

    $errors = $user;
  } else {
    error_log('process_context: error ' . $context['result']->getMessage());
    $error_string = sprintf( __( '<strong>ERROR</strong>: The credential you entered for the username <strong>%1$s</strong> is incorrect.'), $context['name']);
    if (!identity_disable_edit(unserialize($_SESSION['IDENTITY_DISPLAY_ITEMS'])))
      $error_string .= sprintf( __( ' <a href="%1$s" title="Password Lost and Found">Lost your password</a>?'), wp_lostpassword_url());
		$errors->add( 'incorrect_password', $error_string);
  }
  return $errors;
}

/**
 * Should we disable edits? User is not using a password.
 */
function identity_disable_edit($display_items) {
  $disable_edit = true;
  if (count($display_items) == 1) {
    error_log('identity_disable_edit looking at display item named: ' . $display_items[0]->getName());
    if ($display_items[0]->getName() == 'passphrase') {
      $disable_edit = FALSE;
    }
  }
  return $disable_edit;
}

function identity_preauthenticate($username) {
  $provider = identity_service_provider();
  $errors = new WP_Error();
  if (!get_option('identity_login_enabled', FALSE)) { // do a fake login
    if (username_exists($username)) {
      $_SESSION['IDENTITY_USERNAME'] = $username;
      $d = new DisplayItem('passphrase');
      $d->setDisplayName('Password');
      $d->setNickName('Password');
      $d->setFormElement('<input id="AuthParam0" type="password" name="passphrase" class="input"/>');
      $_SESSION['IDENTITY_DISPLAY_ITEMS'] = serialize(array($d));
    } else
      $errors->add('username_notfound',  __('<strong>ERROR</strong>: Invalid username or e-mail.'));
  } else {
    $pretext = $provider->preAuthenticate($username);
    if ($pretext['result']->getText() == 'SUCCESS') {
      $_SESSION['IDENTITY_USERNAME'] = $pretext['name'];
      $_SESSION['IDENTITY_DISPLAY_ITEMS'] = serialize($pretext['display_items']);
    } else {
      error_log('identity_preauthenticate: error ' . $pretext['result']->getMessage());
      $errors->add('invalid_username', sprintf(__('<strong>ERROR</strong>: Invalid username. <a href="%s" title="Password Lost and Found">Lost your password</a>?'), wp_lostpassword_url()));
    }
  }
  return $errors;
}

function identity_authenticate() {
  $provider = identity_service_provider();
  if (!get_option('identity_login_enabled', FALSE)) {
    $name = $_SESSION['IDENTITY_USERNAME'];
    unset($_SESSION['IDENTITY_USERNAME']);
    unset($_SESSION['IDENTITY_DISPLAY_ITEMS']);
    return wp_authenticate_username_password(NULL, $name, $_POST['passphrase']);
  } else {
    $params = array();

    $display_items = unserialize($_SESSION['IDENTITY_DISPLAY_ITEMS']);

    $packed = true;
    foreach ($display_items as $display_item) {
      $parameter_name = $display_item->getName();
      error_log('identity_authenticate: looking for ' . print_r($parameter_name, true));
      if (!empty($_POST[$parameter_name]))
        $params[$parameter_name] = $_POST[$parameter_name];
      else {
        error_log('identity_authenticate: ' . $parameter_name . ' not found');
        $packed = FALSE;
      }
    }
    if ($packed) {
      $context = $provider->authenticate($_SESSION['IDENTITY_USERNAME'], $params);
      return process_context($context);
    } else
      return new WP_Error('empty_password', __('<strong>ERROR</strong>: Empty password.'));
  }
}

add_action('password_reset', 'identity_password_reset', 1, 2);
function identity_password_reset($user, $new_pass) {
  $provider = identity_service_provider();
  $params = array('type' => 'update', 'passphrase' => $new_pass,);
  $context = $provider->reenroll($user->user_login, $params);
  if ($context['result']->getText() != 'SUCCESS') {
    error_log('error updating profile of '. $context['name'] . ' due to ' . $context['result']->getMessage());
  }
}

add_action('delete_user', 'identity_delete_user');
function identity_delete_user($id) {
  $user = new WP_User($id);
  if (get_option('identity_editing_disabled', FALSE)) {
    wp_redirect(admin_url('users.php'));
    exit;
  }

  if (get_option('identity_login_enabled', FALSE)) {
    $provider = identity_service_provider();
    $context = $provider->reenroll($user->user_login, array('type' => 'delete'));
    if ($context['result']->getText() != 'SUCCESS') {
      error_log('error deleting user ' . $context['name'] . ' due to ' . $context['result']->getMessage());
    }
  }
}

add_filter('show_password_fields', 'identity_show_password_fields', 20, 2);
function identity_show_password_fields($show, $profileuser = FALSE) {
  if ($profileuser) {
    $show = !get_user_meta($profileuser->ID, 'disable_forget_password', true);
  }
  return $show;
}

function identity_user_profile_update($errors, $update, $user) {
  if (get_option('identity_editing_disabled', FALSE) && $update) {
    $errors->add('userprofile', __('<strong>ERROR</strong>: Updating profile disabled, please try again later.'));
    return;
  }
  if (!get_option('identity_login_enabled', FALSE)) // if were not enabled, don't interfere
    return;

  if ($errors->get_error_messages()) // already errors, don't do anything
    return;

  if ($update) {
    $old_user = WP_User::get_data_by( 'id', $user->ID );
    $params = array();
    if ($user->user_email != $old_user->user_email) {
      $params['email'] = $old_user->user_email;
      $params['new-email'] = $user->user_email;
    }
    if (isset($user->user_login) && ($user->user_login != $old_user->user_login)) {
      $params['name'] = $old_user->user_login;
      $params['new-name'] = $user->user_login;
    }
    if (!empty($user->user_pass))
      $params['passphrase'] = $user->user_pass;

    if (!empty($params)) {
      $provider = identity_service_provider();
      $params['type'] = 'update';
      $context = $provider->reenroll($old_user->user_login, $params);
      if ($context['result']->getText() != 'SUCCESS') {
        error_log('error updating profile of '. $context['name'] . ' due to ' . $context['result']->getMessage());
        $errors->add('userprofile',  __('<strong>ERROR</strong>: Error updating profile.'));
      }
    } else
      error_log('nothing to update for ' . $old_user->user_login);
  } else {
    $provider = identity_service_provider();
    $context = $provider->enroll($user->user_login, array('type' => 'new', 'email' => $user->user_email, 'passphrase' => $user->user_pass));
    if ($context['result']->getText() != 'SUCCESS') {
      error_log('error adding profile of '. $context['name'] . ' due to ' . $context['result']->getMessage());
      $errors->add('userprofile',  __('<strong>ERROR</strong>: Error updating profile.'));
    }
  }
}
add_filter('user_profile_update_errors', 'identity_user_profile_update', 10, 3);

function identity_registration_errors($errors, $sanitized_user_login, $user_email) {
  error_log('identity_registration_errors : username ' . $sanitized_user_login . ', email ' . $user_email . ', ip ' . $_SERVER['REMOTE_ADDR']);
  if (get_option('identity_login_enabled', FALSE)) {
    $provider = identity_service_provider();
    $pretext = $provider->preEnroll($sanitized_user_login, array('type' => 'pre', 'email' => $user_email));
    if (($pretext['result']->getText() != 'SUCCESS') && ($pretext['result']->getCode() != 2)) {
      error_log('preenroll returned ' . $pretext['result']->getMessage() . ' (' . $pretext['result']->getText() . ') with a confidence of ' . $pretext['result']->getConfidence());
      $errors->add('registerfail', __('Unable to process registration'));
    }
  }
  return $errors;
}
add_filter('registration_errors', 'identity_registration_errors', 10, 3);

/*
 * Unfortunately we have to override this pluggable. This is the only
 * place we get the plain text password to enroll AND are assured the
 * user is succesfully created in WP.
 */
if ( !function_exists('wp_new_user_notification') ) {
function wp_new_user_notification($user_id, $plaintext_pass = '') {
	$user = get_userdata( $user_id );

	// The blogname option is escaped with esc_html on the way into the database in sanitize_option
	// we want to reverse this for the plain text arena of emails.
	$blogname = wp_specialchars_decode(get_option('blogname'), ENT_QUOTES);

	$message  = sprintf(__('New user registration on your site %s:'), $blogname) . "\r\n\r\n";
	$message .= sprintf(__('Username: %s'), $user->user_login) . "\r\n\r\n";
	$message .= sprintf(__('E-mail: %s'), $user->user_email) . "\r\n";

	@wp_mail(get_option('admin_email'), sprintf(__('[%s] New User Registration'), $blogname), $message);

	if ( empty($plaintext_pass) )
		return;

  if (get_option('identity_login_enabled', FALSE)) {
    $provider = identity_service_provider();
    $context = $provider->enroll($user->user_login, array('type' => 'new', 'passphrase' => $plaintext_pass, 'email' => $user->user_email));
    if ($context['result']->getText() != 'SUCCESS') {
      error_log('enroll returned ' . $context['result']->getMessage() . ' (' . $context['result']->getText() . ') with a confidence of ' . $context['result']->getConfidence());
    }
  }

	$message  = sprintf(__('Username: %s'), $user->user_login) . "\r\n";
	$message .= sprintf(__('Password: %s'), $plaintext_pass) . "\r\n";
	$message .= wp_login_url() . "\r\n";

	wp_mail($user->user_email, sprintf(__('[%s] Your username and password'), $blogname), $message);
}
} else
  error_log('wp_new_user_notification already defined');

remove_filter('authenticate', 'wp_authenticate_username_password', 20, 3);
add_filter('authenticate', 'identity_wp_authenticate_username_password', 0, 3);
function identity_wp_authenticate_username_password($user, $username, $password) {
  $priority = has_action('wp_login_failed', 'limit_login_failed');
  if ($priority) {
    $ra = remove_action('wp_login_failed', 'limit_login_failed', $priority);
    error_log('remove action, at priority ' . $priority . ' returns ' . print_r($ra, true));
  }
	if ( is_a($user, 'WP_User') ) { return $user; }

  if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    if (empty($_SESSION['IDENTITY_USERNAME']) && empty($_SESSION['IDENTITY_DISPLAY_ITEMS'])) {
      if ( empty($username) ) {
        return new WP_Error('empty_username', __('<strong>ERROR</strong>: The username field is empty.'));
      } else
        return identity_preauthenticate($username);
    } else {
      return identity_authenticate();
    }
  }
  return new WP_Error();
}

function identity_login_scripts() {
  wp_register_style( 'prefix-style', plugins_url('css/identity.css', __FILE__) );
  wp_enqueue_style( 'prefix-style' );
  //wp_register_script( 'prefix-script', plugins_url('js/identity.js', __FILE__) );
  wp_enqueue_script( 'prefix-script', plugins_url('js/identity.js', __FILE__), array(), '1.0', true );
}
add_action('login_enqueue_scripts','identity_login_scripts');

// admin menu items
add_action('admin_menu', 'register_security_custom_submenu_page');

function register_security_custom_submenu_page() {
	add_options_page( 'Identity', 'Identity', 'manage_options', 'wp-identity.php', 'identity_configuration_callback' );
}

function identity_configuration_callback() {
  $crt_pre = <<<'EOT'
    <p>Usually within 24 hours you will receive a valid certificate. If you have questions please email <a href="mailto:&#105;&#110;&#102;&#111;&#64;&#117;&#102;&#112;&#46;&#99;&#111;&#109;">&#105;&#110;&#102;&#111;&#64;&#117;&#102;&#112;&#46;&#99;&#111;&#109;</a>.</p>
EOT;
  $editing = FALSE;
  $enabled = FALSE;
  if (get_option('identity_editing_disabled', FALSE)) {
    $editing = '<p>Editing is currently disabled while users are being enrolled. Please do not delete or update any users. ';
    $next_scheduled = wp_next_scheduled('identity_check_status_event');
    if ($next_scheduled) {
      $offset = $next_scheduled-time();
      $ceiling = ceil($offset/60);
      $editing .= 'The next check for enrollment status will be in ' . $ceiling . ' minute' . (($ceiling > 1)?'s.':'.');
    } else {
      identity_check_status();
    }
    $editing .= '</p>'.PHP_EOL;
  }

  if (get_option('identity_login_enabled', FALSE)) {
    $enabled = '<p>Identity installed correctly, and enabled.</p>'.PHP_EOL;
  }

  $expires = get_certificate_expires();
  if ($expires)
    $crt_pre = <<<EOT
      <p>Current certificate will expire in $expires days. We will try to contact you 2 months prior to the certificate expiration to provide you with an updated certificate. If you have any questions, please email as at <a href="mailto:&#105;&#110;&#102;&#111;&#64;&#117;&#102;&#112;&#46;&#99;&#111;&#109;">&#105;&#110;&#102;&#111;&#64;&#117;&#102;&#112;&#46;&#99;&#111;&#109;</a>.</p>
EOT;

  if ($enabled)
    $crt_pre = $enabled . $crt_pre;
  if ($editing)
    $crt_pre = $editing . $crt_pre;

  $crt_page = <<<'EOT'
        <h3>Certificate Received</h3>
        <form id="crt" method="post" enctype="multipart/form-data">
          <table class="form-table">
          <tr valign="top">
            <th scope="row">Identity Certificate File</th>
            <td><input type="file" name="file" class="regular-text" title="Identity Certificate File" /></td>
          </tr>
          </table>
EOT;

  $csr_page = <<<'EOT'
        <p>You are almost done. In order to securely connect to the UFP Identity service,
        we will walk you through a couple more steps. First, you will need a Certificate
        and a private key. The form below will generate a Certificate Signing Request and your
        private key.  All you need to do is fill in some information about your site below.
        Where possible, we have pre-populated some fields for you.  Please check these over
        carefully to make sure the information is correct.  Please
        <a href="mailto:&#105;&#110;&#102;&#111;&#64;&#117;&#102;&#112;&#46;&#99;&#111;&#109;?subject=CSR Generation Question">contact us</a>
        if you have any questions.</p>

        <p>Make sure to read carefully and enter the values in
        carefully. If there are errors or inconsistencies we will ask
        you to redo the Certificate Signing Request. The elements you
        will need to provide are as follows:</p>

        <dl>
          <dt>Country Code</dt>
          <dd>This is a two-letter country code. You can find your own country code <a href="http://www.iso.org/iso/country_names_and_code_elements">here.</a></dd>
          <dt>State or Province Name</dt>
          <dd>This is the state or province name fully spelled out, so California rather than CA or any postal abbreviation.</dd>
          <dt>Locality</dt>
          <dd>This further identifies your location, city or other. Again this is fully spelled out so San Franciso rather than SF or any other abbreviation.</dd>
          <dt>Company/Organization</dt>
          <dd>This is your full company name as its registered. The exact abbreviations are required to match however your company is actually registered.</dd>
          <dt>Organizational Unit</dt>
          <dd>This is to further identify what department of your organization is going to be utilizing the UFP Identity service. This field is not required, but is useful for organizational purposes.</dd>
          <dt>Domain Name</dt>
          <dd>Put some thought into your domain name as this is how the UFP Identity service will identify you. You can put anything you like here but typical examples are your
              actual domain name e.g. example.com which would allow you to use the UFP Identity service for a host of machines. You can also tie it to specific machine
              e.g. www.example.com. Any unique identifier will work but if you have questions please don&#39;t hesitate to
              <a href="mailto:&#105;&#110;&#102;&#111;&#64;&#117;&#102;&#112;&#46;&#99;&#111;&#109;?subject=Domain Name Question">contact us</a> with any questions.</dd>
          <dt>Email</dt>
          <dd>This should be a valid email and should allow us to contact someone responsible.</dd>
        </dl>

        <h3>Certificate Request Generation Form</h3>
        <form id="x500" method="post">
          <table class="form-table">
          <tr valign="top">
            <th scope="row"><a href="http://www.iso.org/iso/country_names_and_code_elements">2 Letter Country Code</a> e.g. US</th>
            <td><input type="text" id="country" name="x500[identity_countryName]" class="regular-text" title="Please provide a country code" value="%s" /></td>
          </tr>
          <tr>
            <th scope="row">Full state or province name e.g. California</th>
            <td><input type="text" id="state" name="x500[identity_stateOrProvinceName]" class="regular-text" title="Please provide a state" value="%s" /></td>
          </tr>
          <tr>
            <th scope="row">Full locality name/city e.g. San Francisco</th>
            <td><input type="text" id="locality" name="x500[identity_localityName]" class="regular-text" title="Please provide a locality/city" value="%s" x/></td>
          </tr>
          <tr>
            <th scope="row">Company e.g. Internet Widgets Pty Ltd</th>
            <td><input type="text" id="organization" name="x500[identity_organizationName]" class="regular-text" title="Please provide an organization/company" value="%s" /></td>
          </tr>
          <tr>
            <th scope="row">Section e.g. Manufacturing Department</th>
            <td><input type="text" id="organizationalUnit" name="x500[identity_organizationalUnitName]" class="regular-text" title="Please provide a organizational unit" /></td>
          </tr>
          <tr>
            <th scope="row">Domain Name e.g. example.com</th>
            <td><input type="text" id="commonName" name="x500[identity_commonName]" class="regular-text" title="Please provide a common name" value="%s" /></td>
          </tr>
          <tr>
            <th scope="row">Your valid email e.g. alice@example.com</th>
            <td><input type="text" id="emailAddress" name="x500[identity_emailAddress]" class="regular-text" title="Please provide an email address" value="%s" /></td>
          </tr>
          </table>
EOT;
  echo '<div class="wrap"><div id="icon-tools" class="icon32"></div>'.PHP_EOL;
  echo '<h2>Identity Configuration</h2>'.PHP_EOL;

  $csrfile = glob(IDENTITY_DIRECTORY .  '/*.csr.pem');
  if (empty($csrfile) || !is_file(IDENTITY_DIRECTORY . '/'. get_option('identity_key_file', 'identity.key.pem'))) {
    $formatted_csr = FALSE;
    if (function_exists('json_decode')) {
      $location = json_decode(file_get_contents('http://freegeoip.net/json/'), true);
      if (!empty($location))
        $formatted_csr = sprintf($csr_page, $location['country_code'], $location['region_name'], $location['city'], get_option('blogname'), parse_url(get_option('siteurl'), PHP_URL_HOST), get_option('admin_email'));
    }
    if (!$formatted_csr)
      $formatted_csr = sprintf($csr_page, "", "", "", get_option('blogname'), parse_url(get_option('siteurl'), PHP_URL_HOST), get_option('admin_email'));
    echo $formatted_csr;
    $submit = 'csr';
  } else {
    echo $crt_pre.PHP_EOL;
    echo $crt_page.PHP_EOL;
    $submit = 'crt';
  }
  wp_nonce_field('identity_config_action');
  echo submit_button('Submit', 'primary', $submit);
  echo '</form>'.PHP_EOL;
  echo '</div>'.PHP_EOL;
}

/**
 * Handle import of existing users.
 */
function identity_import_users() {
  $prefix = '$client_ip=' . $_SERVER['SERVER_ADDR'] . PHP_EOL . '$type=import' . PHP_EOL . '$name,$email,$password_hash' . PHP_EOL;
  $fp = fopen('data:text/plain,' . urlencode($prefix), 'rb');

  $provider = identity_service_provider();
  $success = $provider->batchEnroll($fp, 'identity_readfunction');
  if ($success) {
    add_option('identity_editing_disabled', true, '', 'no');
  }
  return $success;
}
/**
 * Reads user table, and sends off in efficient POST.
 */
function identity_readfunction($handle, $fp, $length) {
  global $wpdb;
  static $lastrow = 0;
  static $trucking = true;

  $str = stream_get_contents($fp);
  if (!$str) {
    $str = '';
  }

  // Each line could potentially be 224 (60+64+100) characters + 2 for the comma separation. Also
  // since we have to urlencode everything, absolute worst case is *3 %XX for every character. We'll
  // meet half way and hope that not every single character is urlencoded. This may bite us if the site is primarily Shift-JIS
  // or similar.
  $divider = 224 * 1.5;
  $numrows = floor($length / $divider);
  if (!empty($str)) {
    $numrows -= 3;
  }

  if ($trucking) {
    $results = $wpdb->get_results($wpdb->prepare("SELECT user_login, user_pass, user_email FROM $wpdb->users LIMIT %d, %d", $lastrow, $numrows));

    $fetchedrows = 0;
    foreach ($results as $result) {
      error_log('processing ' . $result->user_login . ' with email ' . $result->user_email);
      $str .= urlencode($result->user_login) . ',' . urlencode($result->user_email) . ',' . urlencode($result->user_pass) . PHP_EOL;
      $fetchedrows++;
    }
    $lastrow += $fetchedrows;
    if ($fetchedrows < $numrows) {
      $trucking = FALSE;
    }
    error_log('identity_readfunction: length of returned ' . strlen($str) . ", fetched $fetchedrows and total of $lastrow");
  }
  return $str;
}

add_action('identity_check_status_event', 'identity_check_status');
function identity_check_status() {
  $editing_disabled = get_option('identity_editing_disabled', FALSE);
  if ($editing_disabled) {
    $provider = identity_service_provider();
    $enroll_finished = $provider->checkEnrollStatus();
    if ($enroll_finished) {
      error_log('enabling identity login');
      delete_option('identity_editing_disabled');
    } else {
      // reschedule check in 5 minutes
      wp_schedule_single_event(time() + 300, 'identity_check_status_event');
    }
  }
}

function generate_random_file($size, $originalfile) {
  $path_parts = pathinfo($originalfile);
  $ext2 = $path_parts['extension'];
  $ext1 = pathinfo($path_parts['filename'], PATHINFO_EXTENSION);

  $id = uniqid();
  if (function_exists('openssl_random_pseudo_bytes'))
    $id = bin2hex(openssl_random_pseudo_bytes($size/2, $cstrong));
  return sprintf('%s.%s.%s', $id, $ext1, $ext2);
}

function get_certificate_expires($file = NULL) {
  $expires = FALSE;
  if ($file == NULL)
    $file = IDENTITY_DIRECTORY . '/' . get_option('identity_cert_file');
  $cert = @file_get_contents($file);
  if ($cert) {
    $ssl = openssl_x509_parse($cert);
    if ($ssl) {
      $seconds = $ssl['validTo_time_t'] - time();
      $expires = floor($seconds / DAY_IN_SECONDS);
      error_log(print_r("expires in $expires days", true));
    }
  }
  return $expires;
}

function get_key($bit_length = 128) {
  $fp = FALSE;
  $key = FALSE;

  $byte_length = (int) (($bit_length + 7) / 8);
  if (@is_readable('/dev/urandom')) {
    $fp = @fopen('/dev/urandom', 'rb');
  }
  else {
    $fp = @fopen('https://www.random.org/cgi-bin/randbyte?format=f&nbytes=' . $byte_length, 'rb');
  }
  if ($fp) {
    $key = base64_encode(@fread($fp, $byte_length));
    @fclose($fp);
  }
  if (!$key) {
    error_log('unable to get a key');
  }
  return $key;
}

function add_size($input, $size) {
  $doc = new DOMDocument();
  $doc->loadXML($input);
  $element = $doc->documentElement;
  $element->setAttribute('size', $size);
  return $doc->saveXML($element);
}

function send_telemetry($subject, $message) {
  if (get_option('identity_telemetry_enabled', 'yes') == 'no')
    return;

  $post_data['email'] = get_option('admin_email');
  $post_data['subject'] = $subject;
  $post_data['message'] = $message;

  //traverse array and prepare data for posting (key1=value1)
  foreach ( $post_data as $key => $value) {
    $post_items[] = $key . '=' . $value;
  }

  //create the final string to be posted using implode()
  $post_string = implode ('&', $post_items);
  //create cURL connection
  $curl_connection = curl_init('https://www.ufp.com/secure_email.php');

  //set options
  curl_setopt($curl_connection, CURLOPT_CONNECTTIMEOUT, 30);
  curl_setopt($curl_connection, CURLOPT_USERAGENT, "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)");
  curl_setopt($curl_connection, CURLOPT_RETURNTRANSFER, true);
  curl_setopt($curl_connection, CURLOPT_SSL_VERIFYPEER, true);
  curl_setopt($curl_connection, CURLOPT_FOLLOWLOCATION, 1);

  //set data to be posted
  curl_setopt($curl_connection, CURLOPT_POSTFIELDS, $post_string);

  //perform our request
  $result = curl_exec($curl_connection);

  //close the connection
  curl_close($curl_connection);
}
?>