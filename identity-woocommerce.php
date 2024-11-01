<?php
/*
Name: UFP Identity Plugin WooCommerce
Description: UFP Identity WooCommerce handling
Author: Richard Levenberg
*/
function identity_woo_override() {
  if ( ! empty( $_POST['login'] ) && ! empty( $_POST['_wpnonce'] ) ) {
    wp_verify_nonce( $_POST['_wpnonce'], 'woocommerce-login' );
    try {
      $creds  = array();
      if ( empty($_SESSION['IDENTITY_USERNAME']) ) {
        if ( empty( $_POST['username'] ) ) {
          throw new Exception( '<strong>' . __( 'Error', 'woocommerce' ) . ':</strong> ' . __( 'Username is required.', 'woocommerce' ) );
        }
        if ( is_email( $_POST['username'] ) && apply_filters( 'woocommerce_get_username_from_email', true ) ) {
          $user = get_user_by( 'email', $_POST['username'] );

          if ( isset( $user->user_login ) ) {
            $creds['user_login']  = $user->user_login;
          } else {
            throw new Exception( '<strong>' . __( 'Error', 'woocommerce' ) . ':</strong> ' . __( 'A user could not be found with this email address.', 'woocommerce' ) );
          }
        } else {
          $creds['user_login']  = $_POST['username'];
        }
      } else
        $creds['user_login'] = $_SESSION['IDENTITY_USERNAME'];

      $creds['remember']      = isset( $_POST['rememberme'] );
      $secure_cookie          = is_ssl() ? true : false;
      $user                   = wp_signon( apply_filters( 'woocommerce_login_credentials', $creds ), $secure_cookie );

      if ( is_wp_error( $user ) ) {
        throw new Exception( $user->get_error_message() );
      } else {
        if ( ! empty( $_POST['redirect'] ) ) {
          $redirect = $_POST['redirect'];
        } elseif ( wp_get_referer() ) {
          $redirect = wp_get_referer();
        } else {
          $redirect = get_permalink( wc_get_page_id( 'myaccount' ) );
        }

        // Feedback
        wc_add_notice( sprintf( __( 'You are now logged in as <strong>%s</strong>', 'woocommerce' ), $user->display_name ) );

        wp_redirect( apply_filters( 'woocommerce_login_redirect', $redirect, $user ) );
        exit;
      }
    } catch (Exception $e) {
      $message = $e->getMessage();
      if (!empty($message))
        wc_add_notice( apply_filters('login_errors', $message ), 'error' );
    }
    unset($_POST['login']);
  }
}
// We use 5 here to ensure we run prior to the woocommerce init functions which default to 10
add_action( 'init', 'identity_woo_override', 5 );

function identity_woocommerce_login_form_start() {
  ob_start();
}
add_action( 'woocommerce_login_form_start', 'identity_woocommerce_login_form_start' );

function identity_woocommerce_login_form() {
  $contents = ob_get_clean();
  $document = new DOMDocument();
  $document->loadHTML($contents);

  $list = $document->documentElement;

  if (!empty($_SESSION['IDENTITY_USERNAME']) && !empty($_SESSION['IDENTITY_DISPLAY_ITEMS'])) {
    wp_enqueue_script( 'prefix-script', plugins_url('js/identity-woocommerce.js', __FILE__), array(), '1.0', true );
    $p_list = $list->getElementsByTagName('p');
    $index = $p_list->length - 2; // set index to username element
    $p_element = $p_list->item($index++);
    $p_element->removeChild($p_element->firstChild->nextSibling);
    $new_element = $document->createElement('span', $_SESSION['IDENTITY_USERNAME']);
    $new_element->setAttribute('id', 'user-text');
    $new_element->setIdAttribute('id', true);
    $p_element->replaceChild($new_element, $p_element->lastChild);

    // now delete the useless password input
    $p_element = $p_list->item($index++);
    $p_element->parentNode->removeChild($p_element);

    $disable_forgot_password = true;
    identity_includes();
    $display_items = unserialize($_SESSION['IDENTITY_DISPLAY_ITEMS']);
    if ((count($display_items) == 1) && ($display_items[0]->getReset() == 'forgettable'))
      $disable_forgot_password = false;
    foreach ($display_items as $index => $display_item) {
      $id = 'AuthParam' . $index;
      $name = $display_item->getDisplayName();
      $nickname =  $display_item->getNickName();

      $label_element = $document->createElement('label');
      $label_element->setAttribute('for', $id);
      $abbr_element = $document->createElement('abbr', $name);
      $abbr_element->setAttribute('title', $nickname);
      $span_element = $document->createElement('span', '*');
      $span_element->setAttribute('class', 'required');

      $label_element->appendChild($abbr_element);
      $label_element->appendChild($span_element);
      $new_p_element = $document->createElement('p');
      $new_p_element->setAttribute('class', 'form-row form-row-wide');
      $new_p_element->appendChild($label_element);
      $documentFragment = $document->createDocumentFragment();
      $documentFragment->appendXML($display_item->getFormElement());
      $new_p_element->appendChild($documentFragment);
      $p_element = $p_list->item(0);
      $p_element->parentNode->appendChild($new_p_element);
    }
  } else {
    $p_list = $list->getElementsByTagName('p');
    $index = $p_list->length - 1; // set index to username element
    $p_element = $p_list->item($index);
    $removed_p_element = $p_element->parentNode->removeChild($p_element);
  }
  echo saveHTMLSnippet($document);
  ob_start();
}
add_action( 'woocommerce_login_form', 'identity_woocommerce_login_form' );

function identity_woocommerce_login_form_end() {
  // here were dealing with forgot password element
  $contents = ob_get_clean();
  $document = new DOMDocument();
  $document->loadHTML($contents);
  if (identity_disable_forgot_password()) {
    $list = $document->documentElement;

    $p_list = $list->getElementsByTagName('p');
    $index = $p_list->length - 1;
    $p_element = $p_list->item($index);
    $removed_p_element = $p_element->parentNode->removeChild($p_element);
  }
  echo saveHTMLSnippet($document);
}
add_action( 'woocommerce_login_form_end', 'identity_woocommerce_login_form_end' );

function identity_woocommerce_created_customer( $customer_id, $new_customer_data, $password_generated ) {
  $provider = identity_service_provider();
  /*
   * We can't rely on the $new_customer_data['user_login'] passed in since woo calls sanitize_user with strict = false
   * and wp calls sanitize_user with strict = true afterwards. The only sure way is to read the user out of the database.
   */
  $user = get_user_by('id', $customer_id);
  error_log('enrolling ' . $user->user_login);
  $context = $provider->enroll($user->user_login, array('type' => 'new', 'email' => $user->user_email, 'passphrase' => $new_customer_data['user_pass']));
  if ($context['result']->getText() != 'SUCCESS') {
    error_log('error adding profile of '. $context['name'] . ' due to ' . $context['result']->getMessage());
  }
}
add_action( 'woocommerce_created_customer', 'identity_woocommerce_created_customer', 10, 3 );

function identity_woocommerce_enqueue_scripts() {
  wp_register_style( 'prefix-style', plugins_url('css/identity.css', __FILE__) );
  wp_enqueue_style( 'prefix-style' );
}
add_action( 'wp_enqueue_scripts', 'identity_woocommerce_enqueue_scripts' );

function identity_woocommerce_user_profile_update_errors($errors, $update, $user_id) {
  if ( wc_notice_count( 'error' ) === 0 ) {
    identity_user_profile_update($errors, $update, $user_id);
  } else {
    error_log('not calling update due to ' . wc_notice_count( 'error' ) . ' errors');
  }
}

if (!is_admin()) {
  remove_action( 'user_profile_update_errors', 'identity_user_profile_update', 10 );
  add_action( 'user_profile_update_errors', 'identity_woocommerce_user_profile_update_errors', 10, 3 );
}

function identity_woocommerce_edit_account_form_start() {
  ob_start();
}
add_action( 'woocommerce_edit_account_form_start', 'identity_woocommerce_edit_account_form_start' );

function identity_woocommerce_edit_account_form_end() {
  $contents = ob_get_clean();
  $document = new DOMDocument();
  $document->loadHTML($contents);
  if (get_user_meta(get_current_user_id(), 'disable_forget_password', true)) {
    $list = $document->documentElement;
    $p_list = $list->getElementsByTagName('fieldset');
    $index = $p_list->length - 1;
    $p_element = $p_list->item($index);
    $removed_p_element = $p_element->parentNode->removeChild($p_element);
  }
  echo saveHTMLSnippet($document);
}
add_action( 'woocommerce_edit_account_form_end', 'identity_woocommerce_edit_account_form_end');

function saveHTMLSnippet($document) {
  return preg_replace(array("/^\<\!DOCTYPE.*?<html><body>/si", "!</body></html>$!si"),
                      "",
                      $document->saveHTML());
}

/*
 * We have to override this function to ensure existing passwords are checked
 * against UFP.
 */
if (get_option('identity_login_enabled')) {
  if ( !function_exists('wp_check_password') ) {
    function wp_check_password($password, $hash, $user_id) {
      $success = false;
      if (!empty($user_id)) {
        $user = get_userdata( $user_id );
        if (!is_wp_error($user)) {
          $provider = identity_service_provider();
          $pretext = $provider->preAuthenticate($user->user_login);
          if ($pretext['result']->getText() == 'SUCCESS') {
            if ((count($pretext['display_items']) == 1) && ($pretext['display_items'][0]->getName() == 'passphrase')) {
              $context = $provider->authenticate($pretext['name'], array('passphrase' => $password, ));
              if ($context['result']->getText() == 'SUCCESS') {
                $success = true;
              }
            }
          }
        }
      }
      return $success;
    }
  }
}
?>