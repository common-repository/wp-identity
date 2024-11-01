<?php
error_reporting(-1);
ini_set('date.timezone', 'America/Los_Angeles');
ini_set('display_errors', 'Off');

require_once("resolver.php");

class IdentityConnectionHandler {
  private $resolver;
  private $contextOptions;

  const BUFFER_SIZE = 4096;

  function __construct() {
    $this->contextOptions =
      array(
        'http' => array(
          'method' => 'POST',
          'header' => 'Content-Type: application/x-www-form-urlencoded',
          'ignore_errors' => true,
          'protocol_version' => 1.1),
        'ssl' => array(
          'verify_peer' => true,
          'allow_self_signed' => true,
          'verify_depth' => 3,
          'disable_compression' => true,
          'ciphers' => 'ALL!EXPORT!EXPORT40!EXPORT56!aNULL!LOW!RC4')
        );
    $this->resolver = new StaticIdentityResolver();
  }

  function setCAInfo($path) {
    $this->contextOptions['ssl']['cafile'] = $path;
  }

  function setSSLCert($path) {
    $this->contextOptions['ssl']['local_cert'] = $path;
  }

  function setSSLKey($path) {
    $this->contextOptions['ssl']['local_pk'] = $path;
  }

  function setSSLPassword($password) {
    $this->contextOptions['ssl']['passphrase'] = $password;
  }

  function setSSLKeyPassword($password) {
    $this->contextOptions['ssl']['passphrase'] = $password;
  }

  function sendMessage($path, $queryparams) {
    set_error_handler("_error_handler");
    $xml = null;
    $url = $this->resolver->getHost() . "/" . $path;
    $this->contextOptions['http']['content'] = http_build_query($queryparams, '', '&');
    $context = stream_context_create($this->contextOptions);
    $stream = fopen($url, 'r', false, $context);
    if ($stream) {
      $http_code = $this->_process_stream_metadata_for_http_code($stream);
      if ($http_code == 200) {
        $length = $this->_process_stream_metadata_for_length($stream);
        $message = fread($stream, $length);
        $xml = new SimpleXMLElement($message);
      } else {
        $error_xml = sprintf('<context><name>%s</name><result xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="defaultResult" message="Identity Service Failure : %d">FAILURE</result></context>', empty($queryparams['name'])?'Unknown':$queryparams['name'], 0 /*$err['type']*/);
        $xml = new SimpleXMLElement($error_xml);
      }
      @fclose($stream);
    } else {
      //$err = error_get_last();
      error_log("returned error: " . print_r(error_get_last(), true));
      $error_xml = sprintf('<context><name>%s</name><result xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="defaultResult" message="Identity Service Failure : %d">FAILURE</result></context>', empty($queryparams['name'])?'Unknown':$queryparams['name'], 0 /*$err['type']*/);
      $xml = new SimpleXMLElement($error_xml);
    }
    unset($this->contextOptions['http']['content']);
    restore_error_handler();
    return $xml;
  }

  function checkEnrollStatus($path) {
    $url = $this->resolver->getHost() . "/" . $path;
    $this->contextOptions['http']['method'] = 'GET';
    $context = stream_context_create($this->contextOptions);
    $http_code = 0;
    $stream = @fopen($url, 'r', false, $context);
    if ($stream) {
      $http_code = $this->_process_stream_metadata_for_http_code($stream);
      @fclose($stream);
    } else
      error_log("returned error: " . print_r(error_get_last(), true));
    $this->contextOptions['http']['method'] = 'POST';
    return $http_code;
  }


  function sendBatched($path, $fp, $readfunction) {
    $http_code = 0;
    error_log('location of temp files: ' . sys_get_temp_dir());
    $content_stream = fopen("php://temp", 'r+');
    if ($content_stream) {
      error_log('temp stream metadata : ' . print_r(stream_get_meta_data($content_stream), true));
      if (is_callable($readfunction)) {
        $str = call_user_func($readfunction, $content_stream, $fp, self::BUFFER_SIZE);
        while (!empty($str)) {
          $written = fwrite($content_stream, $str, strlen($str));
          error_log('wrote ' . $written);
          $str = call_user_func($readfunction, $content_stream, $fp, self::BUFFER_SIZE);
        }
        rewind($content_stream);
      }
    }

    $url = $this->resolver->getHost() . "/" . $path;
    $this->contextOptions['http']['header']  = 'Content-type: application/octet-stream';
    $this->contextOptions['http']['content'] = stream_get_contents($content_stream);
    $context = stream_context_create($this->contextOptions);
    $stream = fopen($url, 'r', false, $context);
    if ($stream) {
      $http_code = $this->_process_stream_metadata_for_http_code($stream);
      fclose($stream);
    } else
      error_log("returned error: " . print_r(error_get_last(), true));
    unset($this->contextOptions['http']['header']);
    unset($this->contextOptions['http']['content']);
    return $http_code;
  }

  function _process_stream_metadata_for_http_code($stream) {
    $http_code = 0;
    $metadata = stream_get_meta_data($stream);
    if (isset($metadata['wrapper_data'][0])) {
        $parts = explode(' ', $metadata['wrapper_data'][0]);
        $http_code = intval($parts[1]);
    }
    return $http_code;
  }

  function _process_stream_metadata_for_length($stream) {
    $metadata = stream_get_meta_data($stream);
    $length = $metadata['unread_bytes'];
    foreach ($metadata['wrapper_data'] as $header) {
      $found = stripos($header, 'Content-Length');
      if ($found !== false) {
        $parts = explode(':', $header);
        $length = intval($parts[1]);
      }
    }
    return $length;
  }

}
function _error_handler($errno, $errstr, $errfile, $errline) {
  error_log('errno : ' . $errno);
  error_log('errstr : ' . $errstr);
  return true;
}
?>