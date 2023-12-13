<?php

/**
 * =====================================================================================
 * Class for base module for Barocert API SDK. It include base functionality for
 * RESTful web service request and parse json result. It uses Linkhub module
 * to accomplish authentication APIs.
 *
 * This module uses curl and openssl for HTTPS Request. So related modules must
 * be installed and enabled.
 *
 * https://www.linkhub.co.kr
 * Author : linkhub dev (code@linkhubcorp.com)
 * Contributor : jws (code@linkhubcorp.com)
 * Written : 2023-03-14
 * Updated : 2023-12-13
 *
 * Thanks for your interest.
 * We welcome any suggestions, feedbacks, blames or anythings.
 * ======================================================================================
 */

namespace Linkhub\Barocert;

use Linkhub\Authority;
use Linkhub\LinkhubException;

class BaseService
{
  const ServiceID = 'BAROCERT';
  const ServiceURL = 'https://barocert.linkhub.co.kr';
  const ServiceURL_Static = 'https://static-barocert.linkhub.co.kr';
  const APIVERSION = '2.1';

  private $Token_Table = array();
  private $Linkhub;
  private $IPRestrictOnOff = true;
  private $UseStaticIP = false;
  private $UseLocalTimeYN = true;
  private $__ServiceURL;

  private $scopes = array();
  private $__requestMode = LINKHUB_COMM_MODE;

  public function __construct($LinkID, $SecretKey, $scope)
  {
    $this->Linkhub = Authority::getInstance($LinkID, $SecretKey);
    $this->scopes[] = 'partner';
    foreach($scope as $value) 
      $this->scopes[] = $value;
  }

  protected function AddScope($scope)
  {
    $this->scopes[] = $scope;
  }

  public function IPRestrictOnOff($V)
  {
    $this->IPRestrictOnOff = $V;
  }

  public function UseStaticIP($V)
  {
    $this->UseStaticIP = $V;
  }

  public function UseLocalTimeYN($V)
  {
    $this->UseLocalTimeYN = $V;
  }

  public function ServiceURL($V)
  {
    $this->__ServiceURL = $V;
  }

  public function AuthURL($V)
  {
    $this->Linkhub->ServiceURL($V);
  }

  private function getTargetURL()
  {
    if(isset($this->__ServiceURL)) {
      return $this->__ServiceURL;
    }

    if ($this->UseStaticIP) {
      return BaseService::ServiceURL_Static;
    }
    return BaseService::ServiceURL;
  }

  private function getsession_Token()
  {
    $targetToken = null;

    if (array_key_exists($this->Linkhub->getLinkID(), $this->Token_Table)) {
      $targetToken = $this->Token_Table[$this->Linkhub->getLinkID()];
    }

    $Refresh = false;

    if (is_null($targetToken)) {
      $Refresh = true;
    } else {
      $Expiration = new DateTime($targetToken->expiration, new DateTimeZone("UTC"));

      $now = $this->Linkhub->getTime($this->UseStaticIP, $this->UseLocalTimeYN, false);
      $Refresh = $Expiration < $now;
    }

    if ($Refresh) {
      try {
        $targetToken = $this->Linkhub->getToken(BaseService::ServiceID, "", $this->scopes, $this->IPRestrictOnOff ? null : "*", $this->UseStaticIP, $this->UseLocalTimeYN, false);
      } catch (LinkhubException $le) {
        throw new BarocertException($le->getMessage(), $le->getCode());
      }
      $this->Token_Table[$this->Linkhub->getLinkID()] = $targetToken;
    }
    return $targetToken->session_token;
  }

  public function executeCURL($uri, $isPost = false, $postdata = null)
  {
    if ($this->__requestMode != "STREAM") {

      $targetURL = $this->getTargetURL();

      $http = curl_init($targetURL . $uri);
      $header = array();

      $header[] = 'Authorization: Bearer ' . $this->getsession_Token($this->Linkhub->getLinkID());
      $header[] = 'Content-Type: Application/json';

      if ($isPost) {
        curl_setopt($http, CURLOPT_POST, 1);
        curl_setopt($http, CURLOPT_POSTFIELDS, $postdata);

        $xDate = $this->Linkhub->getTime($this->UseStaticIP, false, false);

        $digestTarget = 'POST' . chr(10);
        if($postdata){
          $digestTarget = $digestTarget . base64_encode(hash('sha256', $postdata, true)) . chr(10);
        }
        $digestTarget = $digestTarget . $xDate . chr(10);
        $digestTarget = $digestTarget . $uri . chr(10);

        $digest = base64_encode(hash_hmac('sha256', $digestTarget, base64_decode(strtr($this->Linkhub->getSecretKey(), '-_', '+/')), true));

        $header[] = 'x-bc-date: ' . $xDate;
        $header[] = 'x-bc-version: ' . BaseService::APIVERSION;
        $header[] = 'x-bc-auth: ' . $digest;
        $header[] = 'x-bc-encryptionmode: ' . 'GCM';
      }

      curl_setopt($http, CURLOPT_HTTPHEADER, $header);
      curl_setopt($http, CURLOPT_RETURNTRANSFER, TRUE);
      curl_setopt($http, CURLOPT_ENCODING, 'gzip,deflate');

      $responseJson = curl_exec($http);
      $http_status = curl_getinfo($http, CURLINFO_HTTP_CODE);

      $is_gzip = 0 === mb_strpos($responseJson, "\x1f" . "\x8b" . "\x08");

      if ($is_gzip) {
        $responseJson = $this->Linkhub->gzdecode($responseJson);
      }

      $contentType = strtolower(curl_getinfo($http, CURLINFO_CONTENT_TYPE));

      curl_close($http);
      if ($http_status != 200) {
        throw new BarocertException($responseJson);
      }

      return json_decode($responseJson);
    } else {
      $header = array();

      $header[] = 'Accept-Encoding: gzip,deflate';
      $header[] = 'Connection: close';
      $header[] = 'Authorization: Bearer ' . $this->getsession_Token($this->Linkhub->getLinkID());
      

      $header[] = 'Content-Type: Application/json';
      $postbody = $postdata;


      $xDate = $this->Linkhub->getTime($this->UseStaticIP, false, false);

      $digestTarget = 'POST' . chr(10);
      $digestTarget = $digestTarget . base64_encode(hash('sha256', $postdata, true)) . chr(10);
      $digestTarget = $digestTarget . $xDate . chr(10);
      $digestTarget = $digestTarget . $uri . chr(10);

      $digest = base64_encode(hash_hmac('sha256', $digestTarget, base64_decode(strtr($this->Linkhub->getSecretKey(), '-_', '+/')), true));

      $header[] = 'x-bc-date: ' . $xDate;
      $header[] = 'x-bc-version: ' . BaseService::APIVERSION;
      $header[] = 'x-bc-auth: ' . $digest;
      $header[] = 'x-bc-encryptionmode: ' . 'GCM';

      $params = array(
        'http' => array(
          'ignore_errors' => TRUE,
          'protocol_version' => '1.0',
          'method' => 'GET'
        )
      );

      if ($isPost) {
        $params['http']['method'] = 'POST';
        $params['http']['content'] = $postbody;
      }

      if ($header !== null) {
        $head = "";
        foreach ($header as $h) {
          $head = $head . $h . "\r\n";
        }
        $params['http']['header'] = substr($head, 0, -2);
      }

      $ctx = stream_context_create($params);
      $targetURL = $this->getTargetURL();
      $response = file_get_contents($targetURL . $uri, false, $ctx);

      $is_gzip = 0 === mb_strpos($response, "\x1f" . "\x8b" . "\x08");

      if ($is_gzip) {
        $response = $this->Linkhub->gzdecode($response);
      }

      if ($http_response_header[0] != "HTTP/1.1 200 OK") {
        throw new BarocertException($response);
      }

      return json_decode($response);
    }
  }

  public function sha256ToBase64url($data){
    $hash = hash('sha256', $data, true);
    $base64Encoded = rtrim(strtr(base64_encode($hash), '+/', '-_'), '=');
    return $base64Encoded;
  }

  public function encryptTo($data, $algorithm){
    if($algorithm === "AES") {
      return $this->encAES256GCM($data);
    }
    else {
      throw new BarocertException('지원하지 않는 암호화 알고리즘입니다.');
    }
  }

  public function encAES256GCM($data) {
    if(mb_detect_encoding($data, 'EUC-KR,UTF-8') != "UTF-8") {
      $data = iconv("EUC-KR", "UTF-8", $data);
    }
  
    $biv  = openssl_random_pseudo_bytes(12);
    $ciphertext = openssl_encrypt($data, "aes-256-gcm", base64_decode($this->Linkhub->getSecretKey()), 0, $biv, $tagbt);
  
    $concatted = $biv.base64_decode($ciphertext).$tagbt;
    return base64_encode($concatted);
  }

}

class BarocertException extends \Exception
{
  public function __construct($response, $code = -99999999, Exception $previous = null)
  {
    $Err = json_decode($response);
    if (is_null($Err)) {
      parent::__construct($response, $code);
    } else {
      parent::__construct($Err->message, $Err->code);
    }
  }

  public function __toString()
  {
    return __CLASS__ . ": [{$this->code}]: {$this->message}\n";
  }
}

?>
