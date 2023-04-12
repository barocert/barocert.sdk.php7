<?php

/**
 * =====================================================================================
 * Class for base module for Kakaocert API SDK. It include base functionality for
 * RESTful web service request and parse json result. It uses Linkhub module
 * to accomplish authentication APIs.
 *
 * This module uses curl and openssl for HTTPS Request. So related modules must
 * be installed and enabled.
 *
 * https://www.linkhub.co.kr
 * Author : lsh (code@linkhubcorp.com)
 * Written : 2023-03-14
 * Updated : 2023-04-12
 *
 * Thanks for your interest.
 * We welcome any suggestions, feedbacks, blames or anythings.
 * ======================================================================================
 */

namespace linkhub\barocert;

use Linkhub\Authority;
use Linkhub\LinkhubException;

class KakaocertService
{
  const ServiceID = 'BAROCERT';
  const ServiceURL = 'https://barocert.linkhub.co.kr';
  const ServiceURL_Static = 'https://static-barocert.linkhub.co.kr';
  const Version = '2.0';

  private $Token_Table = array();
  private $Linkhub;
  private $IPRestrictOnOff = true;
  private $UseStaticIP = false;
  private $UseLocalTimeYN = true;

  private $scopes = array();
  private $__requestMode = LINKHUB_COMM_MODE;

  public function __construct($LinkID, $SecretKey)
  {
    $this->Linkhub = Authority::getInstance($LinkID, $SecretKey);
    $this->scopes[] = 'partner';
    $this->scopes[] = '401';
    $this->scopes[] = '402';
    $this->scopes[] = '403';
    $this->scopes[] = '404';
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

  private function getTargetURL()
  {
    if ($this->UseStaticIP) {
      return KakaocertService::ServiceURL_Static;
    }
    return KakaocertService::ServiceURL;
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
        $targetToken = $this->Linkhub->getToken(KakaocertService::ServiceID, $CorpNum, $this->scopes, $this->IPRestrictOnOff ? null : "*", $this->UseStaticIP, $this->UseLocalTimeYN, false);
      } catch (LinkhubException $le) {
        throw new BarocertException($le->getMessage(), $le->getCode());
      }
      $this->Token_Table[$this->Linkhub->getLinkID()] = $targetToken;
    }
    return $targetToken->session_token;
  }

  protected function executeCURL($uri, $isPost = false, $postdata = null)
  {
    if ($this->__requestMode != "STREAM") {

      $targetURL = $this->getTargetURL();

      $http = curl_init($targetURL . $uri);
      $header = array();

      $header[] = 'Authorization: Bearer ' . $this->getsession_Token($ClientCode);
      $header[] = 'Content-Type: Application/json';

      if ($isPost) {
        curl_setopt($http, CURLOPT_POST, 1);
        curl_setopt($http, CURLOPT_POSTFIELDS, $postdata);

        $xDate = $this->Linkhub->getTime($this->UseStaticIP, false, false);

        $digestTarget = 'POST' . chr(10);
        $digestTarget = $digestTarget . $uri . chr(10);
        if($postdata){
          $digestTarget = $digestTarget . base64_encode(hash('sha256', $postdata, true)) . chr(10);
        }
        $digestTarget = $digestTarget . $xDate . chr(10);

        $digest = base64_encode(hash_hmac('sha256', $digestTarget, base64_decode(strtr($this->Linkhub->getSecretKey(), '-_', '+/')), true));

        $header[] = 'x-bc-date: ' . $xDate;
        $header[] = 'x-bc-version: ' . '2.0';
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

      if (0 === mb_strpos($contentType, 'application/pdf')) {
        return $responseJson;
      }
      return json_decode($responseJson);
    } else {
      $header = array();

      $header[] = 'Accept-Encoding: gzip,deflate';
      $header[] = 'Connection: close';
      $header[] = 'Authorization: Bearer ' . $this->getsession_Token($ClientCode);
      

      $header[] = 'Content-Type: Application/json';
      $postbody = $postdata;


      $xDate = $this->Linkhub->getTime($this->UseStaticIP, false, false);

      $digestTarget = 'POST' . chr(10);
      $digestTarget = $digestTarget . $uri . chr(10);
      $digestTarget = $digestTarget . base64_encode(hash('sha256', $postdata, true)) . chr(10);
      $digestTarget = $digestTarget . $xDate . chr(10);

      $digest = base64_encode(hash_hmac('sha256', $digestTarget, base64_decode(strtr($this->Linkhub->getSecretKey(), '-_', '+/')), true));

      $header[] = 'x-bc-date: ' . $xDate;
      $header[] = 'x-bc-version: ' . '2.0';
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

      foreach ($http_response_header as $k => $v) {
        $t = explode(':', $v, 2);
        if (preg_match('/^Content-Type:/i', $v, $out)) {
          $contentType = trim($t[1]);
          if (0 === mb_strpos($contentType, 'application/pdf')) {
            return $response;
          }
        }
      }

      return json_decode($response);
    }
  }

  public function encrypt($data){
    return $this->encAES256GCM($data);
  }

  public function encAES256GCM($data) {
    if(mb_detect_encoding($data, 'EUC-KR,UTF-8') != "UTF-8") {
      $data = iconv("EUC-KR", "UTF-8", $data);
    }
  
    $biv  = openssl_random_pseudo_bytes(12);
    $ciphertext = openssl_encrypt($data, "aes-256-gcm", base64_decode($this->Linkhub->getSecretKey()), 0, $biv, $tagbt);
  
    $concatted = $iv.base64_decode($ciphertext).$tagbt;
    return base64_encode($concatted);
  }

 
 /**
   * 본인인증 요청
   */
  public function requestIdentity($ClientCode, $RequestIdentity)
  {
    if (is_null($ClientCode) || empty($ClientCode)) {
      throw new BarocertException('이용기관코드가 입력되지 않았습니다.');
    }
    if (ereg("[^0-9]", $ClientCode)) {
      throw new BarocertException('이용기관코드는 숫자만 입력할 수 있습니다.');
    }
    if (strlen($ClientCode) != 12) {
      throw new BarocertException('이용기관코드는 12자 입니다.');
    }
    if (is_null($RequestIdentity) || empty($RequestIdentity)) {
      throw new BarocertException('본인인증 요청정보가 입력되지 않았습니다.');
    }
    if (is_null($RequestIdentity->ci) || empty($RequestIdentity->ci)) {
      if (is_null($RequestIdentity->receiverHP) || empty($RequestIdentity->receiverHP)) {
        throw new BarocertException('수신자 휴대폰번호가 입력되지 않았습니다.');
      }
      if (is_null($RequestIdentity->receiverName) || empty($RequestIdentity->receiverName)) {
        throw new BarocertException('수신자 성명이 입력되지 않았습니다.');
      }
      if (is_null($RequestIdentity->receiverBirthday) || empty($RequestIdentity->receiverBirthday)) {
        throw new BarocertException('생년월일이 입력되지 않았습니다.');
      }
    }

    if (is_null($RequestIdentity->expireIn) || empty($RequestIdentity->expireIn)) {
      throw new BarocertException('만료시간이 입력되지 않았습니다.');
    }
    if (is_null($RequestIdentity->reqTitle) || empty($RequestIdentity->reqTitle)) {
      throw new BarocertException('인증요청 메시지 제목이 입력되지 않았습니다.');
    }
    if (is_null($RequestIdentity->token) || empty($RequestIdentity->token)) {
      throw new BarocertException('토큰 원문이 입력되지 않았습니다.');
    }

    $postdata = json_encode($RequestIdentity);
    
    $result = $this->executeCURL('/KAKAO/Identity/' . $ClientCode, true, $postdata);

    $ResponseIdentity = new ResponseIdentity();
    $ResponseIdentity->fromJsonInfo($result);
    return $ResponseIdentity;
  }

  /**
   * 본인인증 상태확인
   */
  public function getIdentityStatus($ClientCode, $receiptID)
  {
    if (is_null($ClientCode) || empty($ClientCode)) {
      throw new BarocertException('이용기관코드가 입력되지 않았습니다.');
    }
    if (ereg("[^0-9]", $ClientCode)) {
      throw new BarocertException('이용기관코드는 숫자만 입력할 수 있습니다.');
    }
    if (strlen($ClientCode) != 12) {
      throw new BarocertException('이용기관코드는 12자 입니다.');
    }
    if (is_null($receiptID) || empty($receiptID)) {
      throw new BarocertException('접수아이디가 입력되지 않았습니다.');
    }
    if (ereg("[^0-9]", $receiptID)) {
      throw new BarocertException('접수아이디는 숫자만 입력할 수 있습니다.');
    }
    if (strlen($receiptID) != 32) {
      throw new BarocertException('접수아이디는 32자 입니다.');
    }

    $result = $this->executeCURL('/KAKAO/Identity/' . $ClientCode .'/'. $receiptID, false, null);

    $ResponseIdentityStatus = new ResponseIdentityStatus();
    $ResponseIdentityStatus->fromJsonInfo($result);
    return $ResponseIdentityStatus;
  }

  /**
   * 본인인증 검증
   */
  public function verifyIdentity($ClientCode, $receiptID)
  {
    if (is_null($ClientCode) || empty($ClientCode)) {
      throw new BarocertException('이용기관코드가 입력되지 않았습니다.');
    }
    if (ereg("[^0-9]", $ClientCode)) {
      throw new BarocertException('이용기관코드는 숫자만 입력할 수 있습니다.');
    }
    if (strlen($ClientCode) != 12) {
      throw new BarocertException('이용기관코드는 12자 입니다.');
    }
    if (is_null($receiptID) || empty($receiptID)) {
      throw new BarocertException('접수아이디가 입력되지 않았습니다.');
    }
    if (ereg("[^0-9]", $receiptID)) {
      throw new BarocertException('접수아이디는 숫자만 입력할 수 있습니다.');
    }
    if (strlen($receiptID) != 32) {
      throw new BarocertException('접수아이디는 32자 입니다.');
    }

    $result = $this->executeCURL('/KAKAO/Identity/' . $ClientCode .'/'. $receiptID, true, null);

    $ResponseVerifyIdentity = new ResponseVerifyIdentity();
    $ResponseVerifyIdentity->fromJsonInfo($result);
    return $ResponseVerifyIdentity;
  }

  /**
   * 전자서명 요청(단건)
   */
  public function RequestSign($ClientCode, $RequestSign)
  {
    if (is_null($ClientCode) || empty($ClientCode)) {
      throw new BarocertException('이용기관코드가 입력되지 않았습니다.');
    }
    if (ereg("[^0-9]", $ClientCode)) {
      throw new BarocertException('이용기관코드는 숫자만 입력할 수 있습니다.');
    }
    if (strlen($ClientCode) != 12) {
      throw new BarocertException('이용기관코드는 12자 입니다.');
    }
    if (is_null($RequestSign) || empty($RequestSign)) {
      throw new BarocertException('전자서명 요청정보가 입력되지 않았습니다.');
    }
    if (is_null($RequestSign->ci) || empty($RequestSign->ci)) {
      if (is_null($RequestSign->receiverHP) || empty($RequestSign->receiverHP)) {
        throw new BarocertException('수신자 휴대폰번호가 입력되지 않았습니다.');
      }
      if (is_null($RequestSign->receiverName) || empty($RequestSign->receiverName)) {
        throw new BarocertException('수신자 성명이 입력되지 않았습니다.');
      }
      if (is_null($RequestSign->receiverBirthday) || empty($RequestSign->receiverBirthday)) {
        throw new BarocertException('생년월일이 입력되지 않았습니다.');
      }
    }
    if (is_null($RequestSign->expireIn) || empty($RequestSign->expireIn)) {
      throw new BarocertException('만료시간이 입력되지 않았습니다.');
    }
    if (is_null($RequestSign->reqTitle) || empty($RequestSign->reqTitle)) {
      throw new BarocertException('인증요청 메시지 제목이 입력되지 않았습니다.');
    }
    if (is_null($RequestSign->token) || empty($RequestSign->token)) {
      throw new BarocertException('토큰 원문이 입력되지 않았습니다.');
    }
    if (is_null($RequestSign->tokenType) || empty($RequestSign->tokenType)) {
      throw new BarocertException('원문 유형이 입력되지 않았습니다.');
    }

    $postdata = json_encode($RequestSign);

    $result = $this->executeCURL('/KAKAO/Sign/' . $ClientCode, true,  $postdata);

    $ResponseSign = new ResponseSign();
    $ResponseSign->fromJsonInfo($result);
    return $ResponseSign;
  }


  /**
   * 전자서명 상태 확인(단건)
   */
  public function getSignStatus($ClientCode, $receiptID)
  {
    if (is_null($ClientCode) || empty($ClientCode)) {
      throw new BarocertException('이용기관코드가 입력되지 않았습니다.');
    }
    if (ereg("[^0-9]", $ClientCode)) {
      throw new BarocertException('이용기관코드는 숫자만 입력할 수 있습니다.');
    }
    if (strlen($ClientCode) != 12) {
      throw new BarocertException('이용기관코드는 12자 입니다.');
    }
    if (is_null($receiptID) || empty($receiptID)) {
      throw new BarocertException('접수아이디가 입력되지 않았습니다.');
    }
    if (ereg("[^0-9]", $receiptID)) {
      throw new BarocertException('접수아이디는 숫자만 입력할 수 있습니다.');
    }
    if (strlen($receiptID) != 32) {
      throw new BarocertException('접수아이디는 32자 입니다.');
    }

    $result = $this->executeCURL('/KAKAO/Sign/'. $ClientCode .'/'. $receiptID, false, null);

    $ResponseSignStatus = new ResponseSignStatus();
    $ResponseSignStatus->fromJsonInfo($result);
    return $ResponseSignStatus;
  }

  /**
   * 전자서명 검증(단건)
   */
  public function verifySign($ClientCode, $receiptID)
  {
    if (is_null($ClientCode) || empty($ClientCode)) {
      throw new BarocertException('이용기관코드가 입력되지 않았습니다.');
    }
    if (ereg("[^0-9]", $ClientCode)) {
      throw new BarocertException('이용기관코드는 숫자만 입력할 수 있습니다.');
    }
    if (strlen($ClientCode) != 12) {
      throw new BarocertException('이용기관코드는 12자 입니다.');
    }
    if (is_null($receiptID) || empty($receiptID)) {
      throw new BarocertException('접수아이디가 입력되지 않았습니다.');
    }
    if (ereg("[^0-9]", $receiptID)) {
      throw new BarocertException('접수아이디는 숫자만 입력할 수 있습니다.');
    }
    if (strlen($receiptID) != 32) {
      throw new BarocertException('접수아이디는 32자 입니다.');
    }
    
    $result = $this->executeCURL('/KAKAO/Sign/'. $ClientCode .'/'. $receiptID, true, null);

    $ResponseVerifySign = new ResponseVerifySign();
    $ResponseVerifySign->fromJsonInfo($result);
    return $ResponseVerifySign;
  }

  /**
   * 전자서명 요청(복수)
   */
  public function requestMultiSign($ClientCode, $RequestMultiSign)
  {
    if (is_null($ClientCode) || empty($ClientCode)) {
      throw new BarocertException('이용기관코드가 입력되지 않았습니다.');
    }
    if (is_null($ClientCode) || empty($ClientCode)) {
      throw new BarocertException('이용기관코드가 입력되지 않았습니다.');
    }
    if (ereg("[^0-9]", $ClientCode)) {
      throw new BarocertException('이용기관코드는 숫자만 입력할 수 있습니다.');
    }
    if (strlen($ClientCode) != 12) {
      throw new BarocertException('이용기관코드는 12자 입니다.');
    }
    if (is_null($RequestMultiSign) || empty($RequestMultiSign)) {
      throw new BarocertException('전자서명 요청정보가 입력되지 않았습니다.');
    }
    if (is_null($RequestMultiSign->ci) || empty($RequestMultiSign->ci)) {
      if (is_null($RequestMultiSign->receiverHP) || empty($RequestMultiSign->receiverHP)) {
        throw new BarocertException('수신자 휴대폰번호가 입력되지 않았습니다.');
      }
      if (is_null($RequestMultiSign->receiverName) || empty($RequestMultiSign->receiverName)) {
        throw new BarocertException('수신자 성명이 입력되지 않았습니다.');
      }
      if (is_null($RequestMultiSign->receiverBirthday) || empty($RequestMultiSign->receiverBirthday)) {
        throw new BarocertException('생년월일이 입력되지 않았습니다.');
      }
    }
    if (is_null($RequestMultiSign->expireIn) || empty($RequestMultiSign->expireIn)) {
      throw new BarocertException('만료시간이 입력되지 않았습니다.');
    }
    if ($this->isNullorEmptyTitle($RequestMultiSign->tokens)) {
      throw new BarocertException('인증요청 메시지 제목이 입력되지 않았습니다.');
    }
    if ($this->isNullorEmptyToken($RequestMultiSign->tokens)) {
      throw new BarocertException('토큰 원문이 입력되지 않았습니다.');
    }
    if (is_null($RequestMultiSign->tokenType) || empty($RequestMultiSign->tokenType)) {
      throw new BarocertException('원문 유형이 입력되지 않았습니다.');
    }


    $postdata = json_encode($RequestMultiSign);
    $result = $this->executeCURL('/KAKAO/MultiSign/' . $ClientCode, true, $postdata);

    $ResponseMultiSign = new ResponseMultiSign();
    $ResponseMultiSign->fromJsonInfo($result);
    return $ResponseMultiSign;
  }

  /**
   * 전자서명 상태 확인(복수)
   */
  public function getMultiSignStatus($ClientCode, $receiptID)
  {
    if (is_null($ClientCode) || empty($ClientCode)) {
      throw new BarocertException('이용기관코드가 입력되지 않았습니다.');
    }
    if (ereg("[^0-9]", $ClientCode)) {
      throw new BarocertException('이용기관코드는 숫자만 입력할 수 있습니다.');
    }
    if (strlen($ClientCode) != 12) {
      throw new BarocertException('이용기관코드는 12자 입니다.');
    }
    if (is_null($receiptID) || empty($receiptID)) {
      throw new BarocertException('접수아이디가 입력되지 않았습니다.');
    }
    if (ereg("[^0-9]", $receiptID)) {
      throw new BarocertException('접수아이디는 숫자만 입력할 수 있습니다.');
    }
    if (strlen($receiptID) != 32) {
      throw new BarocertException('접수아이디는 32자 입니다.');
    }

    $result = $this->executeCURL('/KAKAO/MultiSign/' . $ClientCode .'/'. $receiptID, false , null);

    $ResponseMultiSignStatus = new ResponseMultiSignStatus();
    $ResponseMultiSignStatus->fromJsonInfo($result);
    return $ResponseMultiSignStatus;
  }

  /**
   * 전자서명 검증(복수)
   */
  public function verifyMultiSign($ClientCode, $receiptID)
  {
    if (is_null($ClientCode) || empty($ClientCode)) {
      throw new BarocertException('이용기관코드가 입력되지 않았습니다.');
    }
    if (ereg("[^0-9]", $ClientCode)) {
      throw new BarocertException('이용기관코드는 숫자만 입력할 수 있습니다.');
    }
    if (strlen($ClientCode) != 12) {
      throw new BarocertException('이용기관코드는 12자 입니다.');
    }
    if (is_null($receiptID) || empty($receiptID)) {
      throw new BarocertException('접수아이디가 입력되지 않았습니다.');
    }
    if (ereg("[^0-9]", $receiptID)) {
      throw new BarocertException('접수아이디는 숫자만 입력할 수 있습니다.');
    }
    if (strlen($receiptID) != 32) {
      throw new BarocertException('접수아이디는 32자 입니다.');
    }
    
    $result = $this->executeCURL('/KAKAO/MultiSign/'. $ClientCode .'/'. $receiptID, true, null);

    $ResponseVerifyMultiSign = new ResponseVerifyMultiSign();
    $ResponseVerifyMultiSign->fromJsonInfo($result);
    return $ResponseVerifyMultiSign;
  }

  /**
   * 출금동의 요청
   */
  public function requestCMS($ClientCode, $RequestCMS)
  {
    if (is_null($ClientCode) || empty($ClientCode)) {
      throw new BarocertException('이용기관코드가 입력되지 않았습니다.');
    }
    if (ereg("[^0-9]", $ClientCode)) {
      throw new BarocertException('이용기관코드는 숫자만 입력할 수 있습니다.');
    }
    if (strlen($ClientCode) != 12) {
      throw new BarocertException('이용기관코드는 12자 입니다.');
    }
    if (is_null($RequestCMS) || empty($RequestCMS)) {
      throw new BarocertException('자동이체 출금동의 요청정보가 입력되지 않았습니다.');
    }
    if (is_null($RequestCMS->ci) || empty($RequestCMS->ci)) {
      if (is_null($RequestCMS->receiverHP) || empty($RequestCMS->receiverHP)) {
        throw new BarocertException('수신자 휴대폰번호가 입력되지 않았습니다.');
      }
      if (is_null($RequestCMS->receiverName) || empty($RequestCMS->receiverName)) {
        throw new BarocertException('수신자 성명이 입력되지 않았습니다.');
      }
      if (is_null($RequestCMS->receiverBirthday) || empty($RequestCMS->receiverBirthday)) {
        throw new BarocertException('생년월일이 입력되지 않았습니다.');
      }
    }
    if (is_null($RequestCMS->expireIn) || empty($RequestCMS->expireIn)) {
      throw new BarocertException('만료시간이 입력되지 않았습니다.');
    }
    if (is_null($RequestCMS->reqTitle) || empty($RequestCMS->reqTitle)) {
      throw new BarocertException('인증요청 메시지 제목이 입력되지 않았습니다.');
    }
    if (is_null($RequestCMS->requestCorp) || empty($RequestCMS->requestCorp)) {
      throw new BarocertException('청구기관명이 입력되지 않았습니다.');
    }
    if (is_null($RequestCMS->bankName) || empty($RequestCMS->bankName)) {
      throw new BarocertException('은행명이 입력되지 않았습니다.');
    }
    if (is_null($RequestCMS->bankAccountNum) || empty($RequestCMS->bankAccountNum)) {
      throw new BarocertException('계좌번호가 입력되지 않았습니다.');
    }
    if (is_null($RequestCMS->bankAccountName) || empty($RequestCMS->bankAccountName)) {
      throw new BarocertException('예금주명이 입력되지 않았습니다.');
    }
    if (is_null($RequestCMS->bankAccountBirthday) || empty($RequestCMS->bankAccountBirthday)) {
      throw new BarocertException('예금주 생년월일이 입력되지 않았습니다.');
    }
    if (is_null($RequestCMS->bankServiceType) || empty($RequestCMS->bankServiceType)) {
      throw new BarocertException('출금 유형이 입력되지 않았습니다.');
    }

    $postdata = json_encode($RequestCMS);
    
    $result = $this->executeCURL('/KAKAO/CMS/' . $ClientCode, true, $postdata);

    $ResponseCMS = new ResponseCMS();
    $ResponseCMS->fromJsonInfo($result);
    return $ResponseCMS;
  }

  /**
   * 출금동의 상태 확인
   */
  public function getCMSStatus($ClientCode, $receiptID)
  {
    if (is_null($ClientCode) || empty($ClientCode)) {
      throw new BarocertException('이용기관코드가 입력되지 않았습니다.');
    }
    if (ereg("[^0-9]", $ClientCode)) {
      throw new BarocertException('이용기관코드는 숫자만 입력할 수 있습니다.');
    }
    if (strlen($ClientCode) != 12) {
      throw new BarocertException('이용기관코드는 12자 입니다.');
    }
    if (is_null($receiptID) || empty($receiptID)) {
      throw new BarocertException('접수아이디가 입력되지 않았습니다.');
    }
    if (ereg("[^0-9]", $receiptID)) {
      throw new BarocertException('접수아이디는 숫자만 입력할 수 있습니다.');
    }
    if (strlen($receiptID) != 32) {
      throw new BarocertException('접수아이디는 32자 입니다.');
    }

    $result = $this->executeCURL('/KAKAO/CMS/' . $ClientCode .'/'. $receiptID, false, null);

    $ResponseCMSStatus = new ResponseCMSStatus();
    $ResponseCMSStatus->fromJsonInfo($result);
    return $ResponseCMSStatus;
  }

  /**
   * 출금동의 서명 검증
   */
  public function verifyCMS($ClientCode, $receiptID)
  {
    if (is_null($ClientCode) || empty($ClientCode)) {
      throw new BarocertException('이용기관코드가 입력되지 않았습니다.');
    }
    if (ereg("[^0-9]", $ClientCode)) {
      throw new BarocertException('이용기관코드는 숫자만 입력할 수 있습니다.');
    }
    if (strlen($ClientCode) != 12) {
      throw new BarocertException('이용기관코드는 12자 입니다.');
    }
    if (is_null($receiptID) || empty($receiptID)) {
      throw new BarocertException('접수아이디가 입력되지 않았습니다.');
    }
    if (ereg("[^0-9]", $receiptID)) {
      throw new BarocertException('접수아이디는 숫자만 입력할 수 있습니다.');
    }
    if (strlen($receiptID) != 32) {
      throw new BarocertException('접수아이디는 32자 입니다.');
    }

    $result = $this->executeCURL('/KAKAO/CMS/'. $ClientCode .'/'. $receiptID, true, null);

    $ResponseVerifyCMS = new ResponseVerifyCMS();
    $ResponseVerifyCMS->fromJsonInfo($result);
    return $ResponseVerifyCMS;
  }

  public function isNullorEmptyTitle($multiSignTokens){
    if($multiSignTokens == null) return true;
    foreach($multiSignTokens as $signTokens){
      if($signTokens == null) return true;
      if (is_null($signTokens -> reqTitle) || empty($signTokens -> reqTitle)) {
        return true;
      }
    }
    return false;
  }

  public function isNullorEmptyToken($multiSignTokens){
    if($multiSignTokens == null) return true;
    foreach($multiSignTokens as $signTokens){
      if($signTokens == null) return true;
      if (is_null($signTokens -> token) || empty($signTokens -> token)) {
        return true;
      }
    }
    return false;
  }

}

class RequestIdentity
{
	public $receiverHP;
	public $receiverName;
	public $receiverBirthday;
	public $ci;	
	public $reqTitle;
	public $expireIn;
	public $token;
	public $returnURL;
	public $appUseYN;
}

class ResponseIdentity
{
  public $receiptID;
	public $scheme;

  public function fromJsonInfo($jsonInfo)
  {
    isset($jsonInfo->receiptID) ? $this->receiptID = $jsonInfo->receiptID : null;
    isset($jsonInfo->scheme) ? $this->scheme = $jsonInfo->scheme : null;
  }
}

class ResponseIdentityStatus
{
  public $receiptID;
  public $clientCode;
  public $state;
  public $expireIn;
  public $callCenterName;
  public $callCenterNum;
  public $reqTitle;
  public $authCategory;
  public $returnURL;
  public $requestDT;
  public $viewDT;
  public $completeDT;
  public $expireDT;
  public $verifyDT;
  public $scheme;
  public $appUseYN;

  public function fromJsonInfo($jsonInfo)
  {
    isset($jsonInfo->receiptID) ? $this->receiptID = $jsonInfo->receiptID : null;
    isset($jsonInfo->clientCode) ? $this->clientCode = $jsonInfo->clientCode : null;
    isset($jsonInfo->state) ? $this->state = $jsonInfo->state : null;
    isset($jsonInfo->expireIn) ? $this->expireIn = $jsonInfo->expireIn : null;
    isset($jsonInfo->callCenterName) ? $this->callCenterName = $jsonInfo->callCenterName : null;
    isset($jsonInfo->callCenterNum) ? $this->callCenterNum = $jsonInfo->callCenterNum : null;
    isset($jsonInfo->reqTitle) ? $this->reqTitle = $jsonInfo->reqTitle : null;
    isset($jsonInfo->authCategory) ? $this->authCategory = $jsonInfo->authCategory : null;
    isset($jsonInfo->returnURL) ? $this->returnURL = $jsonInfo->returnURL : null;
    isset($jsonInfo->requestDT) ? $this->requestDT = $jsonInfo->requestDT : null;
    isset($jsonInfo->viewDT) ? $this->viewDT = $jsonInfo->viewDT : null;
    isset($jsonInfo->completeDT) ? $this->completeDT = $jsonInfo->completeDT : null;
    isset($jsonInfo->expireDT) ? $this->expireDT = $jsonInfo->expireDT : null;
    isset($jsonInfo->verifyDT) ? $this->verifyDT = $jsonInfo->verifyDT : null;
    isset($jsonInfo->scheme) ? $this->scheme = $jsonInfo->scheme : null;
    isset($jsonInfo->appUseYN) ? $this->appUseYN = $jsonInfo->appUseYN : null;
  }
}

class ResponseVerifyIdentity
{
  public $receiptID;
  public $state;
  public $signedData;

  public function fromJsonInfo($jsonInfo)
  {
    isset($jsonInfo->receiptID) ? $this->receiptID = $jsonInfo->receiptID : null;
    isset($jsonInfo->state) ? $this->state = $jsonInfo->state : null;
    isset($jsonInfo->signedData) ? $this->signedData = $jsonInfo->signedData : null;
  }
}



class RequestSign
{
  public $receiverHP;
  public $receiverName;
  public $receiverBirthday;
  public $ci;
  public $reqTitle;
  public $expireIn;
  public $token;
  public $tokenType;
  public $returnURL;
  public $appUseYN;
}

class ResponseSign
{
  public $receiptID;
  public $scheme;

  public function fromJsonInfo($jsonInfo)
  {
    isset($jsonInfo->receiptID) ? $this->receiptID = $jsonInfo->receiptID : null;
    isset($jsonInfo->scheme) ? $this->scheme = $jsonInfo->scheme : null;
  }
}


class ResponseSignStatus
{
  public $receiptID;
  public $clientCode;
  public $state;
  public $expireIn;
  public $callCenterName;
  public $callCenterNum;
  public $reqTitle;
  public $authCategory;
  public $returnURL;
  public $tokenType;
  public $requestDT;
  public $viewDT;
  public $completeDT;
  public $expireDT;
  public $verifyDT;
  public $scheme;
  public $appUseYN;

  public function fromJsonInfo($jsonInfo)
  {
    isset($jsonInfo->receiptID) ? $this->receiptID = $jsonInfo->receiptID : null;
    isset($jsonInfo->clientCode) ? $this->clientCode = $jsonInfo->clientCode : null;
    isset($jsonInfo->state) ? $this->state = $jsonInfo->state : null;
    isset($jsonInfo->expireIn) ? $this->expireIn = $jsonInfo->expireIn : null;
    isset($jsonInfo->callCenterName) ? $this->callCenterName = $jsonInfo->callCenterName : null;
    isset($jsonInfo->callCenterNum) ? $this->callCenterNum = $jsonInfo->callCenterNum : null;
    isset($jsonInfo->reqTitle) ? $this->reqTitle = $jsonInfo->reqTitle : null;
    isset($jsonInfo->authCategory) ? $this->authCategory = $jsonInfo->authCategory : null;
    isset($jsonInfo->returnURL) ? $this->returnURL = $jsonInfo->returnURL : null;
    isset($jsonInfo->tokenType) ? $this->tokenType = $jsonInfo->tokenType : null;
    isset($jsonInfo->requestDT) ? $this->requestDT = $jsonInfo->requestDT : null;
    isset($jsonInfo->viewDT) ? $this->viewDT = $jsonInfo->viewDT : null;
    isset($jsonInfo->completeDT) ? $this->completeDT = $jsonInfo->completeDT : null;
    isset($jsonInfo->expireDT) ? $this->expireDT = $jsonInfo->expireDT : null;
    isset($jsonInfo->verifyDT) ? $this->verifyDT = $jsonInfo->verifyDT : null;
    isset($jsonInfo->scheme) ? $this->scheme = $jsonInfo->scheme : null;
    isset($jsonInfo->appUseYN) ? $this->appUseYN = $jsonInfo->appUseYN : null;
  }
}

class ResponseVerifySign
{
  public $receiptID;
	public $state;
	public $signedData;
	public $ci;

  public function fromJsonInfo($jsonInfo)
  {
    isset($jsonInfo->receiptID) ? $this->receiptID = $jsonInfo->receiptID : null;
    isset($jsonInfo->state) ? $this->state = $jsonInfo->state : null;
    isset($jsonInfo->signedData) ? $this->signedData = $jsonInfo->signedData : null;
    isset($jsonInfo->ci) ? $this->ci = $jsonInfo->ci : null;
  }
}

class RequestMultiSign
{
  public $receiverHP;
  public $receiverName;
  public $receiverBirthday;
  public $ci;
  public $reqTitle;
  public $expireIn;

  public $tokens;

  public $tokenType;
  public $returnURL;
  public $appUseYN;
}

class MultiSignTokens
{
  public $reqTitle;
  public $token;
}

class ResponseMultiSign
{
  public $receiptID;
  public $scheme;

  public function fromJsonInfo($jsonInfo)
  {
    isset($jsonInfo->receiptID) ? $this->receiptID = $jsonInfo->receiptID : null;
    isset($jsonInfo->scheme) ? $this->scheme = $jsonInfo->scheme : null;
  }
}

class ResponseMultiSignStatus
{
  public $receiptID;
  public $clientCode;
  public $state;
  public $expireIn;
  public $callCenterName;
  public $callCenterNum;
  public $reqTitle;
  public $authCategory;
  public $returnURL;
  public $tokenType;
  public $requestDT;
  public $viewDT;
  public $completeDT;
  public $expireDT;
  public $verifyDT;
  public $scheme;
  public $appUseYN;

  public function fromJsonInfo($jsonInfo)
  {
    isset($jsonInfo->receiptID) ? $this->receiptID = $jsonInfo->receiptID : null;
    isset($jsonInfo->clientCode) ? $this->clientCode = $jsonInfo->clientCode : null;
    isset($jsonInfo->state) ? $this->state = $jsonInfo->state : null;
    isset($jsonInfo->expireIn) ? $this->expireIn = $jsonInfo->expireIn : null;
    isset($jsonInfo->callCenterName) ? $this->callCenterName = $jsonInfo->callCenterName : null;
    isset($jsonInfo->callCenterNum) ? $this->callCenterNum = $jsonInfo->callCenterNum : null;
    isset($jsonInfo->reqTitle) ? $this->reqTitle = $jsonInfo->reqTitle : null;
    isset($jsonInfo->authCategory) ? $this->authCategory = $jsonInfo->authCategory : null;
    isset($jsonInfo->returnURL) ? $this->returnURL = $jsonInfo->returnURL : null;
    isset($jsonInfo->tokenType) ? $this->tokenType = $jsonInfo->tokenType : null;
    isset($jsonInfo->requestDT) ? $this->requestDT = $jsonInfo->requestDT : null;
    isset($jsonInfo->viewDT) ? $this->viewDT = $jsonInfo->viewDT : null;
    isset($jsonInfo->completeDT) ? $this->completeDT = $jsonInfo->completeDT : null;
    isset($jsonInfo->expireDT) ? $this->expireDT = $jsonInfo->expireDT : null;
    isset($jsonInfo->verifyDT) ? $this->verifyDT = $jsonInfo->verifyDT : null;
    isset($jsonInfo->scheme) ? $this->scheme = $jsonInfo->scheme : null;
    isset($jsonInfo->appUseYN) ? $this->appUseYN = $jsonInfo->appUseYN : null;
  }
}

class ResponseVerifyMultiSign
{
  public $receiptID;
	public $state;
	public $multiSignedData;
	public $ci;

  public function fromJsonInfo($jsonInfo)
  {
    isset($jsonInfo->receiptID) ? $this->receiptID = $jsonInfo->receiptID : null;
    isset($jsonInfo->requestID) ? $this->requestID = $jsonInfo->requestID : null;
    isset($jsonInfo->state) ? $this->state = $jsonInfo->state : null;
    isset($jsonInfo->multiSignedData) ? $this->multiSignedData = $jsonInfo->multiSignedData : null;
    isset($jsonInfo->ci) ? $this->ci = $jsonInfo->ci : null;
  }
}

class RequestCMS
{
	public $requestID;
	public $receiverHP;
	public $receiverName;
	public $receiverBirthday;
	public $ci;
	public $reqTitle;
	public $expireIn;
	public $returnURL;	
	public $requestCorp;
	public $bankName;
	public $bankAccountNum;
	public $bankAccountName;
	public $bankAccountBirthday;
	public $bankServiceType;
	public $appUseYN;
}


class ResponseCMS
{
  public $receiptID;
  public $scheme;

  public function fromJsonInfo($jsonInfo)
  {
    isset($jsonInfo->receiptID) ? $this->receiptID = $jsonInfo->receiptID : null;
    isset($jsonInfo->scheme) ? $this->scheme = $jsonInfo->scheme : null;
  }
}

class ResponseCMSStatus
{
  public $receiptID;
  public $clientCode;
  public $state;
  public $expireIn;
  public $callCenterName;
  public $callCenterNum;
  public $reqTitle;
  public $authCategory;
  public $returnURL;
  public $tokenType;
  public $requestDT;
  public $viewDT;
  public $completeDT;
  public $expireDT;
  public $verifyDT;
  public $scheme;
  public $appUseYN;

  public function fromJsonInfo($jsonInfo)
  {
    isset($jsonInfo->receiptID) ? $this->receiptID = $jsonInfo->receiptID : null;
    isset($jsonInfo->clientCode) ? $this->clientCode = $jsonInfo->clientCode : null;
    isset($jsonInfo->state) ? $this->state = $jsonInfo->state : null;
    isset($jsonInfo->expireIn) ? $this->expireIn = $jsonInfo->expireIn : null;
    isset($jsonInfo->callCenterName) ? $this->callCenterName = $jsonInfo->callCenterName : null;
    isset($jsonInfo->callCenterNum) ? $this->callCenterNum = $jsonInfo->callCenterNum : null;
    isset($jsonInfo->reqTitle) ? $this->reqTitle = $jsonInfo->reqTitle : null;
    isset($jsonInfo->authCategory) ? $this->authCategory = $jsonInfo->authCategory : null;
    isset($jsonInfo->returnURL) ? $this->returnURL = $jsonInfo->returnURL : null;
    isset($jsonInfo->tokenType) ? $this->tokenType = $jsonInfo->tokenType : null;
    isset($jsonInfo->requestDT) ? $this->requestDT = $jsonInfo->requestDT : null;
    isset($jsonInfo->viewDT) ? $this->viewDT = $jsonInfo->viewDT : null;
    isset($jsonInfo->completeDT) ? $this->completeDT = $jsonInfo->completeDT : null;
    isset($jsonInfo->expireDT) ? $this->expireDT = $jsonInfo->expireDT : null;
    isset($jsonInfo->verifyDT) ? $this->verifyDT = $jsonInfo->verifyDT : null;
    isset($jsonInfo->scheme) ? $this->scheme = $jsonInfo->scheme : null;
    isset($jsonInfo->appUseYN) ? $this->appUseYN = $jsonInfo->appUseYN : null;
  }
}

class ResponseVerifyCMS
{
  public $receiptID;
	public $state;
	public $signedData;
	public $ci;

  public function fromJsonInfo($jsonInfo)
  {
    isset($jsonInfo->receiptID) ? $this->receiptID = $jsonInfo->receiptID : null;
    isset($jsonInfo->state) ? $this->state = $jsonInfo->state : null;
    isset($jsonInfo->signedData) ? $this->signedData = $jsonInfo->signedData : null;
    isset($jsonInfo->ci) ? $this->ci = $jsonInfo->ci : null;
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