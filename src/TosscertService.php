<?php

namespace Linkhub\Barocert;

require_once 'BaseService.php';
require 'Util.php';

class TosscertService extends BaseService
{
	public function __construct($LinkID, $SecretKey)
	{
		$scope = array('461', '462', '463', '464', '465');
		parent::__construct($LinkID, $SecretKey, $scope);
	}

	public function encrypt($data)
	{
		return parent::encryptTo($data, 'AES');
	}

	// deprecated
	public function sha256_base64url($data)
	{
		return parent::sha256ToBase64url($data);
	}

	public function sha256_base64url_file($data)
	{
		return parent::sha256ToBase64urlFile($data);
	}


	/**
	 * 본인확인 요청
	 */
	public function requestUserIdentity($ClientCode, $TossUserIdentity)
	{
		if (Stringz::isNullorEmpty($ClientCode)) {
			throw new BarocertException('이용기관코드가 입력되지 않았습니다.');
		}
		if (Stringz::isNumber($ClientCode) == 0) {
			throw new BarocertException('이용기관코드는 숫자만 입력할 수 있습니다.');
		}
		if (strlen($ClientCode) != 12) {
			throw new BarocertException('이용기관코드는 12자 입니다.');
		}
		if (Stringz::isNullorEmpty($TossUserIdentity)) {
			throw new BarocertException('본인확인 요청정보가 입력되지 않았습니다.');
		}
		if (Stringz::isNullorEmpty($TossUserIdentity->receiverHP)) {
			throw new BarocertException('수신자 휴대폰번호가 입력되지 않았습니다.');
		}
		if (Stringz::isNullorEmpty($TossUserIdentity->receiverName)) {
			throw new BarocertException('수신자 성명이 입력되지 않았습니다.');
		}
		if (Stringz::isNullorEmpty($TossUserIdentity->receiverBirthday)) {
			throw new BarocertException('생년월일이 입력되지 않았습니다.');
		}
		if (Stringz::isNullorEmpty($TossUserIdentity->expireIn)) {
			throw new BarocertException('만료시간이 입력되지 않았습니다.');
		}

		$postdata = json_encode($TossUserIdentity);

		$result = parent::executeCURL('/TOSS/UserIdentity/' . $ClientCode, true, $postdata);

		$TossUserIdentityReceipt = new TossUserIdentityReceipt();
		$TossUserIdentityReceipt->fromJsonInfo($result);
		return $TossUserIdentityReceipt;
	}

	/**
	 * 본인확인 상태확인
	 */
	public function getUserIdentityStatus($ClientCode, $ReceiptID)
	{
		if (Stringz::isNullorEmpty($ClientCode)) {
			throw new BarocertException('이용기관코드가 입력되지 않았습니다.');
		}
		if (Stringz::isNumber($ClientCode) == 0) {
			throw new BarocertException('이용기관코드는 숫자만 입력할 수 있습니다.');
		}
		if (strlen($ClientCode) != 12) {
			throw new BarocertException('이용기관코드는 12자 입니다.');
		}
		if (Stringz::isNullorEmpty($ReceiptID)) {
			throw new BarocertException('접수아이디가 입력되지 않았습니다.');
		}
		if (Stringz::isNumber($ReceiptID) == 0) {
			throw new BarocertException('접수아이디는 숫자만 입력할 수 있습니다.');
		}
		if (strlen($ReceiptID) != 32) {
			throw new BarocertException('접수아이디는 32자 입니다.');
		}

		$result = parent::executeCURL('/TOSS/UserIdentity/' . $ClientCode . '/' . $ReceiptID, false, null);

		$TossUserIdentityStatus = new TossUserIdentityStatus();
		$TossUserIdentityStatus->fromJsonInfo($result);
		return $TossUserIdentityStatus;
	}

	/**
	 * 본인확인 검증
	 */
	public function verifyUserIdentity($ClientCode, $ReceiptID)
	{
		if (Stringz::isNullorEmpty($ClientCode)) {
			throw new BarocertException('이용기관코드가 입력되지 않았습니다.');
		}
		if (Stringz::isNumber($ClientCode) == 0) {
			throw new BarocertException('이용기관코드는 숫자만 입력할 수 있습니다.');
		}
		if (strlen($ClientCode) != 12) {
			throw new BarocertException('이용기관코드는 12자 입니다.');
		}
		if (Stringz::isNullorEmpty($ReceiptID)) {
			throw new BarocertException('접수아이디가 입력되지 않았습니다.');
		}
		if (Stringz::isNumber($ReceiptID) == 0) {
			throw new BarocertException('접수아이디는 숫자만 입력할 수 있습니다.');
		}
		if (strlen($ReceiptID) != 32) {
			throw new BarocertException('접수아이디는 32자 입니다.');
		}

		$result = parent::executeCURL('/TOSS/UserIdentity/Verify/' . $ClientCode . '/' . $ReceiptID, true, null);

		$TossUserIdentityResult = new TossUserIdentityResult();
		$TossUserIdentityResult->fromJsonInfo($result);
		return $TossUserIdentityResult;
	}

	/**
	 * 본인인증 요청
	 */
	public function requestIdentity($ClientCode, $TossIdentity)
	{
		if (Stringz::isNullorEmpty($ClientCode)) {
			throw new BarocertException('이용기관코드가 입력되지 않았습니다.');
		}
		if (Stringz::isNumber($ClientCode) == 0) {
			throw new BarocertException('이용기관코드는 숫자만 입력할 수 있습니다.');
		}
		if (strlen($ClientCode) != 12) {
			throw new BarocertException('이용기관코드는 12자 입니다.');
		}
		if (Stringz::isNullorEmpty($TossIdentity)) {
			throw new BarocertException('본인인증 요청정보가 입력되지 않았습니다.');
		}
		if (Stringz::isNullorEmpty($TossIdentity->receiverHP)) {
			throw new BarocertException('수신자 휴대폰번호가 입력되지 않았습니다.');
		}
		if (Stringz::isNullorEmpty($TossIdentity->receiverName)) {
			throw new BarocertException('수신자 성명이 입력되지 않았습니다.');
		}
		if (Stringz::isNullorEmpty($TossIdentity->receiverBirthday)) {
			throw new BarocertException('생년월일이 입력되지 않았습니다.');
		}
		if (Stringz::isNullorEmpty($TossIdentity->expireIn)) {
			throw new BarocertException('만료시간이 입력되지 않았습니다.');
		}

		$postdata = json_encode($TossIdentity);

		$result = parent::executeCURL('/TOSS/Identity/' . $ClientCode, true, $postdata);

		$TossIdentityReceipt = new TossIdentityReceipt();
		$TossIdentityReceipt->fromJsonInfo($result);
		return $TossIdentityReceipt;
	}

	/**
	 * 본인인증 상태확인
	 */
	public function getIdentityStatus($ClientCode, $ReceiptID)
	{
		if (Stringz::isNullorEmpty($ClientCode)) {
			throw new BarocertException('이용기관코드가 입력되지 않았습니다.');
		}
		if (Stringz::isNumber($ClientCode) == 0) {
			throw new BarocertException('이용기관코드는 숫자만 입력할 수 있습니다.');
		}
		if (strlen($ClientCode) != 12) {
			throw new BarocertException('이용기관코드는 12자 입니다.');
		}
		if (Stringz::isNullorEmpty($ReceiptID)) {
			throw new BarocertException('접수아이디가 입력되지 않았습니다.');
		}
		if (Stringz::isNumber($ReceiptID) == 0) {
			throw new BarocertException('접수아이디는 숫자만 입력할 수 있습니다.');
		}
		if (strlen($ReceiptID) != 32) {
			throw new BarocertException('접수아이디는 32자 입니다.');
		}

		$result = parent::executeCURL('/TOSS/Identity/' . $ClientCode . '/' . $ReceiptID, false, null);

		$TossIdentityStatus = new TossIdentityStatus();
		$TossIdentityStatus->fromJsonInfo($result);
		return $TossIdentityStatus;
	}

	/**
	 * 본인인증 검증
	 */
	public function verifyIdentity($ClientCode, $ReceiptID)
	{
		if (Stringz::isNullorEmpty($ClientCode)) {
			throw new BarocertException('이용기관코드가 입력되지 않았습니다.');
		}
		if (Stringz::isNumber($ClientCode) == 0) {
			throw new BarocertException('이용기관코드는 숫자만 입력할 수 있습니다.');
		}
		if (strlen($ClientCode) != 12) {
			throw new BarocertException('이용기관코드는 12자 입니다.');
		}
		if (Stringz::isNullorEmpty($ReceiptID)) {
			throw new BarocertException('접수아이디가 입력되지 않았습니다.');
		}
		if (Stringz::isNumber($ReceiptID) == 0) {
			throw new BarocertException('접수아이디는 숫자만 입력할 수 있습니다.');
		}
		if (strlen($ReceiptID) != 32) {
			throw new BarocertException('접수아이디는 32자 입니다.');
		}

		$result = parent::executeCURL('/TOSS/Identity/Verify/' . $ClientCode . '/' . $ReceiptID, true, null);

		$TossIdentityResult = new TossIdentityResult();
		$TossIdentityResult->fromJsonInfo($result);
		return $TossIdentityResult;
	}

	/**
	 * 전자서명 요청(단건)
	 */
	public function RequestSign($ClientCode, $TossSign)
	{
		if (Stringz::isNullorEmpty($ClientCode)) {
			throw new BarocertException('이용기관코드가 입력되지 않았습니다.');
		}
		if (Stringz::isNumber($ClientCode) == 0) {
			throw new BarocertException('이용기관코드는 숫자만 입력할 수 있습니다.');
		}
		if (strlen($ClientCode) != 12) {
			throw new BarocertException('이용기관코드는 12자 입니다.');
		}
		if (Stringz::isNullorEmpty($TossSign)) {
			throw new BarocertException('전자서명 요청정보가 입력되지 않았습니다.');
		}
		if (Stringz::isNullorEmpty($TossSign->receiverHP)) {
			throw new BarocertException('수신자 휴대폰번호가 입력되지 않았습니다.');
		}
		if (Stringz::isNullorEmpty($TossSign->receiverName)) {
			throw new BarocertException('수신자 성명이 입력되지 않았습니다.');
		}
		if (Stringz::isNullorEmpty($TossSign->receiverBirthday)) {
			throw new BarocertException('생년월일이 입력되지 않았습니다.');
		}
		if (Stringz::isNullorEmpty($TossSign->expireIn)) {
			throw new BarocertException('만료시간이 입력되지 않았습니다.');
		}
		if (Stringz::isNullorEmpty($TossSign->reqTitle)) {
			throw new BarocertException('인증요청 메시지 제목이 입력되지 않았습니다.');
		}
		if (Stringz::isNullorEmpty($TossSign->token)) {
			throw new BarocertException('토큰 원문이 입력되지 않았습니다.');
		}
		if (Stringz::isNullorEmpty($TossSign->tokenType)) {
			throw new BarocertException('원문 유형이 입력되지 않았습니다.');
		}

		$postdata = json_encode($TossSign);

		$result = parent::executeCURL('/TOSS/Sign/' . $ClientCode, true, $postdata);

		$TossSignReceipt = new TossSignReceipt();
		$TossSignReceipt->fromJsonInfo($result);
		return $TossSignReceipt;
	}


	/**
	 * 전자서명 상태 확인(단건)
	 */
	public function getSignStatus($ClientCode, $ReceiptID)
	{
		if (Stringz::isNullorEmpty($ClientCode)) {
			throw new BarocertException('이용기관코드가 입력되지 않았습니다.');
		}
		if (Stringz::isNumber($ClientCode) == 0) {
			throw new BarocertException('이용기관코드는 숫자만 입력할 수 있습니다.');
		}
		if (strlen($ClientCode) != 12) {
			throw new BarocertException('이용기관코드는 12자 입니다.');
		}
		if (Stringz::isNullorEmpty($ReceiptID)) {
			throw new BarocertException('접수아이디가 입력되지 않았습니다.');
		}
		if (Stringz::isNumber($ReceiptID) == 0) {
			throw new BarocertException('접수아이디는 숫자만 입력할 수 있습니다.');
		}
		if (strlen($ReceiptID) != 32) {
			throw new BarocertException('접수아이디는 32자 입니다.');
		}

		$result = parent::executeCURL('/TOSS/Sign/' . $ClientCode . '/' . $ReceiptID, false, null);

		$TossSignStatus = new TossSignStatus();
		$TossSignStatus->fromJsonInfo($result);
		return $TossSignStatus;
	}

	/**
	 * 전자서명 검증(단건)
	 */
	public function verifySign($ClientCode, $ReceiptID)
	{
		if (Stringz::isNullorEmpty($ClientCode)) {
			throw new BarocertException('이용기관코드가 입력되지 않았습니다.');
		}
		if (Stringz::isNumber($ClientCode) == 0) {
			throw new BarocertException('이용기관코드는 숫자만 입력할 수 있습니다.');
		}
		if (strlen($ClientCode) != 12) {
			throw new BarocertException('이용기관코드는 12자 입니다.');
		}
		if (Stringz::isNullorEmpty($ReceiptID)) {
			throw new BarocertException('접수아이디가 입력되지 않았습니다.');
		}
		if (Stringz::isNumber($ReceiptID) == 0) {
			throw new BarocertException('접수아이디는 숫자만 입력할 수 있습니다.');
		}
		if (strlen($ReceiptID) != 32) {
			throw new BarocertException('접수아이디는 32자 입니다.');
		}

		$result = parent::executeCURL('/TOSS/Sign/Verify/' . $ClientCode . '/' . $ReceiptID, true, null);

		$TossSignResult = new TossSignResult();
		$TossSignResult->fromJsonInfo($result);
		return $TossSignResult;
	}

	/**
	 * 전자서명 요청(복수)
	 */
	public function requestMultiSign($ClientCode, $TossMultiSign)
	{
		if (Stringz::isNullorEmpty($ClientCode)) {
			throw new BarocertException('이용기관코드가 입력되지 않았습니다.');
		}
		if (Stringz::isNullorEmpty($ClientCode)) {
			throw new BarocertException('이용기관코드가 입력되지 않았습니다.');
		}
		if (Stringz::isNumber($ClientCode) == 0) {
			throw new BarocertException('이용기관코드는 숫자만 입력할 수 있습니다.');
		}
		if (strlen($ClientCode) != 12) {
			throw new BarocertException('이용기관코드는 12자 입니다.');
		}
		if (Stringz::isNullorEmpty($TossMultiSign)) {
			throw new BarocertException('전자서명 요청정보가 입력되지 않았습니다.');
		}
		if (Stringz::isNullorEmpty($TossMultiSign->receiverHP)) {
			throw new BarocertException('수신자 휴대폰번호가 입력되지 않았습니다.');
		}
		if (Stringz::isNullorEmpty($TossMultiSign->receiverName)) {
			throw new BarocertException('수신자 성명이 입력되지 않았습니다.');
		}
		if (Stringz::isNullorEmpty($TossMultiSign->receiverBirthday)) {
			throw new BarocertException('생년월일이 입력되지 않았습니다.');
		}
		if (Stringz::isNullorEmpty($TossMultiSign->expireIn)) {
			throw new BarocertException('만료시간이 입력되지 않았습니다.');
		}
		if ($this->isNullorEmptyToken($TossMultiSign->tokens)) {
			throw new BarocertException('토큰 원문이 입력되지 않았습니다.');
		}
		if ($this->isNullorEmptyTokenType($TossMultiSign->tokens)) {
			throw new BarocertException('원문 유형이 입력되지 않았습니다.');
		}

		$postdata = json_encode($TossMultiSign);
		$result = parent::executeCURL('/TOSS/MultiSign/' . $ClientCode, true, $postdata);

		$TossMultiSignReceipt = new TossMultiSignReceipt();
		$TossMultiSignReceipt->fromJsonInfo($result);
		return $TossMultiSignReceipt;
	}

	/**
	 * 전자서명 상태 확인(복수)
	 */
	public function getMultiSignStatus($ClientCode, $ReceiptID)
	{
		if (Stringz::isNullorEmpty($ClientCode)) {
			throw new BarocertException('이용기관코드가 입력되지 않았습니다.');
		}
		if (Stringz::isNumber($ClientCode) == 0) {
			throw new BarocertException('이용기관코드는 숫자만 입력할 수 있습니다.');
		}
		if (strlen($ClientCode) != 12) {
			throw new BarocertException('이용기관코드는 12자 입니다.');
		}
		if (Stringz::isNullorEmpty($ReceiptID)) {
			throw new BarocertException('접수아이디가 입력되지 않았습니다.');
		}
		if (Stringz::isNumber($ReceiptID) == 0) {
			throw new BarocertException('접수아이디는 숫자만 입력할 수 있습니다.');
		}
		if (strlen($ReceiptID) != 32) {
			throw new BarocertException('접수아이디는 32자 입니다.');
		}

		$result = parent::executeCURL('/TOSS/MultiSign/' . $ClientCode . '/' . $ReceiptID, false, null);

		$TossMultiSignStatus = new TossMultiSignStatus();
		$TossMultiSignStatus->fromJsonInfo($result);
		return $TossMultiSignStatus;
	}

	/**
	 * 전자서명 검증(복수)
	 */
	public function verifyMultiSign($ClientCode, $ReceiptID)
	{
		if (Stringz::isNullorEmpty($ClientCode)) {
			throw new BarocertException('이용기관코드가 입력되지 않았습니다.');
		}
		if (Stringz::isNumber($ClientCode) == 0) {
			throw new BarocertException('이용기관코드는 숫자만 입력할 수 있습니다.');
		}
		if (strlen($ClientCode) != 12) {
			throw new BarocertException('이용기관코드는 12자 입니다.');
		}
		if (Stringz::isNullorEmpty($ReceiptID)) {
			throw new BarocertException('접수아이디가 입력되지 않았습니다.');
		}
		if (Stringz::isNumber($ReceiptID) == 0) {
			throw new BarocertException('접수아이디는 숫자만 입력할 수 있습니다.');
		}
		if (strlen($ReceiptID) != 32) {
			throw new BarocertException('접수아이디는 32자 입니다.');
		}

		$result = parent::executeCURL('/TOSS/MultiSign/Verify/' . $ClientCode . '/' . $ReceiptID, true, null);

		$TossMultiSignResult = new TossMultiSignResult();
		$TossMultiSignResult->fromJsonInfo($result);
		return $TossMultiSignResult;
	}

	/**
	 * 출금동의 요청
	 */
	public function requestCMS($ClientCode, $TossCMS)
	{
		if (Stringz::isNullorEmpty($ClientCode)) {
			throw new BarocertException('이용기관코드가 입력되지 않았습니다.');
		}
		if (Stringz::isNumber($ClientCode) == 0) {
			throw new BarocertException('이용기관코드는 숫자만 입력할 수 있습니다.');
		}
		if (strlen($ClientCode) != 12) {
			throw new BarocertException('이용기관코드는 12자 입니다.');
		}
		if (Stringz::isNullorEmpty($TossCMS)) {
			throw new BarocertException('출금동의 요청정보가 입력되지 않았습니다.');
		}
		if (Stringz::isNullorEmpty($TossCMS->receiverHP)) {
			throw new BarocertException('수신자 휴대폰번호가 입력되지 않았습니다.');
		}
		if (Stringz::isNullorEmpty($TossCMS->receiverName)) {
			throw new BarocertException('수신자 성명이 입력되지 않았습니다.');
		}
		if (Stringz::isNullorEmpty($TossCMS->receiverBirthday)) {
			throw new BarocertException('생년월일이 입력되지 않았습니다.');
		}
		if (Stringz::isNullorEmpty($TossCMS->expireIn)) {
			throw new BarocertException('만료시간이 입력되지 않았습니다.');
		}
		if (Stringz::isNullorEmpty($TossCMS->requestCorp)) {
			throw new BarocertException('청구기관명이 입력되지 않았습니다.');
		}
		if (Stringz::isNullorEmpty($TossCMS->bankName)) {
			throw new BarocertException('은행명이 입력되지 않았습니다.');
		}
		if (Stringz::isNullorEmpty($TossCMS->bankAccountNum)) {
			throw new BarocertException('계좌번호가 입력되지 않았습니다.');
		}
		if (Stringz::isNullorEmpty($TossCMS->bankAccountName)) {
			throw new BarocertException('예금주명이 입력되지 않았습니다.');
		}
		if (Stringz::isNullorEmpty($TossCMS->bankAccountBirthday)) {
			throw new BarocertException('예금주 생년월일이 입력되지 않았습니다.');
		}

		$postdata = json_encode($TossCMS);

		$result = parent::executeCURL('/TOSS/CMS/' . $ClientCode, true, $postdata);

		$TossCMSReceipt = new TossCMSReceipt();
		$TossCMSReceipt->fromJsonInfo($result);
		return $TossCMSReceipt;
	}

	/**
	 * 출금동의 상태확인
	 */
	public function getCMSStatus($ClientCode, $ReceiptID)
	{
		if (Stringz::isNullorEmpty($ClientCode)) {
			throw new BarocertException('이용기관코드가 입력되지 않았습니다.');
		}
		if (Stringz::isNumber($ClientCode) == 0) {
			throw new BarocertException('이용기관코드는 숫자만 입력할 수 있습니다.');
		}
		if (strlen($ClientCode) != 12) {
			throw new BarocertException('이용기관코드는 12자 입니다.');
		}
		if (Stringz::isNullorEmpty($ReceiptID)) {
			throw new BarocertException('접수아이디가 입력되지 않았습니다.');
		}
		if (Stringz::isNumber($ReceiptID) == 0) {
			throw new BarocertException('접수아이디는 숫자만 입력할 수 있습니다.');
		}
		if (strlen($ReceiptID) != 32) {
			throw new BarocertException('접수아이디는 32자 입니다.');
		}

		$result = parent::executeCURL('/TOSS/CMS/' . $ClientCode . '/' . $ReceiptID, false, null);

		$TossCMSStatus = new TossCMSStatus();
		$TossCMSStatus->fromJsonInfo($result);
		return $TossCMSStatus;
	}

	/**
	 * 출금동의 검증
	 */
	public function verifyCMS($ClientCode, $ReceiptID)
	{
		if (Stringz::isNullorEmpty($ClientCode)) {
			throw new BarocertException('이용기관코드가 입력되지 않았습니다.');
		}
		if (Stringz::isNumber($ClientCode) == 0) {
			throw new BarocertException('이용기관코드는 숫자만 입력할 수 있습니다.');
		}
		if (strlen($ClientCode) != 12) {
			throw new BarocertException('이용기관코드는 12자 입니다.');
		}
		if (Stringz::isNullorEmpty($ReceiptID)) {
			throw new BarocertException('접수아이디가 입력되지 않았습니다.');
		}
		if (Stringz::isNumber($ReceiptID) == 0) {
			throw new BarocertException('접수아이디는 숫자만 입력할 수 있습니다.');
		}
		if (strlen($ReceiptID) != 32) {
			throw new BarocertException('접수아이디는 32자 입니다.');
		}

		$result = parent::executeCURL('/TOSS/CMS/Verify/' . $ClientCode . '/' . $ReceiptID, true, null);

		$TossCMSResult = new TossCMSResult();
		$TossCMSResult->fromJsonInfo($result);
		return $TossCMSResult;
	}

	public function isNullorEmptyTokenType($multiSignTokens)
	{
		if ($multiSignTokens == null) return true;
		foreach ($multiSignTokens as $signTokens) {
			if ($signTokens == null) return true;
			if (is_null($signTokens->tokenType) || empty($signTokens->tokenType)) {
				return true;
			}
		}
		return false;
	}

	public function isNullorEmptyToken($multiSignTokens)
	{
		if ($multiSignTokens == null) return true;
		foreach ($multiSignTokens as $signTokens) {
			if ($signTokens == null) return true;
			if (is_null($signTokens->token) || empty($signTokens->token)) {
				return true;
			}
		}
		return false;
	}

}


class TossUserIdentity
{
	public $receiverHP;
	public $receiverName;
	public $receiverBirthday;
	public $expireIn;
	public $token;
	public $returnURL;
	public $deviceOSType;
	public $appUseYN;
}

class TossUserIdentityReceipt
{
	public $receiptID;
	public $scheme;

	public function fromJsonInfo($jsonInfo)
	{
		isset($jsonInfo->receiptID) ? $this->receiptID = $jsonInfo->receiptID : null;
		isset($jsonInfo->scheme) ? $this->scheme = $jsonInfo->scheme : null;
	}
}

class TossUserIdentityStatus
{
	public $receiptID;
	public $clientCode;
	public $state;
	public $expireDT;

	public function fromJsonInfo($jsonInfo)
	{
		isset($jsonInfo->receiptID) ? $this->receiptID = $jsonInfo->receiptID : null;
		isset($jsonInfo->clientCode) ? $this->clientCode = $jsonInfo->clientCode : null;
		isset($jsonInfo->state) ? $this->state = $jsonInfo->state : null;
		isset($jsonInfo->expireDT) ? $this->expireDT = $jsonInfo->expireDT : null;
	}
}

class TossUserIdentityResult
{
	public $receiptID;
	public $state;
	public $receiverName;
	public $receiverYear;
	public $receiverDay;
	public $receiverGender;
	public $receiverForeign;
	public $receiverAgeGroup;
	public $signedData;
	public $ci;
	public $di;

	public function fromJsonInfo($jsonInfo)
	{
		isset($jsonInfo->receiptID) ? $this->receiptID = $jsonInfo->receiptID : null;
		isset($jsonInfo->state) ? $this->state = $jsonInfo->state : null;
		isset($jsonInfo->receiverName) ? $this->receiverName = $jsonInfo->receiverName : null;
		isset($jsonInfo->receiverYear) ? $this->receiverYear = $jsonInfo->receiverYear : null;
		isset($jsonInfo->receiverDay) ? $this->receiverDay = $jsonInfo->receiverDay : null;
		isset($jsonInfo->receiverGender) ? $this->receiverGender = $jsonInfo->receiverGender : null;
		isset($jsonInfo->receiverForeign) ? $this->receiverForeign = $jsonInfo->receiverForeign : null;
		isset($jsonInfo->receiverAgeGroup) ? $this->receiverAgeGroup = $jsonInfo->receiverAgeGroup : null;
		isset($jsonInfo->signedData) ? $this->signedData = $jsonInfo->signedData : null;
		isset($jsonInfo->ci) ? $this->ci = $jsonInfo->ci : null;
		isset($jsonInfo->di) ? $this->di = $jsonInfo->di : null;
	}
}

class TossIdentity
{
	public $receiverHP;
	public $receiverName;
	public $receiverBirthday;
	public $expireIn;
	public $token;
	public $returnURL;
	public $deviceOSType;
	public $appUseYN;
}

class TossIdentityReceipt
{
	public $receiptID;
	public $scheme;

	public function fromJsonInfo($jsonInfo)
	{
		isset($jsonInfo->receiptID) ? $this->receiptID = $jsonInfo->receiptID : null;
		isset($jsonInfo->scheme) ? $this->scheme = $jsonInfo->scheme : null;
	}
}

class TossIdentityStatus
{
	public $receiptID;
	public $clientCode;
	public $state;
	public $expireDT;

	public function fromJsonInfo($jsonInfo)
	{
		isset($jsonInfo->receiptID) ? $this->receiptID = $jsonInfo->receiptID : null;
		isset($jsonInfo->clientCode) ? $this->clientCode = $jsonInfo->clientCode : null;
		isset($jsonInfo->state) ? $this->state = $jsonInfo->state : null;
		isset($jsonInfo->expireDT) ? $this->expireDT = $jsonInfo->expireDT : null;
	}
}

class TossIdentityResult
{
	public $receiptID;
	public $state;
	public $receiverName;
	public $receiverYear;
	public $receiverDay;
	public $receiverHP;
	public $receiverGender;
	public $receiverEmail;
	public $receiverForeign;
	public $receiverAddress;
	public $receiverAddressDetails;
	public $receiverZipCode;
	public $receiverAgeGroup;
	public $signedData;
	public $ci;

	public function fromJsonInfo($jsonInfo)
	{
		isset($jsonInfo->receiptID) ? $this->receiptID = $jsonInfo->receiptID : null;
		isset($jsonInfo->state) ? $this->state = $jsonInfo->state : null;
		isset($jsonInfo->receiverName) ? $this->receiverName = $jsonInfo->receiverName : null;
		isset($jsonInfo->receiverYear) ? $this->receiverYear = $jsonInfo->receiverYear : null;
		isset($jsonInfo->receiverDay) ? $this->receiverDay = $jsonInfo->receiverDay : null;
		isset($jsonInfo->receiverHP) ? $this->receiverHP = $jsonInfo->receiverHP : null;
		isset($jsonInfo->receiverGender) ? $this->receiverGender = $jsonInfo->receiverGender : null;
		isset($jsonInfo->receiverEmail) ? $this->receiverEmail = $jsonInfo->receiverEmail : null;
		isset($jsonInfo->receiverForeign) ? $this->receiverForeign = $jsonInfo->receiverForeign : null;
		isset($jsonInfo->receiverAddress) ? $this->receiverAddress = $jsonInfo->receiverAddress : null;
		isset($jsonInfo->receiverAddressDetails) ? $this->receiverAddressDetails = $jsonInfo->receiverAddressDetails : null;
		isset($jsonInfo->receiverZipCode) ? $this->receiverZipCode = $jsonInfo->receiverZipCode : null;
		isset($jsonInfo->receiverAgeGroup) ? $this->receiverAgeGroup = $jsonInfo->receiverAgeGroup : null;
		isset($jsonInfo->signedData) ? $this->signedData = $jsonInfo->signedData : null;
		isset($jsonInfo->ci) ? $this->ci = $jsonInfo->ci : null;
	}
}

class TossSign
{
	public $receiverHP;
	public $receiverName;
	public $receiverBirthday;
	public $reqTitle;
	public $expireIn;
	public $token;
	public $tokenType;
	public $returnURL;
	public $deviceOSType;
	public $appUseYN;
}

class TossSignReceipt
{
	public $receiptID;
	public $scheme;

	public function fromJsonInfo($jsonInfo)
	{
		isset($jsonInfo->receiptID) ? $this->receiptID = $jsonInfo->receiptID : null;
		isset($jsonInfo->scheme) ? $this->scheme = $jsonInfo->scheme : null;
	}
}

class TossSignStatus
{
	public $receiptID;
	public $clientCode;
	public $state;
	public $expireDT;

	public function fromJsonInfo($jsonInfo)
	{
		isset($jsonInfo->receiptID) ? $this->receiptID = $jsonInfo->receiptID : null;
		isset($jsonInfo->clientCode) ? $this->clientCode = $jsonInfo->clientCode : null;
		isset($jsonInfo->state) ? $this->state = $jsonInfo->state : null;
		isset($jsonInfo->expireDT) ? $this->expireDT = $jsonInfo->expireDT : null;
	}
}

class TossSignResult
{
	public $receiptID;
	public $state;
	public $receiverName;
	public $receiverYear;
	public $receiverDay;
	public $receiverHP;
	public $receiverGender;
	public $receiverEmail;
	public $receiverForeign;
	public $receiverAddress;
	public $receiverAddressDetails;
	public $receiverZipCode;
	public $receiverAgeGroup;
	public $signedData;
	public $ci;
	public $di;

	public function fromJsonInfo($jsonInfo)
	{
		isset($jsonInfo->receiptID) ? $this->receiptID = $jsonInfo->receiptID : null;
		isset($jsonInfo->state) ? $this->state = $jsonInfo->state : null;
		isset($jsonInfo->receiverName) ? $this->receiverName = $jsonInfo->receiverName : null;
		isset($jsonInfo->receiverYear) ? $this->receiverYear = $jsonInfo->receiverYear : null;
		isset($jsonInfo->receiverDay) ? $this->receiverDay = $jsonInfo->receiverDay : null;
		isset($jsonInfo->receiverHP) ? $this->receiverHP = $jsonInfo->receiverHP : null;
		isset($jsonInfo->receiverGender) ? $this->receiverGender = $jsonInfo->receiverGender : null;
		isset($jsonInfo->receiverEmail) ? $this->receiverEmail = $jsonInfo->receiverEmail : null;
		isset($jsonInfo->receiverForeign) ? $this->receiverForeign = $jsonInfo->receiverForeign : null;
		isset($jsonInfo->receiverAddress) ? $this->receiverAddress = $jsonInfo->receiverAddress : null;
		isset($jsonInfo->receiverAddressDetails) ? $this->receiverAddressDetails = $jsonInfo->receiverAddressDetails : null;
		isset($jsonInfo->receiverZipCode) ? $this->receiverZipCode = $jsonInfo->receiverZipCode : null;
		isset($jsonInfo->receiverAgeGroup) ? $this->receiverAgeGroup = $jsonInfo->receiverAgeGroup : null;
		isset($jsonInfo->signedData) ? $this->signedData = $jsonInfo->signedData : null;
		isset($jsonInfo->ci) ? $this->ci = $jsonInfo->ci : null;
		isset($jsonInfo->di) ? $this->di = $jsonInfo->di : null;
	}
}

class TossMultiSign
{
	public $receiverHP;
	public $receiverName;
	public $receiverBirthday;
	public $expireIn;
	public $tokens;
	public $returnURL;
	public $deviceOSType;
	public $appUseYN;
}

class TossMultiSignTokens
{
	public $reqTitle;
	public $tokenType;
	public $token;
}

class TossMultiSignReceipt
{
	public $receiptID;
	public $scheme;

	public function fromJsonInfo($jsonInfo)
	{
		isset($jsonInfo->receiptID) ? $this->receiptID = $jsonInfo->receiptID : null;
		isset($jsonInfo->scheme) ? $this->scheme = $jsonInfo->scheme : null;
	}
}

class TossMultiSignStatus
{
	public $receiptID;
	public $clientCode;
	public $state;
	public $expireDT;

	public function fromJsonInfo($jsonInfo)
	{
		isset($jsonInfo->receiptID) ? $this->receiptID = $jsonInfo->receiptID : null;
		isset($jsonInfo->clientCode) ? $this->clientCode = $jsonInfo->clientCode : null;
		isset($jsonInfo->state) ? $this->state = $jsonInfo->state : null;
		isset($jsonInfo->expireDT) ? $this->expireDT = $jsonInfo->expireDT : null;
	}
}

class TossMultiSignResult
{
	public $receiptID;
	public $state;
	public $receiverName;
	public $receiverYear;
	public $receiverDay;
	public $receiverHP;
	public $receiverGender;
	public $receiverEmail;
	public $receiverForeign;
	public $multiSignedData;
	public $ci;
	public $di;

	public function fromJsonInfo($jsonInfo)
	{
		isset($jsonInfo->receiptID) ? $this->receiptID = $jsonInfo->receiptID : null;
		isset($jsonInfo->state) ? $this->state = $jsonInfo->state : null;
		isset($jsonInfo->receiverName) ? $this->receiverName = $jsonInfo->receiverName : null;
		isset($jsonInfo->receiverYear) ? $this->receiverYear = $jsonInfo->receiverYear : null;
		isset($jsonInfo->receiverDay) ? $this->receiverDay = $jsonInfo->receiverDay : null;
		isset($jsonInfo->receiverHP) ? $this->receiverHP = $jsonInfo->receiverHP : null;
		isset($jsonInfo->receiverGender) ? $this->receiverGender = $jsonInfo->receiverGender : null;
		isset($jsonInfo->receiverEmail) ? $this->receiverEmail = $jsonInfo->receiverEmail : null;
		isset($jsonInfo->receiverForeign) ? $this->receiverForeign = $jsonInfo->receiverForeign : null;
		isset($jsonInfo->multiSignedData) ? $this->multiSignedData = $jsonInfo->multiSignedData : null;
		isset($jsonInfo->ci) ? $this->ci = $jsonInfo->ci : null;
		isset($jsonInfo->di) ? $this->di = $jsonInfo->di : null;
	}
}

class TossCMS
{
	public $receiverHP;
	public $receiverName;
	public $receiverBirthday;
	public $reqTitle;
	public $expireIn;
	public $requestCorp;
	public $bankName;
	public $bankAccountNum;
	public $bankAccountName;
	public $bankAccountBirthday;
	public $returnURL;
	public $deviceOSType;
	public $appUseYN;
}

class TossCMSReceipt
{
	public $receiptID;
	public $scheme;

	public function fromJsonInfo($jsonInfo)
	{
		isset($jsonInfo->receiptID) ? $this->receiptID = $jsonInfo->receiptID : null;
		isset($jsonInfo->scheme) ? $this->scheme = $jsonInfo->scheme : null;
	}
}

class TossCMSStatus
{
	public $receiptID;
	public $clientCode;
	public $state;
	public $expireDT;

	public function fromJsonInfo($jsonInfo)
	{
		isset($jsonInfo->receiptID) ? $this->receiptID = $jsonInfo->receiptID : null;
		isset($jsonInfo->clientCode) ? $this->clientCode = $jsonInfo->clientCode : null;
		isset($jsonInfo->state) ? $this->state = $jsonInfo->state : null;
		isset($jsonInfo->expireDT) ? $this->expireDT = $jsonInfo->expireDT : null;
	}
}

class TossCMSResult
{
	public $receiptID;
	public $state;
	public $receiverName;
	public $receiverYear;
	public $receiverDay;
	public $receiverHP;
	public $receiverGender;
	public $receiverEmail;
	public $receiverForeign;
	public $receiverAddress;
	public $receiverAddressDetails;
	public $receiverZipCode;
	public $receiverAgeGroup;
	public $signedData;
	public $ci;
	public $di;

	public function fromJsonInfo($jsonInfo)
	{
		isset($jsonInfo->receiptID) ? $this->receiptID = $jsonInfo->receiptID : null;
		isset($jsonInfo->state) ? $this->state = $jsonInfo->state : null;
		isset($jsonInfo->receiverName) ? $this->receiverName = $jsonInfo->receiverName : null;
		isset($jsonInfo->receiverYear) ? $this->receiverYear = $jsonInfo->receiverYear : null;
		isset($jsonInfo->receiverDay) ? $this->receiverDay = $jsonInfo->receiverDay : null;
		isset($jsonInfo->receiverHP) ? $this->receiverHP = $jsonInfo->receiverHP : null;
		isset($jsonInfo->receiverGender) ? $this->receiverGender = $jsonInfo->receiverGender : null;
		isset($jsonInfo->receiverEmail) ? $this->receiverEmail = $jsonInfo->receiverEmail : null;
		isset($jsonInfo->receiverForeign) ? $this->receiverForeign = $jsonInfo->receiverForeign : null;
		isset($jsonInfo->receiverAddress) ? $this->receiverAddress = $jsonInfo->receiverAddress : null;
		isset($jsonInfo->receiverAddressDetails) ? $this->receiverAddressDetails = $jsonInfo->receiverAddressDetails : null;
		isset($jsonInfo->receiverZipCode) ? $this->receiverZipCode = $jsonInfo->receiverZipCode : null;
		isset($jsonInfo->receiverAgeGroup) ? $this->receiverAgeGroup = $jsonInfo->receiverAgeGroup : null;
		isset($jsonInfo->signedData) ? $this->signedData = $jsonInfo->signedData : null;
		isset($jsonInfo->ci) ? $this->ci = $jsonInfo->ci : null;
		isset($jsonInfo->di) ? $this->di = $jsonInfo->di : null;
	}
}

?>
