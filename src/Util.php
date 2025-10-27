<?php

namespace Linkhub\Barocert;

class Stringz
{
	public static function isNumber($str)
	{
		return preg_match("/^[0-9]*$/", $str);
	}

	public static function isNullorEmpty($str)
	{
		return (is_null($str) || empty($str));
	}
}

?>