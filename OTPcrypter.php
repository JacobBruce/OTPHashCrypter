<?php
/*
* @author J.D. Bruce
* www.j-d-b.net
*/

require_once(dirname(__FILE__).'/Random.php');
define('HASH_ALG', 'sha256');
define('HASH_LEN', 64);
ini_set('memory_limit', -1);
ini_set('max_execution_time', 300);

class OTPHashCrypter {

	private $seed_key;
	
	private function set_key($key_str) {
	
		$this->seed_key = (string) $key_str;
	}
	
	public function __construct($key_str='') {
	
		$this->set_key($key_str);
	}
	
	public function random_str($length=HASH_LEN) {
		
		return crypt_random_string($length);
	}
	
	public function read_file($filename) {

		$handle = fopen($filename, "rb");
		$contents = fread($handle, filesize($filename));
		
		fclose($handle);
		return $contents;
	}
	
	public function encrypt($binary, $password='') {
	
		if (($password == '') && ($this->seed_key != '')) {
			$password = $this->seed_key;
		}

		$file_hex = bin2hex($binary);
		$file_len = strlen($file_hex);
		$hash_slt = hash(HASH_ALG, $this->random_str());
		$hash_nxt = hash(HASH_ALG, $password.$hash_slt);
		$hash_req = ceil($file_len / HASH_LEN);
		$key_hex = '';
		
		for ($i=0;$i<$hash_req;$i++) {
			$hash_nxt = hash(HASH_ALG, $hash_nxt);
			$key_hex .= $hash_nxt;
		}
		
		$key_hex = substr($key_hex, 0, $file_len);
		$enc_bin = pack('H*', $key_hex) ^ $binary;
		return pack('H*', $hash_slt).$enc_bin;
	}
	
	public function decrypt($binary, $password='') {
	
		if (($password == '') && ($this->seed_key != '')) {
			$password = $this->seed_key;
		}

		$file_hex = bin2hex($binary);
		$hash_slt = substr($file_hex, 0, HASH_LEN);
		$file_hex = substr($file_hex, HASH_LEN);
		$file_len = strlen($file_hex);
		$hash_nxt = hash(HASH_ALG, $password.$hash_slt);
		$hash_req = ceil($file_len / HASH_LEN);
		$key_hex = '';
		
		for ($i=0;$i<$hash_req;$i++) {
			$hash_nxt = hash(HASH_ALG, $hash_nxt);
			$key_hex .= $hash_nxt;
		}
		
		$key_hex = substr($key_hex, 0, $file_len);
		return pack('H*', $key_hex) ^ pack('H*', $file_hex);
	}

	public function encrypt_file($filename, $password='') {
	
		return $this->encrypt($this->read_file($filename), $password);
	}

	public function decrypt_file($filename, $password='') {
	
		return $this->decrypt($this->read_file($filename), $password);
	}
}

?>
