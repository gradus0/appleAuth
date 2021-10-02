<?php
namespace appleAuth;																					

class sign{
		// https://developer.apple.com/account/resources/identifiers/list/serviceId -- indificator value
		protected $clientId = ""; // example: com.youdomen
	
		// your developer account id -> https://developer.apple.com/account/#/membership/
		protected $teamId = "";
	
		// key value show in -> https://developer.apple.com/account/resources/authkeys/list
		protected $key = ""; 

		// your page url where this script
		protected $redirect_uri = ""; // example: youdomen.com/appleAuth.class.php
	
		// path your key file, download file this -> https://developer.apple.com/account/resources/authkeys/list
		protected $keyPath =''; // example: ./AuthKey_key.p8 
	
	
		function __construct($clientId,$teamId,$key,$redirect_uri,$keyPath){
			$this->clientId = $clientId;
			$this->teamId = $teamId;
			$this->key = $key;
			$this->redirect_uri = $this->redirect_uri;
			$this->keyPath = $keyPath;
		}

	
		function get_url($state, $scope = "name email"){
				return 'https://appleid.apple.com/auth/authorize'.'?'.http_build_query([
						'response_type' => "code",
						'response_mode' => 'form_post',
						'client_id' => $this->clientId,
						'redirect_uri' => $this->redirect_uri,
						'state' => $state,
						'scope' => $scope,
					]);
		}
	
		function get_jwt_token($code){
			$datetime = new \DateTime();
			$time = $datetime->getTimestamp();
			$time_end = $time+3600;

			$claims = [
				"iss" => $this->teamId,
				"sub" => $this->clientId,
				"aud" => "https://appleid.apple.com",
				'iat' => $time,
				'exp' => $time_end,
			];

			$headers = [
				'kid' => $this->key,
				'alg' => 'ES256'
			];
			

			return $this->jwt_encode($claims,$headers,file_get_contents($this->keyPath));
		}
	
	
	
		function get_response($code,$jwt_token){
		
			$data = [
					'client_id' => $this->clientId,
					'client_secret' => $jwt_token,
					'code' => $code,
					'grant_type' => 'authorization_code',
					'redirect_uri' => $redirect_uri
				];
			
			$ch = curl_init();
			curl_setopt_array ($ch, [
				CURLOPT_URL => 'https://appleid.apple.com/auth/token',
				CURLOPT_POSTFIELDS => http_build_query($data),
				CURLOPT_RETURNTRANSFER => true
			]);
			$response = curl_exec($ch);
			curl_close ($ch);

			return json_decode($response, true);		
		}
	
		function read_id_token($id_token){
			return $this->jwt_decode($id_token,$this->keyPath);
		}
	
	
	function jwt_decode($jwtToken,$key_path){
		if(!file_exists($key_path)) throw new Exception($key_path. ' file key not found');

		$key = file_get_contents($key_path);

		$jwtArr = array_combine(
			['header', 'payload', 'signature'],
			explode('.', $jwtToken)
		);

		return [
			'header' => json_decode(base64_decode($jwtArr['header'])),
			'payload' => json_decode( base64_decode($jwtArr['payload']) ,1 ),
			'hash' =>  base64_encode( hash_hmac( // сами считаем хеш
				'sha256',
				$jwtArr['header'] . '.' . $jwtArr['payload'],
				$key,
				true))
		];
	}

	function base64url_encode($binary_data) {
		return strtr(rtrim(base64_encode($binary_data), '='), '+/', '-_');
	}

	function jwt_encode($body, $head, $private_key)
	{
		if (! function_exists('openssl_get_md_methods') || ! in_array('sha256', openssl_get_md_methods())) throw new Exception('Requires openssl with sha256 support');

		$msg = $this->base64url_encode(json_encode($head)) . '.' . $this->base64url_encode(json_encode($body));

		$privateKeyRes = openssl_get_privatekey($private_key,null);
		openssl_sign($msg, $der, $privateKeyRes, "sha256");

		// DER unpacking from https://github.com/firebase/php-jwt
		$components = [];
		$pos = 0;
		$size = strlen($der);
		while ($pos < $size) {
			$constructed = (ord($der[$pos]) >> 5) & 0x01;
			$type = ord($der[$pos++]) & 0x1f;
			$len = ord($der[$pos++]);
			if ($len & 0x80) {
				$n = $len & 0x1f;
				$len = 0;
				while ($n-- && $pos < $size) $len = ($len << 8) | ord($der[$pos++]);
			}

			if ($type == 0x03) {
				$pos++;
				$components[] = substr($der, $pos, $len - 1);
				$pos += $len - 1;
			} else if (! $constructed) {
				$components[] = substr($der, $pos, $len);
				$pos += $len;
			}
		}
		foreach ($components as &$c) $c = str_pad(ltrim($c, "\x00"), 32, "\x00", STR_PAD_LEFT);

		return $msg . '.' . $this->base64url_encode(implode('', $components));
	}
		
	
}
