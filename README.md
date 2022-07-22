# appleAuth
Sign in with Apple (apple JWS token)

steps:
* go to https://developer.apple.com/ -> Certificates, Identifiers & Profiles -> Identifiers ( https://developer.apple.com/account/resources/identifiers/list/bundleId ) -> click icon "plus" and create new App Ids. Add Capabilities "Sign In with Apple" and set config width your domen and callback-url
* change filter App Ids to Services IDs ( https://developer.apple.com/account/resources/identifiers/list/serviceId ) -> click icon "plus" and create new Services IDs. Add Capabilities "Sign In with Apple" and set config width your domen and callback-url.
Copy Identifier value - this $clientId
* change menu to Keys ( https://developer.apple.com/account/resources/authkeys/list ) and click icon "plus" and create new Keys.
Copy Key ID value - this $key
Donwload file and set path to $keyPath;
* next go to https://developer.apple.com/account/#!/membership/
Copy Team ID value - this $teamId

example run code:
```php
<?php
include_once "appleAuth.class.php";

// https://developer.apple.com/account/resources/identifiers/list/serviceId -- indificator value
$clientId = ""; // com.youdomen
// your developer account id -> https://developer.apple.com/account/#/membership/
$teamId = "";
// key value show in -> https://developer.apple.com/account/resources/authkeys/list
$key = "";
// your page url where this script
$redirect_uri = ""; // example: youdomen.com/appleAuth.class.php
// path your key file, download file this -> https://developer.apple.com/account/resources/authkeys/list
$keyPath =''; // example: ./AuthKey_key.p8


try{

	$appleAuthObj = new \appleAuth\sign($clientId,$teamId,$key,$redirect_uri,$keyPath);

	if(isset($_REQUEST['code'])){
		$jwt_token = $appleAuthObj->get_jwt_token($_REQUEST['code']);
		$response = $appleAuthObj->get_response($_REQUEST['code'],$jwt_token);
		$result_token = $appleAuthObj->read_id_token($response['id_token']);

		var_dump($response);
		var_dump($result_token);
	}else{

		$state = bin2hex(random_bytes(5));

		echo "<a href='".$appleAuthObj->get_url($state)."'>sign</a>";
	}

} catch (\Exception $e) {
	echo "error: ".$e->getMessage();
}
```
