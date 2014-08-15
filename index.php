<?php

session_start();
require_once(dirname(__FILE__) . '/CSApiClient.php');

$api_id = 'test';
$api_secret = 'test';
$api_redirect_uri = 'http://test.com';

// logout
if (isset($_GET['logout'])) {
	unset($_SESSION['token']);
}

// authorization
try {

	$cs = new CSApiClient();
	$cs->setClientId($api_id);
	$cs->setClientSecret($api_secret);
	$cs->setRedirectUri($api_redirect_uri);
	
	if (isset($_GET['code'])) {
		$cs->authenticate();
		$_SESSION['token'] = $cs->getAccessToken();
		header('Location: /', true, 302);
	}
	elseif (isset($_GET['signed_request'])) {
		$cs->parseSignedRequest($_GET['signed_request']);
		$_SESSION['token'] = $cs->getAccessToken();
	}
	// authorized
	if (!empty($_SESSION['token'])) {
		$cs->setAccessToken($_SESSION['token']);
		if ($cs->accessToken['created'] + $cs->accessToken['expires_in'] < time()) {
			unset($_SESSION['token']);
			if (isset($cs->accessToken['refresh_token'])) {
				$cs->refreshToken($this->accessToken['refresh_token']);
			}
		}
	}
	else {
		header('Location: ' . $cs->createAuthUrl(''), true, 302);
	}
}
catch(Exception $e) {
	echo $e->getMessage();
}

// example call api method
try {
	$res = $cs->api('user/info');
	var_dump($res);
}
catch(Exception $e) {
	echo $e->getMessage();
	echo PHP_EOL;
	echo $e->getCode();
}