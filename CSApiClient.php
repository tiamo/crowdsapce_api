<?php
/**
 * Copyright 2012 Fomru Inc.
 *
 * http://crowdspace.ru
 * @author Kornienko Vladislav (vk.tiamo@gmail.com)
 * @version 1.0
 */

// Check for the required json and curl extensions, the Crowdspace API PHP Client won't function without them.
if (!function_exists('curl_init')) {
	throw new Exception('Crowdspace PHP API Client requires the CURL PHP extension');
}
if (!function_exists('json_decode')) {
	throw new Exception('Crowdspace PHP API Client requires the JSON PHP extension');
}
if (!function_exists('http_build_query')) {
	throw new Exception('Crowdspace PHP API Client requires http_build_query()');
}
if (!ini_get('date.timezone') && function_exists('date_default_timezone_set')) {
	date_default_timezone_set('UTC');
}

class CSApiClient
{
    const OAUTH2_REVOKE_URI = 'http://oauth.crowdspace.ru/revoke';
    const OAUTH2_TOKEN_URI = 'http://oauth.crowdspace.ru/token';
    const OAUTH2_AUTH_URL = 'http://oauth.crowdspace.ru/authorize';
    const API_URL = 'http://api.crowdspace.ru';
	
	const USER_AGENT = 'crowdpsace-api-php-client';
	const SIGNED_REQUEST_ALGORITHM = 'HMAC-SHA256';
	
	public $version = '1.0';
	public $format = 'json'; // xml,json

	public $clientId;
	public $clientSecret;
	public $accessToken;
	public $redirectUri;
	public $state;

	private $_response;
	private $_responseInfo = array();

	/**
	 * Instantiates the class, but does not initiate the login flow, leaving it
	 * to the discretion of the caller (which is done by calling authenticate()).
	 */
	public function __construct($config=array())
	{
		if (!empty($config['client_id'])) {
			$this->clientId = $config['client_id'];
		}
		if (!empty($config['client_secret'])) {
			$this->clientSecret = $config['client_secret'];
		}
		if (!empty($config['redirect_uri'])) {
			$this->redirectUri = $config['redirect_uri'];
		}
	}

	/**
	 * Authenticate
	 * @return string
	 * @throws CSApiAuthException
	 */
	public function authenticate()
	{
		if (isset($_GET['code'])) {
			// We got here from the redirect from a successful authorization grant, fetch the access token
			$response = $this->postRequest(self::OAUTH2_TOKEN_URI, array(
				'code' => $_GET['code'],
				'grant_type' => 'authorization_code',
				'redirect_uri' => $this->redirectUri,
				'client_id' => $this->clientId,
				'client_secret' => $this->clientSecret
			));
			$code = $this->getResponseHttpCode();
			if ($code == 200) {
				$this->setAccessToken($response);
				$this->accessToken['created'] = time();
				return $this->getAccessToken();
			}
			else {
				$decodedResponse = json_decode($response, true);
				if ($decodedResponse != $response && $decodedResponse != null && $decodedResponse['error']) {
					$response = $decodedResponse['error'];
				}
				throw new CSApiAuthException("Error fetching OAuth2 access token, message: '$response'", $code);
			}
		}
	}

	/**
	 * Create a URL to obtain user authorization.
	 * The authorization endpoint allows the user to first
	 * authenticate, and then grant/deny the access request.
	 * @param string $scope The scope is expressed as a list of space-delimited strings.
	 * @return string
	 */
	public function createAuthUrl($scope)
	{
		$params = array(
			'response_type' => 'code',
			'redirect_uri' => $this->redirectUri,
			'client_id' => $this->clientId,
			'scope' => $scope,
		);
		if (isset($this->state)) {
			$params['state'] = urlencode($this->state);
		}
		return self::OAUTH2_AUTH_URL . '?' . http_build_query($params, null, '&');
	}

	/**
	 * Set the OAuth 2.0 access token using the string that resulted from calling authenticate()
	 * @param $accessToken
	 * @throws CSApiAuthException Thrown when $accessToken is invalid.
	 */
	public function setAccessToken($accessToken)
	{
		$accessToken = json_decode($accessToken, true);
		if ($accessToken == null) {
			throw new CSApiAuthException('Could not json decode the access token');
		}
		if (!isset($accessToken['access_token'])) {
			throw new CSApiAuthException("Invalid token format");
		}
		$this->accessToken = $accessToken;
	}

	/**
	 * Get the OAuth 2.0 access token.
	 * @return string $accessToken JSON encoded string in the following format:
	 */
	public function getAccessToken()
	{
		return $this->accessToken ? json_encode($this->accessToken) : null;
	}

	/**
	 * @ignore
	 */
	public function setState($state)
	{
		$this->state = $state;
	}
  
	/**
	 * Parses a signed_request and validates the signature.
	 *
	 * @param string $signed_request A signed token
	 * @return array The payload inside it or null if the sig is wrong
	 */
	public function parseSignedRequest($signed_request)
	{
		list($encoded_sig, $payload) = explode('.', $signed_request, 2);
		// decode the data
		$sig = base64_decode(strtr($encoded_sig, '-_', '+/'));
		$data = json_decode(base64_decode(strtr($payload, '-_', '+/')), true);
		if (strtoupper($data['algorithm']) !== self::SIGNED_REQUEST_ALGORITHM) {
			throw new CSApiAuthException('Unknown algorithm. Expected ' . self::SIGNED_REQUEST_ALGORITHM);
		}
		// check sig
		$expected_sig = hash_hmac('sha256', $payload, $this->clientSecret, true);
		if ($sig !== $expected_sig) {
			// throw new CSApiAuthException('Bad Signed JSON signature!');
		}
		$this->accessToken['access_token'] = $data['access_token'];
		$this->accessToken['expires_in'] = $data['expires_in'];
		$this->accessToken['created'] = time();
		return $data;
	}
	
	/**
	 * Fetches a fresh access token with the given refresh token.
	 * @param string $refreshToken
	 * @throws CSApiAuthException
	 * @return void
	 */
	public function refreshToken($refreshToken)
	{
		$response = $this->postRequest(self::OAUTH2_TOKEN_URI, array(
			'client_id' => $this->clientId,
			'client_secret' => $this->clientSecret,
			'refresh_token' => $refreshToken,
			'grant_type' => 'refresh_token'
		));
		$code = $this->getResponseHttpCode();
		if ($code == 200) {
			$token = @json_decode($response, true);
			if ($token == null) {
				throw new CSApiAuthException("Could not json decode the access token from response: '{$response}'");
			}
			if (!isset($token['access_token']) || !isset($token['expires_in'])) {
				throw new CSApiAuthException("Invalid token format");
			}
			$this->accessToken['access_token'] = $token['access_token'];
			$this->accessToken['expires_in'] = $token['expires_in'];
			$this->accessToken['created'] = time();
		}
		else {
			throw new CSApiAuthException("Error refreshing the OAuth2 token, message: '$response'", $code);
		}
	}

	/**
     * Revoke an OAuth2 access token or refresh token. This method will revoke the current access
     * token, if a token isn't provided.
     * @throws CSApiException
     * @param string|null $token The token (access token or a refresh token) that should be revoked.
     * @return boolean Returns True if the revocation was successful, otherwise False.
     */
	public function revokeToken($token = null)
	{
		if (!$token) {
			$token = $this->accessToken['access_token'];
		}
		$this->postRequest(self::OAUTH2_REVOKE_URI,array('token'=>$token));
		$code = $this->getResponseHttpCode();
		if ($code == 200) {
			$this->accessToken = null;
			return true;
		}
		return false;
	}

	/**
	 * Set the OAuth 2.0 Client ID.
	 * @param string $clientId
	 */
    public function setClientId($id)
	{
		$this->clientId = $id;
	}

	/**
	 * Set the OAuth 2.0 Client Secret.
	 * @param string $clientSecret
	 */
    public function setClientSecret($secret)
	{
		$this->clientSecret = $secret;
	}

	/**
	 * Set the OAuth 2.0 Redirect URI.
	 * @param string $redirectUri
	 */
    public function setRedirectUri($uri)
	{
		$this->redirectUri = $uri;
	}

    /**
     * Get HTTP User Agent
     * @return string
     */
    protected function getUserAgent()
    {
        return self::USER_AGENT .'/'. $this->getVersion();
    }

	/**
	 * Get api version
     * @return string
	 */
	private function getVersion()
	{
        return $this->version;
	}

    /**
     * Call Api method
     * @param string $method calling method name
     * @param array $params method arguments
	 * @throws CSApiException
     * @return array
     */
	public function api($method, array $params = array())
	{
		$params['access_token'] = $this->accessToken['access_token'];
		$params['version'] = $this->getVersion();
		$params['method'] = $method;
		$response = $this->request(self::API_URL .'/?'. http_build_query($params, null, '&'));
		$code = $this->getResponseHttpCode();
			
		if ($code == 200) {
			switch($this->format) {
			// case('xml'):
				// break;
			default:
			case('json'):
				$decodedResponse = json_decode($response, true);
				
				if ($decodedResponse != $response && $decodedResponse != null && !empty($decodedResponse['response'])) {
					return $decodedResponse['response'];
				}
				else {
					//throw new CSApiException("Error calling method: '$method', message: '$response'", $code);
				}
				break;
			}
		}
		
		throw new CSApiException("Error response", $code);
	}

    /**
     * Execute request to server
     * @param string $url
     * @param array $curlOptions
     * @return string
     */
    protected function request($url, array $curlOptions = array())
    {
		$options = array();
		$options[CURLOPT_URL] = $url;
		$options[CURLOPT_HEADER] = false;
		$options[CURLOPT_RETURNTRANSFER] = true;
		$options[CURLOPT_USERAGENT] = $this->getUserAgent();
		$options[CURLOPT_TIMEOUT] = 60;
		$options[CURLOPT_CONNECTTIMEOUT] = 10;
		$options[CURLOPT_HTTPHEADER] = array("Accept: application/json");
		if (preg_match("/https.*$/", $url)) {
			$options[CURLOPT_SSL_VERIFYPEER] = false;
			$options[CURLOPT_SSL_VERIFYHOST] = false;
		}
        $ch = curl_init();
        curl_setopt_array($ch, $options + $curlOptions);
        $this->_response = curl_exec($ch);
		$this->_responseInfo = curl_getinfo($ch);
        return $this->_response;
    }

    /**
     * Execute post request to server
     * @param string $url
     * @param array $data post data
     * @return string
     */
    protected function postRequest($url, $data=array())
    {
		$options = array();
		$options[CURLOPT_POST] = 1;
		$options[CURLOPT_POSTFIELDS] = $data && is_array($data) ? http_build_query($data, null, '&') : $data;
		return $this->request($url,$options);
	}

	/**
	 * @return string
	 */
	protected function getResponseBody()
	{
		return $this->_response;
	}

	/**
	 * @return string
	 */
	protected function getResponseInfo($key)
	{
		return isset($this->_responseInfo[$key]) ? $this->_responseInfo[$key] : null;
	}

	/**
	 * @return string
	 */
	protected function getResponseHttpCode()
	{
		return $this->getResponseInfo('http_code');
	}
}

class CSApiException extends Exception {}
class CSApiAuthException extends Exception {}
