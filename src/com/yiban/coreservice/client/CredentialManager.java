package com.yiban.coreservice.client;

import java.math.BigInteger;
import java.net.URLEncoder;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.text.MessageFormat;

import java.util.Date;

import javax.crypto.Cipher;

import com.google.gson.Gson;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;


public class CredentialManager implements ICredentialManager {

    private static CredentialManager _instance = null;

    private String _appId;
    private String _secret;
    private String _serverUrl;
    private String _serverPort;
    private String _encrptedSecret;
    
    private int _minPerCallTime;
    
    private AuthorizationState _authState = null;
    
    
    public static CredentialManager getInstance() throws Exception
    {
    	if(_instance == null)
    		throw new Exception("请先调用Init函数初始化");
    	
    	return _instance;
    }
	
    public static void Init(String appId, String secret, String serverUrl, String serverPort)
    {
        Init(appId, secret, serverUrl, serverPort, 30);
    }
    
    public static void Init(String appId, String secret, String serverUrl, String serverPort, int minPerCallTime)
    {
        if (_instance == null)
        {
        	synchronized  (CredentialManager.class)
            {
                _instance = new CredentialManager();
                _instance._appId = appId;
                _instance._secret = secret;
                _instance._serverUrl = serverUrl;
                _instance._serverPort = serverPort;
                _instance._minPerCallTime = minPerCallTime;
            }
        }
    }
    
    public CredentialManager() { }
    
	
    private String getServerUrl(String method)
    {
        return MessageFormat.format("http://{0}:{1}/Api/Authorization/{2}", _serverUrl, _serverPort, method);
    }
    
    private String getPublicKey() throws Exception
    {
    	String apiUrl = MessageFormat.format(getServerUrl("GetPublicKey") + "?appId={0}", _appId);
    	
    	String result = HttpHelper.sendGet(apiUrl);
    	Gson gson = new Gson();
    	
    	ResponceResult resp = gson.fromJson(result, ResponceResult.class);
    	
    	if(!resp.code.equals("0"))
    		throw new Exception("获取公钥出错，错误原因：" + resp.message);
    	
    	return resp.data.publicKey;
    }
    
    private String encryptByRSA(String handleStr, String publicKey) throws Exception {
    	
    	Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    	cipher.init(Cipher.ENCRYPT_MODE, decodePublicKeyFromXml(publicKey));
    	byte[] data = handleStr.getBytes("utf-8");
    	byte[] encryptedBytes = cipher.doFinal(data, 0, data.length);
    	return ConvertToBase64(encryptedBytes);
    }
    
	
	private AuthorizationState getAuthState() throws Exception {
		String publicKey = getPublicKey();
		_encrptedSecret = encryptByRSA(_secret, publicKey);
		
		String urlParameters = "grant_type=client_credentials&client_id={0}&client_secret={1}";
		urlParameters = MessageFormat.format( urlParameters, 
				URLEncoder.encode(_appId, "utf-8"), URLEncoder.encode(_encrptedSecret, "utf-8"));
		
		String response = HttpHelper.sendPost(getServerUrl("Token"), urlParameters);
		
		Gson gson = new Gson();
		AuthorizationState authState = gson.fromJson(response, AuthorizationState.class);
		authState.setExpireTime();
		
		return authState;
	}
	
    public void refreshAuthorization() throws Exception {
    	Date now = new Date();
    	if( _authState.expireTime.getTime() - now.getTime() <= (_minPerCallTime * 1000)) {
    		String urlParameters = "grant_type=refresh_token&refresh_token={0}&client_id={1}&client_secret= {2}";
    		urlParameters = MessageFormat.format( urlParameters, 
    				URLEncoder.encode(_authState.refresh_token, "utf-8"),
    				URLEncoder.encode(_appId, "utf-8"),
    				URLEncoder.encode(_encrptedSecret, "utf-8"));
    		
    		String response = HttpHelper.sendPost(getServerUrl("Token"), urlParameters);
    		
    		Gson gson = new Gson();
    		_authState = gson.fromJson(response, AuthorizationState.class);
    		_authState.setExpireTime();
    	}
    }
    
	@Override
	public String getAccessToken() throws Exception {
		
		if(_authState == null || (_authState.expireTime.getTime() >= new Date().getTime())) {
			_authState = getAuthState();
		}
		
		refreshAuthorization();
		
		return _authState.getAccessToken();
	}
	
	private PublicKey decodePublicKeyFromXml(String xml) throws Exception {
		BASE64Decoder decoder = new BASE64Decoder ();
		xml = xml.replaceAll("\r", "").replaceAll("\n", "");
		BigInteger modulus = new BigInteger(1, decoder.decodeBuffer(getMiddleString(xml, "<Modulus>", "</Modulus>")));
		BigInteger publicExponent = new BigInteger(1, decoder.decodeBuffer(getMiddleString(xml, "<Exponent>", "</Exponent>")));
		
		try {
			KeyFactory keyf = KeyFactory.getInstance("RSA");
			RSAPublicKeySpec rsaPubKey = new RSAPublicKeySpec(modulus, publicExponent);
			return keyf.generatePublic(rsaPubKey);
		} catch (Exception e) {
			return null;
		}
	}

	private String ConvertToBase64(byte[] handleBtyes ) throws Exception {
		BASE64Encoder encoder = new BASE64Encoder();
		String resultBytes = encoder.encode(handleBtyes);
		
		return resultBytes;
	}
	
	public static String getMiddleString(String all, String start, String end) {
		int beginIdx = all.indexOf(start) + start.length();
		int endIdx = all.indexOf(end);
		return all.substring(beginIdx, endIdx);
	}
	
	private class ResponceResult
	{
	    public String code;
	    public String message;

	    public RSAKeyInfo data;
	}
	
	private class RSAKeyInfo
	{
	    public String publicKey;
	    public String expiresTime;
	}
	
	private class AuthorizationState
	{
	    private String access_token;
	    private String refresh_token;
	    private transient Date expireTime;
	    private int expires_in;
	    
	    public void setExpireTime() {
	    	Date now = new Date();
	    	expireTime = new Date(now.getTime() + (expires_in * 1000));
	    }
	    
	    public String getAccessToken() {
	    	return access_token;
	    }
	}
}


