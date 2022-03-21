global class SingPass_AuthProvider extends Auth.AuthProviderPluginClass {
  // TODO: change your community base address to run this visualforce page
  static public final String COMMUNITY_BASE_URL = 'https://you-community-base-url';

  global String getCustomMetadataType() {
    return 'SingPass_Detail__mdt';
  }
      
  global PageReference initiate(Map<String, String> authProviderConfiguration, String stateToPropagate) {
    String accessTokenUrl = authProviderConfiguration.get('Token_Url__c');
    String clientId = authProviderConfiguration.get('Client_Id__c');

    // the idea is to send to a visualforce page that with hold the NDI JS and call back
    String authUrl = COMMUNITY_BASE_URL + '/ndi_auth';
    authUrl += '?client_id=' + clientId;
    authUrl += '&state=' + stateToPropagate;
    authUrl += '&nonce=' + Singpass_Crypto.generateNonce();
    
    return new PageReference(authUrl);
  }
  
  public class SignLoginJWTReq {
    String alg;
    String kid;
    String jwt;

    public signLoginJWTReq(String alg, String kid, String jwt) { 
      this.alg = alg; 
      this.kid = kid; 
      this.jwt = jwt; 
    }
  }

  public class SingLoginJWTRes {
      public String status;
      public String jws;
  }

  global String getJWS(String clientId, String kid, String code) {
    // TODO: change your appname or endpoint details
    String herokuAppurl = 'https://yourappname.herokuapp.com/signloginjwt'; 

    Auth.JWT clientAssertion = new Auth.JWT();
    // TODO: change for production
    clientAssertion.setAud('https://stg-id.singpass.gov.sg');
    clientAssertion.setIss(clientId);
    clientAssertion.setSub(clientId);
    clientAssertion.setValidityLength(119);

    String jwtPayload = clientAssertion.toJSONString();

    Map<String, Object> jwt = (Map<String, Object>) JSON.deserializeUntyped(jwtPayload);
    jwt.remove('nbf');
    jwt.remove('jti');
    jwtPayload = JSON.serialize(jwt);
    

    HttpRequest req = new HttpRequest();
    req.setEndpoint(herokuAppUrl);
    req.setHeader('Accept', 'application/json');
    req.setHeader('Content-Type','application/json');
    req.setMethod('POST');

    // TODO: change jwks kid for signing
    SignLoginJWTReq sljreq = new SignLoginJWTReq('ES512', 'your-jwks-sig-kid', jwtPayload);
    String jsonBody = JSON.serialize(sljreq);
    req.setBody(jsonBody);

    Http http = new Http();
    HTTPResponse res = http.send(req);
    String responseBody = res.getBody();
    
    SingLoginJWTRes sljres = (SingLoginJWTRes) JSON.deserialize(responseBody, SingLoginJWTRes.class);

    return sljres.jws;
  }

  global Auth.AuthProviderTokenResponse handleCallback(Map<String, String> authProviderConfiguration, Auth.AuthProviderCallbackState state) {
    String accessTokenUrl = authProviderConfiguration.get('Token_Url__c');
    String clientId = authProviderConfiguration.get('Client_Id__c');
    String redirectUrl = COMMUNITY_BASE_URL + '/ndi_auth_cb';
    String kid = authProviderConfiguration.get('Kid__c');

    Map<String,String> queryParams = state.queryParameters;

    // TODO: check if there is an error query param
    // error
    // error_description

    String code = queryParams.get('code');
    String sfdcState = queryParams.get('state');
    String jws = getJWS(clientId, kid, code);
    
    HttpRequest req = new HttpRequest();
    req.setEndpoint(accessTokenUrl);
    req.setMethod('POST');
    req.setHeader('Accept', 'application/json');
    req.setHeader('Content-Type', 'application/x-www-form-urlencoded; charset=ISO-8859-1');

    String tokenBody = '';
    tokenBody += 'client_assertion_type=' + EncodingUtil.urlEncode('urn:ietf:params:oauth:client-assertion-type:jwt-bearer', 'UTF-8');
    tokenBody += '&client_assertion=' + jws;
    tokenBody += '&client_id=' + clientId;
    tokenBody += '&grant_type=authorization_code';
    tokenBody += '&redirect_uri=' + EncodingUtil.urlEncode(RedirectUrl, 'UTF-8');
    tokenBody += '&code=' + code;

    Http http = new Http();
    HTTPResponse res = http.send(req);
    String responseBody = res.getBody();   
    String accessToken = getTokenValueFromResponse(responseBody, 'access_token');
    String tokenType = getTokenValueFromResponse(responseBody, 'token_type');
    String idToken = getTokenValueFromResponse(responseBody, 'id_token');

    return new Auth.AuthProviderTokenResponse('SingPass', idToken, 'RefreshToken', sfdcState);
    // TODO: don’t hard-code the refresh token value!
  }
  
  
  global Auth.UserData  getUserInfo(Map<string,string> authProviderConfiguration, Auth.AuthProviderTokenResponse response) { 
    //Here the developer is responsible for constructing an Auth.UserData objec
    //TODO decode and verify response, built user data using SOQL lookup

    String id = ''; 
    String fname = 'Paul'; 
    String lname = 'Partner';
    String flname = fname + ' ' + lname;
    String email = 'ppartner@singpass.demo';
    String link = 'https://api.singpass.gov.sg/';
    String uname = 'ppartner@singpass.demo';
    String locale = 'en_US';
    Map<String,String> provMap = new Map<String,String>();

    return new Auth.UserData(id, fname, lname, flname, email, link, uname, locale, 'SingPass', 'https://api.singpass.gov.sg/', provMap);
  }
  
  private String getTokenValueFromResponse(String response, String token) {
    Map<String, Object> m = (Map<String, Object>) JSON.deserializeUntyped(response);

    return (String) m.get(token);
  }
}