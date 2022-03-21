global with sharing class SingPass_NdiAuthController {
    static final Integer NDIAUTH_CACHE_TTL = 300;
    static final String NDIAUTH_CACHE_ALGO = 'MD5';
    static final String NDIAUTH_CACHE_PREFIX = 'NDIAUTH';
    static final String NDIAUTH_CACHE_NAMESPACE = 'local';
    static final String NDIAUTH_CACHE_PARTITION = 'SingPass';

    @RemoteAction
    global static String getStateHash(String state) {
        Blob hash = Crypto.generateDigest(NDIAUTH_CACHE_ALGO, Blob.valueOf(state));
        String key = encodeBlobToAlphaNum(hash);

        Cache.Org.put(NDIAUTH_CACHE_NAMESPACE + '.' + NDIAUTH_CACHE_PARTITION + '.' + NDIAUTH_CACHE_PREFIX + key, state, NDIAUTH_CACHE_TTL);
        return key;
    }

    @RemoteAction
    global static String getStateFromHash(String hash) {
        Object value = Cache.Org.get(NDIAUTH_CACHE_NAMESPACE + '.' + NDIAUTH_CACHE_PARTITION + '.' + NDIAUTH_CACHE_PREFIX + hash);
        return (String) value;
    }

    static String decodeAlphaNumToBlob(String an) {

        String result = '';
        Boolean escape = false;

        for (Integer i = 0; i < an.length(); i++) {
            Integer c = an.charAt(i);

            switch on c {
                when 65 /* 'A' */ {
                    escape = true;
                }
                when else {
                    if (escape) {
                        switch on c {
                            when 48 /* '0' */ {
                                result += 'A';
                            }
                            when 49 /* '1' */ {
                                result += '=';
                            }
                            when 50 /* '2' */ {
                                result += '/';
                            }
                            when 51 /* '3' */ {
                                result += '+';
                            }
                        }
                    } else {
                        result += an.mid(i, 1);
                    }
                    escape = false;
                }
            }
        }

        return result;
    }

    static String encodeBlobToAlphaNum(Blob b) {
        String base64 = EncodingUtil.base64Encode(b);
        String result = '';

        for (Integer i = 0; i < base64.length(); i++) {
            switch on base64.charAt(i) {
                when 65 /* 'A' */ {
                    result += 'A0';
                }
                when 61 /* '=' */ {
                    result += 'A1';
                }
                when 47 /* '/' */ {
                    result += 'A2';
                }
                when 43 /* '+' */ {
                    result += 'A3';
                }
                when else {
                    result += base64.mid(i, 1);
                }
            }
        }

        return result;
    }


    global PageReference redirect() {
        // TODO: verify this is from SingPass

        String hash = System.currentPageReference().getParameters().get('state');
        String code = System.currentPageReference().getParameters().get('code');
        String state = getStateFromHash(hash);

        System.debug('redirecting with state ' + state);
        System.debug('redirecting with code ' + code);

        String url = 'https://community.sfdcsg.com/services/authcallback/SingPass';
        url += '?code=' + code;
        url += '&state=' + state;
        
        PageReference page = new PageReference(url);
        Page.setRedirect(true);

        return page;
    }
}
