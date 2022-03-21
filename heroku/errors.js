class MyInfoGovClientError extends Error {
    /**
     * Constructor for custom error.
     * @param message Error message
     * @param err Optional error caught in a try-catch block
     */
    constructor(message, err) {
        super(message);

        if (err instanceof Error) {
            this.message = `${message}: ${err.message}`;
        } else if (err) {
            this.message = `${message}: ${JSON.stringify(err)}`;
        }

        Error.captureStackTrace(this, this.constructor);
        this.name = this.constructor.name;
    }
}
  
/**
 * Missing parameters in MyInfoGovClient constructor.
 */
class MissingParamsError extends MyInfoGovClientError {
    constructor(
        message = `Missing required parameter(s) in constructor: clientId, clientSecret, singpassEserviceId, redirectEndpoint, clientPrivateKey, myInfoPublicKey`,
    ) {
        super(message);
    }
};
  
/**
 * JWT signature could not be verified
 */
class InvalidTokenSignatureError extends MyInfoGovClientError {
    constructor(
        verifyError,
        message = 'Signature on access token from MyInfo could not be verified',
    ) {
        super(message, verifyError)
    }
};
  
/**
 * JWT had wrong shape
 */
class WrongAccessTokenShapeError extends MyInfoGovClientError {
    constructor(
        message = 'Decoded access token from MyInfo had unexpected shape, so NRIC could not be extracted',
    ) {
        super(message)
    }
};
  
/**
 * Response from Token endpoint did not contain access token
 */
class MissingAccessTokenError extends MyInfoGovClientError {
    constructor(message = 'MyInfo response did not contain valid access token') {
        super(message)
    }
};
  
/**
  * MyInfo returned non-200 response
  */
class MyInfoResponseError extends MyInfoGovClientError {
    constructor(error, message = 'Error while connecting to MyInfo') {
        super(message, error)
    }
};
  
/**
  * Error while decrypting Person data from MyInfo
  */
class DecryptDataError extends MyInfoGovClientError {
    constructor(
        error,
        message = 'Error while decrypting data from MyInfo Person API',
    ) {
      super(message, error)
    }
  };
  
/**
  * Invalid signature on data from Person API
  */
class InvalidDataSignatureError extends MyInfoGovClientError {
    constructor(
        error,
        message = 'Signature on Person API data from MyInfo could not be verified',
    ) {
      super(message, error)
    }
};
  
/**
  * Person data from MyInfo had unexpected shape
  */
class WrongDataShapeError extends MyInfoGovClientError {
    constructor(message = 'Data from MyInfo Person API had unexpected shape') {
        super(message)
    }
};

exports.MissingParamsError = MissingParamsError;
exports.InvalidTokenSignatureError = InvalidTokenSignatureError;
exports.WrongAccessTokenShapeError = WrongAccessTokenShapeError;
exports.MyInfoResponseError = MyInfoResponseError;
exports.DecryptDataError = DecryptDataError;
exports.InvalidDataSignatureError = InvalidDataSignatureError;
exports.WrongAccessTokenShapeError = WrongAccessTokenShapeError;