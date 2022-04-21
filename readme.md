# **Android integration**

In order to integrate Sima to your Android app you need to call it via [Intent](https://developer.android.com/reference/android/content/Intent) with specific parameters (extras). Some of them are listed below:

```java
String PACKAGE_NAME = "az.dpc.sima";
String SIGN_PDF_OPERATION = "sima.sign.pdf"; // operation type to sign pdf
String SIGN_CHALLENGE_OPERATION = "sima.sign.challenge"; // operation type to sign challenge

String SIMA_SIGNATURE_ALGORITHM = "SHA256withECDSA";
String CLIENT_SIGNATURE_ALGORITHM = "HmacSHA256";
String CLIENT_HASH_ALGORITHM = "SHA-256";
String CLIENT_MASTER_KEY = "client_master_key"; // your master key

// Intent field names
String EXTRA_CLIENT_ID_FIELD = "client_id";
String EXTRA_SERVICE_FIELD = "service_name";
String EXTRA_CHALLENGE_FIELD = "challenge";
String EXTRA_SIGNATURE_FIELD = "signature";
String EXTRA_USER_CODE_FIELD = "user_code";
String EXTRA_REQUEST_ID_FIELD = "request_id";
String EXTRA_LOGO_FIELD = "service_logo";

int EXTRA_CLIENT_ID_VALUE = 1; // your client id
String EXTRA_USER_CODE_VALUE = "1234567"; // user FIN code
String EXTRA_SERVICE_VALUE = "Test Bank"; // Name of the service to be displayed in popup
String EXTRA_LOGO_VALUE = "image_data_uri"; // Image to be displayed in popup, max 500KB
```

If Sima App isn't installed on device it's would be a good practice to navigate user to Play Market to install it. Example:

```java
Intent intent = getPackageManager().getLaunchIntentForPackage(PACKAGE_NAME);

if (intent == null) {
    try {
        intent = new Intent(Intent.ACTION_VIEW, Uri.parse("market://details?id=" + PACKAGE_NAME);
    } catch (Exception e) {
        intent = new Intent(Intent.ACTION_VIEW, Uri.parse("https://play.google.com/stoappsdetails?id=" + PACKAGE_NAME));
    }
} else {
    // your code
}
```

For Android 10+ you need also explicitly add Sima package name as a query in your manifest file:

```xml
<manifest>
  ...
  <queries>
      <package android:name="az.dpc.sima" />
  </queries>
  ...
</manifest>
```

Sima App can be used to perform two operations: **signing a document** and **signing a challenge**.  

## **Signing a document**

To sign a document with Sima you need to send it via **Intent**. It is important to include **FLAG_GRANT_READ_URI_PERMISSION** flag for granting access to file. Along with the file you need to send it's **HMACSHA256** signed with your **master key**. There are several other mandatory parameters like your **client ID**, user's FIN code, your service name and logo (will be displayed to the client). The request ID is used to track down your request if there be any problems. Example:

```java
Uri documentUri = ...; // Document's Uri

InputStream stream = getContentResolver().openInputStream(documentUri);
byte[] documentBytes = IOUtils.toByteArray(stream);

MessageDigest md = MessageDigest.getInstance(CLIENT_HASH_ALGORITHM);
md.update(bytes);
byte[] fileHash = md.digest();

Mac mac = Mac.getInstance(CLIENT_SIGNATURE_ALGORITHM);
mac.init(new SecretKeySpec(CLIENT_MASTER_KEY.getBytes(), CLIENT_SIGNATURE_ALGORITHM));
byte[] signature = mac.doFinal(fileHash);

String uuid = UUID.randomUUID().toString();

intent = intent.setAction(SIGN_PDF_OPERATION)
      .setFlags(0)
      .setData(documentUri)
      .addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP)
      .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
      .putExtra(EXTRA_SERVICE_FIELD, EXTRA_SERVICE_VALUE)
      .putExtra(EXTRA_CLIENT_ID_FIELD, EXTRA_CLIENT_ID_VALUE)
      .putExtra(EXTRA_SIGNATURE_FIELD, documentSignature)
      .putExtra(EXTRA_LOGO_FIELD, EXTRA_LOGO_VALUE)
      .putExtra(EXTRA_USER_CODE_FIELD, EXTRA_USER_CODE_VALUE)
      .putExtra(EXTRA_REQUEST_ID_FIELD, uuid);
```

The signed document can be retrieved from activity result as follows:

```java
if (result.getResultCode() == Activity.RESULT_OK) {
    Intent intent = result.getData();

    if (intent == null) {
        handleError("empty-response");
        return;
    }

    String status = intent.getStringExtra("status");
    String message = intent.getStringExtra("message");

    if (status == null || !status.equals("success")) {
        handleError(message);
        return;
    }

    Uri signedDocumentUri = intent.getData();

} else if (result.getResultCode() == Activity.RESULT_CANCELED) {
      handleError("operation-canceled");
}
```

## **Signing a challenge**

The process of signing a challenge is basically the same as signing a pdf, with the only difference that here you need to send a challenge bytes and its **HMACSHA256**.

```java
SecureRandom random = new SecureRandom();
byte[] challenge = new byte[64]; // challenge to be signed
random.nextBytes(challenge);

MessageDigest md = MessageDigest.getInstance(CLIENT_HASH_ALGORITHM);
md.update(challenge);
byte[] hash = md.digest();

Mac mac = Mac.getInstance(CLIENT_SIGNATURE_ALGORITHM);
mac.init(new SecretKeySpec(CLIENT_MASTER_KEY.getBytes(), CLIENT_SIGNATURE_ALGORITHM));
byte[] signature = mac.doFinal(hash);

String uuid = UUID.randomUUID().toString();

intent = intent.setAction(SIGN_CHALLENGE_OPERATION)
        .setFlags(0)
        .addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP)
        .putExtra(EXTRA_CHALLENGE_FIELD, challenge)
        .putExtra(EXTRA_SERVICE_FIELD, EXTRA_SERVICE_VALUE)
        .putExtra(EXTRA_CLIENT_ID_FIELD, EXTRA_CLIENT_ID_VALUE)
        .putExtra(EXTRA_SIGNATURE_FIELD, signature)
        .putExtra(EXTRA_LOGO_FIELD, EXTRA_LOGO_VALUE)
        .putExtra(EXTRA_REQUEST_ID_FIELD, uuid);
```

The proccess of retrieving and verifying a signed challenge:

```java
if (result.getResultCode() == Activity.RESULT_OK) {
    Intent intent = result.getData();

    if (intent == null) {
        handleError("empty-response");
        return;
    }

    String status = intent.getStringExtra("status");
    String message = intent.getStringExtra("message");

    if (status == null || !status.equals("success")) {
        handleError(message);
        return;
    }

    byte[] signatureBytes = intent.getByteArrayExtra("signature");
    byte[] certificateBytes = intent.getByteArrayExtra("certificate");

    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    InputStream certStream = new ByteArrayInputStream(certificateBytes);
    X509Certificate certificate = (X509Certificate) cf.generateCertificate(certStream);

    Signature s = Signature.getInstance(SIMA_SIGNATURE_ALGORITHM);
    s.initVerify(certificate);
    s.update(challenge);

    if (s.verify(signatureBytes)) {
        Principal subject = certificate.getSubjectDN(); // data extracted from user's certificate

        Toast.makeText(this, subject.toString(), Toast.LENGTH_LONG).show();
    } else {
        handleError("signature-verification-error");
    }
} else if (result.getResultCode() == Activity.RESULT_CANCELED) {
    handleError("operation-canceled");
}
```

## **Error handling**

If there would be any error ocurred while opening Sima via an intent you receive it in the **message** field. Here is an example of error handling function with all possible error messages and it's short descriptions:

```java
private void handleError(String error) {
    switch (error) {
        case "operation-canceled": {
            Toast.makeText(this, "User canceled the operation", Toast.LENGTH_LONG).show();
            return;
        }
        case "wrong-operation-type": {
            Toast.makeText(this, "Empty or unknown operation type", Toast.LENGTH_LONG).show();
            return;
        }
        case "empty-data": {
            Toast.makeText(this, "Empty signing data (document or challenge)", Toast.LENGTH_LONG).show();
            return;
        }
        case "empty-service": {
            Toast.makeText(this, "Empty service", Toast.LENGTH_LONG).show();
            return;
        }
        case "empty-client-id": {
            Toast.makeText(this, "Empty client id", Toast.LENGTH_LONG).show();
            return;
        }
        case "empty-signature": {
            Toast.makeText(this, "Empty signature", Toast.LENGTH_LONG).show();
            return;
        }
        case "empty-user-code": {
            Toast.makeText(this, "Empty user-code (FIN)", Toast.LENGTH_LONG).show();
            return;
        }
        case "wrong-user-code": {
            Toast.makeText(this, "Wrong user code (FIN)", Toast.LENGTH_LONG).show();
            return;
        }
        case "wrong-logo-format": {
            Toast.makeText(this, "Wrong logo format", Toast.LENGTH_LONG).show();
            return;
        }
        case "wrong-logo-size": {
            Toast.makeText(this, "Logo size too big (>500KB)", Toast.LENGTH_LONG).show();
            return;
        }
        case "document-processing-error": {
            Toast.makeText(this, "Error processing document data", Toast.LENGTH_LONG).show();
            return;
        }
        case "challenge-processing-error": {
            Toast.makeText(this, "Error processing challenge data", Toast.LENGTH_LONG).show();
            return;
        }
        case "validate-request-error": {
            Toast.makeText(this, "Error validating signing request (wrong client id or signature)", Toast.LENGTH_LONG).show();
            return;
        }
        case "timestamp-request-error": {
            Toast.makeText(this, "Error requesting timestamp for document signing", Toast.LENGTH_LONG).show();
            return;
        }
        case "approve-request-error": {
            Toast.makeText(this, "Error approving signing request", Toast.LENGTH_LONG).show();
            return;
        }
        case "sign-document-error": {
            Toast.makeText(this, "Error singing document", Toast.LENGTH_LONG).show();
            return;
        }
        case "sign-challenge-error": {
            Toast.makeText(this, "Error singing challenge", Toast.LENGTH_LONG).show();
            return;
        }
        case "internal-error": {
            Toast.makeText(this, "Internal Sima error", Toast.LENGTH_LONG).show();
            return;
        }
        case "empty-response": {
            Toast.makeText(this, "Empty response from Sima", Toast.LENGTH_LONG).show();
            return;
        }
        default: {
            Toast.makeText(this, "Unknown error", Toast.LENGTH_LONG).show();
        }
    }
}
```

# **IOS integration**

In order to integrate Sima to your IOS app you need to open it via a custom [URL scheme](https://developer.apple.com/documentation/xcode/defining-a-custom-url-scheme-for-your-app) with specific parameters.

```swift
let SIMA_SCHEME = "sima"
let SIMA_URL = "https://apps.apple.com/us/app/si-ma-beta/id1602500636" // Sima App store fallback URL
    
let SIGN_PDF_OPERATION = "sign-pdf" // operation type to sign pdf
let SIGN_CHALLENGE_OPERATION = "sign-challenge" // operation type to sign challenge
    
let CLIENT_MASTER_KEY = "client_master_key" // your master key
    
let EXTRA_RETURN_SCHEME_FIELD = "scheme"
let EXTRA_DOCUMENT_FIELD = "document"
let EXTRA_DOCUMENT_NAME_FIELD = "document-name"
let EXTRA_CHALLENGE_FIELD = "challenge"
let EXTRA_SIGNATURE_FIELD = "signature"
let EXTRA_SERVICE_FIELD = "service-name"
let EXTRA_LOGO_FIELD = "service-logo"
let EXTRA_USER_CODE_FIELD = "user-code"
let EXTRA_CLIENT_ID_FIELD = "client-id"
let EXTRA_REQUEST_ID_FIELD = "request-id"
    
let EXTRA_RETURN_SCHEME_VALUE = "sima-demo" // your app scheme
let EXTRA_CLIENT_ID_VALUE = 1 // your client id
let EXTRA_SERVICE_VALUE = "Test Bank" // service name to be displayed
let EXTRA_USER_CODE_VALUE = "1234567" // user FIN code

let EXTRA_LOGO_VALUE = "image_data_uri"; // Image to be displayed in popup, max 500KB
```

## **Signing a challenge**

To sign a challenge with Sima you need to open Sima app via **URL** and send challenge as a parameter. To do that you need first add **sima** scheme to **LSApplicationQueriesSchemes** array in your **Info.plist** file. Along with the challenge you need to send it's **HMACSHA256** signed with your **master key**. There are several other mandatory parameters like your **client ID**, your service name and logo (will be displayed to the client). The request ID is used to track down your request if there be any problems. Sima will return results in the same way by calling your app via **URL** so you need to register your app's **URL scheme** and pass it along with other parameters. 

```swift
var randomBytes = Data(count: 64)
let result = randomBytes.withUnsafeMutableBytes {
    SecRandomCopyBytes(kSecRandomDefault, 64, $0.baseAddress!)
}
        
let challenge = Data(randomBytes)

let hash = SHA256.hash(data: challenge).data
let key = SymmetricKey(data: CLIENT_MASTER_KEY.data(using: .utf8)!)
let signature = HMAC<SHA256>.authenticationCode(for: hash, using: key)

let requestId = UUID().uuidString

var components = URLComponents()
components.scheme = SIMA_SCHEME
components.host = SIGN_CHALLENGE_OPERATION
components.path = ""
components.queryItems = [
    URLQueryItem(name: EXTRA_RETURN_SCHEME_FIELD, value: EXTRA_RETURN_SCHEME_VALUE),
    URLQueryItem(name: EXTRA_CHALLENGE_FIELD, value: challenge.base64EncodedString()),
    URLQueryItem(name: EXTRA_SERVICE_FIELD, value: EXTRA_SERVICE_VALUE),
    URLQueryItem(name: EXTRA_CLIENT_ID_FIELD, value: String(EXTRA_CLIENT_ID_VALUE)),
    URLQueryItem(name: EXTRA_SIGNATURE_FIELD, value: Data(signature).base64EncodedString()),
    URLQueryItem(name: EXTRA_LOGO_FIELD, value: EXTRA_LOGO_VALUE),
    URLQueryItem(name: EXTRA_REQUEST_ID_FIELD, value: requestId)]
        
guard let url = components.url else {
    return
}
        
if UIApplication.shared.canOpenURL(url) {
    UIApplication.shared.open(url)
} else {
    UIApplication.shared.open(URL(string: SIMA_URL)!)
}
```

The result would be sent back via the **URL** as well (using the scheme you've provided) so you will be able to catch it in your **AppDelegate**:

```swift
func application(_ app: UIApplication, open url: URL, options: [UIApplication.OpenURLOptionsKey: Any] = [:]) -> Bool {        
  guard let components = URLComponents(url: url, resolvingAgainstBaseURL: true),
        let operation = components.host,
        let params = components.queryItems else {
            self.handleError("parse-url-error");
            return
        }
        
  guard (operation == SIGN_CHALLENGE_OPERATION || operation == SIGN_PDF_OPERATION) else {
      self.handleError("wrong-operation-type");
      return
  }

  var query = Dictionary<String, Any>()
  for item in params {
      query[item.name] = item.value
  }
        
  let status = query["status"] as! String
  let message = query["message"] as? String
        
  guard status == "success" else {
      self.handleError(message);
      return
  }

  if (operation == SIGN_CHALLENGE_OPERATION) {
      let signedChallenge = query["signature"] as! String
      let certificate = query["certificate"] as! String
            
      guard let certificateData = Data(base64Encoded: certificate),
          let secCertificate = SecCertificateCreateWithData(nil, certificateData as CFData) else {
            self.handleError("certificate-parse-error");
            return
      }
            
      guard let publicKey = SecCertificateCopyKey(secCertificate) else {
          self.handleError("public-key-copy-error");
          return
      }
            
      var error: Unmanaged<CFError>?
            
      guard SecKeyVerifySignature(
          publicKey,
          .ecdsaSignatureMessageX962SHA256,
          self.challenge! as CFData,
          Data(base64Encoded: signedChallenge)! as CFData,
          &error) else {
              print(error!.takeRetainedValue() as Error)
              
              self.handleError("signature-verification-error");
              return
          }
  }
}
```

## **Signing a document**

```swift
let document = try Data(contentsOf: url, options: NSData.ReadingOptions())
                                
let hash = SHA256.hash(data: document).data
let key = SymmetricKey(data: CLIENT_MASTER_KEY.data(using: .utf8)!)
let signature = HMAC<SHA256>.authenticationCode(for: hash, using: key)
                
let requestId = UUID().uuidString
                
var components = URLComponents()
components.scheme = SIMA_SCHEME
components.host = SIGN_PDF_OPERATION
components.path = ""
components.queryItems = [
    URLQueryItem(name: EXTRA_RETURN_SCHEME_FIELD, value: EXTRA_RETURN_SCHEME_VALUE),
    URLQueryItem(name: EXTRA_DOCUMENT_FIELD, value: String(describing: document.base64EncodedString())),
    URLQueryItem(name: EXTRA_DOCUMENT_NAME_FIELD, value: url.lastPathComponent),
    URLQueryItem(name: EXTRA_SERVICE_FIELD, value: EXTRA_SERVICE_VALUE),
    URLQueryItem(name: EXTRA_CLIENT_ID_FIELD, value: String(EXTRA_CLIENT_ID_VALUE)),
    URLQueryItem(name: EXTRA_SIGNATURE_FIELD, value: Data(signature).base64EncodedString()),
    URLQueryItem(name: EXTRA_LOGO_FIELD, value: EXTRA_LOGO_VALUE),
    URLQueryItem(name: EXTRA_USER_CODE_FIELD, value: String(EXTRA_USER_CODE_VALUE)),
    URLQueryItem(name: EXTRA_REQUEST_ID_FIELD, value: requestId),
]
                
guard let url = components.url else {
    return
}
                
if UIApplication.shared.canOpenURL(url) {
    UIApplication.shared.open(url)
} else {
    UIApplication.shared.open(URL(string: SIMA_URL)!)
}
```

The signed document might be retrieved as follows:

```swift
if (operation == SIGN_PDF_OPERATION) {
  let documentBase64 = query["document"] as! String
  let document = Data(base64Encoded: documentBase64)
}
```

## **Error handling**

If there would be any error ocurred while opening Sima via URL you receive it in the **message** field. Here is an example of error handling function with all possible error messages and it's short descriptions:

```swift
func handleError(_ error: String?) {
    switch error {
    case "operation-canceled":
        self.showAlert("Error", "Operation has been canceled by user"); break;
    case "wrong-operation-type":
        self.showAlert("Error", "Empty or unknown operation type"); break;
    case "empty-data":
        self.showAlert("Error", "Empty signing data (document or challenge)"); break;
    case "empty-service":
        self.showAlert("Error", "Empty service"); break;
    case "empty-client-id":
        self.showAlert("Error", "Empty client id"); break;
    case "empty-signature":
        self.showAlert("Error", "Empty signature"); break;
    case "empty-user-code":
        self.showAlert("Error", "Empty user code (FIN)"); break;
    case "wrong-user-code":
        self.showAlert("Error", "User code (FIN) does not match"); break;
    case "wrong-logo-format":
        self.showAlert("Error", "Wrong logo format"); break;
    case "wrong-logo-size":
        self.showAlert("Error", "Logo size too big (>500KB)"); break;
    case "document-processing-error":
        self.showAlert("Error", "Error processing document data"); break;
    case "challenge-processing-error":
        self.showAlert("Error", "Error processing сhallenge data"); break;
    case "validate-request-error":
        self.showAlert("Error", "Error validating signing request (wrong client id or signature)"); break;
    case "timestamp-request-error":
        self.showAlert("Error", "Error requesting timestamp for document signing"); break;
    case "approve-request-error":
        self.showAlert("Error", "Error approving signing request"); break;
    case "sign-document-error":
        self.showAlert("Error", "Error singing document"); break;
    case "sign-challenge-error":
        self.showAlert("Error", "Error singing challenge"); break;
    case "internal-error":
        self.showAlert("Error", "Internal Sima error"); break;
    default:
        self.showAlert("Error", "Unknow error")
    }
}
```
