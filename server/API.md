# Tatou API Documentation

---

# Routes

- [create-user](#create-user) — **POST** `/api/create-user`
- [create-watermark](#create-watermark)
  - **POST** `/api/create-watermark/<int:document_id>`
  - **POST** `/api/create-watermark`
- [delete-document](#delete-document)
  - **DELETE** `/api/delete-document/<document_id>`
  - **DELETE, POST** `/api/delete-document`
- [get-document](#get-document)
  - **GET** `/api/get-document/<int:document_id>`
  - **GET** `/api/get-document`
- [get-version](#get-version) — **GET** `/api/get-version/<link>`
- [get-watermarking_methods](#get-watermarking-methods) — **GET** `/api/get-watermarking-methods`
- [healthz](#healthz) — **GET** `/healthz`
- [list-all-versions](#list-all-versions) — **GET** `/api/list-all-versions`
- [list-documents](#list-documents) — **GET** `/api/list-documents`
- [list-versions](#list-versions)
  - **GET** `/api/list-versions/<int:document_id>`
  - **GET** `/api/list-versions`
- [login](#login) — **POST** `/api/login`
- [read-watermark](#read-watermark)
  - **POST** `/api/read-watermark/<int:document_id>`
  - **POST** `/api/read-watermark`
- [rmap-initiate](#rmap-initiate) — **POST** `/api/rmap-initiate`
- [rmap-get-link](#rmap-get-link) — **POST** `/api/rmap-get-link`
- [upload-document](#upload-document) — **POST** `/api/upload-document`



## healthz

**Path**
`GET /api/healthz`

**Description**
This endpoint checks the health of the server and confirms it is running.

**Parameters**
_None_

**Return**

On success:

```json
{
  "message": <string>
}
```

On error:

```json
{
    "error": "<error-message>"
}
```

**Status Codes**

- `200`: Success
- `503`: Service unavailable

**Specification**

 * The healthz endpoint MUST be accessible without authentication.
 * The response MUST always contain a "message" field of type string.

 ## create-user

**Path**
`POST /api/create-user`

**Description**
This endpoint creates a new user account in the system.

**Parameters**
```json
{
  "login": <string>,
  "password": <string>,
  "email": <email>
}
```

**Return**

On success:

```json
{
  "id": <int>,
  "login": <string>,
  "email": <email>
}
```

On error:

```json
{
    "error": "<error-message>"
}
```

**Status Codes**

- `201`: Success
- `400`: Invalid payload
- `409`: User or email already exist
- `503`: Database error

**Specification**

 * The create-user endpoint MUST validate that username, password, and email are provided.
 * The response MUST include a unique id along with the created username and email.
 * The login and email in the response MUST match those in the request.


## login

**Path**
`POST /api/login`

**Description**
This endpoint authenticates a user with their credentials and returns a session token.

**Parameters**
```json
{
  "email": <string>,
  "password": <string>
}
```

**Return**

On success:

```json
{
  "token": <string>,
  "token_type": "bearer",
  "expires_in": <int>
}
```

On error:

```json
{
    "error": "<error-message>"
}
```

**Status Codes**

- `200`: Success
- `400`: Invalid payload
- `401`: Invalid credentials
- `503`: Database error

**Specification**

 * The login endpoint MUST reject requests missing email or password.
 * The response MUST include a token string and its expiration date as an integer Time To Live in seconds.

 ## upload-document

**Path**
`POST /api/upload-document`

**Description**
This endpoint uploads a PDF document to the server and registers its metadata.

**Parameters**
```json
{
  "file": <pdf file>,
  "name": <string>
}
```

**Return**

On success:

```json
{
  "id": <int>,
  "name": <string>,
  "creation": <date ISO 8601>,
  "sha256": <string>,
  "size": <int>
}
```

On error:

```json
{
    "error": "<error-message>"
}
```

**Status Codes**

- `201`: Success
- `400`: Invalid payload
- `401`: Authentication error
- `413`: File exceeds maximum size
- `415`: File is not a PDF
- `500`: Error saving file
- `503`: Database error

**Specification**

 * Requires authentication
 * The upload-pdf endpoint MUST accept only files in PDF format.

## list-documents

**Path**
`GET /api/list-documents`

**Description**
This endpoint lists all uploaded PDF documents along with their metadata.

**Parameters**
_None_

**Return**

On success:

```json
{
  "documents": [
    {
      "id": <int>,
      "name": <string>,
      "creation": <date ISO 8601>,
      "sha256": <string>,
      "size": <int>
    }
  ]
}
```

**Status Codes**

- `200`: Success
- `401`: Authentication error
- `503`: Database error

**Specification**

 * Requires authentication
 * The response MUST return all documents of the user.

 ## list-versions

**Description**
This endpoint lists all watermarked versions of a given PDF document along with their metadata.

**Path**
`GET /api/list-versions`

**Parameters**
```json
{
  "documentid": <int>
}
```

**Path**
`GET /api/list-versions/<int:document_id>`

**Parameters**
_None_

**Return**

On success:

```json
{
  "versions": [
    {
      "id": <string>,
      "documentid": <string>,
      "link": <string>,
      "intended_for": <string>,
      "secret": <string>,
      "method": <string>
    }
  ]
}
```

On error:

```json
{
    "error": "<error-message>"
}
```

**Status Codes**

- `200`: Success
- `400`: Invalid payload
- `401`: Authentication error
- `404`: File not found
- `503`: Database error

**Specification**
 * Requires authentication


 ## list-all-versions

**Path**
`GET /api/list-all-versions`

**Description**
This endpoint lists all versions of all PDF documents for the authenticated user stored in the system.

**Parameters**
_None_

**Return**

On success:

```json
{
  "versions": [
    {
      "id": <string>,
      "documentid": <string>,
      "link": <string>,
      "intended_for": <string>,
      "secret": <string>,
      "method": <string>
    }
  ]
}
```

On error:

```json
{
    "error": "<error-message>"
}
```

**Status Codes**

- `200`: Success
- `401`: Authentication error
- `503`: Database error

**Specification**

 * Requires authentication

 ## get-document

**Description**
This endpoint retrieves a PDF document by fetching a specific one when an `id` is provided.

**Path**
`GET /api/get-document`


**Parameters**
```json
{
  "documentid": <int>
}
```

**Path**
`GET /api/get-document/<int:document_id>`

**Parameters**
_None_

**Return**
On success: Inline PDF file in binary format.

On error:

```json
{
    "error": "<error-message>"
}
```

**Status Codes**

- `400`: Invalid payload
- `401`: Authentication error
- `404`: Document not found
- `410`: File missing on disk
- `415`: File not available (invalid PDF signature)
- `500`: Document path invalid / Error serving file

**Specification**

 * Requires authentication

 ## get-version

**Description**
This endpoint retrieves a specific watermarked version of a document when a `link` is provided.

**Path**
`GET /api/get-version/<str:link>`

**Parameters**
_None_

**Return**
On success: Inline PDF file in binary format.

On error:

```json
{
    "error": "<error-message>"
}
```

**Status Codes**

- `400`: Invalid payload
- `404`: Document not found
- `410`: File missing on disk
- `415`: File not available (invalid PDF signature)
- `500`: Document path invalid / Error serving file
- `503`: Database error

**Specification**

 * The endpoint MUST be reachable without authentication

  ## get-watermarking-methods

**Description**
This endpoint lists all available watermarking methods.

**Path**
`GET /api/get-watermarking-methods`

**Parameters**
_None_

**Return**

On success:

```json
{
    "count": <int>,
    "methods": [
        {
            "description":<string>,
            "name": <string>"
        }
    ]
}
```

**Status Codes**

- `200`: Success

**Specification**

 * The endpoint MUST return all methods in `watermarking_utils.METHODS`.

   ## read-watermark

**Description**
This endpoint reads information contain in a pdf document's watermark with the provided method.

**Path**
`POST /api/read-watermark`

**Parameters**
```json
{
    "method": <string>,
    "position": <string>,
    "key": <string>,
    "id": <int>
}
```

**Path**
`POST /api/read-watermark<int:document_id>`


**Parameters**
```json
{
    "method": <string>,
    "position": <string>,
    "key": <string>
}
```

**Return**

On success:

```json
{
    "documentid": <int>,
    "secret": <string>,
    "method": <string>,
    "position": <string>
}
```

On error:

```json
{
    "error": "<error-message>"
}
```

**Status Codes**

- `201`: Success
- `400`: Invalid payload / Error reading watermark
- `401`: Authentication error
- `404`: Document not found
- `410`: File missing on disk
- `500`: Document path invalid
- `503`: Database error

**Specification**

 * The endpoint MUST return the secret read in the document.


   ## create-watermark

**Description**
This endpoint reads information contain in a pdf document's watermark with the provided method.

**Path**
`POST /api/create-watermark`

**Parameters**

```json
{
    "method": <string>,
    "position": <string>,
    "key": <string>,
    "secret": <string>,
    "intended_for": <string>,
    "id": <int>
}
```

**Path**
`POST /api/create-watermark<int:document_id>`

**Parameters**

```json
{
    "method": <string>,
    "position": <string>,
    "key": <string>,
    "secret": <string>,
    "intended_for": <string>
}
```

**Return**

On success:

```json
{
    "id": <int>,
    "documentid": <int>,
    "link": <string>,
    "intended_for": <string>,
    "method": <string>,
    "position": <string>,
    "filename": <string>,
    "size": <int>
}
```

On error:

```json
{
    "error": "<error-message>"
}
```

**Status Codes**

- `201`: Success
- `400`: Invalid payload / Watermarking method not applicable
- `401`: Authentication error
- `404`: Document not found
- `410`: File missing on disk
- `500`: Document path invalid / Watermarking failed
- `503`: Database error

**Specification**

 * Only the owner of a document should be able to create watermarks for their documents.



 ## delete-document

**Description**
This endpoint deletes a PDF document  when an `id` is provided.

**Path**
`DELETE, POST /api/delete-document`


**Parameters**

```json
{
  "id": <int>
}
```

**Path**
`DELETE /api/delete-document/<int:document_id>`

**Parameters**
_None_

**Return**
On success: *None*

On error:

```json
{
    "error": "<error-message>"
}
```

**Status Codes**

- `200`: Success
- `400`: Invalid payload
- `401`: Authentication error
- `404`: Document not found
- `503`: Database error

**Specification**

 * Requires authentication
 * Only the owner of the document should be able to delete it

---

## RMAP Routes

The following routes implement the RMAP (Roger Michael Authentication Protocol) for client authentication.

### rmap-initiate

**Path**
`POST /api/rmap-initiate`

**Description**
Handles RMAP Message 1 for client authentication initiation. The client sends their nonce and identity encrypted to the server's public key.

**Parameters**
```json
{
    "payload": "<base64-encoded-pgp-message>"
}
```

The decrypted message should contain:
```json
{
    "nonceClient": <64-bit-unsigned-integer>,
    "identity": "<string>"
}
```

**Return**
On success:
```json
{
    "payload": "<base64-encoded-pgp-response>"
}
```

The response payload when decrypted contains:
```json
{
    "nonceClient": <64-bit-unsigned-integer>,
    "nonceServer": <64-bit-unsigned-integer>
}
```

On error:
```json
{
    "error": "<error-message>"
}
```

**Status Codes**

- `200`: Success
- `400`: Invalid payload or unknown identity
- `503`: RMAP system initialization failed

---

### rmap-get-link

**Path**
`POST /api/rmap-get-link`

**Description**
Handles RMAP Message 2 for final authentication step. The client proves they have the server nonce by sending it back encrypted.

**Parameters**
```json
{
    "payload": "<base64-encoded-pgp-message>"
}
```

The decrypted message should contain:
```json
{
    "nonceServer": <64-bit-unsigned-integer>
}
```

**Return**
On success:
```json
{
    "result": "<32-hex-character-string>"
}
```

The result is a 128-bit value represented as 32 hexadecimal characters, computed as: `(nonceClient << 64) | nonceServer`.

On error:
```json
{
    "error": "<error-message>"
}
```

**Status Codes**
- `200`: Success
- `400`: Invalid payload or nonce not found
- `503`: RMAP system initialization failed

**Specification**
- The RMAP protocol requires a two-message handshake
- All payloads are base64-encoded ASCII-armored PGP messages
- Nonces must be 64-bit unsigned integers (0 to 2^64-1)
- The final result concatenates nonces as: NonceClient || NonceServer (big-endian)
