# Tatou - Testing the API

---

This file illustrates how the server routes are tested and the different cases that are considered. For a full description of each route's specification, please refer to the file `tatou/server/API.md`.

**NB:** All routes requiring authentication are tested with mocked authentication, which is initialised via the app configuration variable `"TESTING"=True`.

**NB:** Updates and extra cases that were included after mutation testing are **not** reported in this file. Please refer to the `Mutation Testing Results.md` file in the specialisation-specific deliverables to see those changes.

## healthz

- **Case 1:** Calling the route with the database up and running.

  **Expected outcome:** The route responds successfully

  **Status code:** `200` -  Success

 ## create-user

 * **Case 1:** Calling the route with the expected parameters.

   **Expected outcome:** The route responds successfully, the response values are conforming with the expected return values.

   **Status code:** `200` -  Success

 * **Case 2:** Calling the route with missing email.

   **Expected outcome:** The route fails.

   **Status code:** `400` -  Bad request

 * **Case 3:** Calling the route with missing login.

   **Expected outcome:** The route fails.

   **Status code:** `400` -  Bad request

 * **Case 4:** Calling the route with missing password.

   **Expected outcome:** The route fails.

   **Status code:** `400` -  Bad request

 * **Case 5:** Calling the route with malformed email.

   **Expected outcome:** The route fails.

   **Status code:** `400` -  Bad request


## login

 * **Case 1:** Calling the route with the expected parameters.

   **Expected outcome:** The route responds successfully, the response values are conforming with the expected return values.

   **Status code:** `201` -  Success

 * **Case 2:** Calling the route with missing email.

   **Expected outcome:** The route fails.

   **Status code:** `400` -  Bad request

 * **Case 3:** Calling the route with missing password.

   **Expected outcome:** The route fails.

   **Status code:** `400` -  Bad request

 * **Case 4:** Calling the route with missing email and password.

   **Expected outcome:** The route fails.

   **Status code:** `400` -  Bad request

 * **Case 5** Calling the route with malformed email.

   **Expected outcome:** The route fails. Malformed email interpreted as non existing.

   **Status code:** `401` -  Authentication error

 * **Case 6** Calling the route with wrong password.

   **Expected outcome:** The route fails.

   **Status code:** `401` -  Authentication error

## upload-document

 * **Case 1:** Calling the route with the expected parameters.

   **Expected outcome:** The route responds successfully, the response values are conforming with the expected return values.

   **Status code:** `201` -  Success

 * **Case 2:** Calling the route with missing file.

   **Expected outcome:** The route fails.

   **Status code:** `400` - Bad request

 * **Case 3:** Calling the route with too big file.

   **Expected outcome:** The route fails.

   **Status code:** `413` - Content too large

 * **Case 4:** Calling the route with TXT file.

   **Expected outcome:** The route fails.

   **Status code:** `415` - Unsupported media type

## list-documents

 * **Case 1:** Calling the route.

   **Expected outcome:** The route responds successfully, the response values are conforming with the expected return values.

   **Status code:** `200` -  Success

 ## list-versions

 * **Case 1:** Calling the route with the expected parameters.

   **Expected outcome:** The route responds successfully, the response values are conforming with the expected return values.

   **Status code:** `200` -  Success

 * **Case 2:** Calling the route with missing parameters.

   **Expected outcome:** The route fails.

   **Status code:** `400` - Bad request

 * **Case 3:** Calling the route with malformed parameters (JSON instead of query string).

   **Expected outcome:** The route fails.

   **Status code:** `400` - Bad request

 * **Case 4:** Calling the route with wrong id (missing file).

   **Expected outcome:** The route fails.

   **Status code:** `404` - Not found


 ## list-all-versions

 * **Case 1:** Calling the route.

   **Expected outcome:** The route responds successfully, the response values are conforming with the expected return values.

   **Status code:** `200` -  Success

 ## get-document

 * **Case 1:** Calling the route with the expected parameters.

   **Expected outcome:** The route responds successfully, the response values are conforming with the expected return values.

   **Status code:** N/A

 * **Case 2:** Calling the route with missing parameters.

   **Expected outcome:** The route fails.

   **Status code:** `400` - Bad request

 * **Case 3:** Calling the route with malformed parameters (JSON instead of query string).

   **Expected outcome:** The route fails.

   **Status code:** `400` - Bad request

 * **Case 4:** Calling the route with wrong id (missing file).

   **Expected outcome:** The route fails.

   **Status code:** `404` - Not found

  ## get-watermarking-methods

 * **Case 1:** Calling the route.

   **Expected outcome:** The route responds successfully, the response values are conforming with the expected return values.

   **Status code:** `200` -  Success

   ## create-watermark

 * **Case 1:** Calling the route with the expected parameters.

   **Expected outcome:** The route responds successfully, the response values are conforming with the expected return values.

   **Status code:** `201` -  Success

 * **Case 2:** Calling the route with same parameters.

   **Expected outcome:** The route fails due to duplicate entry.

   **Status code:** `503` -  Service unavailable

 * **Case 3:** Calling the route with non existing method.

   **Expected outcome:** The route fails.

   **Status code:** `400` -  Bad request

 * **Case 4:** Calling the route with non existing document.

   **Expected outcome:** The route fails.

   **Status code:** `404` -  Not found

 * **Case 5:** Calling the route with missing id.

   **Expected outcome:** The route fails.

   **Status code:** `400` -  Bad request

 * **Case 6:** Calling the route with non missing method.

   **Expected outcome:** The route fails.

   **Status code:** `400` -  Bad request

 * **Case 7:** Calling the route with missing position.

   **Expected outcome:** The route returns successfully as position is ignored.

   **Status code:** `201` -  Success

 * **Case 8:** Calling the route with missing key.

   **Expected outcome:** The route fails.

   **Status code:** `400` -  Bad request

 * **Case 9:** Calling the route with missing secret.

   **Expected outcome:** The route fails.

   **Status code:** `400` -  Bad request

 * **Case 10:** Calling the route with missing recipient.

   **Expected outcome:** The route fails.

   **Status code:** `400` -  Bad request

   ## read-watermark

 * **Case 1:** Calling the route with the expected parameters.

   **Expected outcome:** The route responds successfully, the response values are conforming with the expected return values.

   **Status code:** `201` -  Success

 * **Case 2:** Calling the route with non existing document.

   **Expected outcome:** The route fails.

   **Status code:** `404` -  Not found

 * **Case 3:** Calling the route with missing id.

   **Expected outcome:** The route fails.

   **Status code:** `400` -  Bad request

 * **Case 4:** Calling the route with missing method.

   **Expected outcome:** The route fails.

   **Status code:** `400` -  Bad request

 * **Case 5:** Calling the route with missing position.

   **Expected outcome:** The route returns successfully as position is ignored.

   **Status code:** `201` -  Success

 * **Case 6:** Calling the route with missing key.

   **Expected outcome:** The route fails.

   **Status code:** `400` -  Bad request

 ## delete-document

 * **Case 1:** Calling the route with the expected parameters.

   **Expected outcome:** The route responds successfully, the file is removed from the system.

   **Status code:** `200` -  Success

 * **Case 2:** Calling the route with missing id.

   **Expected outcome:** The route fails.

   **Status code:** `400` -  Bad request

 * **Case 3:** Calling the route with non existing document.

   **Expected outcome:** The route fails.

   **Status code:** `404` -  Not found

### rmap-initiate

- **Case 1:** Calling the route with the expected parameters.

  **Expected outcome:** The route responds successfully, the response values are conforming with the expected return values.

  **Status code:** `200` -  Success

- **Case 2:** Calling the route with missing parameters.

  **Expected outcome:** The route fails.

  **Status code:** `400` - Bad request

- **Case 3:** Calling the route with malformed parameters.

  **Expected outcome:** The route fails.

  **Status code:** `503` - Service Unavailable

### rmap-get-link

- **Case 1:** Calling the route with the expected parameters.

  **Expected outcome:** The route responds successfully, the response values are conforming with the expected return values.

  **Status code:** `200` -  Success

- **Case 2:** Calling the route with missing parameters.

  **Expected outcome:** The route fails.

  **Status code:** `400` - Bad request

- **Case 3:** Calling the route with malformed parameters.

  **Expected outcome:** The route fails.

  **Status code:** `503` - Service Unavailable

 ## get-version

 * **Case 1:** Calling the route with the expected parameters.

   **Expected outcome:** The route responds successfully, the response values are conforming with the expected return values.

   **Status code:** N/A

 * **Case 2:** Calling the route with malformed parameters.

   **Expected outcome:** The route fails.

   **Status code:** `404` -  Not found

* **Case 3:** Calling the route with missing parameters.

  **Expected outcome:** The route fails.

  **Status code:** `404` -  Not found
