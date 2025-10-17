# Tatou - Testing the API

---

This file illustrates how the server routes are tested and the different cases that are considered. For a full description of each route's specification, please refer to the file `tatou/server/API.md`.

**NOTE:** All routes requiring authentication are tested with mocked authentication, which is initialised via the app configuration variable `"TESTING"=True`.

## healthz

- **Case 1:** Calling the route with the database up and running.

  **Expected outcome:** The route responds successfully

  **Status code:** `200` -  Success

 ## create-user

 * **Case 1:** Calling the route with the expected parameters.

   **Expected outcome:** The route responds successfully, the response values are conforming with the expected return values.

   **Status code:** `200` -  Success


## login

 * **Case 1:** Calling the route with the expected parameters.

   **Expected outcome:** The route responds successfully, the response values are conforming with the expected return values.

   **Status code:** `201` -  Success

## list-documents

 * **Case 1:** Calling the route with the expected parameters.

   **Expected outcome:** The route responds successfully, the response values are conforming with the expected return values.

   **Status code:** `201` -  Success

 ## list-versions

 * **Case 1:** Calling the route with the expected parameters.

   **Expected outcome:** The route responds successfully, the response values are conforming with the expected return values.

   **Status code:** `200` -  Success


 ## list-all-versions

 * **Case 1:** Calling the route.

   **Expected outcome:** The route responds successfully, the response values are conforming with the expected return values.

   **Status code:** `200` -  Success

 ## get-document

 * **Case 1:** Calling the route with the expected parameters.

   **Expected outcome:** The route responds successfully, the response values are conforming with the expected return values.

   **Status code:** N/A

 ## get-version

 * *Missing*

  ## get-watermarking-methods

 * **Case 1:** Calling the route.

   **Expected outcome:** The route responds successfully, the response values are conforming with the expected return values.
   
   **Status code:** `200` -  Success
   
   
   
   ## read-watermark

 * **Case 1:** Calling the route with the expected parameters.

   **Expected outcome:** The route responds successfully, the response values are conforming with the expected return values.

   **Status code:** `201` -  Success


   ## create-watermark

 * **Case 1:** Calling the route with the expected parameters.

   **Expected outcome:** The route responds successfully, the response values are conforming with the expected return values.

   **Status code:** `201` -  Success



 ## delete-document

 * **Case 1:** Calling the route with the expected parameters.

   **Expected outcome:** The route responds successfully, the response values are conforming with the expected return values.

   **Status code:** `200` -  Success

---

## RMAP Routes

### rmap-initiate

- **Case 1:** Calling the route with the expected parameters.

  **Expected outcome:** The route responds successfully, the response values are conforming with the expected return values.

  **Status code:** `200` -  Success

---

### rmap-get-link

- **Case 1:** Calling the route with the expected parameters.

  **Expected outcome:** The route responds successfully, the response values are conforming with the expected return values.

  **Status code:** `200` -  Success
