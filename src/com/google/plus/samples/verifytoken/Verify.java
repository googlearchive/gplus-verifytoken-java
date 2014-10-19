/*
 * Copyright 2013 Google Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.plus.samples.verifytoken;

import static spark.Spark.get;
import static spark.Spark.post;

import com.google.api.client.auth.oauth2.TokenResponseException;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeTokenRequest;
import com.google.api.client.googleapis.auth.oauth2.GoogleCredential;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleTokenResponse;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.jackson.JacksonFactory;
import com.google.api.services.oauth2.Oauth2;
import com.google.api.services.oauth2.model.Tokeninfo;
import com.google.api.services.plus.Plus;
import com.google.api.services.plus.model.PeopleFeed;
import com.google.gson.Gson;

import spark.Request;
import spark.Response;
import spark.Route;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Scanner;

/**
 * Simple server to demonstrate token verification.
 *
 * @author cartland@google.com (Chris Cartland)
 */
public class Verify {
  /**
   * Replace this with the client ID you got from the Google APIs console.
   */
  private static final String CLIENT_ID = "YOUR_CLIENT_ID";
  /**
   * Optionally replace this with your application's name.
   */
  private static final String APPLICATION_NAME = "Google+ Java Token Verification";

  /**
   * Default HTTP transport to use to make HTTP requests.
   */
  private static final HttpTransport TRANSPORT = new NetHttpTransport();
  /**
   * Default JSON factory to use to deserialize JSON.
   */
  private static final JacksonFactory JSON_FACTORY = new JacksonFactory();
  /**
   * Gson object to serialize JSON responses to requests to this servlet.
   */
  private static final Gson GSON = new Gson();

  /**
   * Register all endpoints that we'll handle in our server.
   * @param args Command-line arguments.
   */
  public static void main(String[] args) {
    // Initialize a session for the current user, and render index.html.
    get(new Route("/") {
      @Override
      public Object handle(Request request, Response response) {
        response.type("text/html");
        try {
          // Fancy way to read index.html into memory, and set the client ID
          // in the HTML before serving it.
          return new Scanner(new File("index.html"), "UTF-8")
              .useDelimiter("\\A").next()
              .replaceAll("[{]{2}\\s*CLIENT_ID\\s*[}]{2}", CLIENT_ID)
              .replaceAll("[{]{2}\\s*APPLICATION_NAME\\s*[}]{2}",
                  APPLICATION_NAME);
        } catch (FileNotFoundException e) {
          // When running the sample, there was some path issue in finding
          // index.html.  Double check the guide.
          e.printStackTrace();
          return e.toString();
        }
      }
    });
    // "Verify an ID Token or an Access Token. 
    // Tokens should be passed in the URL parameters of a POST request.
    post(new Route("/verify") {
      @Override
      public Object handle(Request request, Response response) {
        response.type("application/json");

        String idToken = request.queryParams("id_token");
        String accessToken = request.queryParams("access_token");

        TokenStatus idStatus = new TokenStatus();
        if (idToken != null) {
          // Check that the ID Token is valid.

          Checker checker = new Checker(new String[]{CLIENT_ID}, CLIENT_ID);
          GoogleIdToken.Payload jwt = checker.check(idToken);

          if (jwt == null) {
            // This is not a valid token.
            idStatus.setValid(false);
            idStatus.setId("");
            idStatus.setMessage("Invalid ID Token.");
          } else {
            idStatus.setValid(true);
            String gplusId = (String)jwt.get("sub");
            idStatus.setId(gplusId);
            idStatus.setMessage("ID Token is valid.");
          }
        } else {
          idStatus.setMessage("ID Token not provided");
        }

        TokenStatus accessStatus = new TokenStatus();
        if (accessToken != null) {
          // Check that the Access Token is valid.
          try {
            GoogleCredential credential = new GoogleCredential().setAccessToken(accessToken);
            Oauth2 oauth2 = new Oauth2.Builder(
                TRANSPORT, JSON_FACTORY, credential).build();
            Tokeninfo tokenInfo = oauth2.tokeninfo()
                .setAccessToken(accessToken).execute();
            if (!tokenInfo.getIssuedTo().equals(CLIENT_ID)) {
              // This is not meant for this app. It is VERY important to check
              // the client ID in order to prevent man-in-the-middle attacks.
              accessStatus.setValid(false);
              accessStatus.setId("");
              accessStatus.setMessage("Access Token not meant for this app.");
            } else {
              accessStatus.setValid(true);
              accessStatus.setId(tokenInfo.getUserId());
              accessStatus.setMessage("Access Token is valid.");
            }
          } catch (IOException e) {
            accessStatus.setValid(false);
            accessStatus.setId("");
            accessStatus.setMessage("Invalid Access Token.");
          }
        } else {
          accessStatus.setMessage("Access Token not provided");
        }

        VerificationResponse tokenStatus =
            new VerificationResponse(idStatus, accessStatus);
        return GSON.toJson(tokenStatus);
      }
    });
  }

  /**
   * JSON representation of a token's status.
   */
  public static class TokenStatus {
    public boolean valid;
    public String gplus_id;
    public String message;

    public TokenStatus() {
      valid = false;
      gplus_id = "";
      message = "";
    }

    public void setValid(boolean v) {
      this.valid = v;
    }

    public void setId(String gplus_id) {
      this.gplus_id = gplus_id;
    }

    public void setMessage(String message) {
      this.message = message;
    }
  }

  /**
   * JSON response to verification request.
   *
   * Example JSON response:
   * {
   *   "id_token_status": {
   *     "info": "12345",
   *     "valid": True
   *   },
   *   "access_token_status": {
   *     "Access Token not meant for this app.",
   *     "valid": False
   *   }
   * }
   */
  public static class VerificationResponse {
    public TokenStatus id_token_status;
    public TokenStatus access_token_status;

    private VerificationResponse(TokenStatus _id_token_status, TokenStatus _access_token_status) {
      this.id_token_status = _id_token_status;
      this.access_token_status = _access_token_status;
    }

    public static VerificationResponse newVerificationResponse(TokenStatus id_token_status,
                                          TokenStatus access_token_status) {
      return new VerificationResponse(id_token_status,
                                      access_token_status);
    }
  }
}
