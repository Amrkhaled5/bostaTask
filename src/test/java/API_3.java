import io.restassured.RestAssured;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import static io.restassured.RestAssured.given;


public class API_3 {

    private static final String BASE_URL = "https://stg-app.bosta.co/api/v2";
    private String token;

    @BeforeClass
    public void setup() {
        RestAssured.baseURI = BASE_URL;

        token = System.getenv("API_TOKEN");
        if (token == null) {
            token = "bca27763f5f30353ba0ee3d2ebd8951994f5016e269bbd781798e2884274d631";
        }
    }

    @Test(priority = 1, description = "Check for User Enumeration Vulnerability")
    public void testUserEnumeration() {
        String existingEmail = "amira.mosa+991@bosta.co";
        String fakeEmail = "random.hacker.email.123@bosta.co";

        Response respExist = given()
                .header("Authorization", token)
                .contentType(ContentType.JSON)
                .body("{\"email\": \"" + existingEmail + "\"}")
                .post("/users/forget-password");

        Response respFake = given()
                .header("Authorization", token)
                .contentType(ContentType.JSON)
                .body("{\"email\": \"" + fakeEmail + "\"}")
                .post("/users/forget-password");

        Assert.assertEquals(respExist.getStatusCode(), respFake.getStatusCode(), "ENUMERATION RISK: Status codes differ between valid and invalid emails.");
        Assert.assertEquals(respExist.getBody().asString(), respFake.getBody().asString(), "ENUMERATION RISK: Response body reveals if user exists.");
    }

    @Test(priority = 2, description = "Test Rate Limiting (Email Bombing protection)")
    public void testRateLimiting() {
        String targetEmail = "amira.mosa+991@bosta.co";
        int totalRequests = 10;
        int successfulResponses = 0;

        for (int i = 0; i < totalRequests; i++) {
            Response response = given()
                    .header("Authorization", token)
                    .contentType(ContentType.JSON)
                    .body("{\"email\": \"" + targetEmail + "\"}")
                    .post("/users/forget-password");

            if (response.getStatusCode() == 200) {
                successfulResponses++;
            }
            try { Thread.sleep(100); } catch (InterruptedException e) {}
        }

        Assert.assertTrue(successfulResponses < 6, "Rate Limit Check: Too many emails allowed!");
    }
}