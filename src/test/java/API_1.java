import io.restassured.RestAssured;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import java.time.LocalDate;
import java.util.HashMap;
import java.util.Map;

import static io.restassured.RestAssured.given;

public class API_1 {
    private String AUTH_TOKEN;
    private static final String BASE_URL = "https://stg-app.bosta.co/api/v2/pickups";

    @BeforeClass
    public void setup() {
        RestAssured.baseURI = BASE_URL;

        AUTH_TOKEN = System.getenv("API_TOKEN");

        if (AUTH_TOKEN == null) {
            AUTH_TOKEN = "bca27763f5f30353ba0ee3d2ebd8951994f5016e269bbd781798e2884274d631";
        }
    }

    private Map<String, Object> getBasePayload() {
        Map<String, Object> contact = new HashMap<>();
        contact.put("_id", "_sCFBrHGi");
        contact.put("name", "Test Name");
        contact.put("email", "amira.mosa+991@bosta.co");
        contact.put("phone", "+201055592829");

        Map<String, Object> repeatedData = new HashMap<>();
        repeatedData.put("repeatedType", "One Time");

        Map<String, Object> payload = new HashMap<>();
        payload.put("businessLocationId", "MFqXsoFhxO");
        payload.put("contactPerson", contact);
        payload.put("scheduledDate", "2025-06-30");
        payload.put("numberOfParcels", "3");
        payload.put("hasBigItems", false);
        payload.put("repeatedData", repeatedData);
        payload.put("creationSrc", "Web");

        return payload;
    }

    @Test(priority = 1, description = "Verify user cannot create pickup for another business ID")
    public void testBolaBusinessLocation() {
        Map<String, Object> payload = getBasePayload();
        payload.put("businessLocationId", "VICTIM_LOC_ID_123");
        Response response = given().header("Authorization", AUTH_TOKEN).header("Origin", "https://stg-business.bosta.co").contentType(ContentType.JSON)
                .body(payload).when().post();

        int statusCode = response.getStatusCode();
        Assert.assertTrue(statusCode == 403 || statusCode == 404 || statusCode == 400,
                "CRITICAL: BOLA Vulnerability! API allowed creation with foreign businessLocationId. Status: " + statusCode);
    }

    @Test(priority = 2, description = "Verify unauthorized fee manipulation fields are ignored or rejected")
    public void testMassAssignmentFeeBypass() {
        Map<String, Object> payload = getBasePayload();
        payload.put("fee", 0);
        payload.put("isPaid", true);
        payload.put("wallet_balance", 999999);

        Response response = given().header("Authorization", AUTH_TOKEN).header("Origin", "https://stg-business.bosta.co").contentType(ContentType.JSON)
                .body(payload).when().post();

        if (response.getStatusCode() == 200 || response.getStatusCode() == 201) {
            int fee = response.jsonPath().getInt("fee");
            Assert.assertNotEquals(fee, 0, "CRITICAL: Mass Assignment! Managed to set fee to 0.");
        }
    }

    @Test(priority = 3, description = "Verify API resilience against SQL Injection in text fields")
    public void testSqlInjectionInName() {
        Map<String, Object> payload = getBasePayload();
        @SuppressWarnings("unchecked")
        Map<String, Object> contact = (Map<String, Object>) payload.get("contactPerson");

        contact.put("name", "' OR '1'='1");
        Response response = given().header("Authorization", AUTH_TOKEN).header("Origin", "https://stg-business.bosta.co")
                        .contentType(ContentType.JSON).body(payload).when().post();

        Assert.assertNotEquals(response.getStatusCode(), 500, "CRITICAL: Potential SQL Injection! Server returned 500 Error.");
    }

    @Test(priority = 4, description = "Verify negative parcel counts are rejected")
    public void testNegativeParcelCount() {
        Map<String, Object> payload = getBasePayload();
        payload.put("numberOfParcels", -5);

        Response response = given().header("Authorization", AUTH_TOKEN).header("Origin", "https://stg-business.bosta.co").contentType(ContentType.JSON)
                        .body(payload).when().post();

        Assert.assertTrue(response.getStatusCode() >= 400,"LOGICAL FLAW: API accepted negative parcel count! Status: " + response.getStatusCode());
    }

    @Test(priority = 5, description = "Verify past scheduled dates are rejected")
    public void testPastScheduledDate() {
        Map<String, Object> payload = getBasePayload();
        payload.put("scheduledDate", LocalDate.now().minusDays(1).toString());

        Response response = given().header("Authorization", AUTH_TOKEN).header("Origin", "https://stg-business.bosta.co").contentType(ContentType.JSON)
                        .body(payload).when().post();

        Assert.assertTrue(response.getStatusCode() >= 400, "LOGICAL FLAW: API accepted a date in the past! Status: " + response.getStatusCode());
    }
}