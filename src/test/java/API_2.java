import io.restassured.RestAssured;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.util.HashMap;
import java.util.Map;

import static io.restassured.RestAssured.given;

public class API_2 {

    private String validToken;
    private static final String BASE_URL = "https://stg-app.bosta.co/api/v2";

    @BeforeClass
    public void setup() {
        RestAssured.baseURI = BASE_URL;

        validToken = System.getenv("API_TOKEN");

        if (validToken == null) {
            try {
                Response tokenResponse = given().contentType(ContentType.JSON).post("/users/generate-token-for-interview-task");
                validToken = tokenResponse.jsonPath().getString("token");
            } catch (Exception e) {
                System.out.println("Warning: Could not generate token automatically.");
            }
        }

        // 3. Absolute Fallback: Use hardcoded token
        if (validToken == null) {
            validToken = "bca27763f5f30353ba0ee3d2ebd8951994f5016e269bbd781798e2884274d631";
        }
    }

    private Map<String, Object> createBankPayload(String otp, String beneficiaryName) {
        Map<String, Object> bankInfo = new HashMap<>();
        bankInfo.put("beneficiaryName", beneficiaryName);
        bankInfo.put("bankName", "NBG");
        bankInfo.put("ibanNumber", "EG123456789012345678901234");
        bankInfo.put("accountNumber", "123456789");

        Map<String, Object> payload = new HashMap<>();
        payload.put("bankInfo", bankInfo);

        if (otp != null) {
            payload.put("paymentInfoOtp", otp);
        }
        return payload;
    }

    @Test(priority = 1, description = "CRITICAL: Attempt to update bank info without OTP")
    public void testUpdateBankInfo_MissingOTP() {
        Map<String, Object> payload = createBankPayload(null, "Test Company");

        Response response = given().header("Authorization", validToken)
                .contentType(ContentType.JSON).body(payload).when().post("/businesses/add-bank-info");
        Assert.assertNotEquals(response.getStatusCode(), 200, "SECURITY FAIL: Bank Info updated without OTP!");
    }

    @Test(priority = 2, description = "Verify invalid OTP is rejected")
    public void testUpdateBankInfo_InvalidOTP() {
        Map<String, Object> payload = createBankPayload("000000", "Test Company");

        Response response = given().header("Authorization", validToken).contentType(ContentType.JSON)
                .body(payload).when().post("/businesses/add-bank-info");

        Assert.assertEquals(response.getStatusCode(), 400, "SECURITY FAIL: API accepted an invalid OTP.");
    }

    @Test(priority = 3, description = "Test Stored XSS in Beneficiary Name")
    public void testUpdateBankInfo_XSSInjection() {
        String maliciousName = "<script>alert('Hacked')</script>";
        Map<String, Object> payload = createBankPayload("123456", maliciousName);

        Response response = given().header("Authorization", validToken).contentType(ContentType.JSON)
                .body(payload).when().post("/businesses/add-bank-info");

        Assert.assertNotEquals(response.getStatusCode(), 500, "SECURITY FAIL: Server Error (500) triggered by XSS payload.");

        if (response.getStatusCode() == 200) {
            String respBody = response.getBody().asString();
            Assert.assertFalse(respBody.contains("<script>"), "SECURITY FAIL: XSS payload returned unsanitized!");
        }
    }
}