package com.ckex.example;

import com.ckex.security.AesUtils;
import com.ckex.security.RsaUtils;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * 功能描述
 * <p></p >
 * <a href=" "><i>View Source</i></a >
 *
 * @author ckex868@vip.qq.com
 * @version 1.0
 * @date 30/05/2017
 * @since 1.0
 */
public class ExampleMain {

    // 客户端只有公钥
    public static final String publicKeyData = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDNH+pQ1EigbhMwLD2JDinIPyLv\n" +
            "DBelH8VVQbjOWjEF+pL9JbH7L81rTRTEhdh0nUL1dkE3efRYaIpUz8d1LDts3T0G\n" +
            "sTJ7YS5WkiFFXuG+R4CWqh4o8Js0ZsxdscYmDi745fvfMT6MHdynLPM6Yr/HKCqO\n" +
            "Jfk3/KYS4eDFgNbiIwIDAQAB";

    public static final String privateKeyData = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAM0f6lDUSKBuEzAs\n" +
            "PYkOKcg/Iu8MF6UfxVVBuM5aMQX6kv0lsfsvzWtNFMSF2HSdQvV2QTd59FhoilTP\n" +
            "x3UsO2zdPQaxMnthLlaSIUVe4b5HgJaqHijwmzRmzF2xxiYOLvjl+98xPowd3Kcs\n" +
            "8zpiv8coKo4l+Tf8phLh4MWA1uIjAgMBAAECgYBf/bh8fOtD0F9AYuOlGLCq2gjy\n" +
            "Dxmdl2GURT5DqudYIevZdWN15efed+LpGK2z3Mgx8FYSrQqQuNNLXzS6+6kOsI6v\n" +
            "bSCdf+gGXclhObcGCTqv0oUf2CHK+9XxNEHKRMFHUy3fykPWwW3gI6GSFe6bmjZk\n" +
            "IvPMAMmSn0WAZeVuqQJBAPt5TxnfEJsfeaGvL/e5iWucfuGDZkkOT84Qf3PTECCY\n" +
            "ok6jyekGzLXWD8AMsz1DIg+8foSC3dzpyP4qnqRJgl0CQQDQ0Qw5j77PD2/NIXun\n" +
            "vtvRPgZtllMxO2G1GSXNAPZwG5NQLJx4198mAsnuFYRBDUfTTpBu7/RM0FoTdNic\n" +
            "lK5/AkEA2w3Q2bh1vqqsSStRnXkBO7wWylqrvve4jMfSPhKc+cf7moUSXOqPZ9YP\n" +
            "4jst5y+TfCG2E7fri4QakUyO5I0kAQJAGCh3P5mPu6jPiG3dPnToPXbti3Qev81c\n" +
            "6nS0WNlJqYKnMllW6OwglucvsWmv2U7OBnZKY2tDWjeolCOqg8L3xQJAdU3kkqrr\n" +
            "02Zv8UeQ/h8CLQB5pCGvpJD/rwigCJAsW6rQyal6Iij8E8iVw/KwgqT/1rSUv465\n" +
            "RuJ3IbeiQHyBeA==";


    private Gson gson = new GsonBuilder().create();
    private String password;

    public static void main(String[] args) throws Exception {
        ExampleMain example = new ExampleMain();
        String request = example.postRequest();
        System.out.println("\t\n ---------------------华丽分割线---------------------HTTP-----------------------\t\n ");
        String response = example.postResponse(request);
        System.out.println("\t\n ---------------------华丽分割线---------------------客户端处理Response-----------\t\n ");
        example.processResponse(response);
    }

    private void processResponse(String response) throws Exception {
        Map<String, String> responseMap = gson.fromJson(response, new TypeToken<Map<String, String>>() {
        }.getType());
        System.out.println("response结果:");
        responseMap.forEach((k, v) -> System.out.println(k + "\t=\t" + v));
        String aesResult = responseMap.get("result");
        String resultJson = AesUtils.decode(password, aesResult);

        System.out.println("解密Result结果:");
        Map<String, String> resultMap = gson.fromJson(resultJson, new TypeToken<Map<String, String>>() {
        }.getType());
        resultMap.forEach((k, v) -> System.out.println(k + "\t=\t" + v));

    }

    /**
     * 模拟服务端的处理过程.
     *
     * @param requestJson
     * @return
     * @throws Exception
     */
    public String postResponse(String requestJson) throws Exception {

        System.out.println("服务端接收到请求并开始处理......");
        System.out.println("接收到的请求参数:" + requestJson);

        Map<String, String> request = gson.fromJson(requestJson, new TypeToken<Map<String, String>>() {
        }.getType());

        String token = request.get("token");
        final String pwd = org.apache.commons.codec.binary.StringUtils.newStringUtf8(RsaUtils.rsaDecode(RsaUtils.getPrivateKey(privateKeyData), token)); // 通过私钥解密出原始密码
        System.out.println("用于AES加密的原始密码:\t" + pwd);

        String params = request.get("params");
        String decodeParams = AesUtils.decode(pwd, params);
        System.out.println("原始请求参数:" + decodeParams);

        Map<String, String> requestParams = gson.fromJson(decodeParams, new TypeToken<Map<String, String>>() {
        }.getType());

//        List<String> paramsList = Splitter.on("&").omitEmptyStrings().trimResults().splitToList(decodeParams);
        System.out.println("---------------开始解析请求参数---------------");
//        paramsList.forEach(ele -> System.out.println(ele));
        requestParams.forEach((k, v) -> System.out.println(k + "\t=\t" + v));
        System.out.println("---------------解析请求参数完成---------------");

        Map<String, Object> result = new HashMap<>();
        result.put("status", 0);
        result.put("reason", "通过RR规则");
        String resultJson = gson.toJson(result);
        String aesResult = AesUtils.encode(pwd, resultJson);

        Map<String, Object> response = new HashMap<>();
        response.put("code", 0);
        response.put("message", "success");
        response.put("result", aesResult);

        String responseStr = gson.toJson(response);
        System.out.println("服务端返回结果:" + responseStr);
        return responseStr;
    }

    public String postRequest() throws Exception {
        Map<String, Object> appParams = buildReqeustParams();
        String requestStr = gson.toJson(appParams);
        System.out.println("原始请求参数:\t" + requestStr);

        password = generatePassword();
        System.out.println("用于AES加密的原始密码:\t" + password);

        String aesRequest = AesUtils.encode(password, requestStr);
        System.out.println("AES加密后的请求参数:\t" + aesRequest);

        final String token = RsaUtils.rsaEncode(RsaUtils.getPublicKey(publicKeyData), password); // 通过公钥加密后再传输
        System.out.println("经RSA加密后的密码:\t" + token);

        Map<String, String> params = new HashMap<>();
        params.put("app_key", "credit_app_key"); // 由平台生成
        params.put("timestamp", String.valueOf(System.currentTimeMillis() / 1000));
        params.put("token", token); // token
        params.put("version", "0.9");
        params.put("params", aesRequest); // 业务请求参数

        String requestJson = gson.toJson(params);
        System.out.println("最终请求参数:" + requestJson);
        return requestJson;
    }

    private String generatePassword() {
        return UUID.randomUUID().toString().replaceAll("-", "").substring(0, 16);
    }

    private Map<String, Object> buildReqeustParams() {
        Map<String, Object> params = new HashMap<String, Object>();
        params.put("apply_name", "testApp");
        params.put("cert_no", "34098765678909876789");
        params.put("mobile", "13584321234");
        params.put("marriage", 0);
        params.put("education", 4);
        params.put("income_month", 1);
        params.put("income_other", 1);
        params.put("industry", 1);
        params.put("residence_situation", 1);
        return params;
    }

    //    private String joinParams(Map<String, Object> params) {
    //        StringBuilder sb = new StringBuilder();
    //        params.forEach((k, v) -> sb.append("&").append(k).append("=").append(v.toString()));
    //        return sb.substring(1);
    //    }

}
