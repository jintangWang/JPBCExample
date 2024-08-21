package com.example;

import com.example.B_SetupAlgorithm.SetupParams;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.Field;

import java.util.HashMap;
import java.util.Map;

public class E_PolicyGenerationAlgorithm {

    private static Pairing pairing;
    private static Field G1, G2, Zp;
    private static Element g, g1, g2, eta;
    private static Map<String, Map<String, Element>> ipkMap;
    private static Element apk;

    public static void main(String[] args) {
        // 初始化配对参数
        SetupParams setupParams = B_SetupAlgorithm.getInstance();

        D_CredentialIssuanceAlgorithm.main(null);
        // 获取注册服务实体参数
        ipkMap = C_RegistrationAlgorithm.getIpkMap();
        apk = C_RegistrationAlgorithm.getApk();

        // 初始化其他参数
        initializeSetupParams(setupParams);

        // 生成认证策略
        generateAuthenticationPolicy("CV1");
    }

    private static void initializeSetupParams(SetupParams setupParams) {
        pairing = setupParams.pairing;
        G1 = setupParams.G1;
        G2 = setupParams.G2;
        Zp = pairing.getZr();
        g = setupParams.g;
        g1 = setupParams.g1;
        g2 = setupParams.g2;
        eta = setupParams.eta;
    }

    private static void generateAuthenticationPolicy(String verifierName) {
        long startTime, endTime;

        // 步骤1：生成认证策略密钥对
        startTime = System.currentTimeMillis();
        int Ki = 3;  // 可接受的发行者数量
        Element[] xj = new Element[Ki];
        Element[] vpk = new Element[Ki];
        for (int i = 0; i < Ki; i++) {
            xj[i] = Zp.newRandomElement().getImmutable();
            vpk[i] = g2.powZn(xj[i]).getImmutable();
        }

        Element kappa_i = Zp.newRandomElement().getImmutable();
        Element Z = g.duplicate().powZn(kappa_i).getImmutable();
        Element B1 = g1.powZn(Zp.newOneElement().div(kappa_i)).getImmutable();
        Element B2 = g2.powZn(Zp.newOneElement().div(kappa_i)).getImmutable();

        Map<String, Element> ipkSubset = new HashMap<>();
        for (int i = 0; i < Ki; i++) {
            String issuerName = "CI" + (i + 1);
            if (ipkMap.containsKey(issuerName)) {
                ipkSubset.putAll(ipkMap.get(issuerName));
            }
        }

        Element[] ipkElements = ipkSubset.values().toArray(new Element[0]);
        Element s_i = Zp.newRandomElement().getImmutable();
        Element[] s_i_elements = new Element[ipkElements.length];
        for (int i = 0; i < ipkElements.length; i++) {
            s_i_elements[i] = ipkElements[i].duplicate().powZn(s_i).getImmutable();
        }

        Map<String, Object> policy = new HashMap<>();
        policy.put("vpk", vpk);
        policy.put("ipkSubset", ipkSubset);
        policy.put("Z", Z);
        policy.put("B1", B1);
        policy.put("B2", B2);
        policy.put("s_i_elements", s_i_elements);

        publishToBlockchain(verifierName + " Policy", policy);

        endTime = System.currentTimeMillis();
        System.out.println(verifierName + " 认证策略生成时间: " + (endTime - startTime) + "毫秒");
    }

    private static void publishToBlockchain(String description, Map<String, Object> elements) {
//        System.out.println(description + ":");
//        elements.forEach((key, value) -> {
//            if (value instanceof Element[]) {
//                Element[] array = (Element[]) value;
//                for (int i = 0; i < array.length; i++) {
//                    System.out.println(key + "[" + i + "] = " + array[i]);
//                }
//            } else {
//                System.out.println(key + " = " + value);
//            }
//        });
    }
}
