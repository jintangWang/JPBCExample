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

        D_CredentialIssuanceAlgorithm.main(null);  // 执行之前的发行凭证算法
        // 获取注册服务实体参数
        ipkMap = C_RegistrationAlgorithm.getIpkMap();
        apk = C_RegistrationAlgorithm.getApk();

        // 初始化其他参数
        initializeSetupParams(setupParams);

        // 生成认证策略并生成零知识证明
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
        int Ki = 5;  // 可接受的发行者数量
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

        // 获取部分发行者的公钥
        Map<String, Element> ipkSubset = new HashMap<>();
        for (int i = 0; i < Ki; i++) {
            String issuerName = "CI" + (i + 1);
            if (ipkMap.containsKey(issuerName)) {
                ipkSubset.putAll(ipkMap.get(issuerName));
            }
        }

        Element[] ipkElements = ipkSubset.values().toArray(new Element[0]);

        // 生成并发布零知识证明
        Element[] zkProof = ZkPoK_pol.generateZKProof(xj, kappa_i, g1, g2, ipkElements, Z, B1, B2, pairing);
        publishToBlockchain(verifierName + " Policy", zkProof);

        endTime = System.currentTimeMillis();
        System.out.println(verifierName + " 认证策略生成时间: " + (endTime - startTime) + "毫秒");

        // 步骤2：验证零知识证明
//        startTime = System.currentTimeMillis();
//        boolean proofValid = ZkPoK_pol.verifyZKProof(zkProof, g1, g2, ipkElements, Z, B1, B2, pairing);
//        if (proofValid) {
//            System.out.println(verifierName + " 认证策略零知识证明验证成功");
//        } else {
//            System.out.println(verifierName + " 认证策略零知识证明验证失败");
//        }
//        endTime = System.currentTimeMillis();
//        System.out.println(verifierName + " 认证策略验证时间: " + (endTime - startTime) + "毫秒");
    }

    private static void publishToBlockchain(String description, Element[] zkProof) {
        // 模拟将证明发布到区块链
//        System.out.println(description + " Proof has been published to the blockchain.");
    }
}
