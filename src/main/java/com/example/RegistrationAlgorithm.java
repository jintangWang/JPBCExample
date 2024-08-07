package com.example;

import com.example.SetupAlgorithm.SetupParams;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.Field;

import java.util.HashMap;
import java.util.Map;

public class RegistrationAlgorithm {

    private static Pairing pairing;
    private static Field G1, G2, Zp;
    private static Element g, g1, g2, eta;
    private static Map<String, Map<String, Element>> ipkMap = new HashMap<>();
    private static Element apk;

    public static void main(String[] args) {
        // 初始化配对参数
        SetupParams setupParams = SetupAlgorithm.getInstance();
        initializeSetupParams(setupParams);

        long originTime, exitTime;
        originTime = System.currentTimeMillis();
        // 注册证书发行者
        registerCredentialIssuer("CI1");
        registerCredentialIssuer("CI2");
        registerCredentialIssuer("CI3");

        // 注册证书审核员
        registerCredentialAuditor();

        exitTime = System.currentTimeMillis();
        System.out.println("注册算法成功完成。注册算法总时间为："+ (exitTime - originTime) + "毫秒");
    }

    public static void initializeSetupParams(SetupParams setupParams) {
        pairing = setupParams.pairing;
        G1 = setupParams.G1;
        G2 = setupParams.G2;
        Zp = pairing.getZr();
        g = setupParams.g;
        g1 = setupParams.g1;
        g2 = setupParams.g2;
        eta = setupParams.eta;
    }

    private static void registerCredentialIssuer(String issuerName) {
        long startTime, endTime;

        // 生成证书发行者密钥对
        startTime = System.currentTimeMillis();
        Element x = Zp.newRandomElement().getImmutable();
        Element y1 = Zp.newRandomElement().getImmutable();
        Element y2 = Zp.newRandomElement().getImmutable();
        Element z1 = Zp.newRandomElement().getImmutable();
        Element z2 = Zp.newRandomElement().getImmutable();
        Element X = g2.powZn(x).getImmutable();
        Element Y1 = g2.powZn(y1).getImmutable();
        Element Y2 = g2.powZn(y2).getImmutable();
        Element Z1 = g2.powZn(z1).getImmutable();
        Element Z2 = g2.powZn(z2).getImmutable();

        Map<String, Element> ipk = new HashMap<>();
        ipk.put("X", X);
        ipk.put("Y1", Y1);
        ipk.put("Y2", Y2);
        ipk.put("Z1", Z1);
        ipk.put("Z2", Z2);
        ipkMap.put(issuerName, ipk);  // 将所有公钥元素存储在 ipkMap 中

        // 发布公钥和零知识证明
        publishToBlockchain(issuerName + " Public Key", ipk);
        Element[] isk = {x, y1, y2, z1, z2};
        Element[] ipkElements = {X, Y1, Y2, Z1, Z2};
        publishZKProof(issuerName + " ZK Proof", isk, ipkElements);

        endTime = System.currentTimeMillis();
        System.out.println(issuerName + " 注册时间: " + (endTime - startTime) + "毫秒");
    }

    private static void registerCredentialAuditor() {
        long startTime, endTime;

        // 生成证书审核员密钥对
        startTime = System.currentTimeMillis();
        Element u = Zp.newRandomElement().getImmutable();
        apk = g.powZn(u).getImmutable();

        // 发布公钥和零知识证明
        Map<String, Element> auditorKey = new HashMap<>();
        auditorKey.put("apk", apk);
        publishToBlockchain("Credential Auditor Public Key", auditorKey);
        publishZKProof("Credential Auditor ZK Proof", new Element[]{u}, new Element[]{apk});

        endTime = System.currentTimeMillis();
        System.out.println("证书审核员注册时间: " + (endTime - startTime) + "毫秒");
    }

    private static void publishToBlockchain(String description, Map<String, Element> elements) {
//        System.out.println(description + ":");
//        elements.forEach((key, value) -> System.out.println(key + " = " + value));
    }

    private static void publishZKProof(String description, Element[] secrets, Element[] publicKeys) {
//        System.out.println(description + ":");
        // 这里假设已经有零知识证明算法实现，将秘密和公钥用于生成零知识证明
//        for (int i = 0; i < secrets.length; i++) {
//            System.out.println("Secret " + (i + 1) + " = " + secrets[i]);
//            System.out.println("Public Key " + (i + 1) + " = " + publicKeys[i]);
//        }
    }

    public static Map<String, Map<String, Element>> getIpkMap() {
        return ipkMap;
    }

    public static Element getApk() {
        return apk;
    }
}
