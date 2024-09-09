package com.example;

import com.example.C_SetupAlgorithm.SetupParams;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.Field;

import java.util.HashMap;
import java.util.Map;

public class D_RegistrationAlgorithm {

    private static Pairing pairing;
    private static Field G1, G2, Zp;
    private static Element g, g1, g2, eta;
    private static Map<String, Map<String, Element>> ipkMap = new HashMap<>();
    private static Map<String, Map<String, Element>> privateKeyMap = new HashMap<>();  // 存储小写的私钥
    private static Element apk;

    public static void main(String[] args) {
        // 初始化配对参数
        SetupParams setupParams = C_SetupAlgorithm.getInstance();
        initializeSetupParams(setupParams);

        long originTime, exitTime;
        originTime = System.currentTimeMillis();
        // 注册证书发行者
        registerCredentialIssuer("CI1", setupParams);
        registerCredentialIssuer("CI2", setupParams);
        registerCredentialIssuer("CI3", setupParams);
        registerCredentialIssuer("CI4", setupParams);
        registerCredentialIssuer("CI5", setupParams);

        // 注册证书审核员
        registerCredentialAuditor(setupParams);

        // 生成并发布零知识证明
        publishZKProof("CI ZK Proof", setupParams);

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

    private static void registerCredentialIssuer(String issuerName, SetupParams setupParams) {
        long startTime, endTime;

        // 生成证书发行者密钥对
        startTime = System.currentTimeMillis();
        Element x = Zp.newRandomElement().getImmutable();
        Element y1 = Zp.newRandomElement().getImmutable();
        Element y2 = Zp.newRandomElement().getImmutable();
        Element z1 = Zp.newRandomElement().getImmutable();
        Element z2 = Zp.newRandomElement().getImmutable();
        Element X = setupParams.g2.powZn(x).getImmutable();   // 使用 B_SetupAlgorithm 中生成的 g2
        Element Y1 = setupParams.g2.powZn(y1).getImmutable();
        Element Y2 = setupParams.g2.powZn(y2).getImmutable();
        Element Z1 = setupParams.g2.powZn(z1).getImmutable();
        Element Z2 = setupParams.g2.powZn(z2).getImmutable();

        // 存储公钥
        Map<String, Element> ipk = new HashMap<>();
        ipk.put("X", X);
        ipk.put("Y1", Y1);
        ipk.put("Y2", Y2);
        ipk.put("Z1", Z1);
        ipk.put("Z2", Z2);
        ipkMap.put(issuerName, ipk);  // 将所有公钥元素存储在 ipkMap 中

        // 存储私钥
        Map<String, Element> privateKey = new HashMap<>();
        privateKey.put("x", x);
        privateKey.put("y1", y1);
        privateKey.put("y2", y2);
        privateKey.put("z1", z1);
        privateKey.put("z2", z2);
        privateKeyMap.put(issuerName, privateKey);  // 存储小写私钥

        // 发布公钥
        publishToBlockchain(issuerName + " Public Key", ipk);

        endTime = System.currentTimeMillis();
        System.out.println(issuerName + " 注册时间: " + (endTime - startTime) + "毫秒");
    }

    private static void registerCredentialAuditor(SetupParams setupParams) {
        long startTime, endTime;

        // 生成证书审核员密钥对
        startTime = System.currentTimeMillis();
        Element u = setupParams.pairing.getZr().newRandomElement().getImmutable();
        apk = setupParams.g.powZn(u).getImmutable();

        // 发布公钥和零知识证明
        Map<String, Element> auditorKey = new HashMap<>();
        auditorKey.put("apk", apk);
        publishToBlockchain("Credential Auditor Public Key", auditorKey);

        endTime = System.currentTimeMillis();
        System.out.println("证书审核员注册时间: " + (endTime - startTime) + "毫秒");
    }

    private static void publishToBlockchain(String description, Map<String, Element> elements) {
        // System.out.println(description + ":");
        // elements.forEach((key, value) -> System.out.println(key + " = " + value));
    }

    private static void publishZKProof(String description, SetupParams setupParams) {
        Element x = Zp.newRandomElement().getImmutable();
        Element y1 = Zp.newRandomElement().getImmutable();
        Element y2 = Zp.newRandomElement().getImmutable();
        Element z1 = Zp.newRandomElement().getImmutable();
        Element z2 = Zp.newRandomElement().getImmutable();

        Element g2 = setupParams.g2; // 获取 g2 元素

        // 生成零知识证明
        Element[] zkProof = ZkPoK_CI.generateZKProof(x, y1, y2, z1, z2, g2, pairing);

        // 验证零知识证明
        boolean isValid = ZkPoK_CI.verifyZKProof(zkProof, g2);
        // 上传到智能合约 do....
    }

    public static Map<String, Map<String, Element>> getIpkMap() {
        return ipkMap;
    }

    public static Map<String, Map<String, Element>> getPrivateKeyMap() {
        return privateKeyMap;
    }

    public static Element getApk() {
        return apk;
    }
}
