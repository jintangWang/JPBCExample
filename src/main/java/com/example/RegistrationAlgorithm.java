package com.example;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.HashMap;
import java.util.Map;

public class RegistrationAlgorithm {

    private static Pairing pairing;
    private static Field G1, G2, Zp;
    private static Element g, g1, g2, eta;

    public static void main(String[] args) {
        // 初始化配对参数
        initializeSetup();

        // 证书发行者注册
        registerCredentialIssuer();

        // 证书审核员注册
        registerCredentialAuditor();
    }

    private static void initializeSetup() {
        long startTime, endTime;

        // 读取配对参数
        startTime = System.currentTimeMillis();
        PairingParameters params = PairingFactory.getPairingParameters("params/a.properties");
        pairing = PairingFactory.getPairing(params);
        G1 = pairing.getG1();
        G2 = pairing.getG2();
        Zp = pairing.getZr();
        g = G1.newRandomElement().getImmutable();
        g1 = G1.newRandomElement().getImmutable();
        g2 = G2.newRandomElement().getImmutable();
        eta = pairing.getGT().newRandomElement().getImmutable();
        endTime = System.currentTimeMillis();
        System.out.println("初始化配对参数时间: " + (endTime - startTime) + "毫秒");
    }

    private static void registerCredentialIssuer() {
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

        // 发布公钥和零知识证明
        publishToBlockchain("Credential Issuer Public Key", ipk);
        Element[] isk = {x, y1, y2, z1, z2};
        Element[] ipkElements = {X, Y1, Y2, Z1, Z2};
        publishZKProof("Credential Issuer ZK Proof", isk, ipkElements);

        endTime = System.currentTimeMillis();
        System.out.println("证书发行者注册时间: " + (endTime - startTime) + "毫秒");
    }

    private static void registerCredentialAuditor() {
        long startTime, endTime;

        // 生成证书审核员密钥对
        startTime = System.currentTimeMillis();
        Element u = Zp.newRandomElement().getImmutable();
        Element apk = g.powZn(u).getImmutable();

        // 发布公钥和零知识证明
        Map<String, Element> auditorKey = new HashMap<>();
        auditorKey.put("apk", apk);
        publishToBlockchain("Credential Auditor Public Key", auditorKey);
        publishZKProof("Credential Auditor ZK Proof", new Element[]{u}, new Element[]{apk});

        endTime = System.currentTimeMillis();
        System.out.println("证书审核员注册时间: " + (endTime - startTime) + "毫秒");
    }

    private static void publishToBlockchain(String description, Map<String, Element> elements) {
        System.out.println(description + ":");
        elements.forEach((key, value) -> System.out.println(key + " = " + value));
    }

    private static void publishZKProof(String description, Element[] secrets, Element[] publicKeys) {
        System.out.println(description + ":");
        // 这里我们假设已经有零知识证明算法实现，将秘密和公钥用于生成零知识证明
        for (int i = 0; i < secrets.length; i++) {
            System.out.println("Secret " + (i + 1) + " = " + secrets[i]);
            System.out.println("Public Key " + (i + 1) + " = " + publicKeys[i]);
        }
    }
}
