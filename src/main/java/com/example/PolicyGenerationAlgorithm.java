package com.example;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.jpbc.Field;

import java.util.HashMap;
import java.util.Map;

public class PolicyGenerationAlgorithm {

    private static Pairing pairing;
    private static Field G1, G2, Zp;
    private static Element g1, g2, eta;

    public static void main(String[] args) {
        // 初始化配对参数
        initializeSetup();

        // 认证策略生成
        generateAuthenticationPolicy();
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
        g1 = G1.newRandomElement().getImmutable();
        g2 = G2.newRandomElement().getImmutable();
        eta = pairing.getGT().newRandomElement().getImmutable();
        endTime = System.currentTimeMillis();
        System.out.println("初始化配对参数时间: " + (endTime - startTime) + "毫秒");
    }

    private static void generateAuthenticationPolicy() {
        long startTime, endTime;

        // 生成认证策略
        startTime = System.currentTimeMillis();
        int Ki = 3; // 假设CV想接受的最大发行者数量
        Element[] xj = new Element[Ki];
        Element[] vpk = new Element[Ki];
        for (int j = 0; j < Ki; j++) {
            xj[j] = Zp.newRandomElement().getImmutable();
            vpk[j] = g2.powZn(xj[j]).getImmutable();
        }

        Element kappa_i = Zp.newRandomElement().getImmutable();
        Element product_ipk = g2.duplicate();
        // 这里假设ipk_j是之前注册的发行者公钥，实际应用中应替换为正确的公钥
        Element[] ipk_j = new Element[Ki];
        for (int j = 0; j < Ki; j++) {
            ipk_j[j] = G2.newRandomElement().getImmutable(); // 模拟公钥
            product_ipk = product_ipk.mul(ipk_j[j].powZn(xj[j])).getImmutable();
        }
        Element Z = product_ipk.powZn(kappa_i).getImmutable();
        Element B1 = g1.powZn(kappa_i.invert()).getImmutable();
        Element B2 = g2.powZn(kappa_i.invert()).getImmutable();

        // 生成认证策略pol_i
        Map<String, Object> pol_i = new HashMap<>();
        pol_i.put("vpk", vpk);
        pol_i.put("ipk_j", ipk_j);
        pol_i.put("T_j", "Attribute Subsets");
        pol_i.put("s_i", new Element[]{Z, B1, B2});

        // 上传认证策略到区块链（模拟打印到控制台）
        uploadPolicyToBlockchain("Authentication Policy", pol_i);

        // 生成并发布零知识证明
        Element[] zkProofSecrets = new Element[Ki + 1];
        System.arraycopy(xj, 0, zkProofSecrets, 0, Ki);
        zkProofSecrets[Ki] = kappa_i;
        Element[] zkProofPublicKeys = new Element[Ki + 3];
        System.arraycopy(vpk, 0, zkProofPublicKeys, 0, Ki);
        zkProofPublicKeys[Ki] = Z;
        zkProofPublicKeys[Ki + 1] = B1;
        zkProofPublicKeys[Ki + 2] = B2;
        publishZKProof("Verifier ZK Proof", zkProofSecrets, zkProofPublicKeys);

        endTime = System.currentTimeMillis();
        System.out.println("认证策略生成时间: " + (endTime - startTime) + "毫秒");
    }

    private static void uploadPolicyToBlockchain(String description, Map<String, Object> policy) {
        System.out.println(description + ":");
        policy.forEach((key, value) -> {
            if (value instanceof Element[]) {
                System.out.print(key + " = ");
                for (Element elem : (Element[]) value) {
                    System.out.print(elem + " ");
                }
                System.out.println();
            } else {
                System.out.println(key + " = " + value);
            }
        });
    }

    private static void publishZKProof(String description, Element[] secrets, Element[] publicKeys) {
        System.out.println(description + ":");
        // 这里假设已经有零知识证明算法实现，将秘密和公钥用于生成零知识证明
        for (int i = 0; i < secrets.length; i++) {
            System.out.println("Secret " + (i + 1) + " = " + secrets[i]);
        }
        for (int i = 0; i < publicKeys.length; i++) {
            System.out.println("Public Key " + (i + 1) + " = " + publicKeys[i]);
        }
    }
}
