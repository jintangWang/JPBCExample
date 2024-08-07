package com.example;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.jpbc.Field;

import java.util.HashMap;
import java.util.Map;

public class CredentialIssuanceAlgorithm {

    private static Pairing pairing;
    private static Field G1, G2, Zp;
    private static Element g1, g2, eta;

    public static void main(String[] args) {
        // 初始化配对参数
        initializeSetup();

        // 用户注册和凭证颁发
        userRegistrationAndCredentialIssuance();
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

    private static void userRegistrationAndCredentialIssuance() {
        long startTime, endTime;

        // 步骤1：用户生成公私钥对
        startTime = System.currentTimeMillis();
        Element rho1 = Zp.newRandomElement().getImmutable();
        Element rho2 = Zp.newRandomElement().getImmutable();
        Element usk = Zp.newElement().set(rho1).set(rho2).getImmutable();

        // 构建aux
        String aux = "auxiliary data";
        Element h = pairing.getZr().newElement().setFromHash(aux.getBytes(), 0, aux.length()).getImmutable();

        Element T1 = g1.powZn(h.mul(rho1)).getImmutable();
        Element T2 = g1.powZn(h.mul(rho2)).getImmutable();
        Element upkT1 = g1.powZn(rho1).getImmutable();
        Element upkT2 = g2.powZn(rho2).getImmutable();

        // 构建commitment
        String attributeSet = "attribute set";
        Element r = Zp.newRandomElement().getImmutable();
        Element C_Aj = pairing.getG1().newElement().setFromHash(attributeSet.getBytes(), 0, attributeSet.length()).powZn(r).getImmutable();

        Element[] V1 = new Element[]{g1, g1.duplicate().powZn(eta)};
        Element[] V2 = new Element[]{g2, g2.duplicate().powZn(eta)};

        Element f_A_alpha = computeF_A_alpha(new String[]{"attr1", "attr2"});
        Element M1 = T1.powZn(f_A_alpha).getImmutable();
        Element M2 = T2.powZn(eta).getImmutable();
        Element N1 = g2.powZn(f_A_alpha).getImmutable();
        Element N2 = g2.powZn(eta).getImmutable();

        Element[] M = new Element[]{M1, M2};
        Element[] N = new Element[]{N1, N2};

        // 生成并发布零知识证明
        Element[] zkProofSecrets = {rho1, rho2, f_A_alpha};
        Element[] zkProofPublicKeys = {T1, T2, M1, N1};
        publishZKProof("User ZK Proof", zkProofSecrets, zkProofPublicKeys);

        // 发送(aux, upk, (M, N), pi_CH)给发行者
        Map<String, Object> requestData = new HashMap<>();
        requestData.put("aux", aux);
        requestData.put("upk", new Element[]{T1, T2});
        requestData.put("M", M);
        requestData.put("N", N);
        requestData.put("zkProof", "Zero-Knowledge Proof Data");
        // 模拟发送数据到发行者

        endTime = System.currentTimeMillis();
        System.out.println("用户注册和凭证请求时间: " + (endTime - startTime) + "毫秒");

        // 步骤2：发行者验证并生成凭证
        startTime = System.currentTimeMillis();
        // 假设发行者收到并验证了请求数据
        boolean proofValid = verifyZKProof(zkProofSecrets, zkProofPublicKeys);
        if (!proofValid) {
            System.out.println("零知识证明验证失败");
            return;
        }

        // 生成凭证
        Element[] zkProofElements = (Element[]) requestData.get("upk");
        Element g1h = g1.powZn(h).getImmutable();
        Element b = zkProofElements[0].powZn(zkProofSecrets[1]).mul(zkProofElements[1].powZn(zkProofSecrets[2])).getImmutable();
        Element s = g1h.powZn(zkProofSecrets[0]).mul(M1.powZn(zkProofSecrets[1])).mul(M2.powZn(zkProofSecrets[2])).getImmutable();

        Map<String, Object> cred = new HashMap<>();
        cred.put("M", M);
        cred.put("N", N);
        cred.put("upk", zkProofElements);
        cred.put("sigma", new Element[]{g1h, b, s});

        // 将cred返回给用户并存储在本地数据库中
        endTime = System.currentTimeMillis();
        System.out.println("发行者生成和返回凭证时间: " + (endTime - startTime) + "毫秒");

        // 用户验证凭证
        startTime = System.currentTimeMillis();
        Element[] sigma = (Element[]) cred.get("sigma");
        boolean credValid = verifyCredential(sigma, zkProofElements, M);
        if (credValid) {
            System.out.println("凭证验证成功");
            // 将凭证存储到用户的本地数据库中
        } else {
            System.out.println("凭证验证失败");
        }
        endTime = System.currentTimeMillis();
        System.out.println("用户验证凭证时间: " + (endTime - startTime) + "毫秒");
    }

    private static Element computeF_A_alpha(String[] attributes) {
        Element f_A_alpha = Zp.newOneElement();
        for (String attr : attributes) {
            Element attrElem = Zp.newElement().setFromHash(attr.getBytes(), 0, attr.length());
            f_A_alpha = f_A_alpha.mul(attrElem);
        }
        return f_A_alpha.getImmutable();
    }

    private static void publishZKProof(String description, Element[] secrets, Element[] publicKeys) {
        System.out.println(description + ":");
        // 这里假设已经有零知识证明算法实现，将秘密和公钥用于生成零知识证明
        for (int i = 0; i < secrets.length; i++) {
            System.out.println("Secret " + (i + 1) + " = " + secrets[i]);
            System.out.println("Public Key " + (i + 1) + " = " + publicKeys[i]);
        }
    }

    private static boolean verifyZKProof(Element[] secrets, Element[] publicKeys) {
        // 假设零知识证明验证逻辑已经实现
        return true;
    }

    private static boolean verifyCredential(Element[] sigma, Element[] upk, Element[] M) {
        // 假设凭证验证逻辑已经实现
        return true;
    }
}
