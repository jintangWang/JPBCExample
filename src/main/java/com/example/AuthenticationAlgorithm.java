package com.example;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.jpbc.Field;

import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

public class AuthenticationAlgorithm {

    private static Pairing pairing;
    private static Field G1, G2, Zp;
    private static Element g1, g2, eta;
    private static Map<String, Element> credentialIssuersPublicKeys;
    private static Element spk;

    public static void main(String[] args) {
        // 初始化配对参数
        initializeSetup();

        // 生成链上认证请求
        generateOnChainAuthenticationRequest();
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
        spk = G1.newRandomElement().getImmutable(); // 模拟生成的共享公钥
        endTime = System.currentTimeMillis();
        System.out.println("初始化配对参数时间: " + (endTime - startTime) + "毫秒");

        // 初始化示例发行者公钥
        credentialIssuersPublicKeys = new HashMap<>();
        credentialIssuersPublicKeys.put("CI1", G2.newRandomElement().getImmutable());
        credentialIssuersPublicKeys.put("CI2", G2.newRandomElement().getImmutable());
        credentialIssuersPublicKeys.put("CI3", G2.newRandomElement().getImmutable());
    }

    private static void generateOnChainAuthenticationRequest() {
        long startTime, endTime;

        // Step 1: 生成用户凭证和认证标识符
        startTime = System.currentTimeMillis();
        Element[] credentials = generateUserCredentials();
        String aid = generateUniqueIdentifier();
        endTime = System.currentTimeMillis();
        System.out.println("生成用户凭证和认证标识符时间: " + (endTime - startTime) + "毫秒");

        // Step 2: 聚合凭证并生成认证请求
        startTime = System.currentTimeMillis();
        Element sigma = aggregateCredentials(credentials);
        Element epsilon = Zp.newRandomElement().getImmutable();
        Element blindedSigma = sigma.powZn(epsilon).getImmutable();
        Element[] zkProofSigma = generateZKProofSigma(blindedSigma, epsilon, credentials);

        Map<String, Object> onChainAuthRequest = new HashMap<>();
        onChainAuthRequest.put("aid", aid);
        onChainAuthRequest.put("blindedSigma", blindedSigma);
        onChainAuthRequest.put("zkProofSigma", zkProofSigma);

        uploadAuthRequestToBlockchain("On-chain Authentication Request", onChainAuthRequest);
        endTime = System.currentTimeMillis();
        System.out.println("生成链上认证请求时间: " + (endTime - startTime) + "毫秒");

        // Step 3: 验证认证请求
        startTime = System.currentTimeMillis();
        boolean isAuthValid = verifyOnChainAuthRequest(onChainAuthRequest);
        endTime = System.currentTimeMillis();
        System.out.println("验证认证请求时间: " + (endTime - startTime) + "毫秒");

        if (isAuthValid) {
            System.out.println("认证请求验证成功");
            // 生成短期离线访问令牌
            startTime = System.currentTimeMillis();
            Element delta = generateShortTermToken();
            endTime = System.currentTimeMillis();
            System.out.println("生成短期离线访问令牌时间: " + (endTime - startTime) + "毫秒");

            // 模拟发送离线访问请求
            sendOffChainAuthRequest(aid, delta);
        } else {
            System.out.println("认证请求验证失败");
        }
    }

    private static Element[] generateUserCredentials() {
        // 模拟生成用户凭证
        Element credential1 = pairing.getG1().newRandomElement().getImmutable();
        Element credential2 = pairing.getG1().newRandomElement().getImmutable();
        Element credential3 = pairing.getG1().newRandomElement().getImmutable();
        return new Element[]{credential1, credential2, credential3};
    }

    private static String generateUniqueIdentifier() {
        // 生成唯一认证标识符
        SecureRandom random = new SecureRandom();
        byte[] aidBytes = new byte[16]; // 128位标识符
        random.nextBytes(aidBytes);
        StringBuilder sb = new StringBuilder();
        for (byte b : aidBytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private static Element aggregateCredentials(Element[] credentials) {
        // 聚合用户凭证
        Element sigma = G1.newOneElement().getImmutable();
        for (Element credential : credentials) {
            sigma = sigma.mul(credential).getImmutable();
        }
        return sigma;
    }

    private static Element[] generateZKProofSigma(Element blindedSigma, Element epsilon, Element[] credentials) {
        // 模拟生成零知识证明
        return new Element[]{blindedSigma, epsilon}; // 简单的证明表示
    }

    private static void uploadAuthRequestToBlockchain(String description, Map<String, Object> authRequest) {
        System.out.println(description + ":");
        authRequest.forEach((key, value) -> {
            if (value instanceof Element) {
                System.out.println(key + " = " + value);
            } else if (value instanceof Element[]) {
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

    private static boolean verifyOnChainAuthRequest(Map<String, Object> authRequest) {
        // 模拟验证链上认证请求
        Element blindedSigma = (Element) authRequest.get("blindedSigma");
        Element[] zkProofSigma = (Element[]) authRequest.get("zkProofSigma");

        // 简单检查证明的有效性
        return blindedSigma != null && zkProofSigma != null && zkProofSigma.length == 2;
    }

    private static Element generateShortTermToken() {
        // 生成短期离线访问令牌
        return Zp.newRandomElement().getImmutable();
    }

    private static void sendOffChainAuthRequest(String aid, Element delta) {
        // 模拟发送离线访问请求
        System.out.println("发送离线访问请求: aid = " + aid + ", delta = " + delta);
    }
}
