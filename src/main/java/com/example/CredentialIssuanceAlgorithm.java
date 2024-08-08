package com.example;

import com.example.SetupAlgorithm.SetupParams;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.Field;

import java.util.HashMap;
import java.util.Map;

public class CredentialIssuanceAlgorithm {

    private static Pairing pairing;
    private static Field G1, G2, Zp;
    private static Element g, g1, g2, eta;
    private static Map<String, Map<String, Element>> ipkMap;
    private static Element apk;

    public static void main(String[] args) {
        // 初始化配对参数
        SetupParams setupParams = SetupAlgorithm.getInstance();
        initializeSetupParams(setupParams);

        // 注册服务实体
        RegistrationAlgorithm.main(null);  // 调用 RegistrationAlgorithm 注册实体
        ipkMap = RegistrationAlgorithm.getIpkMap();
        apk = RegistrationAlgorithm.getApk();

        // 用户注册和凭证颁发
        userRegistrationAndCredentialIssuance();
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

    public static void userRegistrationAndCredentialIssuance() {
        long startTime, endTime;
        long originTime, exitTime;
        originTime = System.currentTimeMillis();

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
        Element b = zkProofElements[0].powZn(zkProofSecrets[1]).mul(zkProofElements[1]).getImmutable();
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
        boolean credValid = verifyCredential(sigma, zkProofElements, M, N);
        if (credValid) {
            System.out.println("凭证验证成功");
            // 将凭证存储到用户的本地数据库中
        } else {
            System.out.println("凭证验证失败");
        }
        endTime = System.currentTimeMillis();
        System.out.println("用户验证凭证时间: " + (endTime - startTime) + "毫秒");

        exitTime = System.currentTimeMillis();
        System.out.println("用户注册和凭证分发算法成功完成。用户注册和凭证分发算法总时间为："+ (exitTime - originTime) + "毫秒");
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
//        System.out.println(description + ":");
//        // 这里假设已经有零知识证明算法实现，将秘密和公钥用于生成零知识证明
//        for (int i = 0; i < secrets.length; i++) {
//            System.out.println("Secret " + (i + 1) + " = " + secrets[i]);
//        }
//        for (int i = 0; i < publicKeys.length; i++) {
//            System.out.println("Public Key " + (i + 1) + " = " + publicKeys[i]);
//        }
    }

    private static boolean verifyZKProof(Element[] secrets, Element[] publicKeys) {
        // 假设零知识证明验证逻辑已经实现
        return true;
    }

    private static boolean verifyCredential(Element[] sigma, Element[] upk, Element[] M, Element[] N) {
        Element g1h = sigma[0];
        Element b = sigma[1];
        Element s = sigma[2];

        // 检查所有元素是否为 null
        if (g1h == null) {
            System.out.println("g1h is null");
        }
        if (b == null) {
            System.out.println("b is null");
        }
        if (s == null) {
            System.out.println("s is null");
        }
        if (upk == null) {
            System.out.println("upk is null");
        } else {
            if (upk[0] == null) {
                System.out.println("upk[0] is null");
            }
            if (upk[1] == null) {
                System.out.println("upk[1] is null");
            }
        }
        if (M == null) {
            System.out.println("M is null");
        } else {
            if (M[0] == null) {
                System.out.println("M[0] is null");
            }
            if (M[1] == null) {
                System.out.println("M[1] is null");
            }
        }
        if (N == null) {
            System.out.println("N is null");
        } else {
            if (N[0] == null) {
                System.out.println("N[0] is null");
            }
            if (N[1] == null) {
                System.out.println("N[1] is null");
            }
        }
        // 假设ipkMap中存储的是发行者的公钥
        Map<String, Element> issuerKeys = ipkMap.get("CI1");  // 假设CI1是其中一个发行者
        if (issuerKeys == null) {
            System.out.println("issuerKeys is null");
            return false;
        }
        Element X = issuerKeys.get("X");
        Element Y1 = issuerKeys.get("Y1");
        Element Y2 = issuerKeys.get("Y2");
        Element Z1 = issuerKeys.get("Z1");
        Element Z2 = issuerKeys.get("Z2");

        // 检查公钥是否为 null
        if (X == null) {
            System.out.println("X is null");
        }
        if (Y1 == null) {
            System.out.println("Y1 is null");
        }
        if (Y2 == null) {
            System.out.println("Y2 is null");
        }
        if (Z1 == null) {
            System.out.println("Z1 is null");
        }
        if (Z2 == null) {
            System.out.println("Z2 is null");
        }

        // 调试输出以检查中间值
//        System.out.println("g1h: " + g1h);
//        System.out.println("X: " + X);
//        System.out.println("M[0]: " + M[0]);
//        System.out.println("Y1: " + Y1);
//        System.out.println("M[1]: " + M[1]);
//        System.out.println("Y2: " + Y2);
//        System.out.println("s: " + s);
//        System.out.println("g2: " + g2);

        Element pairing1 = pairing.pairing(g1h, X);
        Element pairing2 = pairing.pairing(M[0], Y1);
        Element pairing3 = pairing.pairing(M[1], Y2);
        Element pairing4 = pairing.pairing(s, g2);

//        System.out.println("pairing(g1h, X): " + pairing1);
//        System.out.println("pairing(M[0], Y1): " + pairing2);
//        System.out.println("pairing(M[1], Y2): " + pairing3);
//        System.out.println("pairing(s, g2): " + pairing4);

        boolean firstCheck = pairing1.mul(pairing2).mul(pairing3).isEqual(pairing4);

        Element pairing5 = pairing.pairing(b, g2);
        Element pairing6 = pairing.pairing(upk[0], Z1);
        Element pairing7 = pairing.pairing(upk[1], Z2);

//        System.out.println("pairing(b, g2): " + pairing5);
//        System.out.println("pairing(upk[0], Z1): " + pairing6);
//        System.out.println("pairing(upk[1], Z2): " + pairing7);

        boolean secondCheck = pairing5.isEqual(pairing6.mul(pairing7));

        boolean thirdCheck = pairing.pairing(upk[0], N[0]).isEqual(pairing.pairing(M[0], g2)) && pairing.pairing(upk[1], N[1]).isEqual(pairing.pairing(M[1], g2));

        // 添加调试输出以检查检查结果
//        System.out.println("firstCheck: " + firstCheck);
//        System.out.println("secondCheck: " + secondCheck);
//        System.out.println("thirdCheck: " + thirdCheck);

        return firstCheck && secondCheck && thirdCheck;
    }
}
