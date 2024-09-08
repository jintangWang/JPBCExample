package com.example;

import com.example.C_SetupAlgorithm.SetupParams;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.Field;

import java.util.HashMap;
import java.util.Map;

public class E_CredentialIssuanceAlgorithm {

    private static Pairing pairing;
    private static Field G1, G2, Zp;
    private static Element g, g1, g2, alpha, eta;
    private static Map<String, Map<String, Element>> ipkMap;
    private static Element apk;

    public static void main(String[] args) {
        // 初始化配对参数
        SetupParams setupParams = C_SetupAlgorithm.getInstance();
        initializeSetupParams(setupParams);

        // 注册服务实体
        D_RegistrationAlgorithm.main(null);  // 调用 RegistrationAlgorithm 注册实体
        ipkMap = D_RegistrationAlgorithm.getIpkMap();
        apk = D_RegistrationAlgorithm.getApk();

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
        alpha = setupParams.alpha;
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
        String attributeSet = "attribute set";
        Element r = Zp.newRandomElement().getImmutable();
        // C_{A_j} = H'(A_j || r)
        Element C_Aj = pairing.getG1().newElement()
                .setFromHash((attributeSet + r.toString()).getBytes(), 0, (attributeSet + r.toString()).length())
                .getImmutable();

        String aux = g1.powZn(rho1).toString() + g2.powZn(rho2).toString() + C_Aj.toString(); // 结合 g1^rho1, g2^rho2 和 C_Aj
        Element h = pairing.getZr().newElement().setFromHash(aux.getBytes(), 0, aux.length()).getImmutable();

        Element T1 = g1.powZn(h.mul(rho1)).getImmutable();
        Element T2 = g1.powZn(h.mul(rho2)).getImmutable();

        // 计算 f_A(alpha) 的值
        Element f_A_alpha = computeF_A_alpha(new String[]{"attr1", "attr2"}, alpha);
        Element M1 = T1.powZn(f_A_alpha).getImmutable();
        Element M2 = T2.powZn(eta).getImmutable();
        Element N1 = g2.powZn(f_A_alpha).getImmutable();
        Element N2 = g2.powZn(eta).getImmutable();

        Element[] M = new Element[]{M1, M2};
        Element[] N = new Element[]{N1, N2};

        // 调用零知识证明生成函数时传递 pairing 对象
        Element[] zkProof = ZkPoK_CH.generateZKProof(rho1, rho2, new Element[]{f_A_alpha}, g1, g2, h, T1, T2, f_A_alpha, pairing);
        publishZKProof("User ZK Proof", zkProof);

        // 发送(aux, upk, (M, N), pi_CH)给发行者
        Map<String, Object> requestData = new HashMap<>();
        requestData.put("aux", aux);
        requestData.put("upk", new Element[]{T1, T2});
        requestData.put("M", M);
        requestData.put("N", N);
        requestData.put("zkProof", zkProof);
        // 模拟发送数据到发行者

        endTime = System.currentTimeMillis();
        System.out.println("用户注册和凭证请求时间: " + (endTime - startTime) + "毫秒");

        // 步骤2：发行者验证并生成凭证
        startTime = System.currentTimeMillis();
        // 假设发行者收到并验证了请求数据
        boolean proofValid = ZkPoK_CH.verifyZKProof(zkProof, g1, g2, h, f_A_alpha, pairing);
        if (!proofValid) {
            System.out.println("零知识证明验证失败");
            return;
        } else {
            System.out.println("零知识证明验证成功");
        }

        // 生成凭证
        Element[] zkProofElements = (Element[]) requestData.get("upk");
        Element g1h = g1.powZn(h).getImmutable();
        Element b = zkProofElements[0].powZn(rho2).mul(zkProofElements[1]).getImmutable();
        Element s = g1h.powZn(rho1).mul(M1.powZn(rho2)).mul(M2.powZn(f_A_alpha)).getImmutable();

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
            System.out.println("凭证验证失败");
        } else {
            System.out.println("凭证验证成功");
        }
        endTime = System.currentTimeMillis();
        System.out.println("用户验证凭证时间: " + (endTime - startTime) + "毫秒");

        exitTime = System.currentTimeMillis();
        System.out.println("用户注册和凭证分发算法成功完成。用户注册和凭证分发算法总时间为："+ (exitTime - originTime) + "毫秒");
    }

    private static Element computeF_A_alpha(String[] attributes, Element alpha) {
        Element f_A_alpha = Zp.newOneElement(); // 初始化为 1，用于乘积
        for (String attr : attributes) {
            Element attrElem = Zp.newElement().setFromHash(attr.getBytes(), 0, attr.length());
            Element term = alpha.duplicate().sub(attrElem); // 计算 (α - a_i)
            f_A_alpha = f_A_alpha.mul(term); // 将所有 (α - a_i) 相乘
        }
        return f_A_alpha.getImmutable();
    }

    private static void publishZKProof(String description, Element[] zkProof) {
        // 调用智能合约这里将零知识证明发布到区块链
        // System.out.println(description + " Zero-Knowledge Proof: " + Arrays.toString(zkProof));
    }

    private static boolean verifyCredential(Element[] sigma, Element[] upk, Element[] M, Element[] N) {
        Element g1h = sigma[0];
        Element b = sigma[1];
        Element s = sigma[2];

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

        Element pairing1 = pairing.pairing(g1h, X);
        Element pairing2 = pairing.pairing(M[0], Y1);
        Element pairing3 = pairing.pairing(M[1], Y2);
        Element pairing4 = pairing.pairing(s, g2);

        boolean firstCheck = pairing1.mul(pairing2).mul(pairing3).isEqual(pairing4);

        Element pairing5 = pairing.pairing(b, g2);
        Element pairing6 = pairing.pairing(upk[0], Z1);
        Element pairing7 = pairing.pairing(upk[1], Z2);

        boolean secondCheck = pairing5.isEqual(pairing6.mul(pairing7));

        boolean thirdCheck = pairing.pairing(upk[0], N[0]).isEqual(pairing.pairing(M[0], g2)) && pairing.pairing(upk[1], N[1]).isEqual(pairing.pairing(M[1], g2));

        return firstCheck && secondCheck && thirdCheck;
    }
}
