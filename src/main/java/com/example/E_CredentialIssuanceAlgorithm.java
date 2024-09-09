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
    private static Map<String, Map<String, Element>> privateKeyMap;
    private static Element apk;
    private static Element b, s, g1h;  // 新增全局变量

    public static void main(String[] args) {
        // 初始化配对参数
        SetupParams setupParams = C_SetupAlgorithm.getInstance();
        initializeSetupParams(setupParams);

        // 注册服务实体
        D_RegistrationAlgorithm.main(null);  // 调用 RegistrationAlgorithm 注册实体
        ipkMap = D_RegistrationAlgorithm.getIpkMap();
        privateKeyMap = D_RegistrationAlgorithm.getPrivateKeyMap();  // 获取私钥映射
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

        endTime = System.currentTimeMillis();
        System.out.println("用户注册和凭证请求时间: " + (endTime - startTime) + "毫秒");

        // 发行者验证并生成凭证
        boolean proofValid = ZkPoK_CH.verifyZKProof(zkProof, g1, g2, h, f_A_alpha, pairing);
        if (!proofValid) {
            System.out.println("零知识证明验证失败");
            return;
        } else {
            System.out.println("零知识证明验证成功");
        }

        // 从 privateKeyMap 中获取 z1、z2、x、y1、y2
        Map<String, Element> issuerPrivateKeys = privateKeyMap.get("CI1");  // 假设CI1是其中一个发行者
        if (issuerPrivateKeys == null) {
            System.out.println("issuerPrivateKeys is null");
            return;
        }
        Element z1 = issuerPrivateKeys.get("z1");
        Element z2 = issuerPrivateKeys.get("z2");
        Element x = issuerPrivateKeys.get("x");
        Element y1 = issuerPrivateKeys.get("y1");
        Element y2 = issuerPrivateKeys.get("y2");

        // 生成凭证
        Element[] zkProofElements = (Element[]) requestData.get("upk");
        g1h = g1.powZn(h).getImmutable();
        b = zkProofElements[0].powZn(z1).mul(zkProofElements[1].powZn(z2)).getImmutable();  // 正确计算 b
        s = g1h.powZn(x)  // (g_1^h)^x
                .mul(M1.powZn(y1))  // M1^y1
                .mul(M2.powZn(y2))  // M2^y2
                .getImmutable();    // 正确计算 s

        // 将cred返回给用户并存储在本地数据库中
        endTime = System.currentTimeMillis();
        System.out.println("发行者生成和返回凭证时间: " + (endTime - startTime) + "毫秒");

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
    }

    // 获取生成的 b 和 s，用于认证算法
    public static Element[] getCredential() {
        return new Element[]{g1h, b, s};
    }
}
