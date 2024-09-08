package com.example;

import com.example.C_SetupAlgorithm.SetupParams;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.Field;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Random;

public class H_AuthenticationAlgorithm_Phase2 {

    private static SetupParams setupParams;
    private static Pairing pairing;
    private static Field G1, G2, Zp;
    private static Element g, g1, g2, eta;

    public static void main(String[] args) {
        // 初始化 SetupParams 和注册算法的公钥
        setupParams = C_SetupAlgorithm.getInstance();
        initializeSetupParams(setupParams);

        // 从 C_RegistrationAlgorithm 获取注册的公钥信息
        D_RegistrationAlgorithm.main(null);  // 调用 RegistrationAlgorithm 注册实体
        Map<String, Map<String, Element>> ipkMap = D_RegistrationAlgorithm.getIpkMap();
        Element apk = D_RegistrationAlgorithm.getApk();

        // 假设从 C_RegistrationAlgorithm 中获取的发行者信息
        int K_i = ipkMap.size();  // 使用的发行者数量

        long originTime, exitTime;
        originTime = System.currentTimeMillis();
        // 1. 选择唯一认证标识符 aid
        String aid = generateRandomString(128);

        // 2. 查询等价关系 R_ipk，模拟 ipk' -> ipk 和 s_i' -> s_i 的随机化
        List<Element> ipk_prime = new ArrayList<>();
        List<Element> s_i_prime = new ArrayList<>();
        for (String issuerName : ipkMap.keySet()) {
            Map<String, Element> ipk = ipkMap.get(issuerName);
            Element randomizedIpk = randomizeElement(ipk.get("X"));  // 假设随机化 X
            ipk_prime.add(randomizedIpk);

            // s_i' 的随机化处理
            Element s_i = randomizeElement(Zp.newRandomElement());
            s_i_prime.add(s_i);
        }

        // 3. 聚合发行者
        Element aggregated_b = pairing.getGT().newOneElement();  // 初始化为 GT 中的 1
        Element aggregated_s = pairing.getZr().newOneElement();  // 初始化为 Zp 中的 1
        for (int j = 0; j < K_i; j++) {
            aggregated_b = aggregated_b.mul(randomizeElement(pairing.getGT().newRandomElement())).getImmutable();
            aggregated_s = aggregated_s.mul(s_i_prime.get(j)).getImmutable();
        }

        // 4. 变换并随机化聚合数据
        Element alpha_vk_prime = randomizeElement(pairing.getZr().newRandomElement());
        Element sigma_prime = randomizeElement(pairing.getGT().newRandomElement());

        // 5. 查询等价关系 R_TDH 并随机化
        Element mu = randomizeElement(pairing.getZr().newRandomElement());
        Element nu = randomizeElement(pairing.getZr().newRandomElement());
        Element sigma_double_prime = randomizeElement(pairing.getGT().newRandomElement());

        // 6. 生成伪名
        Element Nym = apk.powZn(mu).getImmutable();  // 使用审核员的公钥 apk

        // 7. 生成子集见证并随机化
        Element W = pairing.getGT().newOneElement();  // 初始化为 1
        for (int j = 0; j < K_i; j++) {
            Element W_j = generateSubsetWitness();
            W = W.mul(W_j).getImmutable();
        }
        Element W_prime = W.powZn(mu.mul(nu)).getImmutable();

        // 8. 构建认证对象
        Authentication auth = new Authentication(sigma_double_prime, Nym, s_i_prime, W_prime);
        String pi_auth = generateProofOfKnowledge(auth);

        // 9. 生成 ID 和 delta
        Element gamma = randomizeElement(pairing.getZr().newRandomElement());
        Element ID_1 = g.powZn(gamma).getImmutable();  // 使用全局参数 g
        Element ID_2 = apk.powZn(gamma).mul(ID_1).getImmutable();  // 使用审核员公钥 apk 和 ID_1
        String ID = "ID1: " + ID_1.toString() + ", ID2: " + ID_2.toString();

        Element delta = randomizeElement(pairing.getZr().newRandomElement());
        Element Delta = g.powZn(delta).getImmutable();  // 使用全局参数 g

        exitTime = System.currentTimeMillis();
        System.out.println("子阶段 2 算法成功完成。算法总时间为："+ (exitTime - originTime) + "毫秒");
        // 调用智能合约的 Auth 方法
        callAuthContract(aid, auth, ID, pi_auth, Delta.toString());
    }

    // 初始化 SetupParams
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

    private static String generateRandomString(int length) {
        StringBuilder sb = new StringBuilder(length);
        Random random = new Random();
        for (int i = 0; i < length; i++) {
            sb.append((char) ('0' + random.nextInt(2)));
        }
        return sb.toString();
    }

    private static Element randomizeElement(Element element) {
        return element.powZn(pairing.getZr().newRandomElement()).getImmutable();
    }

    private static Element generateSubsetWitness() {
        return randomizeElement(pairing.getGT().newRandomElement());
    }

    private static String generateProofOfKnowledge(Authentication auth) {
        return "Proof_of_knowledge";  // 占位符，实际中应该使用 ZKP
    }

    private static void callAuthContract(String aid, Authentication auth, String ID, String pi_auth, String delta) {
        // 模拟调用智能合约的 Auth 方法
//        F_AuthenticationContract contract = new F_AuthenticationContract();
//        Context ctx = new Context();  // 示例上下文（需要正确初始化）
//        contract.Auth(ctx, aid, auth.toString(), ID, pi_auth, delta);

        System.out.println("Auth 请求已发送至智能合约。");
    }
}

// 占位符类
class Authentication {
    Element sigma;
    Element Nym;
    List<Element> s_i_prime;
    Element W_prime;

    public Authentication(Element sigma, Element Nym, List<Element> s_i_prime, Element W_prime) {
        this.sigma = sigma;
        this.Nym = Nym;
        this.s_i_prime = s_i_prime;
        this.W_prime = W_prime;
    }

    @Override
    public String toString() {
        return "AuthObject";
    }
}
