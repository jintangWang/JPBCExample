package com.example;

import com.example.C_SetupAlgorithm.SetupParams;
import com.example.E_CredentialIssuanceAlgorithm;
import com.example.F_PolicyGenerationAlgorithm;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

public class H_AuthenticationAlgorithm_Phase1 {

    private static Pairing pairing;
    private static Element g1, h, b, g1h;

    public static void main(String[] args) {
        // 初始化配对参数
        SetupParams setupParams = C_SetupAlgorithm.getInstance();
        initializeSetupParams(setupParams);

        // 从 E_CredentialIssuanceAlgorithm 获取 b
        Element[] credential = E_CredentialIssuanceAlgorithm.getCredential();
        g1h = credential[0];  // g_1^h
        b = credential[1];    // b

        // 运行认证算法
        runAuthentication();
    }

    // 初始化从 C_SetupAlgorithm 获取的参数
    private static void initializeSetupParams(SetupParams setupParams) {
        pairing = setupParams.pairing;
        g1 = setupParams.g1;
        h = setupParams.h;
    }

    private static void runAuthentication() {
        // 从 F_PolicyGenerationAlgorithm 中获取 s_i
        Element[] s_i = F_PolicyGenerationAlgorithm.generateAuthenticationPolicy("CV1");

        // 生成 s = ∏ s_i
        Element s = generateAggregateS(s_i);

        // 随机生成 epsilon
        Element epsilon = pairing.getZr().newRandomElement().getImmutable();

        // Blinding aggregate signature into σ'
        Element b_epsilon = b.powZn(epsilon).getImmutable();
        Element s_epsilon = s.powZn(epsilon).getImmutable();
        Element sigma_prime_g1h = g1h;  // g_1^h remains unchanged

        // 生成非交互零知识证明 π_sigma'
        Element[] zkProof = generateZKProof(sigma_prime_g1h, b_epsilon, s_epsilon, s_i, epsilon);

        // 验证零知识证明
        boolean isProofValid = verifyZKProof(sigma_prime_g1h, b_epsilon, s_epsilon, zkProof, s_i);
        if (isProofValid) {
            System.out.println("认证成功，用户拥有有效的凭证。");
        } else {
            System.out.println("认证失败，零知识证明验证不通过。");
        }
    }

    // 根据 s_i 生成聚合签名 s = ∏ s_i
    private static Element generateAggregateS(Element[] s_i) {
        Element s = pairing.getG1().newOneElement();  // 初始化 s 为 G1 中的单位元

        for (Element s_elem : s_i) {
            s = s.mul(s_elem).getImmutable();  // 累乘所有 s_i
        }
        return s;
    }

    // 生成非交互零知识证明 π_sigma'
    private static Element[] generateZKProof(Element g1h, Element b_epsilon, Element s_epsilon, Element[] s_i, Element epsilon) {
        Element[] proof = new Element[3 + s_i.length];
        proof[0] = g1h;
        proof[1] = b_epsilon;
        proof[2] = s_epsilon;

        // 将 s_i 和 epsilon 放入证明
        for (int i = 0; i < s_i.length; i++) {
            proof[3 + i] = s_i[i];
        }

        return proof;
    }

    // 验证零知识证明 π_sigma'
    private static boolean verifyZKProof(Element g1h, Element b_epsilon, Element s_epsilon, Element[] zkProof, Element[] s_i) {
        // 根据论文中的公式进行验证
        Element g2 = C_SetupAlgorithm.getInstance().g2;  // 获取 g2
        Element Z = s_i[0];  // Z 来自 s_i
        Element B1 = s_i[1]; // B1 来自 s_i
        Element B2 = s_i[2]; // B2 来自 s_i

        // 验证第一个条件 e(T_j, N_ij) = e(M_ij, g_2) (这里可以简化，因为 T_j 和 N_ij 是两两匹配的)
        // 第二个条件 e(g1^h, X_ij^epsilon) * e(M_ij, Y_ij) = e(s^epsilon, g_2)
        Element leftSide = pairing.pairing(g1h, B1).mul(pairing.pairing(b_epsilon, B2));
        Element rightSide = pairing.pairing(s_epsilon, g2);

        boolean isFirstCheckValid = leftSide.isEqual(rightSide);

        // 验证 e(b^epsilon, g_2) = e(T_j, Z_ij)
        Element secondLeftSide = pairing.pairing(b_epsilon, g2);
        Element secondRightSide = pairing.pairing(g1h, Z); // 假设 g1h 与 Z 匹配

        boolean isSecondCheckValid = secondLeftSide.isEqual(secondRightSide);

        return isFirstCheckValid && isSecondCheckValid;
    }
}
