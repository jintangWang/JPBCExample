package com.example;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

public class ZkPoK_SigmaPrime {

    // 生成零知识证明
    public static Element[] generateZKProof(Element epsilon, Element[][] M, Element[][] N, Element[][] T, Element[] X, Element[] Y1, Element[] Y2, Element s_epsilon, Element b_epsilon, Pairing pairing, Element g1h, Element g2, int t) {

        // 生成随机挑战 c
        Element c = pairing.getZr().newRandomElement().getImmutable();  // 从 Zr 域生成随机挑战

        // 计算零知识证明中涉及的元素
        Element[] zkProof = new Element[t * 6 + 3]; // 存储生成的零知识证明

        // 遍历 t 个证书
        for (int i = 0; i < t; i++) {
            // 遍历 j = 1 到 2 的双重循环 (针对公式的 e(T_j, N_ij) 和 e(M_ij, g_2))
            for (int j = 0; j < 2; j++) {
                // 计算 e(T_j, N_ij) = e(M_ij, g_2)
                Element pairingLeft = pairing.pairing(T[j][i], N[j][i]);
                Element pairingRight = pairing.pairing(M[j][i], g2);

                // 验证左边和右边的配对是否相等
                if (!pairingLeft.isEqual(pairingRight)) {
                    System.out.println("配对验证失败： e(T_j, N_ij) != e(M_ij, g_2)");
                    return null;
                }
            }

            // 计算 e(g_1^h, X_ij^epsilon) 和 e(M_ij, Y_ij)
            Element leftTerm = pairing.pairing(g1h, X[i].powZn(epsilon));
            Element middleTerm1 = pairing.pairing(M[0][i], Y1[i]);
            Element middleTerm2 = pairing.pairing(M[1][i], Y2[i]);

            // 计算组合配对结果
            Element pairingResult = leftTerm.mul(middleTerm1).mul(middleTerm2);
            Element rightTerm = pairing.pairing(s_epsilon, g2);

            // 验证左边和右边的配对是否相等
            if (!pairingResult.isEqual(rightTerm)) {
                System.out.println("配对验证失败： ∏ e(g_1^h, X_ij^epsilon) * ∏ e(M_ij, Y_ij) != e(s^epsilon, g_2)");
                return null;
            }

            // 计算 e(b^epsilon, g_2)
            Element bPairing = pairing.pairing(b_epsilon, g2);

            // 计算 ∏ e(T_j, Z_ij)
            Element zProduct = pairing.getGT().newOneElement();
            for (int j = 0; j < 2; j++) {
                zProduct = zProduct.mul(pairing.pairing(T[j][i], N[j][i]));
            }

            // 验证 e(b^epsilon, g_2) = ∏ e(T_j, Z_ij)
            if (!bPairing.isEqual(zProduct)) {
                System.out.println("配对验证失败： e(b^epsilon, g_2) != ∏ e(T_j, Z_ij)");
                return null;
            }
        }

        // 生成响应 s_epsilon = epsilon * c
        Element s_epsilon_response = epsilon.duplicate().mul(c).getImmutable();

        // 将生成的零知识证明存储到 zkProof 中
        zkProof[0] = epsilon;
        zkProof[1] = s_epsilon_response;
        zkProof[2] = c;

        return zkProof;
    }

    // 验证零知识证明
    public static boolean verifyZKProof(Element[] zkProof, Element[][] M, Element[][] N, Element[][] T, Element[] X, Element[] Y1, Element[] Y2, Element g1h, Element g2, Pairing pairing, Element s_epsilon, Element b_epsilon, int t) {

        // 提取零知识证明中的元素
        Element epsilon = zkProof[0];
        Element s_epsilon_response = zkProof[1];
        Element c = zkProof[2];

        // 遍历 t 个证书，验证每个配对条件
        for (int i = 0; i < t; i++) {
            for (int j = 0; j < 2; j++) {
                // 验证 e(T_j, N_ij) = e(M_ij, g_2)
                Element pairingLeft = pairing.pairing(T[j][i], N[j][i]);
                Element pairingRight = pairing.pairing(M[j][i], g2);

                if (!pairingLeft.isEqual(pairingRight)) {
                    return false;
                }
            }

            // 验证 ∏ e(g_1^h, X_ij^epsilon) * ∏ e(M_ij, Y_ij) = e(s^epsilon, g_2)
            Element leftTerm = pairing.pairing(g1h, X[i].powZn(epsilon));
            Element middleTerm1 = pairing.pairing(M[0][i], Y1[i]);
            Element middleTerm2 = pairing.pairing(M[1][i], Y2[i]);

            Element pairingResult = leftTerm.mul(middleTerm1).mul(middleTerm2);
            Element rightTerm = pairing.pairing(s_epsilon, g2);

            if (!pairingResult.isEqual(rightTerm)) {
                return false;
            }

            // 验证 e(b^epsilon, g_2) = ∏ e(T_j, Z_ij)
            Element bPairing = pairing.pairing(b_epsilon, g2);
            Element zProduct = pairing.getGT().newOneElement();

            for (int j = 0; j < 2; j++) {
                zProduct = zProduct.mul(pairing.pairing(T[j][i], N[j][i]));
            }

            if (!bPairing.isEqual(zProduct)) {
                return false;
            }
        }

        return true;
    }
}
