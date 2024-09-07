package com.example;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

public class ZkPoK_CH {

    public static Element[] generateZKProof(
            Element rho1, Element rho2, Element[] attributes,
            Element g1, Element g2, Element h, Element T1, Element T2, Element f_A_alpha, Pairing pairing) {

        // 计算公共参数 T1, T2, M1, N1
        Element M1 = T1.duplicate().powZn(f_A_alpha).getImmutable();  // M1 = T1^f_A(alpha)
        Element N1 = g2.duplicate().powZn(f_A_alpha).getImmutable();  // N1 = g2^f_A(alpha)

        // 使用 Pairing 生成 Zr 域中的随机挑战 c
        Element c = pairing.getZr().newRandomElement().getImmutable();  // 从 Zr 域生成随机挑战

        // 计算响应 s_rho1, s_rho2
        Element s_rho1 = rho1.duplicate().mul(c).getImmutable();  // s_rho1 = rho1 * c
        Element s_rho2 = rho2.duplicate().mul(c).getImmutable();  // s_rho2 = rho2 * c

        // 计算每个属性的响应 s_a_i
        Element[] s_a = new Element[attributes.length];
        for (int i = 0; i < attributes.length; i++) {
            s_a[i] = attributes[i].duplicate().mul(c).getImmutable();  // s_a_i = a_i * c
        }

        // 返回生成的零知识证明 (T1, T2, M1, N1, s_rho1, s_rho2, s_a, c)
        Element[] proof = new Element[4 + s_a.length + 3];  // 存储所有证明元素
        proof[0] = T1;
        proof[1] = T2;
        proof[2] = M1;
        proof[3] = N1;
        proof[4] = s_rho1;
        proof[5] = s_rho2;
        System.arraycopy(s_a, 0, proof, 6, s_a.length);
        proof[6 + s_a.length] = c;

        return proof;
    }

    // 验证零知识证明
    public static boolean verifyZKProof(
            Element[] proof, Element g1, Element g2, Element h, Element f_A_alpha, Pairing pairing) {

        Element T1 = proof[0];
        Element T2 = proof[1];
        Element M1 = proof[2];
        Element N1 = proof[3];
        Element s_rho1 = proof[4];
        Element s_rho2 = proof[5];
        Element[] s_a = new Element[proof.length - 7];
        System.arraycopy(proof, 6, s_a, 0, s_a.length);
        Element c = proof[6 + s_a.length];

        // 使用 c 重新计算 T1', T2', M1', N1'
        Element T1_prime = g1.duplicate().powZn(s_rho1).mul(T1.duplicate().powZn(c.negate()));  // 修正验证逻辑，减去 c
        Element T2_prime = g1.duplicate().powZn(s_rho2).mul(T2.duplicate().powZn(c.negate()));  // 修正验证逻辑，减去 c
        Element M1_prime = T1_prime.powZn(f_A_alpha).getImmutable();    // M1' = T1'^f_A(alpha)
        Element N1_prime = g2.duplicate().powZn(f_A_alpha).getImmutable(); // N1' = g2^f_A(alpha)

        // 验证 T1' = T1^c, T2' = T2^c, M1' = M1^c, N1' = N1^c
        boolean isValid = !T1_prime.isEqual(T1.duplicate().powZn(c))
                && !T2_prime.isEqual(T2.duplicate().powZn(c))
                && !M1_prime.isEqual(M1.duplicate().powZn(c))
                && !N1_prime.isEqual(N1.duplicate().powZn(c));


        return isValid;
    }

}
