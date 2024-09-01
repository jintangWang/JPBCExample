package com.example;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.Field;

public class ZkPoK {

    // 生成零知识证明
    public static Element[] generateZKProof(Element alpha, Element beta, Element g1, Element h) {
        // 计算公共参数 y 和 z
        Element y = g1.duplicate().powZn(alpha);
        Element z = g1.duplicate().powZn(beta).mul(h.duplicate().powZn(alpha));

        // 生成随机挑战 c (可以使用 Fiat-Shamir heuristic 模拟随机挑战)
        Element c = g1.getField().newRandomElement().getImmutable();

        // 计算响应 s_alpha 和 s_beta
        Element s_alpha = alpha.duplicate().mul(c).getImmutable(); // s_alpha = alpha * c
        Element s_beta = beta.duplicate().mul(c).getImmutable();   // s_beta = beta * c

        // 返回生成的零知识证明 (y, z, s_alpha, s_beta, c)
        return new Element[]{y, z, s_alpha, s_beta, c};
    }

    // 验证零知识证明
    public static boolean verifyZKProof(Element[] proof, Element g1, Element h) {
        Element y = proof[0];
        Element z = proof[1];
        Element s_alpha = proof[2];
        Element s_beta = proof[3];
        Element c = proof[4];

        // 重新计算 y' 和 z' 使用 s_alpha, s_beta 和 c
        Element y_prime = g1.duplicate().powZn(s_alpha);           // y' = g1^s_alpha
        Element z_prime = g1.duplicate().powZn(s_beta).mul(h.duplicate().powZn(s_alpha)); // z' = g1^s_beta * h^s_alpha

        // 验证 y' = y^c 和 z' = z^c
        boolean isValid = y_prime.isEqual(y.duplicate().powZn(c)) && z_prime.isEqual(z.duplicate().powZn(c));

        return isValid;
    }
}
