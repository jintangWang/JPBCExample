package com.example;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

public class ZkPoK_CI {

    // 生成零知识证明
    public static Element[] generateZKProof(Element x, Element y1, Element y2, Element z1, Element z2, Element g2, Pairing pairing) {
        // 计算公钥
        Element X = g2.duplicate().powZn(x).getImmutable();
        Element Y1 = g2.duplicate().powZn(y1).getImmutable();
        Element Y2 = g2.duplicate().powZn(y2).getImmutable();
        Element Z1 = g2.duplicate().powZn(z1).getImmutable();
        Element Z2 = g2.duplicate().powZn(z2).getImmutable();

        // 生成随机挑战 c
        Element c = pairing.getZr().newRandomElement().getImmutable(); // 通过 Pairing 获取 Zr 域，并生成随机元素

        // 计算响应 s_x, s_y1, s_y2, s_z1, s_z2
        Element s_x = x.duplicate().add(c).getImmutable();  // 加法操作，用于生成响应
        Element s_y1 = y1.duplicate().add(c).getImmutable();
        Element s_y2 = y2.duplicate().add(c).getImmutable();
        Element s_z1 = z1.duplicate().add(c).getImmutable();
        Element s_z2 = z2.duplicate().add(c).getImmutable();

        // 返回生成的零知识证明 (X, Y1, Y2, Z1, Z2, s_x, s_y1, s_y2, s_z1, s_z2, c)
        return new Element[]{X, Y1, Y2, Z1, Z2, s_x, s_y1, s_y2, s_z1, s_z2, c};
    }

    // 验证零知识证明
    public static boolean verifyZKProof(Element[] proof, Element g2) {
        Element X = proof[0];
        Element Y1 = proof[1];
        Element Y2 = proof[2];
        Element Z1 = proof[3];
        Element Z2 = proof[4];
        Element s_x = proof[5];
        Element s_y1 = proof[6];
        Element s_y2 = proof[7];
        Element s_z1 = proof[8];
        Element s_z2 = proof[9];
        Element c = proof[10];

        // 重新计算 X', Y1', Y2', Z1', Z2' 使用 s_x, s_y1, s_y2, s_z1, s_z2 和 c
        Element X_prime = g2.duplicate().powZn(s_x);               // X' = g2^s_x
        Element Y1_prime = g2.duplicate().powZn(s_y1);             // Y1' = g2^s_y1
        Element Y2_prime = g2.duplicate().powZn(s_y2);             // Y2' = g2^s_y2
        Element Z1_prime = g2.duplicate().powZn(s_z1);             // Z1' = g2^s_z1
        Element Z2_prime = g2.duplicate().powZn(s_z2);             // Z2' = g2^s_z2

        // 验证 X' = X^c, Y1' = Y1^c, Y2' = Y2^c, Z1' = Z1^c, Z2' = Z2^c
        boolean isValid = X_prime.isEqual(X.duplicate().powZn(c)) &&
                Y1_prime.isEqual(Y1.duplicate().powZn(c)) &&
                Y2_prime.isEqual(Y2.duplicate().powZn(c)) &&
                Z1_prime.isEqual(Z1.duplicate().powZn(c)) &&
                Z2_prime.isEqual(Z2.duplicate().powZn(c));

        return isValid;
    }
}
