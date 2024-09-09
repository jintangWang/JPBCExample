package com.example;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

public class ZkPoK_pol {

    // 生成零知识证明
    public static Element[] generateZKProof(
            Element[] xj, Element kappa_i, Element g1, Element g2,
            Element[][] ZElements, Element B1, Element B2, Pairing pairing) {

        int Ki = xj.length;

        // 生成随机挑战 c
        Element c = pairing.getZr().newRandomElement().getImmutable();  // 从 Zr 域生成随机挑战

        // 计算响应 s_xj 和 s_kappa_i
        Element[] s_xj = new Element[Ki];
        for (int i = 0; i < Ki; i++) {
            s_xj[i] = xj[i].duplicate().mul(c).getImmutable();  // s_xj = xj * c
        }
        Element s_kappa_i = kappa_i.duplicate().mul(c).getImmutable();  // s_kappa_i = kappa_i * c

        // 计算 proof 数组大小：Ki 个 vpk, 5 个 Z 的部分, 1 个 B1, 1 个 B2, Ki 个 s_xj, 1 个 s_kappa_i, 1 个 c
        Element[] proof = new Element[Ki + 5 + 3 + Ki + 2];  // 修正数组长度

        // 将 xj 拷贝到 proof
        System.arraycopy(xj, 0, proof, 0, Ki);

        // 手动将 Z1, Z2, X, Y1, Y2 拷贝到 proof
        proof[Ki] = ZElements[0][0];  // Z1
        proof[Ki + 1] = ZElements[1][0];  // Z2
        proof[Ki + 2] = ZElements[2][0];  // X
        proof[Ki + 3] = ZElements[3][0];  // Y1
        proof[Ki + 4] = ZElements[4][0];  // Y2

        // 将 B1 和 B2 插入到 proof
        proof[Ki + 5] = B1;
        proof[Ki + 6] = B2;

        // 将 s_xj 拷贝到 proof
        System.arraycopy(s_xj, 0, proof, Ki + 7, Ki);

        // 将 s_kappa_i 和 c 插入到 proof
        proof[Ki + 7 + Ki] = s_kappa_i;
        proof[Ki + 8 + Ki] = c;

        return proof;
    }


    // 验证零知识证明
    public static boolean verifyZKProof(
            Element[] proof, Element g1, Element g2, Element[][] ZElements, Element B1, Element B2, Pairing pairing) {

        int Ki = ZElements.length;

        // 从 proof 中提取元素
        Element[] vpk = new Element[Ki];
        System.arraycopy(proof, 0, vpk, 0, Ki);

        // 提取 Z1, Z2, X, Y1, Y2
        Element[] Z_prime = new Element[5];
        System.arraycopy(proof, Ki, Z_prime, 0, 5);

        Element B1_prime = proof[Ki + 5];
        Element B2_prime = proof[Ki + 6];
        Element[] s_xj = new Element[Ki];
        System.arraycopy(proof, Ki + 7, s_xj, 0, Ki);
        Element s_kappa_i = proof[Ki + 7 + Ki];
        Element c = proof[Ki + 8 + Ki];

        // 重新计算 vpk'，使用 c.negate() 得到的是负标量
        Element c_negate = c.duplicate().negate();
        for (int i = 0; i < Ki; i++) {
            Element vpk_prime = g2.powZn(s_xj[i]);  // 计算 g2^s_xj
            Element vpk_c_negate = vpk[i].powZn(c_negate);  // 计算 vpk^(-c)
            vpk_prime = vpk_prime.mul(vpk_c_negate);  // 正确的点乘操作
            if (!vpk_prime.isEqual(vpk[i])) {
                return false;  // 验证 vpk' 失败
            }
        }

        // 验证 Z', B1', B2'
        for (int i = 0; i < ZElements.length; i++) {
            Z_prime[i] = ZElements[i][0].duplicate().powZn(s_kappa_i).mul(ZElements[i][0].duplicate().powZn(c_negate));  // Z' = Z^s_kappa_i * Z^-c
            if (!Z_prime[i].isEqual(ZElements[i][0])) {
                return false;  // 验证 Z' 失败
            }
        }

        B1_prime = g1.powZn(pairing.getZr().newOneElement().div(s_kappa_i));  // B1 = g1^(1/s_kappa_i)
        if (!B1_prime.isEqual(B1)) {
            return false;  // 验证 B1' 失败
        }

        B2_prime = g2.powZn(pairing.getZr().newOneElement().div(s_kappa_i));  // B2 = g2^(1/s_kappa_i)
        if (!B2_prime.isEqual(B2)) {
            return false;  // 验证 B2' 失败
        }

        return true;
    }
}
