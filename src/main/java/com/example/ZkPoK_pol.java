package com.example;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

public class ZkPoK_pol {

    // 生成零知识证明
    public static Element[] generateZKProof(
            Element[] xj, Element kappa_i, Element g1, Element g2,
            Element[] ipkElements, Element Z, Element B1, Element B2, Pairing pairing) {

        int Ki = xj.length;

        // 生成随机挑战 c
        Element c = pairing.getZr().newRandomElement().getImmutable();  // 从 Zr 域生成随机挑战

        // 计算响应 s_xj 和 s_kappa_i
        Element[] s_xj = new Element[Ki];
        for (int i = 0; i < Ki; i++) {
            s_xj[i] = xj[i].duplicate().mul(c).getImmutable();  // s_xj = xj * c
        }
        Element s_kappa_i = kappa_i.duplicate().mul(c).getImmutable();  // s_kappa_i = kappa_i * c

        // 计算 proof 数组大小：Ki 个 vpk, 1 个 Z, 1 个 B1, 1 个 B2, Ki 个 s_xj, 1 个 s_kappa_i, 1 个 c
        Element[] proof = new Element[Ki + 3 + Ki + 2];  // 修正数组长度

        // 将 xj 拷贝到 proof
        System.arraycopy(xj, 0, proof, 0, Ki);
        proof[Ki] = Z;
        proof[Ki + 1] = B1;
        proof[Ki + 2] = B2;

        // 将 s_xj 拷贝到 proof
        System.arraycopy(s_xj, 0, proof, Ki + 3, Ki);
        proof[Ki + 3 + Ki] = s_kappa_i;  // 将 s_kappa_i 放入 proof
        proof[Ki + 4 + Ki] = c;  // 将 c 放入 proof

        return proof;
    }

    // 验证零知识证明
    public static boolean verifyZKProof(
            Element[] proof, Element g1, Element g2, Element[] ipkElements, Element Z, Element B1, Element B2, Pairing pairing) {

        int Ki = ipkElements.length;

        // 从 proof 中提取元素
        Element[] vpk = new Element[Ki];
        System.arraycopy(proof, 0, vpk, 0, Ki);
        Element Z_prime = proof[Ki];
        Element B1_prime = proof[Ki + 1];
        Element B2_prime = proof[Ki + 2];
        Element[] s_xj = new Element[Ki];
        System.arraycopy(proof, Ki + 3, s_xj, 0, Ki);
        Element s_kappa_i = proof[Ki + 3 + Ki];
        Element c = proof[Ki + 4 + Ki];

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
        Z_prime = Z.duplicate().powZn(s_kappa_i).mul(Z.duplicate().powZn(c_negate));  // Z' = Z^s_kappa_i * Z^-c
        if (!Z_prime.isEqual(Z)) {
            return false;  // 验证 Z' 失败
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
