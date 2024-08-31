package com.example;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.jpbc.Field;

import java.util.HashMap;
import java.util.Map;
import java.util.List;
import java.util.Arrays;

public class B_SetupAlgorithm {

    // 单例模式：存储 SetupParams 实例
    private static SetupParams instance;

    public static SetupParams initializeSetup() {
        if (instance == null) {
            synchronized (B_SetupAlgorithm.class) {
                if (instance == null) {
                    long startTime, endTime;
                    long originTime, exitTime;
                    originTime = System.currentTimeMillis();

                    // 步骤1：生成安全参数
                    startTime = System.currentTimeMillis();
                    int lambda = 256; // 安全参数的比特长度
                    PairingParameters params = PairingFactory.getPairingParameters("params/a.properties");
                    Pairing pairing = PairingFactory.getPairing(params);
                    Field G1 = pairing.getG1();
                    Field G2 = pairing.getG2();
                    Field GT = pairing.getGT();
                    // 从 G1 中随机选取元素
                    Element g = G1.newRandomElement().getImmutable();
                    Element g1 = G1.newRandomElement().getImmutable();
                    Element g2 = G2.newRandomElement().getImmutable();
                    Element h = G1.newRandomElement().getImmutable(); // 新增 h 参数
                    Element eta = GT.newRandomElement().getImmutable();
                    endTime = System.currentTimeMillis();
                    System.out.println("生成安全参数时间: " + (endTime - startTime) + "毫秒");

                    // 步骤2：安全分布式密钥生成
                    startTime = System.currentTimeMillis();
                    int N = 5; // 委员会成员数量
                    int T = 3; // 安全级别
                    Map<Integer, Element> sk = new HashMap<>();
                    Map<Integer, Element> inf = new HashMap<>();
                    Element s = pairing.getZr().newRandomElement().getImmutable();

                    // 生成多项式系数
                    Element[] coeffs = new Element[T];
                    coeffs[0] = s;
                    for (int j = 1; j < T; j++) {
                        coeffs[j] = pairing.getZr().newRandomElement().getImmutable();
                    }

                    // 生成私钥和参考信息
                    for (int i = 1; i <= N; i++) {
                        Element ski = coeffs[0].duplicate();
                        for (int j = 1; j < T; j++) {
                            // powZn 表示幂运算
                            ski = ski.add(coeffs[j].duplicate().mulZn(pairing.getZr().newElement(i).powZn(pairing.getZr().newElement(j))));
                        }
                        sk.put(i, ski.getImmutable());
                        inf.put(i, g.duplicate().powZn(ski).getImmutable());
                    }

                    Element spk = g1.powZn(s).getImmutable();
                    endTime = System.currentTimeMillis();
                    System.out.println("分布式密钥生成时间: " + (endTime - startTime) + "毫秒");

                    // 步骤3：协商trapdoor α并计算向量
                    startTime = System.currentTimeMillis();
                    Element alpha = pairing.getZr().newRandomElement().getImmutable();
                    int k = 5; // 最大属性集基数
                    Element[] V1 = new Element[k];
                    Element[] V2 = new Element[k];
                    for (int i = 0; i < k; i++) {
                        V1[i] = g1.duplicate().powZn(alpha.duplicate().powZn(pairing.getZr().newElement(i + 1))).getImmutable();
                        V2[i] = g2.duplicate().powZn(alpha.duplicate().powZn(pairing.getZr().newElement(i + 1))).getImmutable();
                    }
                    endTime = System.currentTimeMillis();
                    System.out.println("协商trapdoor和计算向量时间: " + (endTime - startTime) + "毫秒");

                    exitTime = System.currentTimeMillis();
                    System.out.println("设置算法成功完成。设置算法总时间为："+ (exitTime - originTime) + "毫秒");

                    instance = new SetupParams(params, pairing, G1, G2, GT, g, g1, g2, h, eta, sk, inf, spk, V1, V2);
                }
            }
        }
        return instance;
    }

    public static void main(String[] args) {
        // 初始化配对参数
        initializeSetup();
    }

    public static SetupParams getInstance() {
        if (instance == null) {
            return initializeSetup();
        }
        return instance;
    }

    public static class SetupParams {
        public PairingParameters params;
        public Pairing pairing;
        public Field G1, G2, GT;
        public Element g, g1, g2, h, eta;
        public Map<Integer, Element> sk, inf;
        public Element spk;
        public Element[] V1, V2;

        public SetupParams(PairingParameters params, Pairing pairing, Field G1, Field G2, Field GT, Element g, Element g1, Element g2, Element h, Element eta, Map<Integer, Element> sk, Map<Integer, Element> inf, Element spk, Element[] V1, Element[] V2) {
            this.params = params;
            this.pairing = pairing;
            this.G1 = G1;
            this.G2 = G2;
            this.GT = GT;
            this.g = g;
            this.g1 = g1;
            this.g2 = g2;
            this.h = h;
            this.eta = eta;
            this.sk = sk;
            this.inf = inf;
            this.spk = spk;
            this.V1 = V1;
            this.V2 = V2;
        }

        // 等价关系 R_TDH 的验证方法
        public boolean checkRTDH(List<Element> M, List<Element> N, List<Element> MPrime, List<Element> NPrime, Element mu, Element nu) {
            if (M.size() != N.size() || M.size() != MPrime.size() || N.size() != NPrime.size()) {
                return false;
            }

            for (int i = 0; i < M.size(); i++) {
                Element expectedMPrime = M.get(i).duplicate().powZn(mu.duplicate().mul(nu));
                Element expectedNPrime = N.get(i).duplicate().powZn(nu);
                if (!expectedMPrime.isEqual(MPrime.get(i)) || !expectedNPrime.isEqual(NPrime.get(i))) {
                    return false;
                }
            }
            return true;
        }

        // 等价关系 R_ipk 的验证方法
        public boolean checkRIpk(List<Element> ipk, List<Element> ipkPrime, Element omega) {
            if (ipk.size() != ipkPrime.size()) {
                return false;
            }

            for (int i = 0; i < ipk.size(); i++) {
                Element expectedIpkPrime = ipk.get(i).duplicate().powZn(omega);
                if (!expectedIpkPrime.isEqual(ipkPrime.get(i))) {
                    return false;
                }
            }
            return true;
        }

        // 等价关系 R_isk 的验证方法
        public boolean checkRIsk(List<Element> isk, List<Element> iskPrime, Element omega) {
            if (isk.size() != iskPrime.size()) {
                return false;
            }

            for (int i = 0; i < isk.size(); i++) {
                Element expectedIskPrime = isk.get(i).duplicate().mul(omega);
                if (!expectedIskPrime.isEqual(iskPrime.get(i))) {
                    return false;
                }
            }
            return true;
        }

        // 等价关系 R_upk 的验证方法
        public boolean checkRUpk(List<Element> upk, List<Element> upkPrime, Element mu) {
            if (upk.size() != upkPrime.size()) {
                return false;
            }

            for (int i = 0; i < upk.size(); i++) {
                Element expectedUpkPrime = upk.get(i).duplicate().powZn(mu);
                if (!expectedUpkPrime.isEqual(upkPrime.get(i))) {
                    return false;
                }
            }
            return true;
        }

        // 等价关系 R_usk 的验证方法
        public boolean checkRUsk(List<Element> usk, List<Element> uskPrime, Element mu) {
            if (usk.size() != uskPrime.size()) {
                return false;
            }

            for (int i = 0; i < usk.size(); i++) {
                Element expectedUskPrime = usk.get(i).duplicate().mul(mu);
                if (!expectedUskPrime.isEqual(uskPrime.get(i))) {
                    return false;
                }
            }
            return true;
        }
    }
}
