package com.example;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.jpbc.Field;

import java.util.HashMap;
import java.util.Map;

public class SetupAlgorithm {

    // 单例模式：存储 SetupParams 实例
    private static SetupParams instance;

    public static SetupParams initializeSetup() {
        if (instance == null) {
            synchronized (SetupAlgorithm.class) {
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
                    Element g = G1.newRandomElement().getImmutable();
                    Element g1 = G1.newRandomElement().getImmutable();
                    Element g2 = G2.newRandomElement().getImmutable();
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
                    int t = 5; // 最大属性集基数
                    Element[] V1 = new Element[t];
                    Element[] V2 = new Element[t];
                    for (int i = 0; i < t; i++) {
                        V1[i] = g1.duplicate().powZn(alpha.duplicate().powZn(pairing.getZr().newElement(i + 1))).getImmutable();
                        V2[i] = g2.duplicate().powZn(alpha.duplicate().powZn(pairing.getZr().newElement(i + 1))).getImmutable();
                    }
                    endTime = System.currentTimeMillis();
                    System.out.println("协商trapdoor和计算向量时间: " + (endTime - startTime) + "毫秒");

                    exitTime = System.currentTimeMillis();
                    System.out.println("设置算法成功完成。设置算法总时间为："+ (exitTime - originTime) + "毫秒");

                    instance = new SetupParams(params, pairing, G1, G2, GT, g, g1, g2, eta, sk, inf, spk, V1, V2);
                }
            }
        }
        return instance;
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
        public Element g, g1, g2, eta;
        public Map<Integer, Element> sk, inf;
        public Element spk;
        public Element[] V1, V2;

        public SetupParams(PairingParameters params, Pairing pairing, Field G1, Field G2, Field GT, Element g, Element g1, Element g2, Element eta, Map<Integer, Element> sk, Map<Integer, Element> inf, Element spk, Element[] V1, Element[] V2) {
            this.params = params;
            this.pairing = pairing;
            this.G1 = G1;
            this.G2 = G2;
            this.GT = GT;
            this.g = g;
            this.g1 = g1;
            this.g2 = g2;
            this.eta = eta;
            this.sk = sk;
            this.inf = inf;
            this.spk = spk;
            this.V1 = V1;
            this.V2 = V2;
        }

        public boolean isEmpty() {
            if (params == null || pairing == null || G1 == null || G2 == null || GT == null ||
                    g == null || g1 == null || g2 == null || eta == null || sk == null || inf == null ||
                    spk == null || V1 == null || V2 == null) {
                return true;
            }
            if (sk.isEmpty() || inf.isEmpty()) {
                return true;
            }
            for (Element v : V1) {
                if (v == null) {
                    return true;
                }
            }
            for (Element v : V2) {
                if (v == null) {
                    return true;
                }
            }
            return false;
        }
    }
}
