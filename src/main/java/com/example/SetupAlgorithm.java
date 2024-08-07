package com.example;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.jpbc.Field;

import java.util.HashMap;
import java.util.Map;

public class SetupAlgorithm {

    public static void main(String[] args) {
        long startTime, endTime;

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

        // 步骤4：写入创世区块
//        startTime = System.currentTimeMillis();
//        GenesisBlock genesisBlock = new GenesisBlock(params, spk, inf, V1, V2);
//        endTime = System.currentTimeMillis();
//        System.out.println("写入创世区块时间: " + (endTime - startTime) + "毫秒");

        System.out.println("设置算法成功完成。");
    }
}

//class GenesisBlock {
//    PairingParameters params;
//    Element spk;
//    Map<Integer, Element> inf;
//    Element[] V1;
//    Element[] V2;
//
//    public GenesisBlock(PairingParameters params, Element spk, Map<Integer, Element> inf, Element[] V1, Element[] V2) {
//        this.params = params;
//        this.spk = spk;
//        this.inf = inf;
//        this.V1 = V1;
//        this.V2 = V2;
//    }
//
//    // 可以在此处添加处理创世区块逻辑（例如序列化）的其他方法
//}
