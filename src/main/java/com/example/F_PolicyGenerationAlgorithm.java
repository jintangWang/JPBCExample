package com.example;

import com.example.C_SetupAlgorithm.SetupParams;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.Field;

import java.util.HashMap;
import java.util.Map;

public class F_PolicyGenerationAlgorithm {

    private static Pairing pairing;
    private static Field G1, G2, Zp;
    private static Element g, g1, g2, eta;
    private static Map<String, Map<String, Element>> ipkMap;
    private static Element apk;
    private static Element[] s_i; // 用于存储生成的 s_i

    public static void main(String[] args) {
        // 初始化配对参数
        SetupParams setupParams = C_SetupAlgorithm.getInstance();

        E_CredentialIssuanceAlgorithm.main(null);  // 执行之前的发行凭证算法
        // 获取注册服务实体参数
        ipkMap = D_RegistrationAlgorithm.getIpkMap();
        apk = D_RegistrationAlgorithm.getApk();

        // 初始化其他参数
        initializeSetupParams(setupParams);

        // 生成认证策略并生成零知识证明
        s_i = generateAuthenticationPolicy("CV1");
    }

    private static void initializeSetupParams(SetupParams setupParams) {
        pairing = setupParams.pairing;
        G1 = setupParams.G1;
        G2 = setupParams.G2;
        Zp = pairing.getZr();
        g = setupParams.g;
        g1 = setupParams.g1;
        g2 = setupParams.g2;
        eta = setupParams.eta;
    }

    // 生成认证策略并返回签名 s_i
    public static Element[] generateAuthenticationPolicy(String verifierName) {
        long startTime, endTime;

        // 步骤1：生成认证策略密钥对
        startTime = System.currentTimeMillis();
        int Ki = 5;  // 可接受的发行者数量
        Element[] xj = new Element[Ki];
        Element[] vpk = new Element[Ki];
        for (int i = 0; i < Ki; i++) {
            xj[i] = Zp.newRandomElement().getImmutable();
            vpk[i] = g2.powZn(xj[i]).getImmutable();
        }

        Element kappa_i = Zp.newRandomElement().getImmutable();

        // 获取部分发行者的公钥，并确保对应关系
        Element[] ipkElementsZ1 = new Element[Ki];  // 对应 Z1 的公钥部分
        Element[] ipkElementsZ2 = new Element[Ki];  // 对应 Z2 的公钥部分
        Element[] ipkElementsX = new Element[Ki];   // 对应 X 的公钥部分
        Element[] ipkElementsY1 = new Element[Ki];  // 对应 Y1 的公钥部分
        Element[] ipkElementsY2 = new Element[Ki];  // 对应 Y2 的公钥部分

        for (int i = 0; i < Ki; i++) {
            String issuerName = "CI" + (i + 1);
            if (ipkMap.containsKey(issuerName)) {
                Map<String, Element> issuerKeys = ipkMap.get(issuerName);
                ipkElementsZ1[i] = issuerKeys.get("Z1");
                ipkElementsZ2[i] = issuerKeys.get("Z2");
                ipkElementsX[i] = issuerKeys.get("X");
                ipkElementsY1[i] = issuerKeys.get("Y1");
                ipkElementsY2[i] = issuerKeys.get("Y2");
            }
        }

        // 计算 Z1, Z2, X, Y1, Y2 的值
        Element Z1 = computeProductAndExponent(ipkElementsZ1, xj, kappa_i);
        Element Z2 = computeProductAndExponent(ipkElementsZ2, xj, kappa_i);
        Element X = computeProductAndExponent(ipkElementsX, xj, kappa_i);
        Element Y1 = computeProductAndExponent(ipkElementsY1, xj, kappa_i);
        Element Y2 = computeProductAndExponent(ipkElementsY2, xj, kappa_i);

        // B1 和 B2 计算
        Element B1 = g1.powZn(Zp.newOneElement().div(kappa_i)).getImmutable();
        Element B2 = g2.powZn(Zp.newOneElement().div(kappa_i)).getImmutable();

        // 生成 Z
        Element Z = computeProductAndExponent(ipkElementsZ1, xj, kappa_i);  // 假设使用 Z1 进行计算

        // 将 Z, B1, B2 作为 s_i 返回
        Element[] s_i_local = new Element[]{Z, B1, B2};

        // 输出计算时间
        endTime = System.currentTimeMillis();
        System.out.println(verifierName + " 认证策略生成时间: " + (endTime - startTime) + "毫秒");

        // 返回签名 s_i
        return s_i_local;
    }

    // 获取生成的 s_i
    public static Element[] getSi() {
        return s_i;
    }

    // 辅助函数：计算 Z1, Z2, X, Y1, Y2 的通用函数
    private static Element computeProductAndExponent(Element[] ipkElements, Element[] xj, Element kappa_i) {
        Element result = ipkElements[0].getField().newOneElement();  // 确保 result 初始化为群元素的单位元

        for (int j = 0; j < ipkElements.length; j++) {
            result = result.mul(ipkElements[j].powZn(xj[j]));  // 对群元素执行幂运算
        }

        result = result.powZn(kappa_i).getImmutable();  // 对整个乘积取 kappa_i 次幂
        return result;
    }

    private static void publishToBlockchain(String description, Element[] zkProof) {
        // 模拟将证明发布到区块链
        // System.out.println(description + " Proof has been published to the blockchain.");
    }
}
