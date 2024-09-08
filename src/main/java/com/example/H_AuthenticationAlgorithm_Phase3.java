package com.example;

import it.unisa.dia.gas.jpbc.Element;
import com.example.C_SetupAlgorithm.SetupParams;

public class H_AuthenticationAlgorithm_Phase3 {

    private G_AuthenticationContract contract;

    // 构造函数传递智能合约实例
    public H_AuthenticationAlgorithm_Phase3(G_AuthenticationContract contract) {
        this.contract = contract;
    }

    // 执行子阶段 3 的认证过程
    public String offChainAuth(String aid, Element alphaProof, Element betaProof, String delta, String timestamp) {
        System.out.println("OffChainAuth: 开始离线认证过程");

        // Step 1: 从智能合约查询链上数据
        String queryResult = contract.Query(aid);
        if (queryResult.contains("Invalid state")) {
            throw new RuntimeException("OffChainAuth: 无效的认证状态，aid: " + aid);
        }

        // 从查询结果中解析链上的 Rst 和 TmpCreds 数据
        boolean rst = parseRstFromQueryResult(queryResult);  // 解析 rst
        String tmpCreds = parseTmpCredsFromQueryResult(queryResult);  // 解析 tmpCreds

        // Step 2: 本地验证数据
        if (!rst || !delta.equals(tmpCreds)) {
            throw new RuntimeException("OffChainAuth: 认证失败，aid: " + aid);
        }

        // 从 B_SetupAlgorithm 中获取系统参数
        SetupParams setupParams = C_SetupAlgorithm.getInstance();
        Element g1 = setupParams.g1;
        Element h = setupParams.g2;  // 使用 g2 作为 h 的占位符
        Element y = setupParams.spk;  // 假设 y 是从 spk 生成的
        Element z = setupParams.eta;  // 假设 z 是从 eta 生成的

        // Step 3: 验证零知识证明
        boolean proofValid = ZkPoK.verify(y, z, g1, h, alphaProof, betaProof);
        if (!proofValid) {
            throw new RuntimeException("OffChainAuth: 零知识证明无效，aid: " + aid);
        }

        // Step 4: 本地协商会话密钥 (假设会话密钥协商在此进行)
        String sessionKey = negotiateSessionKey();

        // Step 5: 调用合约记录认证信息
        contract.Record(aid, timestamp, "离线认证成功，资源访问已记录");

        // 返回认证结果
        return "OffChainAuth: 认证成功，sessionKey: " + sessionKey;
    }

    // 假设解析链上数据的辅助函数
    private boolean parseRstFromQueryResult(String queryResult) {
        // 实现解析逻辑，从 queryResult 中提取 Rst
        return queryResult.contains("Result: true");  // 占位符
    }

    private String parseTmpCredsFromQueryResult(String queryResult) {
        // 实现解析逻辑，从 queryResult 中提取 TmpCreds
        return queryResult.split(", Off-chain token: ")[1];  // 占位符
    }

    // 假设会话密钥协商的辅助函数
    private String negotiateSessionKey() {
        // 实现会话密钥协商逻辑
        return "negotiated_session_key";  // 占位符
    }

    public class ZkPoK {

        // 修改 verify 方法，实现新的 ZkPoK 证明验证逻辑
        public static boolean verify(Element y, Element z, Element g1, Element h, Element alphaProof, Element betaProof) {
            // 假设 alphaProof 和 betaProof 是验证者传递的零知识证明
            // 验证 y = g1^alpha
            Element yVerification = g1.duplicate().powZn(alphaProof);
            boolean yIsValid = yVerification.isEqual(y);

            // 验证 z = g1^beta * h^alpha
            Element zVerification = g1.duplicate().powZn(betaProof).mul(h.duplicate().powZn(alphaProof));
            boolean zIsValid = zVerification.isEqual(z);

            // 如果两个验证都通过，则返回 true
            return yIsValid && zIsValid;
        }
    }
}

