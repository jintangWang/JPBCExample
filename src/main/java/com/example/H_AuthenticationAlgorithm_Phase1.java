package com.example;

import com.example.C_SetupAlgorithm.SetupParams;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

public class H_AuthenticationAlgorithm_Phase1 {

    private static Element b, s, g1h;
    private static Element[] s_i;
    private static Element[][] M, N, T;
    private static Element[] X, Y1, Y2;
    private static int t = 5; // 假设 t 是 5

    public static void main(String[] args) {
        runAuthentication();
    }

    public static void runAuthentication() {
        SetupParams setupParams = C_SetupAlgorithm.getInstance();
        Pairing pairing = setupParams.pairing;
        Element g2 = setupParams.g2;
        g1h = setupParams.g1;

        F_PolicyGenerationAlgorithm.initializeSetupParams(setupParams);  // 初始化参数
        // 从 E_CredentialIssuanceAlgorithm 获取 b
        Element[] credential = E_CredentialIssuanceAlgorithm.getCredential();
        b = credential[1];
        s = credential[2];

        // 从 F_PolicyGenerationAlgorithm 获取 s_i
        s_i = F_PolicyGenerationAlgorithm.generateAuthenticationPolicy("CV1");


        // 假设 M, N, T, X, Y1, Y2 已经初始化并赋值
        // 选择一个随机数 epsilon ∈ G_p^*
        Element epsilon = pairing.getZr().newRandomElement().getImmutable();

        // 对 b 和 s 执行模糊签名变换
        Element b_epsilon = b.powZn(epsilon).getImmutable();   // b^epsilon
        Element s_epsilon = s.powZn(epsilon).getImmutable();   // s^epsilon

        // 生成零知识证明 pi_sigma'
        Element[] zkProof = ZkPoK_SigmaPrime.generateZKProof(epsilon, M, N, T, X, Y1, Y2, s_epsilon, b_epsilon, pairing, g1h, g2, t);

        // 如果生成失败，退出
        if (zkProof == null) {
            System.out.println("零知识证明生成失败");
            return;
        }

        // 模拟传输给区块链的过程并验证
        boolean isValid = ZkPoK_SigmaPrime.verifyZKProof(zkProof, M, N, T, X, Y1, Y2, g1h, g2, pairing, s_epsilon, b_epsilon, t);

        if (isValid) {
            System.out.println("零知识证明验证成功，认证通过");
        } else {
            System.out.println("零知识证明验证失败，认证拒绝");
        }
    }
}
