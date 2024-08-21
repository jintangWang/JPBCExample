package com.example;

import org.hyperledger.fabric.contract.Context;
import org.hyperledger.fabric.contract.ContractInterface;
import org.hyperledger.fabric.contract.annotation.Contract;
import org.hyperledger.fabric.contract.annotation.Transaction;
import org.hyperledger.fabric.shim.ChaincodeStub;

import java.util.HashMap;
import java.util.Map;

@Contract(name = "AuthenticationContract")
public class F_AuthenticationContract implements ContractInterface {

    private static final Map<String, Object> State = new HashMap<>();
    private static final Map<String, Object> Req = new HashMap<>();
    private static final Map<String, Object> IDs = new HashMap<>();
    private static final Map<String, Object> TmpCreds = new HashMap<>();
    private static final Map<String, Integer> Vote = new HashMap<>();
    private static final Map<String, Integer> Num = new HashMap<>();
    private static final Map<String, Object> Share = new HashMap<>();
    private static final Map<String, Boolean> Rst = new HashMap<>();
    private static final Map<String, String> Rec = new HashMap<>();

    private static int T; // Credential Committee Members count
    private static Map<String, Object> params; // System parameters like pp, spk, etc.

    @Transaction
    public void Init(Context ctx, int t, Map<String, Object> systemParams) {
        T = t;  // Set number of credential committee members
        params = systemParams;  // Initialize system parameters

        State.clear();
        Req.clear();
        IDs.clear();
        TmpCreds.clear();
        Vote.clear();
        Share.clear();
        Rst.clear();
        Rec.clear();
        Num.clear();

        System.out.println("Init: Contract parameters have been initialized");
    }

    @Transaction
    public void Auth(Context ctx, String aid, String auth, String ID, String proofAuth, String delta) {
        System.out.println("Auth: Received authentication request from holder");

        // Assert 0 = State[aid]
        if (State.get(aid) != null && (int) State.get(aid) != 0) {
            throw new RuntimeException("Auth: Invalid state for aid: " + aid);
        }

        Req.put(aid, auth);
        IDs.put(aid, ID);
        TmpCreds.put(aid, delta);
        Num.put(aid, 0);
        Rst.put(aid, false);
        State.put(aid, 1); // Update state to 1
        Vote.put(aid, 1); // Initialize vote state to 1

        System.out.println("Auth: Authentication request processed, state updated to 1");
    }

    @Transaction
    public void Vote(Context ctx, String aid, String CCM_i, int T_i, String proofVote, int tag) {
        System.out.println("Vote: Received voting request from committee member");

        // Assert 1 = State[aid]
        if (State.get(aid) == null || (int) State.get(aid) != 1) {
            throw new RuntimeException("Vote: Invalid state for aid: " + aid);
        }

        if (Num.get(aid) == T_i && Vote.get(aid) == 1) {
            // If T = Num[aid] and 1 = Vote[aid], compute final result
            Rst.put(aid, check(Share.get(aid)));
            State.put(aid, 2); // Update state to 2
            System.out.println("Vote: All committee members voted, state updated to 2");
        } else {
            // Assert 0 = CCM_i[aid].Submit()
            if (tag == 1) {
                boolean zkProofValid = zkVerify(CCM_i, proofVote);
                if (zkProofValid) {
                    Num.put(aid, Num.get(aid) + 1);
                    Share.put(aid, T_i);
                    System.out.println("Vote: Vote passed, incremented vote count");
                } else {
                    System.out.println("Vote: Zero-knowledge proof verification failed");
                }
            } else {
                Vote.put(aid, 0);
                System.out.println("Vote: Voting failed, updated vote state to 0");
            }
        }
    }

    @Transaction
    public String Query(Context ctx, String aid) {
        System.out.println("Query: Querying authentication result");

        if (State.get(aid) != null && (int) State.get(aid) == 2) {
            return "Result: " + Rst.get(aid) + ", Off-chain token: " + TmpCreds.get(aid);
        }
        return "Query: Invalid state for aid: " + aid;
    }

    @Transaction
    public void Record(Context ctx, String aid, String timestamp, String desc) {
        System.out.println("Record: Recording off-chain authentication result");

        if (State.get(aid) != null && (int) State.get(aid) == 2) {
            Rec.put(aid, timestamp + ":" + desc);
            System.out.println("Record: Successfully recorded");
        } else {
            throw new RuntimeException("Record: Invalid state for aid: " + aid);
        }
    }

    @Transaction
    public String Audit(Context ctx, String aid) {
        System.out.println("Audit: Auditing user identity");

        if (State.get(aid) != null && (int) State.get(aid) == 2) {
            return "User ID: " + IDs.get(aid);
        }
        return "Audit: Invalid state for aid: " + aid;
    }

    private boolean check(Object share) {
        // Simulated check function
        return true;
    }

    private boolean zkVerify(String CCM_i, String proofVote) {
        // Simulated zero-knowledge proof verification
        return true;
    }
}
