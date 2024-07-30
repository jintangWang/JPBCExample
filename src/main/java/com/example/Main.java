package com.example;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class Main {
    public static void main(String[] args) {
        Pairing pairing = PairingFactory.getPairing("params/curves/a/a.properties");
        Element g = pairing.getG1().newRandomElement();
        Element h = pairing.getG1().newRandomElement();

        Element result = pairing.pairing(g, h);
        System.out.println("g: " + g);
        System.out.println("h: " + h);
        System.out.println("Result of pairing: " + result);
    }
}
