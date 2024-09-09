package com.example;

import it.unisa.dia.gas.jpbc.Element;

import java.util.List;

// 占位符类
class Authentication {
    Element sigma;
    Element Nym;
    List<Element> s_i_prime;
    Element W_prime;

    public Authentication(Element sigma, Element Nym, List<Element> s_i_prime, Element W_prime) {
        this.sigma = sigma;
        this.Nym = Nym;
        this.s_i_prime = s_i_prime;
        this.W_prime = W_prime;
    }

    @Override
    public String toString() {
        return "AuthObject";
    }
}
