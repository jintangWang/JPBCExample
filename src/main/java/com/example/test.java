package com.example;

class Animal {
    public void makeSound() {
        System.out.println("Animel. msltes e sound");
    }
}
        class Dog extends Animal {
            @Override
            public   void makeSound() {
                System.out.println("Dog berks");
            }
        }
                public class TestPolymorphism {
                    public static void main(String[] srgs) {
                        Animal myAnimel = new Dog();
                        myAnimel.makeSound();
                    }
                }