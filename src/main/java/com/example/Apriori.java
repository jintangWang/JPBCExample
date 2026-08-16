package com.example;

import java.util.*;

public class Apriori {

    public static Set<Set<String>> generateCandidates(Set<Set<String>> frequentItemsets, int k) {
        Set<Set<String>> candidates = new HashSet<>();
        for (Set<String> itemset1 : frequentItemsets) {
            for (Set<String> itemset2 : frequentItemsets) {
                Set<String> union = new HashSet<>(itemset1);
                union.addAll(itemset2);
                if (union.size() == k) {
                    candidates.add(union);
                }
            }
        }
        return candidates;
    }

    public static List<Rule> apriori(List<Set<String>> transactions, double minSupport, double minConfidence) {
        Set<String> items = new HashSet<>();
        for (Set<String> transaction : transactions) {
            items.addAll(transaction);
        }

        Set<Set<String>> itemset = new HashSet<>();
        for (String item : items) {
            Set<String> singleton = new HashSet<>();
            singleton.add(item);
            itemset.add(singleton);
        }

        Map<Set<String>, Integer> itemsetCount = new HashMap<>();
        int n = transactions.size();

        // Count occurrences of each itemset
        for (Set<String> transaction : transactions) {
            for (Set<String> item : itemset) {
                if (transaction.containsAll(item)) {
                    itemsetCount.put(item, itemsetCount.getOrDefault(item, 0) + 1);
                }
            }
        }

        List<Set<Set<String>>> frequentItemsets = new ArrayList<>();
        frequentItemsets.add(new HashSet<>());
        for (Set<String> item : itemset) {
            if ((itemsetCount.getOrDefault(item, 0) / (double) n) >= minSupport) {
                frequentItemsets.get(0).add(item);
            }
        }

        int k = 2;
        while (!frequentItemsets.get(frequentItemsets.size() - 1).isEmpty()) {
            Set<Set<String>> candidates = generateCandidates(frequentItemsets.get(frequentItemsets.size() - 1), k);
            for (Set<String> candidate : candidates) {
                for (Set<String> transaction : transactions) {
                    if (transaction.containsAll(candidate)) {
                        itemsetCount.put(candidate, itemsetCount.getOrDefault(candidate, 0) + 1);
                    }
                }
            }
            Set<Set<String>> frequentSet = new HashSet<>();
            for (Set<String> candidate : candidates) {
                if ((itemsetCount.getOrDefault(candidate, 0) / (double) n) >= minSupport) {
                    frequentSet.add(candidate);
                }
            }
            frequentItemsets.add(frequentSet);
            k++;
        }

        List<Set<String>> allFrequentItemsets = new ArrayList<>();
        for (Set<Set<String>> sets : frequentItemsets) {
            allFrequentItemsets.addAll(sets);
        }

        // Generate association rules
        List<Rule> rules = new ArrayList<>();
        for (Set<String> currentItemset : allFrequentItemsets) {
            if (currentItemset.size() > 1) {
                List<String> itemList = new ArrayList<>(currentItemset);
                int setSize = currentItemset.size();
                for (int i = 1; i < setSize; i++) {
                    List<Set<String>> combinations = getCombinations(itemList, i);
                    for (Set<String> antecedent : combinations) {
                        Set<String> consequent = new HashSet<>(currentItemset);
                        consequent.removeAll(antecedent);
                        if (itemsetCount.containsKey(antecedent) && itemsetCount.containsKey(currentItemset)) {
                            double confidence = itemsetCount.get(currentItemset) / (double) itemsetCount.get(antecedent);
                            if (confidence >= minConfidence) {
                                double support = itemsetCount.get(currentItemset) / (double) n;
                                rules.add(new Rule(antecedent, consequent, support, confidence));
                            }
                        }
                    }
                }
            }
        }

        return rules;
    }

    // Generate combinations of items
    public static List<Set<String>> getCombinations(List<String> items, int k) {
        List<Set<String>> result = new ArrayList<>();
        generateCombinations(items, new HashSet<>(), 0, k, result);
        return result;
    }

    private static void generateCombinations(List<String> items, Set<String> current, int index, int k, List<Set<String>> result) {
        if (current.size() == k) {
            result.add(new HashSet<>(current));
            return;
        }
        if (index == items.size()) {
            return;
        }
        current.add(items.get(index));
        generateCombinations(items, current, index + 1, k, result);
        current.remove(items.get(index));
        generateCombinations(items, current, index + 1, k, result);
    }

    public static void main(String[] args) {
        // First dataset
        List<Set<String>> transactions1 = Arrays.asList(
                new HashSet<>(Arrays.asList("student", "teach", "school")),
                new HashSet<>(Arrays.asList("student", "school", "mathematics")),
                new HashSet<>(Arrays.asList("teach", "school", "city", "game")),
                new HashSet<>(Arrays.asList("basketball", "football")),
                new HashSet<>(Arrays.asList("basketball", "sporter", "audience")),
                new HashSet<>(Arrays.asList("football", "trainer", "game", "team")),
                new HashSet<>(Arrays.asList("basketball", "team", "city", "game"))
        );

        double minSupport = 0.2;
        double minConfidence = 0.6;

        List<Rule> rules1 = apriori(transactions1, minSupport, minConfidence);

        System.out.println("Rules for the first dataset:");
        for (Rule rule : rules1) {
            System.out.printf("%s -> %s (Support: %.2f, Confidence: %.2f)\n", rule.antecedent, rule.consequent, rule.support, rule.confidence);
        }

        // Second dataset
        List<Set<String>> transactions2 = Arrays.asList(
                new HashSet<>(Arrays.asList("Blouse")),
                new HashSet<>(Arrays.asList("Shoes", "Skirt", "TShirt")),
                new HashSet<>(Arrays.asList("Jeans", "TShirt")),
                new HashSet<>(Arrays.asList("Jeans", "Shoes", "TShirt")),
                new HashSet<>(Arrays.asList("Jeans", "Shorts")),
                new HashSet<>(Arrays.asList("Shoes", "TShirt")),
                new HashSet<>(Arrays.asList("Jeans", "Skirt")),
                new HashSet<>(Arrays.asList("Jeans", "Shoes", "Shorts", "TShirt")),
                new HashSet<>(Arrays.asList("Jeans")),
                new HashSet<>(Arrays.asList("Jeans", "Shoes", "TShirt")),
                new HashSet<>(Arrays.asList("TShirt")),
                new HashSet<>(Arrays.asList("Blouse", "Jeans", "Shoes", "Skirt", "TShirt")),
                new HashSet<>(Arrays.asList("Jeans", "Shoes", "Shorts", "TShirt")),
                new HashSet<>(Arrays.asList("Shoes", "Skirt", "TShirt")),
                new HashSet<>(Arrays.asList("Jeans", "TShirt")),
                new HashSet<>(Arrays.asList("Skirt", "TShirt")),
                new HashSet<>(Arrays.asList("Blouse", "Jeans", "Skirt")),
                new HashSet<>(Arrays.asList("Jeans", "Shoes", "Shorts", "TShirt")),
                new HashSet<>(Arrays.asList("Jeans")),
                new HashSet<>(Arrays.asList("Jeans", "Shoes", "Shorts", "TShirt"))
        );

        List<Rule> rules2 = apriori(transactions2, minSupport, minConfidence);

        System.out.println("\nRules for the second dataset:");
        for (Rule rule : rules2) {
            System.out.printf("%s -> %s (Support: %.2f, Confidence: %.2f)\n", rule.antecedent, rule.consequent, rule.support, rule.confidence);
        }
    }
}

// Helper class to store rules
class Rule {
    Set<String> antecedent;
    Set<String> consequent;
    double support;
    double confidence;

    public Rule(Set<String> antecedent, Set<String> consequent, double support, double confidence) {
        this.antecedent = antecedent;
        this.consequent = consequent;
        this.support = support;
        this.confidence = confidence;
    }
}
