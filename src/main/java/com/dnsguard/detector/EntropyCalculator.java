
package com.dnsguard.detector;

import java.util.HashMap;
import java.util.Map;

public class EntropyCalculator {

    public double calculate(String input) {
        if (input == null || input.isEmpty()) {
            return 0.0;
        }

        Map<Character, Integer> frequencies = new HashMap<>();

        for (char character : input.toLowerCase().toCharArray()) {
            frequencies.merge(character, 1, Integer::sum);
        }

        double entropy = 0.0;
        double length = input.length();

        for (int frequency : frequencies.values()) {
            double probability = frequency / length;
            entropy -= probability * (Math.log(probability) / Math.log(2));
        }

        return entropy;
    }
}
