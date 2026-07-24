package com.example;

/**
 * Example usage in Javadoc:
 *   Class.forName("com.example.ghost.Driver")
 *   Class.forName("org.sqlite.JDBC")
 *
 * These should NOT fire the reflection heuristic — they live in comments.
 */
public class A {
    public void real() throws Exception {
        // This genuine Class.forName call MUST register as reflective.
        Class.forName("com.example.real.Driver");
    }
}
