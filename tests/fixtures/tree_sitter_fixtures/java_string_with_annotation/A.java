package com.example;

import org.springframework.stereotype.Service;

@Service
public class A {
    /**
     * Documents the REST controller pattern:
     *   @RestController
     * Also shows Spring DI:
     *   @Autowired private Dep dep;
     */
    private String doc = "@Autowired private Foo foo;";
    private String snippet = "@RestController public class Ghost {}";
    private String another = "use @Qualifier(\"bean\")";

    public void real() {
        // ... the only real annotation on this class is @Service above.
    }
}
