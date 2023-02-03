package org.owasp.dependencycheck;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;

import java.io.File;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

public class MineTest {
    public static void main(String... strings) throws Throwable {
        ObjectMapper mapper = new JsonMapper();
        JsonNode original = mapper.readTree(new File("target/test-classes/jsonreport/dependencies.json"));
        JsonNode analyzed = mapper.readTree(new File("target/test-classes/jsonreport/dependency-check-complete.json"));
        Set<?> set1 = StreamSupport.stream(analyzed
                        .get("dependencies")
                        .spliterator(), false)
                .collect(Collectors.toSet());

        Set<?> set2 = StreamSupport.stream(original
                        .get("dependencies")
                        .spliterator(), false)
                .collect(Collectors.toSet());


        System.out.println(set1.removeAll(set2));
    }
}
