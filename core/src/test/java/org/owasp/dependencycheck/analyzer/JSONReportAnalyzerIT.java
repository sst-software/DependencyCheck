package org.owasp.dependencycheck.analyzer;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.exception.ExceptionCollection;
import org.owasp.dependencycheck.exception.ReportException;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Testing the JSON Report Analyzer.
 *
 * @author Silas de Graaf
 */
public class JSONReportAnalyzerIT extends BaseTest {
    private static final Logger LOGGER = LoggerFactory.getLogger(PipAnalyzerIT.class);

    /**
     * The analyzer to test.
     */
    private JSONReportAnalyzer analyzer;

    /**
     * Correctly setup the analyzer for testing.
     *
     * @throws Exception thrown if there is a problem
     */
    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        getSettings().setBoolean(Settings.KEYS.ANALYZER_REPORT_JSON_ENABLED, true);
        analyzer = new JSONReportAnalyzer();
        analyzer.setFilesMatched(true);
        analyzer.initialize(getSettings());
    }

    /**
     * Cleanup the analyzer's temp files, etc.
     *
     * @throws Exception thrown if there is a problem
     */
    @After
    @Override
    public void tearDown() throws Exception {
        if (analyzer != null) {
            getSettings().setBoolean(Settings.KEYS.ANALYZER_REPORT_JSON_ENABLED, false);
            analyzer.close();
            analyzer = null;
        }
        super.tearDown();
    }

    /**
     * Tests if the original report and the report generated from the JSON Report Analyzer are equal.
     *
     * @throws AnalysisException thrown if there is a problem
     */
    @Test
    public void testNoChange() throws ReportException, IOException {
        String testClasses = "target/test-classes";

        //settings
        getSettings().setBoolean(Settings.KEYS.AUTO_UPDATE, false);
        getSettings().setBoolean(Settings.KEYS.ANALYZER_EXPERIMENTAL_ENABLED, true);
        getSettings().setBoolean(Settings.KEYS.PRETTY_PRINT, true);

        //Analyzers that the JSON Report Analyzer does not work on
        getSettings().setBoolean(Settings.KEYS.ANALYZER_NODE_AUDIT_ENABLED, false);
        getSettings().setBoolean(Settings.KEYS.ANALYZER_YARN_AUDIT_ENABLED, false);
        getSettings().setBoolean(Settings.KEYS.ANALYZER_PNPM_AUDIT_ENABLED, false);
        getSettings().setBoolean(Settings.KEYS.ANALYZER_RETIREJS_ENABLED, false);

        //Experimental analyzers that the JSON Report Analyzer does not work on
        getSettings().setBoolean(Settings.KEYS.ANALYZER_GOLANG_MOD_ENABLED, false);
        getSettings().setBoolean(Settings.KEYS.ANALYZER_PE_ENABLED, false);
        getSettings().setBoolean(Settings.KEYS.ANALYZER_MAVEN_INSTALL_ENABLED, false);


        getSettings().disableAllAnalyzers();
        getSettings().setBoolean(Settings.KEYS.ANALYZER_JAR_ENABLED, true);
        getSettings().setBoolean(Settings.KEYS.ANALYZER_NVD_CVE_ENABLED, true);
        getSettings().setBoolean(Settings.KEYS.ANALYZER_REPORT_JSON_ENABLED, true);
        getSettings().setBoolean(Settings.KEYS.ANALYZER_DEPENDENCY_BUNDLING_ENABLED, true);
        getSettings().setBoolean(Settings.KEYS.ANALYZER_DEPENDENCY_MERGING_ENABLED, true);
        getSettings().setBoolean(Settings.KEYS.ANALYZER_NPM_CPE_ENABLED, true);
        getSettings().setBoolean(Settings.KEYS.ANALYZER_CPE_SUPPRESSION_ENABLED, true);
        getSettings().setBoolean(Settings.KEYS.ANALYZER_CPE_ENABLED, true);
        getSettings().setBoolean(Settings.KEYS.ANALYZER_CENTRAL_ENABLED, true);
        getSettings().setBoolean(Settings.KEYS.ANALYZER_HINT_ENABLED, true);
        getSettings().setBoolean(Settings.KEYS.ANALYZER_VERSION_FILTER_ENABLED, true);


        ExceptionCollection exceptions = null;
        try (Engine instance = new Engine(getSettings())) {
            // delete dependencies.json in case it wasn't deleted on the last test run
            new File("./target/test-classes/jsonreport/dependencies.json").delete();
            instance.scan(testClasses);
            assertTrue(instance.getDependencies().length > 0);
            try {
                instance.analyzeDependencies();
            } catch (ExceptionCollection ex) {
                exceptions = ex;
            }
            instance.writeReports("dependency-check sample", new File("./target/test-classes/jsonreport/"), "COMPLETE"
                    , exceptions);
        }

        Path source = Paths.get("./target/test-classes/jsonreport/dependency-check-complete.json");
        Path target = Paths.get("./target/test-classes/jsonreport/dependencies.json");
        Files.copy(source, target, StandardCopyOption.REPLACE_EXISTING);

        try (Engine engine = new Engine(getSettings())) {
            List<File> files = new ArrayList<>();
            // the main file to scan
            files.add(BaseTest.getResourceAsFile(this, "jsonreport/dependencies.json"));

            engine.scan(files);
            ExceptionCollection exceptions2 = null;
            try {
                engine.analyzeDependencies();
            } catch (ExceptionCollection ex) {
                exceptions2 = ex;
            }
            engine.writeReports("dependency-check sample", new File("./target/test-classes/jsonreport/"), "COMPLETE",
                    exceptions2);
        }

        ObjectMapper mapper = new JsonMapper();
        JsonNode original = mapper.readTree(BaseTest.getResourceAsFile(this, "jsonreport/dependencies.json"));
        JsonNode analyzed = mapper.readTree(BaseTest.getResourceAsFile(this,
                "jsonreport/dependency-check-complete" + ".json"));

        assertEquals(StreamSupport.stream(original.get("dependencies").spliterator(), false).collect(Collectors.toSet()), StreamSupport.stream(analyzed.get("dependencies").spliterator(), false).collect(Collectors.toSet()));

        // delete dependencies.json so it doesn't get analyzed itself in the next scan
//        BaseTest.getResourceAsFile(this, "jsonreport/dependencies.json").delete();
    }
}
