package org.owasp.dependencycheck.analyzer;

import org.apache.commons.lang3.ArrayUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.owasp.dependencycheck.BaseDBTestCase;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.EvidenceType;

import java.io.File;
import java.util.ArrayList;

import static org.junit.Assert.*;

/**
 * Unit tests for JSONReportAnalyzer.
 *
 * @author Silas de Graaf
 */
public class JSONReportAnalyzerTest extends BaseDBTestCase {

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
        analyzer = new JSONReportAnalyzer();
        analyzer.initialize(getSettings());
        analyzer.setFilesMatched(true);
        analyzer.prepare(null);
    }

    /**
     * Cleanup the analyzer's temp files, etc.
     *
     * @throws Exception thrown if there is a problem
     */
    @After
    @Override
    public void tearDown() throws Exception {
        analyzer.close();
        super.tearDown();
    }

    /**
     * Test of getName method, of class JSONReportAnalyzer.
     */
    @Test
    public void testGetName() {
        assertEquals("JSON Report Analyzer", analyzer.getName());
    }

    /**
     * Test of getAnalysisPhase method, of class JSONReportAnalyzer.
     */
    @Test
    public void testGetAnalysisPhase() {
        assertEquals(analyzer.getAnalysisPhase(), AnalysisPhase.INFORMATION_COLLECTION);
    }

    /**
     * Test of getAnalyzerEnabledSettingKey method, of class JSONReportAnalyzer.
     */
    @Test
    public void testGetAnalyzerEnabledSettingKey() {
        assertEquals(analyzer.getAnalyzerEnabledSettingKey(), "analyzer.report.json.enabled");
    }

    /**
     * Test of supportsExtension method, of class JSONReportAnalyzer.
     */
    @Test
    public void testSupportsFiles() {
        assertTrue(analyzer.accept(new File("dependencies.json")));
    }

    /**
     * Test of analyzeDependency method, of class PythonDistributionAnalyzer.
     *
     * @throws AnalysisException is thrown when an exception occurs.
     */
    @Test
    public void testAnalyzeDependency() throws Exception {
        try (Engine engine = new Engine(getSettings())) {
            final Dependency source = new Dependency(BaseTest.getResourceAsFile(this,
                    "dependencies.json"));
            //simulate normal operation when the dependencies.json is already added to the engine as a dependency
            engine.addDependency(source);
            analyzer.analyze(source, engine);
            //make sure the redundant dependencies.json is removed
            assertFalse(ArrayUtils.contains(engine.getDependencies(), source));
            assertEquals(10, engine.getDependencies().length);
            boolean found = false;
            for (Dependency d : engine.getDependencies()) {
                if ("loader-utils:2.0.2".equals(d.getFileName())) {
                    found = true;
                    assertEquals(1, d.getEvidence(EvidenceType.PRODUCT).size());
                    assertEquals("2.0.2", new ArrayList<>(d.getEvidence(EvidenceType.VERSION)).get(0).getValue());
                    assertEquals(new ArrayList<>(d.getSoftwareIdentifiers()).get(0).getUrl(), "https://ossindex.sonatype.org/component/pkg:npm/loader-utils@2.0.2?utm_source=dependency-check&utm_medium=integration&utm_content=7.3.0");
                }
            }
            assertTrue("Expected to find loader-utils", found);
        }
    }
}

