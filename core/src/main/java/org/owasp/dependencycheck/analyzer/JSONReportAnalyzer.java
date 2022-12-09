package org.owasp.dependencycheck.analyzer;

import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.data.jsonreport.JSONReportParser;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.utils.FileFilterBuilder;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.json.stream.JsonParsingException;
import java.io.FileFilter;
import java.io.FileInputStream;
import java.io.IOException;

/**
 * Used to analyze pre-existing json report files to eliminate the need to re-scan a project each
 * time the dependencies need to be checked against the vulnerability database.
 *
 * @author Silas de Graaf
 */
public class JSONReportAnalyzer extends AbstractFileTypeAnalyzer {

    /**
     * The logger for use throughout this class.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(JSONReportAnalyzer.class);

    /**
     * The name of the analyzer.
     */
    private static final String ANALYZER_NAME = "JSON Report Analyzer";

    /**
     * Name of the file to analyze.
     */
    public static final String DEPENDENCIES_JSON = "dependencies.json";

    /**
     * The file filter for dependencies.json
     */
    private static final FileFilter JSON_FILTER = FileFilterBuilder.newInstance()
            .addFilenames(DEPENDENCIES_JSON)
            .build();

    /**
     * Returns the name of the JSON Report Analyzer.
     *
     * @return the name of the analyzer
     */
    @Override
    public String getName() {
        return ANALYZER_NAME;
    }

    /**
     * Specify that this analyzer is used for information collection.
     *
     * @return INFORMATION_COLLECTION
     */
    @Override
    public AnalysisPhase getAnalysisPhase() {
        return AnalysisPhase.INFORMATION_COLLECTION;
    }

    /**
     * Returns the key name for the analyzers enabled setting.
     *
     * @return the key name for the analyzers enabled setting
     */
    @Override
    protected String getAnalyzerEnabledSettingKey() {
        return Settings.KEYS.ANALYZER_REPORT_JSON_ENABLED;
    }

    /**
     * Returns the FileFilter
     *
     * @return the FileFilter
     */
    @Override
    protected FileFilter getFileFilter() {
        return JSON_FILTER;
    }

    /**
     * Initialize the analyzer. Do nothing.
     *
     * @param engine a reference to the dependency-check engine
     * @throws InitializationException never thrown
     */
    @Override
    protected void prepareFileTypeAnalyzer(Engine engine) throws InitializationException {
        // do nothing
    }

    /**
     * Entry point for the analyzer.
     *
     * @param dependency the dependency to analyze
     * @param engine the engine scanning
     * @throws AnalysisException if there's a failure during analysis
     */
    @Override
    protected void analyzeDependency(Dependency dependency, Engine engine) throws AnalysisException {
        engine.removeDependency(dependency);
        try (FileInputStream fis = new FileInputStream(dependency.getActualFile())) {
            final JSONReportParser parser = new JSONReportParser(fis);
            parser.process();
            parser.getDependencies().forEach(dep -> {
                LOGGER.debug("Adding dependency {}", dep.getDisplayFileName());
                engine.addDependency(dep);
            });
        } catch (IOException ex) {
            LOGGER.warn("Error opening dependency {}", dependency.getActualFilePath(), ex);
        } catch (JsonParsingException ex) {
            LOGGER.warn("Error parsing dependencies.json {}", dependency.getActualFilePath(), ex);
        }
    }
}
