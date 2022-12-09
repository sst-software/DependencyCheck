package org.owasp.dependencycheck.data.jsonreport;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import org.owasp.dependencycheck.data.composer.ComposerException;
import org.owasp.dependencycheck.dependency.*;
import org.owasp.dependencycheck.dependency.naming.CpeIdentifier;
import org.owasp.dependencycheck.dependency.naming.GenericIdentifier;
import org.owasp.dependencycheck.dependency.naming.Identifier;
import org.owasp.dependencycheck.dependency.naming.PurlIdentifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import us.springett.parsers.cpe.CpeParser;
import us.springett.parsers.cpe.exceptions.CpeParsingException;

import javax.json.*;
import javax.json.stream.JsonParsingException;
import java.io.InputStream;
import java.util.*;
import java.util.stream.Collectors;

public class JSONReportParser {

    /**
     * The JsonReader for parsing JSON
     */
    private final JsonReader jsonReader;

    /**
     * The List of ComposerDependencies found
     */
    private final List<Dependency> dependencies;

    /**
     * The LOGGER
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(JSONReportParser.class);

    /**
     * Creates a ComposerLockParser from a JsonReader and an InputStream.
     *
     * @param inputStream the InputStream to parse
     */
    public JSONReportParser(InputStream inputStream) {
        LOGGER.debug("Creating a JSONReportParser");
        this.jsonReader = Json.createReader(inputStream);
        this.dependencies = new ArrayList<>();
    }

    /**
     * Process the input stream to create the list of dependencies.
     */
    public void process() {
        LOGGER.debug("Beginning dependencies.json processing");
        try {
            final JsonObject report = jsonReader.readObject();

            LOGGER.debug("Analyzing dependencies");
            final JsonArray dependencies = report.getJsonArray("dependencies");
            for (JsonObject dep : dependencies.getValuesAs(JsonObject.class)) {
                Dependency dependency = parseStandard(dep);

                if (dep.containsKey("availableVersions")) {
                    dep.getJsonArray("availableVersions")
                            .getValuesAs(JsonString.class)
                            .forEach(version -> {
                                dependency.addAvailableVersion(version.getString());
                            });
                }

                if (dep.containsKey("projectReferences")) {
                    dependency.addAllProjectReferences(dep
                            .getJsonArray("projectReferences")
                            .getValuesAs(JsonString.class)
                            .stream()
                            .map(JsonString::getString)
                            .collect(Collectors.toSet()));
                }

                if (dep.containsKey("relatedDependencies")) {
                    dep.getJsonArray("relatedDependencies")
                            .getValuesAs(JsonObject.class)
                            .forEach(related -> {
                                try {
                                    dependency.addRelatedDependency(parseRelated(related));
                                } catch (MalformedPackageURLException e) {
                                    throw new RuntimeException(e);
                                }
                            });
                }
                JsonObject evidence = dep.getJsonObject("evidenceCollected");
                JsonArray vendorList = evidence.getJsonArray("vendorEvidence");
                for (JsonValue vendor : vendorList) {
                    dependency.addEvidence(EvidenceType.VENDOR, parseEvidence(vendor.asJsonObject()));
                }
                if (evidence.containsKey("vendorWeightings")) {
                    evidence.getJsonArray("vendorWeightings")
                            .getValuesAs(JsonString.class)
                            .forEach(weighting -> {
                                dependency.addVendorWeighting(weighting.getString());
                            });
                }
                JsonArray productList = evidence.getJsonArray("productEvidence");
                for (JsonValue product : productList) {
                    dependency.addEvidence(EvidenceType.PRODUCT, parseEvidence(product.asJsonObject()));
                }
                if (evidence.containsKey("productWeightings")) {
                    evidence.getJsonArray("productWeightings")
                            .getValuesAs(JsonString.class)
                            .forEach(weighting -> {
                                dependency.addProductWeighting(weighting.getString());
                            });
                }
                JsonArray versionList = evidence.getJsonArray("versionEvidence");
                for (JsonValue version : versionList) {
                    dependency.addEvidence(EvidenceType.VERSION, parseEvidence(version.asJsonObject()));
                }

                parseIdentifier(dep, "packages").forEach(dependency::addSoftwareIdentifier);
                parseIdentifier(dep, "vulnerabilityIds").forEach(dependency::addVulnerableSoftwareIdentifier);
                parseIdentifier(dep, "suppressedVulnerabilityIds").forEach(dependency::addSuppressedIdentifier);

//                if (dep.containsKey("vulnerabilities")) {
//                    dependency.addVulnerabilities(dep
//                            .getJsonArray("vulnerabilities")
//                            .getValuesAs(JsonObject.class)
//                            .stream()
//                            .map(this::parseVulnerability)
//                            .collect(Collectors.toList()));
//                }

                this.dependencies.add(dependency);
            }
        } catch (MalformedPackageURLException ex) {
            throw new JSONReportParseException("Problem parsing Identifier", ex);
        } catch (JsonParsingException ex) {
            throw new JSONReportParseException("Problem parsing json file", ex);
        } catch (ClassCastException ex) {
            throw new JSONReportParseException("Incorrect json structure", ex);
        }
    }

    /**
     * Parses the standard values of a dependency from a JsonObject into a new Dependency object
     * @param obj JsonObject to be parsed
     * @return parsed Dependency
     */
    private Dependency parseStandard(JsonObject obj) {
        boolean isVirtual = obj.getBoolean("isVirtual");
        Dependency dependency = new Dependency(isVirtual);
        dependency.setFileName(obj.getString("fileName"));
        if (obj.containsKey("filePath")) {
            dependency.setFilePath(obj.getString("filePath"));
        }
        if (obj.containsKey("actualFilePath")) {
            dependency.setActualFilePath(obj.getString("actualFilePath"));
        }
        if (obj.containsKey("md5")) {
            dependency.setMd5sum(obj.getString("md5"));
        }
        if (obj.containsKey("sha1")) {
            dependency.setSha1sum(obj.getString("sha1"));
        }
        if (obj.containsKey("sha256")) {
            dependency.setSha256sum(obj.getString("sha256"));
        }
        if (obj.containsKey("description")) {
            dependency.setDescription(obj.getString("description"));
        }
        if (obj.containsKey("license")) {
            dependency.setLicense(obj.getString("license"));
        }
        if (obj.containsKey("packagePath")) {
            dependency.setPackagePath(obj.getString("packagePath"));
        }
        if (obj.containsKey("displayName")) {
            dependency.setDisplayFileName(obj.getString("displayName"));
        }
        if (obj.containsKey("name")) {
            dependency.setName(obj.getString("name"));
        }
        if (obj.containsKey("version")) {
            dependency.setVersion(obj.getString("version"));
        }
        if (obj.containsKey("ecosystem")) {
            dependency.setEcosystem(obj.getString("ecosystem"));
        }
        return dependency;
    }

    /**
     * Parses JsonObject into a dependency to add as related to an existing one
     * @param obj JsonObject to be parsed
     * @return parsed Dependency
     * @throws MalformedPackageURLException
     */
    private Dependency parseRelated(JsonObject obj) throws MalformedPackageURLException {
        Dependency dep = parseStandard(obj);
        parseIdentifier(obj, "packageIds").forEach(dep::addSoftwareIdentifier);
        return dep;
    }

    /**
     * Parses JsonObject into Identifiers given a key
     * @param obj JsonObject to be parsed
     * @param key Key to be used
     * @return Collection of parsed identifiers
     * @throws MalformedPackageURLException
     */
    private Collection<Identifier> parseIdentifier(JsonObject obj, String key) throws MalformedPackageURLException {
        if (obj.containsKey(key)) {
            JsonArray packages = obj.getJsonArray(key);
            return packages.getValuesAs(JsonObject.class).stream().map(pack -> {
                Identifier id;
                String idValue = pack.getString("id");
                if (idValue.startsWith("pkg")) {
                    try {
                        id = new PurlIdentifier(
                                new PackageURL(idValue),
                                Confidence.valueOf(pack.getString("confidence")));
                    } catch (MalformedPackageURLException e) {
                        throw new RuntimeException(e);
                    }
                } else if (idValue.startsWith("cpe")) {
                    try {
                        id = new CpeIdentifier(CpeParser.parse(idValue),
                                Confidence.valueOf(pack.getString("confidence")));
                    } catch (CpeParsingException e) {
                        throw new RuntimeException(e);                    }
                } else {
                    id = new GenericIdentifier(idValue,
                            Confidence.valueOf(pack.getString("confidence")));
                }
                if (pack.containsKey("url")) {
                    id.setUrl(pack.getString("url"));
                }
                if (pack.containsKey("notes")) {
                    id.setNotes(pack.getString("notes"));
                }
                return id;
            }).collect(Collectors.toSet());
        }
        return new HashSet<>();
    }

    /**
     * Parses JsonObject into Evidence
     *
     * @param obj JsonObject to be parsed
     * @return parsed Evidence
     */
    private Evidence parseEvidence(JsonObject obj) {
        Evidence evidence = new Evidence();
        evidence.setConfidence(Confidence.valueOf(obj.getString("confidence")));
        evidence.setSource(obj.getString("source"));
        evidence.setName(obj.getString("name"));
        evidence.setValue(obj.getString("value"));
        return evidence;
    }

//    /**
//     * Parses a JsonObject into a Vulnerability
//     * @Param obj JsonObject to be parsed
//     * @return parsed Vulnerability
//     */
//    private Vulnerability parseVulnerability(JsonObject obj) {
//        Vulnerability vul = new Vulnerability(obj.getString("name"));
//        vul.setSource(Vulnerability.Source.valueOf(obj.getString("source")));
//        if (obj.containsKey("unscored") && obj.getBoolean("unscored")) {
//            vul.setUnscoredSeverity(obj.getString("severity"));
//        }
//        if (obj.containsKey("cvssv2")) {
//            vul.setCvssV2(parseCvssV2(obj.getJsonObject("cvssv2")));
//        }
//    }
//
//    private CvssV2 parseCvssV2(JsonObject obj) {
//        return new CvssV2(
//                parseFloat(obj.getString("score")),
//                obj.getString("accessVector"),
//
//        );
//    }


    /**
     * Gets the list of dependencies.
     *
     * @return the list of dependencies
     */
    public List<Dependency> getDependencies() {
        return dependencies;
    }
}
